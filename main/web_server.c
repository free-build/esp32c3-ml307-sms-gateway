#include "web_server.h"

#include "cJSON.h"
#include "config_store.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "modem_service.h"
#include "sms_service.h"
#include "web_ui.h"
#include "wifi_service.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** ESP-IDF 构建系统嵌入的正式管理页面。 */
extern const unsigned char management_html_start[] asm("_binary_management_html_start");
extern const unsigned char management_html_end[] asm("_binary_management_html_end");

/** HTTP JSON 请求体最大长度。 */
#define WEB_MAX_BODY 8192U
/** 登录会话有效期，单位为微秒。 */
#define WEB_SESSION_LIFETIME_US (30LL * 60LL * 1000000LL)
/** 同时保存的登录会话数量。 */
#define WEB_SESSION_CAPACITY 4U
/** 会话令牌和 CSRF 令牌的十六进制字符数。 */
#define WEB_TOKEN_HEX_LENGTH 48U
/** Web 可查看日志的行数。 */
#define WEB_LOG_LINE_COUNT 120U
/** 单行日志的最大长度。 */
#define WEB_LOG_LINE_SIZE 256U
/** 连续登录失败次数阈值。 */
#define WEB_LOGIN_FAILURE_LIMIT 5U

/** 单个管理会话。 */
typedef struct {
    char token[WEB_TOKEN_HEX_LENGTH + 1U];
    char csrf[WEB_TOKEN_HEX_LENGTH + 1U];
    int64_t expires_us;
} web_session_t;

/** HTTP URI 路由定义。 */
typedef struct {
    const char *uri;
    httpd_method_t method;
    esp_err_t (*handler)(httpd_req_t *request);
} web_route_t;

/** 模块日志标签。 */
static const char *const g_tag = "web";
/** HTTP 服务句柄。 */
static httpd_handle_t g_server;
/** 登录会话数组。 */
static web_session_t g_sessions[WEB_SESSION_CAPACITY];
/** 保护登录会话的互斥锁。 */
static SemaphoreHandle_t g_session_mutex;
/** 保护日志环形缓冲区的互斥锁。 */
static SemaphoreHandle_t g_log_mutex;
/** Web 日志环形缓冲区。 */
static char g_log_lines[WEB_LOG_LINE_COUNT][WEB_LOG_LINE_SIZE];
/** 日志环形缓冲区中最旧行的位置。 */
static size_t g_log_head;
/** 当前有效日志行数。 */
static size_t g_log_count;
/** ESP-IDF 原日志输出函数。 */
static vprintf_like_t g_previous_vprintf;
/** 当前连续登录失败次数。 */
static unsigned g_failed_logins;
/** 登录封禁结束时间，单位为微秒。 */
static int64_t g_login_block_until;

/** @brief 生成指定字节数的随机十六进制文本。 */
static void random_hex(char *output, size_t byte_count) {
    /** 十六进制字符表。 */
    static const char hex[] = "0123456789abcdef";
    for (size_t index = 0U; index < byte_count; ++index) {
        const uint8_t value = (uint8_t)(esp_random() & 0xffU);
        output[index * 2U] = hex[value >> 4U];
        output[index * 2U + 1U] = hex[value & 0x0fU];
    }
    output[byte_count * 2U] = '\0';
}

/** @brief 同时输出 ESP-IDF 日志并写入 Web 日志环形缓冲区。 */
static int capture_vprintf(const char *format, va_list arguments) {
    va_list copy;
    int result;
    va_copy(copy, arguments);
    result = g_previous_vprintf != NULL ? g_previous_vprintf(format, arguments) : vprintf(format, arguments);
    if (g_log_mutex != NULL) {
        xSemaphoreTake(g_log_mutex, portMAX_DELAY);
        const size_t slot = (g_log_head + g_log_count) % WEB_LOG_LINE_COUNT;
        vsnprintf(g_log_lines[slot], WEB_LOG_LINE_SIZE, format, copy);
        if (g_log_count < WEB_LOG_LINE_COUNT) ++g_log_count;
        else g_log_head = (g_log_head + 1U) % WEB_LOG_LINE_COUNT;
        xSemaphoreGive(g_log_mutex);
    }
    va_end(copy);
    return result;
}

/** @brief 发送 cJSON 对象并释放该对象。 */
static esp_err_t send_json(httpd_req_t *request, int status, cJSON *root) {
    char status_text[24];
    char *text;
    snprintf(status_text, sizeof(status_text), "%d %s", status, status < 300 ? "OK" : "Error");
    httpd_resp_set_status(request, status_text);
    httpd_resp_set_type(request, "application/json");
    text = cJSON_PrintUnformatted(root);
    const esp_err_t error = httpd_resp_sendstr(request, text != NULL ? text : "{}");
    cJSON_free(text);
    cJSON_Delete(root);
    return error;
}

/** @brief 发送只包含 message 字段的 JSON 响应。 */
static esp_err_t send_message(httpd_req_t *request, int status, const char *value) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "message", value);
    return send_json(request, status, root);
}

/** @brief 读取一个 HTTP 请求头。 */
static bool header_value(httpd_req_t *request, const char *name, char *output, size_t output_size) {
    const size_t length = httpd_req_get_hdr_value_len(request, name);
    if (length == 0U || length + 1U > output_size) { if (output_size > 0U) output[0] = '\0'; return false; }
    return httpd_req_get_hdr_value_str(request, name, output, output_size) == ESP_OK;
}

/** @brief 从 Cookie 请求头提取 SMSSESSION 令牌。 */
static bool cookie_token(httpd_req_t *request, char *output, size_t output_size) {
    char cookie[640];
    const char *key = "SMSSESSION=";
    char *start;
    char *end;
    size_t length;
    if (!header_value(request, "Cookie", cookie, sizeof(cookie))) return false;
    start = strstr(cookie, key);
    if (start == NULL) return false;
    start += strlen(key);
    end = strchr(start, ';');
    length = end != NULL ? (size_t)(end - start) : strlen(start);
    if (length + 1U > output_size) return false;
    memcpy(output, start, length);
    output[length] = '\0';
    return true;
}

/** @brief 校验会话 Cookie，并按需校验 CSRF 令牌。 */
static bool authenticated(httpd_req_t *request, bool csrf_required) {
    char token[WEB_TOKEN_HEX_LENGTH + 1U];
    char csrf[WEB_TOKEN_HEX_LENGTH + 1U] = {0};
    const int64_t now = esp_timer_get_time();
    bool valid = false;
    if (!csrf_required && !config_store_web_auth_enabled()) return true;
    if (!cookie_token(request, token, sizeof(token))) return false;
    if (csrf_required && !header_value(request, "X-CSRF-Token", csrf, sizeof(csrf))) return false;
    xSemaphoreTake(g_session_mutex, portMAX_DELAY);
    for (size_t index = 0U; index < WEB_SESSION_CAPACITY; ++index) {
        web_session_t *session = &g_sessions[index];
        if (session->token[0] != '\0' && session->expires_us > now &&
            strcmp(session->token, token) == 0 &&
            (!csrf_required || strcmp(session->csrf, csrf) == 0)) {
            session->expires_us = now + WEB_SESSION_LIFETIME_US;
            valid = true;
            break;
        }
    }
    xSemaphoreGive(g_session_mutex);
    return valid;
}

/** @brief 创建一个带 CSRF 令牌的管理会话。 */
static esp_err_t create_session(httpd_req_t *request) {
    const int64_t now = esp_timer_get_time();
    web_session_t created = {0};
    size_t slot = 0U;
    char cookie[128];
    random_hex(created.token, WEB_TOKEN_HEX_LENGTH / 2U);
    random_hex(created.csrf, WEB_TOKEN_HEX_LENGTH / 2U);
    created.expires_us = now + WEB_SESSION_LIFETIME_US;
    xSemaphoreTake(g_session_mutex, portMAX_DELAY);
    for (size_t index = 0U; index < WEB_SESSION_CAPACITY; ++index) {
        if (g_sessions[index].token[0] == '\0' || g_sessions[index].expires_us <= now) {
            slot = index;
            break;
        }
    }
    memcpy(&g_sessions[slot], &created, sizeof(created));
    xSemaphoreGive(g_session_mutex);
    snprintf(cookie, sizeof(cookie), "SMSSESSION=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800", created.token);
    httpd_resp_set_hdr(request, "Set-Cookie", cookie);
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "csrf", created.csrf);
    cJSON_AddBoolToObject(root, "auth_enabled", config_store_web_auth_enabled());
    cJSON_AddBoolToObject(root, "authenticated", true);
    return send_json(request, 200, root);
}

/** @brief 接收并解析有长度上限的 JSON 请求体。 */
static cJSON *receive_json(httpd_req_t *request) {
    char *body;
    size_t offset = 0U;
    cJSON *json;
    if (request->content_len <= 0 || request->content_len > (int)WEB_MAX_BODY) return NULL;
    body = malloc((size_t)request->content_len + 1U);
    if (body == NULL) return NULL;
    while (offset < (size_t)request->content_len) {
        const int count = httpd_req_recv(request, body + offset, (size_t)request->content_len - offset);
        if (count <= 0) { free(body); return NULL; }
        offset += (size_t)count;
    }
    body[offset] = '\0';
    json = cJSON_ParseWithLength(body, offset);
    free(body);
    return json;
}

/** @brief 从 JSON 对象复制一个有长度上限的字符串。 */
static bool json_string(cJSON *root, const char *key, char *output, size_t output_size,
                        bool required) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        if (output_size > 0U) output[0] = '\0';
        return !required;
    }
    if (strlen(item->valuestring) + 1U > output_size) return false;
    snprintf(output, output_size, "%s", item->valuestring);
    return true;
}

/** @brief 按“字段缺失则保持、空密钥则保持”的规则更新配置字符串。 */
static bool update_string(cJSON *root, const char *key, char *target, size_t target_size,
                          bool secret) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (item == NULL) return true;
    if (!cJSON_IsString(item) || item->valuestring == NULL || strlen(item->valuestring) >= target_size) return false;
    if (!secret || item->valuestring[0] != '\0') snprintf(target, target_size, "%s", item->valuestring);
    return true;
}

/** @brief 判断 URL 为空或使用 HTTP/HTTPS。 */
static bool valid_url(const char *value) {
    return value[0] == '\0' || strncmp(value, "http://", 7U) == 0 || strncmp(value, "https://", 8U) == 0;
}

/** @brief 返回普通管理页或 AP 配网页。 */
static esp_err_t root_handler(httpd_req_t *request) {
    httpd_resp_set_type(request, "text/html; charset=utf-8");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store, no-cache, must-revalidate");
    httpd_resp_set_hdr(request, "Pragma", "no-cache");
    if (wifi_service_provisioning()) {
        return httpd_resp_send(request, g_web_provision_page, HTTPD_RESP_USE_STRLEN);
    }
    return httpd_resp_send(request, (const char *)management_html_start,
                           (ssize_t)(management_html_end - management_html_start - 1U));
}

/** @brief 保存 AP 配网页提交的 Wi-Fi 凭据。 */
static esp_err_t provision_handler(httpd_req_t *request) {
    char ssid[APP_WIFI_SSID_SIZE];
    char password[APP_WIFI_PASSWORD_SIZE];
    if (!wifi_service_provisioning()) return send_message(request, 403, "provisioning is not active");
    if (!authenticated(request, true)) return send_message(request, 401, "authentication or CSRF failed");
    cJSON *json = receive_json(request);
    if (json == NULL) return send_message(request, 400, "invalid JSON body");
    const bool valid = json_string(json, "ssid", ssid, sizeof(ssid), true) &&
                       json_string(json, "password", password, sizeof(password), true);
    cJSON_Delete(json);
    if (!valid || wifi_service_update_credentials(ssid, password) != ESP_OK) {
        return send_message(request, 400, "invalid Wi-Fi credentials");
    }
    return send_message(request, 202, "credentials accepted; testing Wi-Fi before saving");
}

/** @brief 扫描并返回配网热点附近的 2.4 GHz Wi-Fi。 */
static esp_err_t wifi_scan_handler(httpd_req_t *request) {
    app_wifi_network_t networks[APP_WIFI_SCAN_MAX_RESULTS] = {0};
    size_t count = 0U;
    if (!wifi_service_provisioning()) return send_message(request, 403, "provisioning is not active");
    if (!authenticated(request, false)) return send_message(request, 401, "authentication failed");
    const esp_err_t error = wifi_service_scan(networks, APP_WIFI_SCAN_MAX_RESULTS, &count);
    if (error != ESP_OK) {
        ESP_LOGW(g_tag, "Wi-Fi scan failed: %s", esp_err_to_name(error));
        return send_message(request, error == ESP_ERR_INVALID_STATE ? 409 : 503,
                            "Wi-Fi scan is temporarily unavailable");
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *items = cJSON_AddArrayToObject(root, "networks");
    for (size_t index = 0U; index < count; ++index) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "ssid", networks[index].ssid);
        cJSON_AddNumberToObject(item, "rssi", networks[index].rssi);
        cJSON_AddNumberToObject(item, "channel", networks[index].channel);
        cJSON_AddBoolToObject(item, "secure", networks[index].secure);
        cJSON_AddItemToArray(items, item);
    }
    return send_json(request, 200, root);
}

/** @brief 返回配网连接结果和可供手机跳转的后台地址。 */
static esp_err_t provision_status_handler(httpd_req_t *request) {
    char ip[16] = {0};
    char url[32] = {0};
    const app_wifi_provision_state_t state = wifi_service_provision_status(ip, sizeof(ip));
    if (!authenticated(request, false)) return send_message(request, 401, "authentication failed");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "state", state);
    if (state == APP_WIFI_PROVISION_CONNECTED && ip[0] != '\0') {
        snprintf(url, sizeof(url), "http://%s/", ip);
        cJSON_AddStringToObject(root, "ip", ip);
        cJSON_AddStringToObject(root, "management_url", url);
    }
    return send_json(request, 200, root);
}

/** @brief 将门户探测地址重定向到配网首页。 */
static esp_err_t captive_404_handler(httpd_req_t *request, httpd_err_code_t error) {
    (void)error;
    if (!wifi_service_provisioning()) return httpd_resp_send_err(request, HTTPD_404_NOT_FOUND, "not found");
    httpd_resp_set_status(request, "303 See Other");
    httpd_resp_set_hdr(request, "Location", "/");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store, no-cache, must-revalidate");
    httpd_resp_set_type(request, "text/plain; charset=utf-8");
    /* iOS 要求门户重定向响应带有非空正文。 */
    return httpd_resp_sendstr(request, "Redirect to the Wi-Fi setup portal");
}

/** @brief 校验管理员凭据并创建会话。 */
static esp_err_t login_handler(httpd_req_t *request) {
    char username[33];
    char password[73];
    const int64_t now = esp_timer_get_time();
    if (!config_store_web_auth_enabled()) {
        cJSON *anonymous = receive_json(request);
        cJSON_Delete(anonymous);
        return create_session(request);
    }
    if (now < g_login_block_until) return send_message(request, 429, "too many failed logins; retry later");
    cJSON *json = receive_json(request);
    if (json == NULL) return send_message(request, 400, "invalid JSON body");
    const bool parsed = json_string(json, "username", username, sizeof(username), true) &&
                        json_string(json, "password", password, sizeof(password), true);
    cJSON_Delete(json);
    if (!parsed || strcmp(username, "admin") != 0 || !config_store_verify_password(password)) {
        if (++g_failed_logins >= WEB_LOGIN_FAILURE_LIMIT) {
            g_login_block_until = now + 60LL * 1000000LL;
            g_failed_logins = 0U;
        }
        return send_message(request, 401, "invalid credentials");
    }
    g_failed_logins = 0U;
    return create_session(request);
}

/** @brief 返回认证模式，并在免密模式下建立匿名写会话。 */
static esp_err_t session_info_handler(httpd_req_t *request) {
    if (!config_store_web_auth_enabled()) return create_session(request);
    if (authenticated(request, false)) return create_session(request);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "auth_enabled", true);
    cJSON_AddBoolToObject(root, "authenticated", false);
    return send_json(request, 200, root);
}

/** @brief 删除当前 Cookie 对应的管理会话。 */
static esp_err_t logout_handler(httpd_req_t *request) {
    char token[WEB_TOKEN_HEX_LENGTH + 1U];
    if (cookie_token(request, token, sizeof(token))) {
        xSemaphoreTake(g_session_mutex, portMAX_DELAY);
        for (size_t index = 0U; index < WEB_SESSION_CAPACITY; ++index) {
            if (strcmp(g_sessions[index].token, token) == 0) memset(&g_sessions[index], 0, sizeof(g_sessions[index]));
        }
        xSemaphoreGive(g_session_mutex);
    }
    httpd_resp_set_hdr(request, "Set-Cookie", "SMSSESSION=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    return send_message(request, 200, "logged out");
}

/** @brief 返回 Wi-Fi、模组和密码状态。 */
static esp_err_t status_handler(httpd_req_t *request) {
    char ip[16];
    modem_status_t modem;
    app_config_t *config;
    unsigned channel_count = 0U;
    if (!authenticated(request, false)) return send_message(request, 401, "authentication required");
    wifi_service_ip_address(ip, sizeof(ip));
    modem_service_status(&modem);
    config = malloc(sizeof(*config));
    if (config == NULL) return send_message(request, 500, "out of memory");
    config_store_get(config);
    for (size_t index = 0U; index < APP_MAX_PUSH_CHANNELS; ++index) {
        if (config->push_channels[index].enabled) ++channel_count;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "ip", ip);
    cJSON_AddBoolToObject(root, "wifi_connected", wifi_service_connected());
    cJSON_AddNumberToObject(root, "wifi_rssi", wifi_service_rssi());
    cJSON_AddBoolToObject(root, "modem_ready", modem_service_ready());
    cJSON_AddBoolToObject(root, "packet_data_disabled", modem_service_data_safely_disabled());
    cJSON_AddStringToObject(root, "idf_version", esp_get_idf_version());
    cJSON_AddBoolToObject(root, "password_change_required", config_store_password_change_required());
    cJSON_AddStringToObject(root, "wifi_ssid", config->wifi_ssid);
    cJSON_AddBoolToObject(root, "auth_enabled", config_store_web_auth_enabled());
    cJSON_AddBoolToObject(root, "sim_ready", modem.sim_ready);
    cJSON_AddBoolToObject(root, "network_registered", modem.registered);
    cJSON_AddBoolToObject(root, "network_roaming", modem.roaming);
    cJSON_AddNumberToObject(root, "signal_dbm", modem.signal_dbm == INT16_MIN ? 0 : modem.signal_dbm);
    cJSON_AddNumberToObject(root, "signal_bars", modem.signal_bars);
    cJSON_AddNumberToObject(root, "modem_status_age", modem.age_seconds);
    cJSON_AddStringToObject(root, "operator", modem.operator_name);
    cJSON_AddStringToObject(root, "modem_model", modem.model);
    cJSON_AddBoolToObject(root, "smtp_configured", config->smtp_server[0] != '\0' && config->smtp_recipient[0] != '\0');
    cJSON_AddNumberToObject(root, "enabled_channels", channel_count);
    cJSON_AddNumberToObject(root, "uptime_seconds", (double)(esp_timer_get_time() / 1000000LL));
    free(config);
    return send_json(request, 200, root);
}

/** @brief 返回不含密钥的当前配置。 */
static esp_err_t config_get_handler(httpd_req_t *request, const app_config_t *config) {
    cJSON *root = cJSON_CreateObject();
    cJSON *channels;
    cJSON_AddStringToObject(root, "wifi_ssid", config->wifi_ssid);
    cJSON_AddStringToObject(root, "smtp_server", config->smtp_server);
    cJSON_AddNumberToObject(root, "smtp_port", config->smtp_port);
    cJSON_AddStringToObject(root, "smtp_user", config->smtp_user);
    cJSON_AddStringToObject(root, "smtp_recipient", config->smtp_recipient);
    cJSON_AddBoolToObject(root, "smtp_password_configured", config->smtp_password[0] != '\0');
    cJSON_AddStringToObject(root, "admin_phone", config->admin_phone);
    cJSON_AddBoolToObject(root, "admin_commands_enabled", config->admin_commands_enabled);
    cJSON_AddStringToObject(root, "number_blacklist", config->number_blacklist);
    cJSON_AddBoolToObject(root, "web_auth_enabled", config_store_web_auth_enabled());
    channels = cJSON_AddArrayToObject(root, "push_channels");
    for (size_t index = 0U; index < APP_MAX_PUSH_CHANNELS; ++index) {
        const push_channel_t *channel = &config->push_channels[index];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddBoolToObject(item, "enabled", channel->enabled);
        cJSON_AddNumberToObject(item, "type", channel->type);
        cJSON_AddStringToObject(item, "name", channel->name);
        cJSON_AddStringToObject(item, "url", channel->url);
        cJSON_AddBoolToObject(item, "key1_configured", channel->key1[0] != '\0');
        cJSON_AddBoolToObject(item, "key2_configured", channel->key2[0] != '\0');
        cJSON_AddBoolToObject(item, "custom_body_configured", channel->custom_body[0] != '\0');
        cJSON_AddStringToObject(item, "custom_body", "");
        cJSON_AddItemToArray(channels, item);
    }
    return send_json(request, 200, root);
}

/** @brief 应用 POST JSON 中的推送通道配置。 */
static bool update_channels(cJSON *json, app_config_t *config) {
    cJSON *channels = cJSON_GetObjectItemCaseSensitive(json, "push_channels");
    cJSON *item;
    size_t index = 0U;
    if (channels == NULL) return true;
    if (!cJSON_IsArray(channels) || cJSON_GetArraySize(channels) > (int)APP_MAX_PUSH_CHANNELS) return false;
    cJSON_ArrayForEach(item, channels) {
        if (index >= APP_MAX_PUSH_CHANNELS || !cJSON_IsObject(item)) return false;
        push_channel_t *channel = &config->push_channels[index++];
        cJSON *field = cJSON_GetObjectItemCaseSensitive(item, "enabled");
        if (cJSON_IsBool(field)) channel->enabled = cJSON_IsTrue(field);
        field = cJSON_GetObjectItemCaseSensitive(item, "type");
        if (cJSON_IsNumber(field)) {
            if (field->valueint < 0 || field->valueint > 10) return false;
            channel->type = (push_type_t)field->valueint;
        }
        if (channel->type == PUSH_TYPE_NONE) {
            memset(channel, 0, sizeof(*channel));
            continue;
        }
        if (!update_string(item, "name", channel->name, sizeof(channel->name), false) ||
            !update_string(item, "url", channel->url, sizeof(channel->url), false) ||
            !update_string(item, "key1", channel->key1, sizeof(channel->key1), true) ||
            !update_string(item, "key2", channel->key2, sizeof(channel->key2), true) ||
            !update_string(item, "custom_body", channel->custom_body, sizeof(channel->custom_body), true) ||
            !valid_url(channel->url)) return false;
    }
    return true;
}

/** @brief 读取或更新设备配置。 */
static esp_err_t config_handler(httpd_req_t *request) {
    app_config_t *config;
    if (!authenticated(request, request->method == HTTP_POST)) {
        return send_message(request, 401, "authentication or CSRF failed");
    }
    config = malloc(sizeof(*config));
    if (config == NULL) return send_message(request, 500, "out of memory");
    config_store_get(config);
    if (request->method == HTTP_GET) {
        const esp_err_t result = config_get_handler(request, config);
        free(config);
        return result;
    }
    cJSON *json = receive_json(request);
    if (json == NULL) { free(config); return send_message(request, 400, "invalid JSON body"); }
    cJSON *password_item = cJSON_GetObjectItemCaseSensitive(json, "web_password");
    cJSON *auth_item = cJSON_GetObjectItemCaseSensitive(json, "web_auth_enabled");
    if (cJSON_IsBool(auth_item)) {
        const bool enable_auth = cJSON_IsTrue(auth_item);
        esp_err_t error = ESP_OK;
        if (enable_auth) {
            if (!cJSON_IsString(password_item) || password_item->valuestring == NULL) error = ESP_ERR_INVALID_ARG;
            else error = config_store_set_web_password(password_item->valuestring);
        }
        if (error == ESP_OK) error = config_store_set_web_auth_enabled(enable_auth);
        cJSON_Delete(json); free(config);
        return error == ESP_OK ? send_message(request, 200, enable_auth ? "login protection enabled" : "login protection disabled")
                               : send_message(request, 400, "a new password of 10-72 characters is required");
    }
    bool valid = update_string(json, "wifi_ssid", config->wifi_ssid, sizeof(config->wifi_ssid), false) &&
                 update_string(json, "wifi_password", config->wifi_password, sizeof(config->wifi_password), true) &&
                 update_string(json, "smtp_server", config->smtp_server, sizeof(config->smtp_server), false) &&
                 update_string(json, "smtp_user", config->smtp_user, sizeof(config->smtp_user), false) &&
                 update_string(json, "smtp_password", config->smtp_password, sizeof(config->smtp_password), true) &&
                 update_string(json, "smtp_recipient", config->smtp_recipient, sizeof(config->smtp_recipient), false) &&
                 update_string(json, "admin_phone", config->admin_phone, sizeof(config->admin_phone), false) &&
                 update_string(json, "number_blacklist", config->number_blacklist, sizeof(config->number_blacklist), false);
    cJSON *port = cJSON_GetObjectItemCaseSensitive(json, "smtp_port");
    if (cJSON_IsNumber(port)) {
        if (port->valuedouble < 1.0 || port->valuedouble > 65535.0) valid = false;
        else config->smtp_port = (uint16_t)port->valueint;
    }
    cJSON *enabled = cJSON_GetObjectItemCaseSensitive(json, "admin_commands_enabled");
    if (cJSON_IsBool(enabled)) config->admin_commands_enabled = cJSON_IsTrue(enabled);
    valid = valid && update_channels(json, config);
    cJSON_Delete(json);
    if (!valid || (config->smtp_port != 465U && config->smtp_port != 587U)) {
        free(config); return send_message(request, 400, "configuration validation failed");
    }
    const esp_err_t error = config_store_save(config);
    free(config);
    return error == ESP_OK ? send_message(request, 200, "configuration saved; reconnect Wi-Fi if credentials changed")
                           : send_message(request, 500, "failed to persist configuration");
}

/** @brief 创建短信发送异步任务。 */
static esp_err_t sms_handler(httpd_req_t *request) {
    char phone[APP_PHONE_SIZE];
    char text[APP_SMS_TEXT_SIZE];
    if (!authenticated(request, true)) return send_message(request, 401, "authentication or CSRF failed");
    cJSON *json = receive_json(request);
    if (json == NULL) return send_message(request, 400, "invalid JSON body");
    const bool valid = json_string(json, "phone", phone, sizeof(phone), true) &&
                       json_string(json, "message", text, sizeof(text), true);
    cJSON_Delete(json);
    const uint32_t id = valid ? modem_service_submit_sms(phone, text) : 0U;
    if (id == 0U) return send_message(request, 503, "modem queue unavailable");
    cJSON *root = cJSON_CreateObject(); cJSON_AddNumberToObject(root, "job_id", id);
    return send_json(request, 202, root);
}

/** @brief 返回按新到旧排列且可跨重启恢复的最近十条短信。 */
static esp_err_t inbox_handler(httpd_req_t *request) {
    if (!authenticated(request, false)) return send_message(request, 401, "authentication required");
    const size_t count = sms_service_inbox_count();
    httpd_resp_set_type(request, "application/json");
    esp_err_t error = httpd_resp_send_chunk(request, "{\"messages\":[", HTTPD_RESP_USE_STRLEN);
    for (size_t index = 0U; index < count; ++index) {
        sms_inbox_entry_t entry;
        if (error != ESP_OK || !sms_service_inbox_get(index, &entry)) break;
        cJSON *item = cJSON_CreateObject();
        if (item == NULL) { error = ESP_ERR_NO_MEM; break; }
        cJSON_AddNumberToObject(item, "id", entry.id);
        cJSON_AddStringToObject(item, "sender", entry.message.sender);
        cJSON_AddStringToObject(item, "text", entry.message.text);
        cJSON_AddStringToObject(item, "timestamp", entry.message.timestamp);
        char *encoded = cJSON_PrintUnformatted(item);
        cJSON_Delete(item);
        if (encoded == NULL) { error = ESP_ERR_NO_MEM; break; }
        if (index > 0U) error = httpd_resp_send_chunk(request, ",", 1U);
        if (error == ESP_OK) error = httpd_resp_send_chunk(request, encoded, HTTPD_RESP_USE_STRLEN);
        free(encoded);
    }
    if (error == ESP_OK) error = httpd_resp_send_chunk(request, "]}", 2U);
    if (error == ESP_OK) error = httpd_resp_send_chunk(request, NULL, 0U);
    return error;
}

/** @brief 创建只读 AT 查询异步任务。 */
static esp_err_t at_handler(httpd_req_t *request) {
    char command[40];
    if (!authenticated(request, true)) return send_message(request, 401, "authentication or CSRF failed");
    cJSON *json = receive_json(request);
    if (json == NULL) return send_message(request, 400, "invalid JSON body");
    const bool valid = json_string(json, "command", command, sizeof(command), true);
    cJSON_Delete(json);
    const uint32_t id = valid ? modem_service_submit_safe_query(command) : 0U;
    if (id == 0U) return send_message(request, 403, "command is not on the read-only allowlist");
    cJSON *root = cJSON_CreateObject(); cJSON_AddNumberToObject(root, "job_id", id);
    return send_json(request, 202, root);
}

/** @brief 创建模组软重启或硬重启异步任务。 */
static esp_err_t modem_restart_handler(httpd_req_t *request) {
    char mode[9];
    if (!authenticated(request, true)) return send_message(request, 401, "authentication or CSRF failed");
    cJSON *json = receive_json(request);
    if (json == NULL) return send_message(request, 400, "invalid JSON body");
    json_string(json, "mode", mode, sizeof(mode), false);
    cJSON_Delete(json);
    const uint32_t id = strcmp(mode, "hard") == 0 ? modem_service_submit_hard_reset()
                                                   : modem_service_submit_soft_reset();
    cJSON *root = cJSON_CreateObject(); cJSON_AddNumberToObject(root, "job_id", id);
    return send_json(request, 202, root);
}

/** @brief 延迟执行系统重启。 */
static void delayed_restart(void *argument) {
    (void)argument;
    vTaskDelay(pdMS_TO_TICKS(500U));
    esp_restart();
}

/** @brief 鉴权后安排 ESP32-C3 重启。 */
static esp_err_t system_restart_handler(httpd_req_t *request) {
    if (!authenticated(request, true)) return send_message(request, 401, "authentication or CSRF failed");
    send_message(request, 202, "system restart scheduled");
    xTaskCreate(delayed_restart, "restart", 2048U, NULL, 5U, NULL);
    return ESP_OK;
}

/** @brief 鉴权后触发 Wi-Fi STA 重连。 */
static esp_err_t wifi_reconnect_handler(httpd_req_t *request) {
    if (!authenticated(request, true)) return send_message(request, 401, "authentication or CSRF failed");
    return wifi_service_reconnect() == ESP_OK
        ? send_message(request, 202, "Wi-Fi reconnect started")
        : send_message(request, 409, "cannot reconnect while provisioning");
}

/** @brief 返回日志环形缓冲区内容。 */
static esp_err_t logs_handler(httpd_req_t *request) {
    if (!authenticated(request, false)) return send_message(request, 401, "authentication required");
    cJSON *root = cJSON_CreateObject();
    cJSON *lines = cJSON_AddArrayToObject(root, "lines");
    xSemaphoreTake(g_log_mutex, portMAX_DELAY);
    for (size_t index = 0U; index < g_log_count; ++index) {
        const size_t slot = (g_log_head + index) % WEB_LOG_LINE_COUNT;
        cJSON_AddItemToArray(lines, cJSON_CreateString(g_log_lines[slot]));
    }
    xSemaphoreGive(g_log_mutex);
    return send_json(request, 200, root);
}

/** @brief 返回指定异步模组任务状态。 */
static esp_err_t job_handler(httpd_req_t *request) {
    const char *last;
    uint32_t id;
    job_status_t status;
    if (!authenticated(request, false)) return send_message(request, 401, "authentication required");
    last = strrchr(request->uri, '/');
    id = last != NULL ? (uint32_t)strtoul(last + 1U, NULL, 10) : 0U;
    if (id == 0U || !modem_service_job_status(id, &status)) return send_message(request, 404, "job not found");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "id", status.id);
    cJSON_AddNumberToObject(root, "state", status.state);
    cJSON_AddStringToObject(root, "message", status.message);
    return send_json(request, 200, root);
}

/** HTTP 服务注册的固定路由表。 */
static const web_route_t g_routes[] = {
    {"/", HTTP_GET, root_handler}, {"/api/provision", HTTP_POST, provision_handler},
    {"/api/provision/status", HTTP_GET, provision_status_handler},
    {"/api/wifi/scan", HTTP_GET, wifi_scan_handler},
    {"/api/session", HTTP_GET, session_info_handler}, {"/api/session", HTTP_POST, login_handler},
    {"/api/session", HTTP_DELETE, logout_handler},
    {"/api/status", HTTP_GET, status_handler}, {"/api/config", HTTP_GET, config_handler},
    {"/api/config", HTTP_POST, config_handler}, {"/api/sms", HTTP_POST, sms_handler},
    {"/api/inbox", HTTP_GET, inbox_handler},
    {"/api/at/query", HTTP_POST, at_handler}, {"/api/modem/restart", HTTP_POST, modem_restart_handler},
    {"/api/system/restart", HTTP_POST, system_restart_handler},
    {"/api/wifi/reconnect", HTTP_POST, wifi_reconnect_handler}, {"/api/logs", HTTP_GET, logs_handler},
    {"/api/jobs/*", HTTP_GET, job_handler}};

esp_err_t web_server_start(void) {
    if (g_server != NULL) return ESP_OK;
    g_session_mutex = xSemaphoreCreateMutex();
    g_log_mutex = xSemaphoreCreateMutex();
    if (g_session_mutex == NULL || g_log_mutex == NULL) return ESP_ERR_NO_MEM;
    g_previous_vprintf = esp_log_set_vprintf(capture_vprintf);
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 12288U;
    config.max_uri_handlers = sizeof(g_routes) / sizeof(g_routes[0]) + 2U;
    config.max_open_sockets = 13;
    config.lru_purge_enable = true;
    config.uri_match_fn = httpd_uri_match_wildcard;
    /* 门户探测会制造大量预期内的未匹配 URI，不需要在串口重复报警。 */
    esp_log_level_set("httpd_uri", ESP_LOG_ERROR);
    esp_log_level_set("httpd_txrx", ESP_LOG_ERROR);
    esp_log_level_set("httpd_parse", ESP_LOG_ERROR);
    esp_err_t error = httpd_start(&g_server, &config);
    if (error != ESP_OK) return error;
    for (size_t index = 0U; index < sizeof(g_routes) / sizeof(g_routes[0]); ++index) {
        httpd_uri_t uri = {.uri = g_routes[index].uri, .method = g_routes[index].method,
                           .handler = g_routes[index].handler, .user_ctx = NULL};
        error = httpd_register_uri_handler(g_server, &uri);
        if (error != ESP_OK) return error;
    }
    error = httpd_register_err_handler(g_server, HTTPD_404_NOT_FOUND, captive_404_handler);
    if (error != ESP_OK) return error;
    ESP_LOGI(g_tag, "HTTP management server started");
    return ESP_OK;
}

void web_server_stop(void) {
    if (g_server != NULL) {
        httpd_stop(g_server);
        g_server = NULL;
    }
}
