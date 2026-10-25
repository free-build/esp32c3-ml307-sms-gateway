#include "notification_service.h"

#include "cJSON.h"
#include "config_store.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "smtp_client.h"
#include "wifi_service.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/** 通知队列深度。 */
#define NOTIFY_QUEUE_DEPTH 16U
/** HTTP 响应正文最大长度。 */
#define NOTIFY_MAX_RESPONSE 4096U
/** HTTP 请求最多重试次数。 */
#define NOTIFY_MAX_ATTEMPTS 3U

/** HTTP 响应收集缓冲区。 */
typedef struct {
    char body[NOTIFY_MAX_RESPONSE + 1U];
    size_t length;
} http_response_t;

/** 模块日志标签。 */
static const char *const g_tag = "notify";
/** 待投递短信指针队列。 */
static QueueHandle_t g_notify_queue;

/** @brief 按 printf 格式分配精确长度的字符串。 */
static char *format_alloc(const char *format, ...) {
    va_list arguments;
    va_list copy;
    int needed;
    char *result;
    va_start(arguments, format);
    va_copy(copy, arguments);
    needed = vsnprintf(NULL, 0U, format, copy);
    va_end(copy);
    if (needed < 0) { va_end(arguments); return NULL; }
    result = malloc((size_t)needed + 1U);
    if (result != NULL) vsnprintf(result, (size_t)needed + 1U, format, arguments);
    va_end(arguments);
    return result;
}

/** @brief 把一段文本 URL 编码为新分配字符串。 */
static char *url_encode(const char *input) {
    /** URL 百分号编码使用的大写十六进制表。 */
    static const char hex[] = "0123456789ABCDEF";
    const size_t length = strlen(input);
    char *output = malloc(length * 3U + 1U);
    size_t written = 0U;
    if (output == NULL) return NULL;
    for (size_t index = 0U; index < length; ++index) {
        const unsigned char value = (unsigned char)input[index];
        if (isalnum(value) || value == '-' || value == '_' || value == '.' || value == '~') {
            output[written++] = (char)value;
        } else {
            output[written++] = '%';
            output[written++] = hex[value >> 4U];
            output[written++] = hex[value & 0x0fU];
        }
    }
    output[written] = '\0';
    return output;
}

/** @brief 计算 HMAC-SHA256 并返回 Base64 文本。 */
static bool hmac_base64(const char *key, const char *message, char *output,
                        size_t output_size) {
    uint8_t digest[32];
    size_t written = 0U;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL || mbedtls_md_hmac(md, (const unsigned char *)key, strlen(key),
                                     (const unsigned char *)message, strlen(message), digest) != 0 ||
        mbedtls_base64_encode((unsigned char *)output, output_size - 1U, &written,
                              digest, sizeof(digest)) != 0) return false;
    output[written] = '\0';
    return true;
}

/** @brief 收集 HTTP 客户端接收到的响应正文。 */
static esp_err_t http_event(esp_http_client_event_t *event) {
    http_response_t *response = (http_response_t *)event->user_data;
    if (event->event_id == HTTP_EVENT_ON_DATA && response != NULL && event->data_len > 0 &&
        response->length + (size_t)event->data_len <= NOTIFY_MAX_RESPONSE) {
        memcpy(response->body + response->length, event->data, (size_t)event->data_len);
        response->length += (size_t)event->data_len;
        response->body[response->length] = '\0';
    }
    return ESP_OK;
}

/** @brief 判断特定推送平台的响应正文是否表示成功。 */
static bool body_success(push_type_t type, const char *body) {
    switch (type) {
        case PUSH_TYPE_DINGTALK: return strstr(body, "\"errcode\":0") != NULL;
        case PUSH_TYPE_FEISHU: return strstr(body, "\"code\":0") != NULL;
        case PUSH_TYPE_PUSHPLUS: return strstr(body, "\"code\":200") != NULL;
        case PUSH_TYPE_SERVERCHAN: return strstr(body, "\"code\":0") != NULL;
        case PUSH_TYPE_TELEGRAM: return strstr(body, "\"ok\":true") != NULL;
        default: return true;
    }
}

/** @brief 将 cJSON 对象序列化并接管返回文本。 */
static char *print_json(cJSON *root) {
    char *text = root != NULL ? cJSON_PrintUnformatted(root) : NULL;
    cJSON_Delete(root);
    return text;
}

/** @brief 为普通、Bark、Gotify 或 Telegram 请求创建 JSON。 */
static char *simple_json_body(push_type_t type, const push_channel_t *channel,
                              const sms_message_t *sms) {
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return NULL;
    switch (type) {
        case PUSH_TYPE_POST_JSON:
            cJSON_AddStringToObject(root, "sender", sms->sender);
            cJSON_AddStringToObject(root, "message", sms->text);
            cJSON_AddStringToObject(root, "timestamp", sms->timestamp);
            break;
        case PUSH_TYPE_BARK:
            cJSON_AddStringToObject(root, "title", sms->sender);
            cJSON_AddStringToObject(root, "body", sms->text);
            break;
        case PUSH_TYPE_PUSHPLUS:
            cJSON_AddStringToObject(root, "token", channel->key1);
            char title[APP_PHONE_SIZE + 16U];
            snprintf(title, sizeof(title), "SMS from %s", sms->sender);
            cJSON_AddStringToObject(root, "title", title);
            cJSON_AddStringToObject(root, "content", sms->text);
            cJSON_AddStringToObject(root, "channel", channel->key2[0] != '\0' ? channel->key2 : "wechat");
            break;
        case PUSH_TYPE_GOTIFY: {
            char title[APP_PHONE_SIZE + 16U];
            snprintf(title, sizeof(title), "SMS from %s", sms->sender);
            cJSON_AddStringToObject(root, "title", title);
            cJSON_AddStringToObject(root, "message", sms->text);
            cJSON_AddNumberToObject(root, "priority", 5);
            break;
        }
        case PUSH_TYPE_TELEGRAM: {
            char *text = format_alloc("SMS from %s\n%s\n%s", sms->sender, sms->text, sms->timestamp);
            cJSON_AddStringToObject(root, "chat_id", channel->key1);
            cJSON_AddStringToObject(root, "text", text != NULL ? text : "");
            free(text);
            break;
        }
        default:
            cJSON_Delete(root);
            return NULL;
    }
    return print_json(root);
}

/** @brief 替换自定义正文内的全部占位符。 */
static char *replace_all(char *source, const char *token, const char *value) {
    char *position;
    while (source != NULL && (position = strstr(source, token)) != NULL) {
        const size_t prefix = (size_t)(position - source);
        const size_t new_length = strlen(source) - strlen(token) + strlen(value);
        char *replacement = malloc(new_length + 1U);
        if (replacement == NULL) { free(source); return NULL; }
        memcpy(replacement, source, prefix);
        memcpy(replacement + prefix, value, strlen(value));
        strcpy(replacement + prefix + strlen(value), position + strlen(token));
        free(source);
        source = replacement;
    }
    return source;
}

/** @brief 构造并发送一个推送通道请求。 */
static bool send_channel(const push_channel_t *channel, const sms_message_t *sms) {
    char *url = strdup(channel->url);
    char *body = NULL;
    const char *content_type = "application/json";
    bool get_request = false;
    if (url == NULL) return false;
    switch (channel->type) {
        case PUSH_TYPE_POST_JSON:
        case PUSH_TYPE_BARK:
            body = simple_json_body(channel->type, channel, sms);
            break;
        case PUSH_TYPE_GET: {
            char *sender = url_encode(sms->sender);
            char *message = url_encode(sms->text);
            char *timestamp = url_encode(sms->timestamp);
            char *next = format_alloc("%s%c%s%s%s%s%s", url, strchr(url, '?') == NULL ? '?' : '&',
                                      "sender=", sender != NULL ? sender : "",
                                      "&message=", message != NULL ? message : "", "");
            char *complete = next != NULL ? format_alloc("%s&timestamp=%s", next, timestamp != NULL ? timestamp : "") : NULL;
            free(sender); free(message); free(timestamp); free(next); free(url); url = complete;
            get_request = true;
            break;
        }
        case PUSH_TYPE_DINGTALK: {
            if (channel->key1[0] != '\0') {
                const long long now_ms = (long long)time(NULL) * 1000LL;
                char sign_input[APP_CHANNEL_KEY_SIZE + 32U];
                char signature[64];
                snprintf(sign_input, sizeof(sign_input), "%lld\n%s", now_ms, channel->key1);
                if (hmac_base64(channel->key1, sign_input, signature, sizeof(signature))) {
                    char *encoded = url_encode(signature);
                    char *next = format_alloc("%s%c%s%lld&sign=%s", url,
                                              strchr(url, '?') == NULL ? '?' : '&', "timestamp=",
                                              now_ms, encoded != NULL ? encoded : "");
                    free(encoded); free(url); url = next;
                }
            }
            cJSON *root = cJSON_CreateObject();
            cJSON *text = cJSON_CreateObject();
            char *content = format_alloc("SMS\nFrom: %s\n%s\n%s", sms->sender, sms->text, sms->timestamp);
            cJSON_AddStringToObject(root, "msgtype", "text");
            cJSON_AddStringToObject(text, "content", content != NULL ? content : "");
            cJSON_AddItemToObject(root, "text", text);
            body = print_json(root);
            free(content);
            break;
        }
        case PUSH_TYPE_PUSHPLUS:
            if (url[0] == '\0') { free(url); url = strdup("https://www.pushplus.plus/send"); }
            body = simple_json_body(channel->type, channel, sms);
            break;
        case PUSH_TYPE_SERVERCHAN: {
            if (url[0] == '\0') { free(url); url = format_alloc("https://sctapi.ftqq.com/%s.send", channel->key1); }
            char title[APP_PHONE_SIZE + 16U];
            snprintf(title, sizeof(title), "SMS from %s", sms->sender);
            char *encoded_title = url_encode(title);
            char *encoded_text = url_encode(sms->text);
            body = format_alloc("title=%s&desp=%s", encoded_title != NULL ? encoded_title : "",
                                encoded_text != NULL ? encoded_text : "");
            free(encoded_title); free(encoded_text);
            content_type = "application/x-www-form-urlencoded";
            break;
        }
        case PUSH_TYPE_CUSTOM:
            body = strdup(channel->custom_body);
            body = replace_all(body, "{sender}", sms->sender);
            body = replace_all(body, "{message}", sms->text);
            body = replace_all(body, "{timestamp}", sms->timestamp);
            break;
        case PUSH_TYPE_FEISHU: {
            cJSON *root = cJSON_CreateObject();
            cJSON *content = cJSON_CreateObject();
            char *text = format_alloc("SMS\nFrom: %s\n%s\n%s", sms->sender, sms->text, sms->timestamp);
            if (channel->key1[0] != '\0') {
                char seconds[24];
                char sign_key[APP_CHANNEL_KEY_SIZE + 32U];
                char signature[64];
                snprintf(seconds, sizeof(seconds), "%lld", (long long)time(NULL));
                snprintf(sign_key, sizeof(sign_key), "%s\n%s", seconds, channel->key1);
                if (hmac_base64(sign_key, "", signature, sizeof(signature))) {
                    cJSON_AddStringToObject(root, "timestamp", seconds);
                    cJSON_AddStringToObject(root, "sign", signature);
                }
            }
            cJSON_AddStringToObject(root, "msg_type", "text");
            cJSON_AddStringToObject(content, "text", text != NULL ? text : "");
            cJSON_AddItemToObject(root, "content", content);
            body = print_json(root);
            free(text);
            break;
        }
        case PUSH_TYPE_GOTIFY: {
            const bool slash = url[0] != '\0' && url[strlen(url) - 1U] == '/';
            char *key = url_encode(channel->key1);
            char *next = format_alloc("%s%smessage?token=%s", url, slash ? "" : "/", key != NULL ? key : "");
            free(key); free(url); url = next;
            body = simple_json_body(channel->type, channel, sms);
            break;
        }
        case PUSH_TYPE_TELEGRAM: {
            if (url[0] == '\0') { free(url); url = strdup("https://api.telegram.org"); }
            const size_t length = strlen(url);
            if (length > 0U && url[length - 1U] == '/') url[length - 1U] = '\0';
            char *next = format_alloc("%s/bot%s/sendMessage", url, channel->key2);
            free(url); url = next;
            body = simple_json_body(channel->type, channel, sms);
            break;
        }
        default:
            free(url);
            return false;
    }
    if (url == NULL || (strncmp(url, "http://", 7U) != 0 && strncmp(url, "https://", 8U) != 0)) {
        free(url); free(body); return false;
    }
    for (unsigned attempt = 0U; attempt < NOTIFY_MAX_ATTEMPTS; ++attempt) {
        http_response_t response = {0};
        esp_http_client_config_t config = {
            .url = url,
            .event_handler = http_event,
            .user_data = &response,
            .timeout_ms = 10000,
            .disable_auto_redirect = false,
            .crt_bundle_attach = esp_crt_bundle_attach};
        if (attempt > 0U) vTaskDelay(pdMS_TO_TICKS(500U << (attempt - 1U)));
        esp_http_client_handle_t client = esp_http_client_init(&config);
        if (client == NULL) continue;
        esp_http_client_set_method(client, get_request ? HTTP_METHOD_GET : HTTP_METHOD_POST);
        if (!get_request) {
            esp_http_client_set_header(client, "Content-Type", content_type);
            esp_http_client_set_post_field(client, body != NULL ? body : "", body != NULL ? (int)strlen(body) : 0);
        }
        const esp_err_t error = esp_http_client_perform(client);
        const int status = esp_http_client_get_status_code(client);
        esp_http_client_cleanup(client);
        if (error == ESP_OK && status >= 200 && status < 300 && body_success(channel->type, response.body)) {
            free(url); free(body); return true;
        }
        if (status >= 400 && status < 500 && status != 429) break;
    }
    ESP_LOGE(g_tag, "channel '%s' delivery failed", channel->name);
    free(url); free(body);
    return false;
}

/** @brief 从队列获取短信并投递到所有启用通道。 */
static void notification_task(void *argument) {
    (void)argument;
    while (true) {
        sms_message_t *sms = NULL;
        if (xQueueReceive(g_notify_queue, &sms, portMAX_DELAY) != pdTRUE || sms == NULL) continue;
        if (!wifi_service_connected()) {
            ESP_LOGW(g_tag, "Wi-Fi offline; notification cannot be delivered");
            free(sms);
            continue;
        }
        app_config_t *config = malloc(sizeof(*config));
        if (config == NULL) { free(sms); continue; }
        config_store_get(config);
        for (size_t index = 0U; index < APP_MAX_PUSH_CHANNELS; ++index) {
            if (config->push_channels[index].enabled) send_channel(&config->push_channels[index], sms);
        }
        smtp_client_config_t smtp = {0};
        snprintf(smtp.server, sizeof(smtp.server), "%s", config->smtp_server);
        smtp.port = config->smtp_port;
        snprintf(smtp.user, sizeof(smtp.user), "%s", config->smtp_user);
        snprintf(smtp.password, sizeof(smtp.password), "%s", config->smtp_password);
        snprintf(smtp.recipient, sizeof(smtp.recipient), "%s", config->smtp_recipient);
        free(config);
        if (smtp.server[0] != '\0') {
            char error[APP_JOB_MESSAGE_SIZE];
            char subject[APP_PHONE_SIZE + 16U];
            char *body = format_alloc("From: %s\nTime: %s\n\n%s", sms->sender, sms->timestamp, sms->text);
            bool sent = false;
            snprintf(subject, sizeof(subject), "SMS from %s", sms->sender);
            for (unsigned attempt = 0U; attempt < 3U && !sent; ++attempt) {
                if (attempt > 0U) vTaskDelay(pdMS_TO_TICKS(1000U << (attempt - 1U)));
                sent = body != NULL && smtp_client_send(&smtp, subject, body, error, sizeof(error));
            }
            if (!sent) {
                ESP_LOGE(g_tag, "SMTP delivery failed: %s", error);
            } else {
                ESP_LOGI(g_tag, "SMTP delivery succeeded");
            }
            free(body);
        }
        memset(&smtp, 0, sizeof(smtp));
        free(sms);
    }
}

esp_err_t notification_service_start(void) {
    g_notify_queue = xQueueCreate(NOTIFY_QUEUE_DEPTH, sizeof(sms_message_t *));
    if (g_notify_queue == NULL) return ESP_ERR_NO_MEM;
    return xTaskCreate(notification_task, "notify_task", 14336U, NULL, 6U, NULL) == pdPASS
        ? ESP_OK : ESP_ERR_NO_MEM;
}

bool notification_service_enqueue_sms(const sms_message_t *sms) {
    sms_message_t *copy;
    if (sms == NULL || g_notify_queue == NULL) return false;
    copy = malloc(sizeof(*copy));
    if (copy == NULL) return false;
    memcpy(copy, sms, sizeof(*copy));
    if (xQueueSend(g_notify_queue, &copy, 0U) != pdTRUE) {
        free(copy);
        ESP_LOGE(g_tag, "notification queue full; newest message rejected");
        return false;
    }
    return true;
}
