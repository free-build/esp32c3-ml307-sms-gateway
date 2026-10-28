#include "config_store.h"

#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/base64.h"
#include "mbedtls/pkcs5.h"
#include "nvs.h"
#include "nvs_flash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** 当前配置格式版本。 */
#define CONFIG_SCHEMA_VERSION 3U
/** 密码盐字节数。 */
#define CONFIG_SALT_BYTES 16U
/** 密码哈希字节数。 */
#define CONFIG_HASH_BYTES 32U
/** PBKDF2 迭代次数。 */
#define CONFIG_PBKDF2_ROUNDS 120000U
/** Base64 密码盐缓冲区长度。 */
#define CONFIG_SALT_TEXT_SIZE 32U
/** Base64 密码哈希缓冲区长度。 */
#define CONFIG_HASH_TEXT_SIZE 64U
/** 模块日志标签。 */
static const char *const g_tag = "config";
/** 当前配置使用的 NVS 命名空间。 */
static const char *const g_namespace = "sms_idf";
/** 内存中的当前配置。 */
static app_config_t g_config;
/** 配置及密码状态互斥锁。 */
static SemaphoreHandle_t g_config_mutex;
/** Base64 编码后的 Web 密码盐。 */
static char g_password_salt[CONFIG_SALT_TEXT_SIZE];
/** Base64 编码后的 Web 密码哈希。 */
static char g_password_hash[CONFIG_HASH_TEXT_SIZE];
/** 是否启用后台密码登录；新装和升级设备均默认关闭。 */
static bool g_web_auth_enabled;

/**
 * @brief 安全复制字符串并确保结尾存在空字符。
 * @param target 目标缓冲区。
 * @param target_size 目标缓冲区长度。
 * @param source 源字符串，可为 NULL。
 */
static void copy_text(char *target, size_t target_size, const char *source) {
    if (target == NULL || target_size == 0U) return;
    snprintf(target, target_size, "%s", source != NULL ? source : "");
}

/**
 * @brief 从 NVS 读取字符串到固定缓冲区。
 * @param handle 已打开的 NVS 句柄。
 * @param key 键名。
 * @param output 目标缓冲区。
 * @param output_size 目标缓冲区长度。
 * @param fallback 键不存在或读取失败时的默认值。
 */
static void read_string(nvs_handle_t handle, const char *key, char *output, size_t output_size,
                        const char *fallback) {
    size_t required = 0;
    if (nvs_get_str(handle, key, NULL, &required) != ESP_OK || required == 0U || required > output_size ||
        nvs_get_str(handle, key, output, &required) != ESP_OK) {
        copy_text(output, output_size, fallback);
    }
}

/**
 * @brief 将字符串写入 NVS 并保留首个错误码。
 * @param handle 已打开的 NVS 句柄。
 * @param key 键名。
 * @param value 字符串值。
 * @param first_error 首个错误码存储位置。
 */
static void write_string(nvs_handle_t handle, const char *key, const char *value,
                         esp_err_t *first_error) {
    const esp_err_t error = nvs_set_str(handle, key, value != NULL ? value : "");
    if (*first_error == ESP_OK && error != ESP_OK) *first_error = error;
}

/**
 * @brief 把二进制数据编码为 Base64 文本。
 * @param data 输入数据。
 * @param data_length 输入长度。
 * @param output 输出缓冲区。
 * @param output_size 输出缓冲区长度。
 * @return 编码成功时返回 true。
 */
static bool encode_base64(const uint8_t *data, size_t data_length, char *output,
                          size_t output_size) {
    size_t written = 0;
    if (mbedtls_base64_encode((unsigned char *)output, output_size - 1U, &written, data,
                              data_length) != 0) return false;
    output[written] = '\0';
    return true;
}

/**
 * @brief 解码 Base64 文本。
 * @param input Base64 文本。
 * @param output 输出缓冲区。
 * @param output_size 输出缓冲区长度。
 * @param written 返回实际字节数。
 * @return 解码成功时返回 true。
 */
static bool decode_base64(const char *input, uint8_t *output, size_t output_size,
                          size_t *written) {
    return input != NULL &&
           mbedtls_base64_decode(output, output_size, written, (const unsigned char *)input,
                                 strlen(input)) == 0;
}

/**
 * @brief 使用 PBKDF2-HMAC-SHA256 计算密码哈希。
 * @param password 明文密码。
 * @param salt 密码盐。
 * @param salt_length 密码盐长度。
 * @param output 32 字节结果缓冲区。
 * @return 计算成功时返回 true。
 */
static bool password_hash(const char *password, const uint8_t *salt, size_t salt_length,
                          uint8_t output[CONFIG_HASH_BYTES]) {
    if (password == NULL || salt_length > CONFIG_SALT_BYTES) return false;
    /*
     * 使用 mbedTLS 内建 PBKDF2 复用 HMAC 上下文，与旧实现的
     * PBKDF2-HMAC-SHA256 结果兼容，避免每轮重建上下文阻塞单核 C3。
     */
    return mbedtls_pkcs5_pbkdf2_hmac_ext(
               MBEDTLS_MD_SHA256, (const unsigned char *)password, strlen(password),
               salt, salt_length, CONFIG_PBKDF2_ROUNDS, CONFIG_HASH_BYTES, output) == 0;
}

/**
 * @brief 以常量时间比较两个文本。
 * @param left 左侧文本。
 * @param right 右侧文本。
 * @return 完全相同时返回 true。
 */
static bool secure_equal(const char *left, const char *right) {
    const size_t left_length = strlen(left);
    const size_t right_length = strlen(right);
    unsigned char difference = (unsigned char)(left_length ^ right_length);
    const size_t maximum = left_length > right_length ? left_length : right_length;
    for (size_t index = 0; index < maximum; ++index) {
        const unsigned char a = index < left_length ? (unsigned char)left[index] : 0U;
        const unsigned char b = index < right_length ? (unsigned char)right[index] : 0U;
        difference |= (unsigned char)(a ^ b);
    }
    return difference == 0U;
}

/**
 * @brief 将内存配置和密码状态写入当前 NVS 命名空间。
 * @return ESP-IDF 错误码。
 */
static esp_err_t persist_locked(void) {
    nvs_handle_t handle;
    esp_err_t error = nvs_open(g_namespace, NVS_READWRITE, &handle);
    esp_err_t first_error = ESP_OK;
    if (error != ESP_OK) {
        ESP_LOGE(g_tag, "open namespace '%s' for writing: %s", g_namespace, esp_err_to_name(error));
        return error;
    }
    if ((error = nvs_set_u32(handle, "schema", CONFIG_SCHEMA_VERSION)) != ESP_OK) first_error = error;
    for (size_t index = 0U; index < APP_MAX_WIFI_PROFILES; ++index) {
        char key[12];
        snprintf(key, sizeof(key), "w%ussid", (unsigned)index);
        write_string(handle, key, g_config.wifi_profiles[index].used
            ? g_config.wifi_profiles[index].ssid : "", &first_error);
        snprintf(key, sizeof(key), "w%upass", (unsigned)index);
        write_string(handle, key, g_config.wifi_profiles[index].used
            ? g_config.wifi_profiles[index].password : "", &first_error);
    }
    if ((error = nvs_set_u8(handle, "wifi_last", g_config.last_successful_wifi)) != ESP_OK &&
        first_error == ESP_OK) first_error = error;
    write_string(handle, "smtp_host", g_config.smtp_server, &first_error);
    if ((error = nvs_set_u16(handle, "smtp_port", g_config.smtp_port)) != ESP_OK && first_error == ESP_OK) first_error = error;
    write_string(handle, "smtp_user", g_config.smtp_user, &first_error);
    write_string(handle, "smtp_pass", g_config.smtp_password, &first_error);
    write_string(handle, "smtp_to", g_config.smtp_recipient, &first_error);
    write_string(handle, "admin_phone", g_config.admin_phone, &first_error);
    if ((error = nvs_set_u8(handle, "admin_cmd", g_config.admin_commands_enabled ? 1U : 0U)) != ESP_OK && first_error == ESP_OK) first_error = error;
    write_string(handle, "num_black", g_config.number_blacklist, &first_error);
    write_string(handle, "web_salt", g_password_salt, &first_error);
    write_string(handle, "web_hash", g_password_hash, &first_error);
    if ((error = nvs_set_u8(handle, "auth_en", g_web_auth_enabled ? 1U : 0U)) != ESP_OK && first_error == ESP_OK) first_error = error;
    for (size_t index = 0; index < APP_MAX_PUSH_CHANNELS; ++index) {
        char key[16];
        const push_channel_t *channel = &g_config.push_channels[index];
        snprintf(key, sizeof(key), "p%uen", (unsigned)index);
        if ((error = nvs_set_u8(handle, key, channel->enabled ? 1U : 0U)) != ESP_OK && first_error == ESP_OK) first_error = error;
        snprintf(key, sizeof(key), "p%utype", (unsigned)index);
        if ((error = nvs_set_u8(handle, key, (uint8_t)channel->type)) != ESP_OK && first_error == ESP_OK) first_error = error;
        snprintf(key, sizeof(key), "p%uname", (unsigned)index); write_string(handle, key, channel->name, &first_error);
        snprintf(key, sizeof(key), "p%uurl", (unsigned)index); write_string(handle, key, channel->url, &first_error);
        snprintf(key, sizeof(key), "p%uk1", (unsigned)index); write_string(handle, key, channel->key1, &first_error);
        snprintf(key, sizeof(key), "p%uk2", (unsigned)index); write_string(handle, key, channel->key2, &first_error);
        snprintf(key, sizeof(key), "p%ubody", (unsigned)index); write_string(handle, key, channel->custom_body, &first_error);
    }
    if (first_error == ESP_OK) first_error = nvs_commit(handle);
    nvs_close(handle);
    if (first_error != ESP_OK) ESP_LOGE(g_tag, "commit namespace '%s': %s", g_namespace, esp_err_to_name(first_error));
    return first_error;
}

/**
 * @brief 从当前 NVS 命名空间加载配置。
 * @return ESP_OK 表示成功，ESP_ERR_NOT_FOUND 表示尚未创建配置。
 */
static esp_err_t load_current(void) {
    nvs_handle_t handle;
    uint32_t schema = 0;
    esp_err_t error = nvs_open(g_namespace, NVS_READONLY, &handle);
    if (error != ESP_OK) return error;
    if (nvs_get_u32(handle, "schema", &schema) != ESP_OK || schema != CONFIG_SCHEMA_VERSION) {
        nvs_close(handle);
        return ESP_ERR_NOT_FOUND;
    }
    memset(&g_config, 0, sizeof(g_config));
    g_config.schema_version = CONFIG_SCHEMA_VERSION;
    g_config.smtp_port = 465U;
    g_config.last_successful_wifi = UINT8_MAX;
    for (size_t index = 0U; index < APP_MAX_WIFI_PROFILES; ++index) {
        char key[12];
        snprintf(key, sizeof(key), "w%ussid", (unsigned)index);
        read_string(handle, key, g_config.wifi_profiles[index].ssid,
                    sizeof(g_config.wifi_profiles[index].ssid), "");
        snprintf(key, sizeof(key), "w%upass", (unsigned)index);
        read_string(handle, key, g_config.wifi_profiles[index].password,
                    sizeof(g_config.wifi_profiles[index].password), "");
        g_config.wifi_profiles[index].used = g_config.wifi_profiles[index].ssid[0] != '\0';
    }
    nvs_get_u8(handle, "wifi_last", &g_config.last_successful_wifi);
    if (g_config.last_successful_wifi >= APP_MAX_WIFI_PROFILES ||
        !g_config.wifi_profiles[g_config.last_successful_wifi].used) {
        g_config.last_successful_wifi = UINT8_MAX;
    }
    read_string(handle, "smtp_host", g_config.smtp_server, sizeof(g_config.smtp_server), "");
    nvs_get_u16(handle, "smtp_port", &g_config.smtp_port);
    read_string(handle, "smtp_user", g_config.smtp_user, sizeof(g_config.smtp_user), "");
    read_string(handle, "smtp_pass", g_config.smtp_password, sizeof(g_config.smtp_password), "");
    read_string(handle, "smtp_to", g_config.smtp_recipient, sizeof(g_config.smtp_recipient), "");
    read_string(handle, "admin_phone", g_config.admin_phone, sizeof(g_config.admin_phone), "");
    uint8_t enabled = 0U;
    nvs_get_u8(handle, "admin_cmd", &enabled);
    g_config.admin_commands_enabled = enabled != 0U;
    read_string(handle, "num_black", g_config.number_blacklist, sizeof(g_config.number_blacklist), "");
    read_string(handle, "web_salt", g_password_salt, sizeof(g_password_salt), "");
    read_string(handle, "web_hash", g_password_hash, sizeof(g_password_hash), "");
    enabled = 0U;
    nvs_get_u8(handle, "auth_en", &enabled);
    g_web_auth_enabled = enabled != 0U;
    for (size_t index = 0; index < APP_MAX_PUSH_CHANNELS; ++index) {
        char key[16];
        push_channel_t *channel = &g_config.push_channels[index];
        channel->type = PUSH_TYPE_POST_JSON;
        snprintf(key, sizeof(key), "p%uen", (unsigned)index); enabled = 0U; nvs_get_u8(handle, key, &enabled); channel->enabled = enabled != 0U;
        snprintf(key, sizeof(key), "p%utype", (unsigned)index); enabled = 1U; nvs_get_u8(handle, key, &enabled); channel->type = (push_type_t)enabled;
        snprintf(key, sizeof(key), "p%uname", (unsigned)index); read_string(handle, key, channel->name, sizeof(channel->name), "");
        snprintf(key, sizeof(key), "p%uurl", (unsigned)index); read_string(handle, key, channel->url, sizeof(channel->url), "");
        snprintf(key, sizeof(key), "p%uk1", (unsigned)index); read_string(handle, key, channel->key1, sizeof(channel->key1), "");
        snprintf(key, sizeof(key), "p%uk2", (unsigned)index); read_string(handle, key, channel->key2, sizeof(channel->key2), "");
        snprintf(key, sizeof(key), "p%ubody", (unsigned)index); read_string(handle, key, channel->custom_body, sizeof(channel->custom_body), "");
    }
    nvs_close(handle);
    return ESP_OK;
}

/** @brief 建立一份最小默认配置。 */
static esp_err_t create_defaults(void) {
    memset(&g_config, 0, sizeof(g_config));
    g_config.schema_version = CONFIG_SCHEMA_VERSION;
    g_config.last_successful_wifi = UINT8_MAX;
    g_config.smtp_port = 465U;
    g_web_auth_enabled = false;
    g_password_salt[0] = '\0';
    g_password_hash[0] = '\0';
    return persist_locked();
}

esp_err_t config_store_init(void) {
    esp_err_t error;
    if (g_config_mutex == NULL) {
        g_config_mutex = xSemaphoreCreateMutex();
        if (g_config_mutex == NULL) return ESP_ERR_NO_MEM;
    }
    error = nvs_flash_init();
    ESP_LOGI(g_tag, "nvs_flash_init: %s", esp_err_to_name(error));
    if (error == ESP_ERR_NVS_NO_FREE_PAGES || error == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGE(g_tag, "NVS requires recovery; refusing automatic erase (%s)", esp_err_to_name(error));
        return error;
    }
    if (error != ESP_OK) return error;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    error = load_current();
    ESP_LOGI(g_tag, "load current configuration: %s", esp_err_to_name(error));
    if (error == ESP_ERR_NOT_FOUND || error == ESP_ERR_NVS_NOT_FOUND) {
        error = create_defaults();
        ESP_LOGI(g_tag, "create default configuration: %s", esp_err_to_name(error));
    }
    xSemaphoreGive(g_config_mutex);
    return error;
}

void config_store_get(app_config_t *output) {
    if (output == NULL || g_config_mutex == NULL) return;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    memcpy(output, &g_config, sizeof(*output));
    xSemaphoreGive(g_config_mutex);
}

void config_store_get_status_summary(int active_wifi_slot, config_status_summary_t *output) {
    if (output == NULL || g_config_mutex == NULL) return;
    memset(output, 0, sizeof(*output));
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    const uint8_t display_slot = active_wifi_slot >= 0
                                     ? (uint8_t)active_wifi_slot
                                     : g_config.last_successful_wifi;
    if (display_slot < APP_MAX_WIFI_PROFILES && g_config.wifi_profiles[display_slot].used) {
        copy_text(output->wifi_ssid, sizeof(output->wifi_ssid),
                  g_config.wifi_profiles[display_slot].ssid);
    }
    output->smtp_configured =
        g_config.smtp_server[0] != '\0' && g_config.smtp_recipient[0] != '\0';
    for (size_t index = 0U; index < APP_MAX_PUSH_CHANNELS; ++index) {
        if (g_config.push_channels[index].enabled) ++output->enabled_channels;
    }
    xSemaphoreGive(g_config_mutex);
}

void config_store_get_sms_policy(config_sms_policy_t *output) {
    if (output == NULL || g_config_mutex == NULL) return;
    memset(output, 0, sizeof(*output));
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    copy_text(output->admin_phone, sizeof(output->admin_phone), g_config.admin_phone);
    output->admin_commands_enabled = g_config.admin_commands_enabled;
    copy_text(output->number_blacklist, sizeof(output->number_blacklist),
              g_config.number_blacklist);
    xSemaphoreGive(g_config_mutex);
}

bool config_store_get_push_channel(size_t index, push_channel_t *output) {
    if (output == NULL || index >= APP_MAX_PUSH_CHANNELS || g_config_mutex == NULL) return false;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    memcpy(output, &g_config.push_channels[index], sizeof(*output));
    xSemaphoreGive(g_config_mutex);
    return true;
}

void config_store_get_smtp_settings(config_smtp_settings_t *output) {
    if (output == NULL || g_config_mutex == NULL) return;
    memset(output, 0, sizeof(*output));
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    copy_text(output->server, sizeof(output->server), g_config.smtp_server);
    output->port = g_config.smtp_port;
    copy_text(output->user, sizeof(output->user), g_config.smtp_user);
    copy_text(output->password, sizeof(output->password), g_config.smtp_password);
    copy_text(output->recipient, sizeof(output->recipient), g_config.smtp_recipient);
    xSemaphoreGive(g_config_mutex);
}

size_t config_store_get_wifi_profiles(wifi_profile_t profiles[APP_MAX_WIFI_PROFILES],
                                      uint8_t *last_successful_slot) {
    size_t count = 0U;
    if (profiles == NULL || g_config_mutex == NULL) return 0U;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    memcpy(profiles, g_config.wifi_profiles, sizeof(g_config.wifi_profiles));
    for (size_t index = 0U; index < APP_MAX_WIFI_PROFILES; ++index) {
        if (profiles[index].used) ++count;
    }
    if (last_successful_slot != NULL) *last_successful_slot = g_config.last_successful_wifi;
    xSemaphoreGive(g_config_mutex);
    return count;
}

esp_err_t config_store_save_wifi_profile(int slot, const char *ssid, const char *password,
                                         bool keep_password, uint8_t *saved_slot) {
    esp_err_t error;
    if (ssid == NULL || password == NULL || g_config_mutex == NULL || ssid[0] == '\0' ||
        strlen(ssid) >= APP_WIFI_SSID_SIZE || strlen(password) >= APP_WIFI_PASSWORD_SIZE ||
        (password[0] != '\0' && strlen(password) < 8U)) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    int target = slot;
    if (target < 0) {
        for (size_t index = 0U; index < APP_MAX_WIFI_PROFILES; ++index) {
            if (g_config.wifi_profiles[index].used && strcmp(g_config.wifi_profiles[index].ssid, ssid) == 0) {
                target = (int)index;
                break;
            }
        }
    }
    if (target < 0) {
        for (size_t index = 0U; index < APP_MAX_WIFI_PROFILES; ++index) {
            if (!g_config.wifi_profiles[index].used) { target = (int)index; break; }
        }
    }
    if (target < 0 || target >= (int)APP_MAX_WIFI_PROFILES) {
        xSemaphoreGive(g_config_mutex);
        return ESP_ERR_NO_MEM;
    }
    wifi_profile_t *profile = &g_config.wifi_profiles[target];
    char old_password[APP_WIFI_PASSWORD_SIZE];
    copy_text(old_password, sizeof(old_password), profile->password);
    memset(profile, 0, sizeof(*profile));
    profile->used = true;
    copy_text(profile->ssid, sizeof(profile->ssid), ssid);
    copy_text(profile->password, sizeof(profile->password), keep_password ? old_password : password);
    error = persist_locked();
    if (saved_slot != NULL) *saved_slot = (uint8_t)target;
    xSemaphoreGive(g_config_mutex);
    return error;
}

esp_err_t config_store_delete_wifi_profile(uint8_t slot) {
    if (slot >= APP_MAX_WIFI_PROFILES || g_config_mutex == NULL) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    memset(&g_config.wifi_profiles[slot], 0, sizeof(g_config.wifi_profiles[slot]));
    if (g_config.last_successful_wifi == slot) g_config.last_successful_wifi = UINT8_MAX;
    const esp_err_t error = persist_locked();
    xSemaphoreGive(g_config_mutex);
    return error;
}

esp_err_t config_store_mark_wifi_success(uint8_t slot) {
    if (slot >= APP_MAX_WIFI_PROFILES || g_config_mutex == NULL) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    if (!g_config.wifi_profiles[slot].used) {
        xSemaphoreGive(g_config_mutex);
        return ESP_ERR_NOT_FOUND;
    }
    if (g_config.last_successful_wifi == slot) {
        xSemaphoreGive(g_config_mutex);
        return ESP_OK;
    }
    g_config.last_successful_wifi = slot;
    const esp_err_t error = persist_locked();
    xSemaphoreGive(g_config_mutex);
    return error;
}

esp_err_t config_store_save(const app_config_t *config) {
    esp_err_t error;
    if (config == NULL || g_config_mutex == NULL) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    memcpy(&g_config, config, sizeof(g_config));
    g_config.schema_version = CONFIG_SCHEMA_VERSION;
    error = persist_locked();
    xSemaphoreGive(g_config_mutex);
    return error;
}

bool config_store_verify_password(const char *password) {
    uint8_t salt[CONFIG_SALT_BYTES];
    uint8_t hash[CONFIG_HASH_BYTES];
    size_t salt_length = 0;
    char encoded[CONFIG_HASH_TEXT_SIZE];
    bool valid = false;
    if (password == NULL || g_config_mutex == NULL) return false;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    if (decode_base64(g_password_salt, salt, sizeof(salt), &salt_length) &&
        password_hash(password, salt, salt_length, hash) &&
        encode_base64(hash, sizeof(hash), encoded, sizeof(encoded))) {
        valid = secure_equal(g_password_hash, encoded);
    }
    xSemaphoreGive(g_config_mutex);
    return valid;
}

esp_err_t config_store_set_web_password(const char *password) {
    uint8_t salt[CONFIG_SALT_BYTES];
    uint8_t hash[CONFIG_HASH_BYTES];
    esp_err_t error;
    if (password == NULL || strlen(password) < 10U || strlen(password) > 72U || g_config_mutex == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_fill_random(salt, sizeof(salt));
    if (!password_hash(password, salt, sizeof(salt), hash)) return ESP_FAIL;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    if (!encode_base64(salt, sizeof(salt), g_password_salt, sizeof(g_password_salt)) ||
        !encode_base64(hash, sizeof(hash), g_password_hash, sizeof(g_password_hash))) {
        xSemaphoreGive(g_config_mutex);
        return ESP_FAIL;
    }
    error = persist_locked();
    xSemaphoreGive(g_config_mutex);
    return error;
}

bool config_store_web_auth_enabled(void) {
    bool enabled;
    if (g_config_mutex == NULL) return false;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    enabled = g_web_auth_enabled;
    xSemaphoreGive(g_config_mutex);
    return enabled;
}

esp_err_t config_store_set_web_auth_enabled(bool enabled) {
    esp_err_t error;
    if (g_config_mutex == NULL) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    g_web_auth_enabled = enabled;
    error = persist_locked();
    xSemaphoreGive(g_config_mutex);
    return error;
}
