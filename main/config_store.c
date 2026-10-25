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
#define CONFIG_SCHEMA_VERSION 2U
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
/** 历史 AP 密码字段缓冲区长度，仅用于保持 NVS 兼容。 */
#define CONFIG_SETUP_PASSWORD_SIZE 32U

/** 模块日志标签。 */
static const char *const g_tag = "config";
/** 当前配置使用的 NVS 命名空间。 */
static const char *const g_namespace = "sms_idf";
/** Arduino 旧固件使用的 NVS 命名空间。 */
static const char *const g_legacy_namespace = "sms_config";
/** 内存中的当前配置。 */
static app_config_t g_config;
/** 配置及密码状态互斥锁。 */
static SemaphoreHandle_t g_config_mutex;
/** Base64 编码后的 Web 密码盐。 */
static char g_password_salt[CONFIG_SALT_TEXT_SIZE];
/** Base64 编码后的 Web 密码哈希。 */
static char g_password_hash[CONFIG_HASH_TEXT_SIZE];
/** 兼容旧版布局而保留的随机 AP 密码。 */
static char g_setup_password[CONFIG_SETUP_PASSWORD_SIZE];
/** 是否要求用户修改初始管理密码；仅为旧版 NVS 字段保留。 */
static bool g_force_password_change;
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
 * @brief 生成仅用于兼容 NVS 结构的随机 AP 密码。
 */
static void generate_setup_password(void) {
    /** 排除易混淆字符的随机密码字符表。 */
    static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    for (size_t index = 0; index < 12U; ++index) {
        g_setup_password[index] = alphabet[esp_random() % (sizeof(alphabet) - 1U)];
    }
    g_setup_password[12] = '\0';
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
    write_string(handle, "wifi_ssid", g_config.wifi_ssid, &first_error);
    write_string(handle, "wifi_pass", g_config.wifi_password, &first_error);
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
    write_string(handle, "setup_pass", g_setup_password, &first_error);
    if ((error = nvs_set_u8(handle, "force_pw", g_force_password_change ? 1U : 0U)) != ESP_OK && first_error == ESP_OK) first_error = error;
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
 * @brief 从当前 NVS 命名空间加载版本 2 配置。
 * @return ESP_OK 表示成功，ESP_ERR_NOT_FOUND 表示需要迁移。
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
    g_config.schema_version = schema;
    g_config.smtp_port = 465U;
    read_string(handle, "wifi_ssid", g_config.wifi_ssid, sizeof(g_config.wifi_ssid), "");
    read_string(handle, "wifi_pass", g_config.wifi_password, sizeof(g_config.wifi_password), "");
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
    read_string(handle, "setup_pass", g_setup_password, sizeof(g_setup_password), "");
    enabled = 1U;
    nvs_get_u8(handle, "force_pw", &enabled);
    g_force_password_change = enabled != 0U;
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

/**
 * @brief 从 Arduino 旧命名空间导入可兼容配置。
 * @return 保存迁移结果时产生的 ESP-IDF 错误码。
 */
static esp_err_t import_legacy(void) {
    nvs_handle_t handle;
    memset(&g_config, 0, sizeof(g_config));
    g_config.schema_version = CONFIG_SCHEMA_VERSION;
    g_config.smtp_port = 465U;
    if (nvs_open(g_legacy_namespace, NVS_READONLY, &handle) == ESP_OK) {
        int32_t port = 465;
        read_string(handle, "smtpServer", g_config.smtp_server, sizeof(g_config.smtp_server), "");
        nvs_get_i32(handle, "smtpPort", &port);
        if (port < 1) port = 1;
        if (port > 65535) port = 65535;
        g_config.smtp_port = (uint16_t)port;
        read_string(handle, "smtpUser", g_config.smtp_user, sizeof(g_config.smtp_user), "");
        read_string(handle, "smtpPass", g_config.smtp_password, sizeof(g_config.smtp_password), "");
        read_string(handle, "smtpSendTo", g_config.smtp_recipient, sizeof(g_config.smtp_recipient), "");
        read_string(handle, "adminPhone", g_config.admin_phone, sizeof(g_config.admin_phone), "");
        read_string(handle, "numBlkList", g_config.number_blacklist, sizeof(g_config.number_blacklist), "");
        for (size_t index = 0; index < APP_MAX_PUSH_CHANNELS; ++index) {
            char key[20];
            uint8_t value = 0U;
            push_channel_t *channel = &g_config.push_channels[index];
            channel->type = PUSH_TYPE_POST_JSON;
            snprintf(key, sizeof(key), "push%uen", (unsigned)index); nvs_get_u8(handle, key, &value); channel->enabled = value != 0U;
            snprintf(key, sizeof(key), "push%utype", (unsigned)index); value = 1U; nvs_get_u8(handle, key, &value); channel->type = (push_type_t)value;
            snprintf(key, sizeof(key), "push%uname", (unsigned)index); read_string(handle, key, channel->name, sizeof(channel->name), "");
            snprintf(key, sizeof(key), "push%uurl", (unsigned)index); read_string(handle, key, channel->url, sizeof(channel->url), "");
            snprintf(key, sizeof(key), "push%uk1", (unsigned)index); read_string(handle, key, channel->key1, sizeof(channel->key1), "");
            snprintf(key, sizeof(key), "push%uk2", (unsigned)index); read_string(handle, key, channel->key2, sizeof(channel->key2), "");
            snprintf(key, sizeof(key), "push%ubody", (unsigned)index); read_string(handle, key, channel->custom_body, sizeof(channel->custom_body), "");
        }
        char old_url[APP_CHANNEL_URL_SIZE];
        read_string(handle, "httpUrl", old_url, sizeof(old_url), "");
        if (old_url[0] != '\0' && !g_config.push_channels[0].enabled) {
            uint8_t bark_mode = 0U;
            nvs_get_u8(handle, "barkMode", &bark_mode);
            g_config.push_channels[0].enabled = true;
            g_config.push_channels[0].type = bark_mode != 0U ? PUSH_TYPE_BARK : PUSH_TYPE_POST_JSON;
            copy_text(g_config.push_channels[0].name, sizeof(g_config.push_channels[0].name), "legacy migrated channel");
            copy_text(g_config.push_channels[0].url, sizeof(g_config.push_channels[0].url), old_url);
        }
        nvs_close(handle);
        ESP_LOGI(g_tag, "legacy configuration imported without modifying namespace '%s'", g_legacy_namespace);
    } else {
        ESP_LOGI(g_tag, "no legacy configuration found; starting with defaults");
    }
    return persist_locked();
}

/**
 * @brief 确保 Web 密码哈希和兼容字段均已初始化。
 * @return ESP-IDF 错误码。
 */
static esp_err_t ensure_password_state(void) {
    bool changed = false;
    if (g_setup_password[0] == '\0') {
        generate_setup_password();
        changed = true;
    }
    if (g_password_hash[0] == '\0' || g_password_salt[0] == '\0') {
        uint8_t salt[CONFIG_SALT_BYTES];
        uint8_t hash[CONFIG_HASH_BYTES];
        esp_fill_random(salt, sizeof(salt));
        /*
         * 新装设备默认关闭 Web 认证。仍需初始化哈希字段以兼容旧版 NVS，
         * 但使用每台设备独立的随机值，避免固件内存在可公开利用的固定密码。
         * 用户启用登录保护时必须同时设置一个 10-72 字符的新密码。
         */
        if (!encode_base64(salt, sizeof(salt), g_password_salt, sizeof(g_password_salt)) ||
            !password_hash(g_setup_password, salt, sizeof(salt), hash) ||
            !encode_base64(hash, sizeof(hash), g_password_hash, sizeof(g_password_hash))) {
            return ESP_FAIL;
        }
        g_force_password_change = false;
        changed = true;
    }
    return changed ? persist_locked() : ESP_OK;
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
        error = import_legacy();
        ESP_LOGI(g_tag, "legacy configuration migration: %s", esp_err_to_name(error));
    }
    if (error == ESP_OK) error = ensure_password_state();
    ESP_LOGI(g_tag, "password state initialization: %s", esp_err_to_name(error));
    xSemaphoreGive(g_config_mutex);
    return error;
}

void config_store_get(app_config_t *output) {
    if (output == NULL || g_config_mutex == NULL) return;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    memcpy(output, &g_config, sizeof(*output));
    xSemaphoreGive(g_config_mutex);
}

void config_store_get_wifi(char *ssid, size_t ssid_size, char *password, size_t password_size) {
    if (ssid == NULL || password == NULL || g_config_mutex == NULL) return;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    copy_text(ssid, ssid_size, g_config.wifi_ssid);
    copy_text(password, password_size, g_config.wifi_password);
    xSemaphoreGive(g_config_mutex);
}

esp_err_t config_store_set_wifi(const char *ssid, const char *password) {
    esp_err_t error;
    if (ssid == NULL || password == NULL || g_config_mutex == NULL) return ESP_ERR_INVALID_ARG;
    if (strlen(ssid) >= sizeof(g_config.wifi_ssid) || strlen(password) >= sizeof(g_config.wifi_password)) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    copy_text(g_config.wifi_ssid, sizeof(g_config.wifi_ssid), ssid);
    copy_text(g_config.wifi_password, sizeof(g_config.wifi_password), password);
    error = persist_locked();
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
    g_force_password_change = false;
    error = persist_locked();
    xSemaphoreGive(g_config_mutex);
    return error;
}

bool config_store_password_change_required(void) {
    bool required;
    if (g_config_mutex == NULL) return true;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    required = g_force_password_change;
    xSemaphoreGive(g_config_mutex);
    return required;
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
    g_force_password_change = false;
    error = persist_locked();
    xSemaphoreGive(g_config_mutex);
    return error;
}
