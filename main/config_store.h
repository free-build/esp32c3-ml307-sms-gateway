#pragma once

#include "app_types.h"
#include "esp_err.h"

/** 管理首页需要的小型配置摘要，避免为状态查询复制整份大配置。 */
typedef struct {
    char wifi_ssid[APP_WIFI_SSID_SIZE];
    bool smtp_configured;
    unsigned enabled_channels;
} config_status_summary_t;

/** 短信入箱后处理所需的小型配置。 */
typedef struct {
    char admin_phone[APP_PHONE_SIZE];
    bool admin_commands_enabled;
    char number_blacklist[APP_BLACKLIST_SIZE];
} config_sms_policy_t;

/** SMTP 投递所需配置。 */
typedef struct {
    char server[APP_SMTP_HOST_SIZE];
    uint16_t port;
    char user[APP_SMTP_FIELD_SIZE];
    char password[APP_SMTP_FIELD_SIZE];
    char recipient[APP_SMTP_FIELD_SIZE];
} config_smtp_settings_t;

/**
 * @brief 初始化 NVS 并加载配置。
 * @return ESP_OK 表示成功，其他值表示 NVS 错误。
 */
esp_err_t config_store_init(void);

/**
 * @brief 复制当前完整配置。
 * @param output 接收配置的有效指针。
 */
void config_store_get(app_config_t *output);

/** @brief 只复制管理首页必需的配置摘要。 */
void config_store_get_status_summary(int active_wifi_slot, config_status_summary_t *output);

/** @brief 只复制短信过滤与管理命令配置。 */
void config_store_get_sms_policy(config_sms_policy_t *output);

/** @brief 复制一个推送通道。 */
bool config_store_get_push_channel(size_t index, push_channel_t *output);

/** @brief 只复制 SMTP 配置。 */
void config_store_get_smtp_settings(config_smtp_settings_t *output);

/**
 * @brief 复制当前 Wi-Fi 凭据，避免在小栈任务中复制完整配置。
 * @param ssid SSID 输出缓冲区。
 * @param ssid_size SSID 输出缓冲区长度。
 * @param password 密码输出缓冲区。
 * @param password_size 密码输出缓冲区长度。
 */
size_t config_store_get_wifi_profiles(wifi_profile_t profiles[APP_MAX_WIFI_PROFILES],
                                      uint8_t *last_successful_slot);

/**
 * @brief 只更新并持久化 Wi-Fi 凭据。
 * @param ssid 新 SSID。
 * @param password 新 Wi-Fi 密码，可为空字符串。
 * @return ESP-IDF 错误码。
 */
esp_err_t config_store_save_wifi_profile(int slot, const char *ssid, const char *password,
                                         bool keep_password, uint8_t *saved_slot);

/** @brief 删除指定 Wi-Fi 槽位。 */
esp_err_t config_store_delete_wifi_profile(uint8_t slot);

/** @brief 把成功联网的槽位记为下次首选。 */
esp_err_t config_store_mark_wifi_success(uint8_t slot);

/**
 * @brief 保存完整配置并维持当前密码状态。
 * @param config 待保存配置。
 * @return ESP-IDF 错误码。
 */
esp_err_t config_store_save(const app_config_t *config);

/**
 * @brief 校验 Web 管理密码。
 * @param password 明文候选密码。
 * @return 密码正确时返回 true。
 */
bool config_store_verify_password(const char *password);

/**
 * @brief 设置新的 Web 管理密码。
 * @param password 长度为 10 至 72 字节的新密码。
 * @return ESP-IDF 错误码。
 */
esp_err_t config_store_set_web_password(const char *password);

/** @brief 返回后台是否要求密码登录。 */
bool config_store_web_auth_enabled(void);

/** @brief 启用或关闭后台密码登录。 */
esp_err_t config_store_set_web_auth_enabled(bool enabled);
