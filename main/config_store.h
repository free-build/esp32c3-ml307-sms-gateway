#pragma once

#include "app_types.h"
#include "esp_err.h"

/**
 * @brief 初始化 NVS 并加载或迁移配置。
 * @return ESP_OK 表示成功，其他值表示 NVS 错误。
 */
esp_err_t config_store_init(void);

/**
 * @brief 复制当前完整配置。
 * @param output 接收配置的有效指针。
 */
void config_store_get(app_config_t *output);

/**
 * @brief 复制当前 Wi-Fi 凭据，避免在小栈任务中复制完整配置。
 * @param ssid SSID 输出缓冲区。
 * @param ssid_size SSID 输出缓冲区长度。
 * @param password 密码输出缓冲区。
 * @param password_size 密码输出缓冲区长度。
 */
void config_store_get_wifi(char *ssid, size_t ssid_size, char *password, size_t password_size);

/**
 * @brief 只更新并持久化 Wi-Fi 凭据。
 * @param ssid 新 SSID。
 * @param password 新 Wi-Fi 密码，可为空字符串。
 * @return ESP-IDF 错误码。
 */
esp_err_t config_store_set_wifi(const char *ssid, const char *password);

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

/**
 * @brief 查询是否仍需修改初始密码。
 * @return 需要修改时返回 true。
 */
bool config_store_password_change_required(void);

/** @brief 返回后台是否要求密码登录。 */
bool config_store_web_auth_enabled(void);

/** @brief 启用或关闭后台密码登录。 */
esp_err_t config_store_set_web_auth_enabled(bool enabled);
