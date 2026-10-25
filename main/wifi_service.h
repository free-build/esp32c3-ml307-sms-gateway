#pragma once

#include "esp_err.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/** 门户一次返回的附近 Wi-Fi 数量上限。 */
#define APP_WIFI_SCAN_MAX_RESULTS 20U

/** 门户展示的一条附近 Wi-Fi 信息。 */
typedef struct {
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    bool secure;
} app_wifi_network_t;

/** 配网连接过程状态。 */
typedef enum {
    APP_WIFI_PROVISION_IDLE = 0,
    APP_WIFI_PROVISION_CONNECTING,
    APP_WIFI_PROVISION_CONNECTED,
    APP_WIFI_PROVISION_FAILED,
} app_wifi_provision_state_t;

/** @brief 启动 Wi-Fi STA 或开放式配网热点。 */
esp_err_t wifi_service_start(void);

/** @brief 保存新 Wi-Fi 凭据并从配网热点切换到 STA。 */
esp_err_t wifi_service_update_credentials(const char *ssid, const char *password);

/** @brief 主动触发 STA 重连。 */
esp_err_t wifi_service_reconnect(void);

/**
 * @brief 在配网模式扫描附近 Wi-Fi，并按驱动返回的信号强度顺序去重。
 * @param networks 输出网络数组。
 * @param capacity 数组容量。
 * @param count 实际写入数量。
 */
esp_err_t wifi_service_scan(app_wifi_network_t *networks, size_t capacity, size_t *count);

/**
 * @brief 返回配网连接状态，并在成功时写入 STA 局域网地址。
 */
app_wifi_provision_state_t wifi_service_provision_status(char *ip, size_t ip_size);

/** @brief 返回当前是否已获得 STA 地址。 */
bool wifi_service_connected(void);

/** @brief 返回当前是否处于开放式 AP 配网模式。 */
bool wifi_service_provisioning(void);

/** @brief 把当前接口地址写入输出缓冲区。 */
void wifi_service_ip_address(char *output, size_t output_size);

/** @brief 返回 STA RSSI；未连接时返回 -127。 */
int8_t wifi_service_rssi(void);
