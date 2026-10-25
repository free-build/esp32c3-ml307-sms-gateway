#pragma once

#include "esp_err.h"

/** 门户 DNS 服务句柄。 */
typedef struct captive_dns_server *captive_dns_handle_t;

/**
 * @brief 启动通配 DNS 服务，把所有 A 记录指向指定网络接口。
 * @param netif_key ESP-NETIF 接口键，例如 WIFI_AP_DEF。
 * @return 成功时返回句柄，失败时返回 NULL。
 */
captive_dns_handle_t captive_dns_start(const char *netif_key);

/**
 * @brief 停止门户 DNS 服务并释放资源。
 * @param handle 由 captive_dns_start 返回的句柄。
 */
void captive_dns_stop(captive_dns_handle_t handle);
