/*
 * 基于 ESP-IDF v5.5.2 examples/protocols/http_server/captive_portal 的
 * dns_server 组件改造，保留 CC0-1.0 / Unlicense 授权。
 */

#include "captive_dns.h"
#include "captive_dns_packet.h"

#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** DNS 服务端口。 */
#define CAPTIVE_DNS_PORT 53
/** 可接收的 DNS 数据包上限。 */
#define CAPTIVE_DNS_QUERY_SIZE 256U
/** DNS 响应数据包上限。 */
#define CAPTIVE_DNS_REPLY_SIZE 512U

/** 门户 DNS 服务运行状态。 */
struct captive_dns_server {
    atomic_bool running;
    TaskHandle_t task;
    char netif_key[16];
};

/** 模块日志标签。 */
static const char *const g_tag = "captive_dns";

/**
 * @brief 门户 DNS FreeRTOS 任务。
 * @param argument captive_dns_server 句柄。
 */
static void captive_dns_task(void *argument) {
    struct captive_dns_server *server = (struct captive_dns_server *)argument;
    struct sockaddr_in bind_address = {0};
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 250000};
    uint8_t query[CAPTIVE_DNS_QUERY_SIZE];
    uint8_t reply[CAPTIVE_DNS_REPLY_SIZE];
    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (socket_fd < 0) {
        ESP_LOGE(g_tag, "cannot create DNS socket: errno=%d", errno);
        server->task = NULL;
        vTaskDelete(NULL);
        return;
    }
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons(CAPTIVE_DNS_PORT);
    bind_address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(socket_fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) != 0) {
        ESP_LOGE(g_tag, "cannot bind DNS socket: errno=%d", errno);
        close(socket_fd);
        server->task = NULL;
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(g_tag, "official-style wildcard DNS server started");
    while (atomic_load(&server->running)) {
        struct sockaddr_storage source = {0};
        socklen_t source_length = sizeof(source);
        const int received = recvfrom(socket_fd, query, sizeof(query), 0,
                                      (struct sockaddr *)&source, &source_length);
        if (received <= 0) continue;
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey(server->netif_key);
        esp_netif_ip_info_t info = {0};
        if (netif == NULL || esp_netif_get_ip_info(netif, &info) != ESP_OK) continue;
        const int reply_length = captive_dns_build_reply(query, (size_t)received, reply,
                                                         sizeof(reply), info.ip.addr);
        if (reply_length > 0) {
            sendto(socket_fd, reply, (size_t)reply_length, 0,
                   (struct sockaddr *)&source, source_length);
        }
    }
    close(socket_fd);
    server->task = NULL;
    vTaskDelete(NULL);
}

/** @brief 创建句柄并启动官方风格的通配 DNS 任务。 */
captive_dns_handle_t captive_dns_start(const char *netif_key) {
    struct captive_dns_server *server;
    if (netif_key == NULL || strlen(netif_key) >= sizeof(server->netif_key)) return NULL;
    server = calloc(1U, sizeof(*server));
    if (server == NULL) return NULL;
    snprintf(server->netif_key, sizeof(server->netif_key), "%s", netif_key);
    atomic_store(&server->running, true);
    if (xTaskCreate(captive_dns_task, "captive_dns", 4096U, server, 5U, &server->task) != pdPASS) {
        free(server);
        return NULL;
    }
    return server;
}

/** @brief 等待 DNS 任务退出后释放服务句柄。 */
void captive_dns_stop(captive_dns_handle_t handle) {
    if (handle == NULL) return;
    atomic_store(&handle->running, false);
    for (unsigned attempt = 0U; attempt < 50U && handle->task != NULL; ++attempt) {
        vTaskDelay(pdMS_TO_TICKS(10U));
    }
    if (handle->task != NULL) vTaskDelete(handle->task);
    free(handle);
}
