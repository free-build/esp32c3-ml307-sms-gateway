#include "wifi_service.h"

#include "captive_dns.h"
#include "config_store.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/** 连续离线超过此时间后开启恢复热点。 */
#define WIFI_RECOVERY_DELAY_US (180LL * 1000000LL)
/** 配网响应发送完成后切换到 STA 的延迟。 */
#define WIFI_PROVISION_SWITCH_DELAY_MS 800U
/** 新凭据试连超时；失败后恢复配网热点且不持久化错误凭据。 */
#define WIFI_PROVISION_CONNECT_TIMEOUT_MS 30000U
/** 成功后保留门户的时间，供页面取得后台 IP 并发起跳转。 */
#define WIFI_PROVISION_REDIRECT_GRACE_MS 15000U

/** AP 配网完成后传递给异步切换任务的凭据。 */
typedef struct {
    char ssid[APP_WIFI_SSID_SIZE];
    char password[APP_WIFI_PASSWORD_SIZE];
    uint8_t slot;
} wifi_transition_request_t;

/** 模块日志标签。 */
static const char *const g_tag = "wifi";
/** STA 网络接口句柄。 */
static esp_netif_t *g_sta_netif;
/** AP 网络接口句柄。 */
static esp_netif_t *g_ap_netif;
/** 基于官方门户示例的通配 DNS 服务句柄。 */
static captive_dns_handle_t g_dns_server;
/** STA 是否已经获得 IP 地址。 */
static atomic_bool g_connected;
/** STA 驱动是否正在建立连接。 */
static atomic_bool g_connecting;
/** 设备是否处于 AP 配网模式。 */
static atomic_bool g_provisioning;
/** 当前连续重连计数。 */
static atomic_uint g_reconnect_attempts;
/** 是否已经排队 AP 到 STA 的切换任务。 */
static atomic_bool g_transition_pending;
/** 是否正在执行门户 Wi-Fi 扫描。 */
static atomic_bool g_scan_active;
/** 当前配网连接过程状态。 */
static atomic_int g_provision_state;
/** 当前正在尝试或已连接的凭据槽位。 */
static atomic_int g_active_slot = -1;
/** 连续离线起始时间。 */
static atomic_llong g_offline_since_us;
/** 最近一次断开原因。 */
static atomic_int g_last_disconnect_reason;
/** 管理重连与恢复热点的后台任务。 */
static TaskHandle_t g_manager_task;
/** @brief 启动开放式配网 AP，供异步切换失败时恢复。 */
static esp_err_t start_provisioning_ap(void);

/**
 * @brief 处理 Wi-Fi 与 IP 事件并维护连接状态。
 */
static void wifi_event_handler(void *argument, esp_event_base_t base, int32_t id, void *data) {
    (void)argument;
    if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED) {
        const wifi_event_ap_staconnected_t *event = (const wifi_event_ap_staconnected_t *)data;
        ESP_LOGI(g_tag, "portal client " MACSTR " joined, aid=%d", MAC2STR(event->mac), event->aid);
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STADISCONNECTED) {
        const wifi_event_ap_stadisconnected_t *event = (const wifi_event_ap_stadisconnected_t *)data;
        ESP_LOGI(g_tag, "portal client " MACSTR " left, aid=%d reason=%d",
                 MAC2STR(event->mac), event->aid, event->reason);
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *event = (const wifi_event_sta_disconnected_t *)data;
        atomic_store(&g_connected, false);
        atomic_store(&g_connecting, false);
        atomic_store(&g_last_disconnect_reason, event->reason);
        if (atomic_load(&g_offline_since_us) == 0) atomic_store(&g_offline_since_us, esp_timer_get_time());
        if (g_manager_task != NULL) xTaskNotifyGive(g_manager_task);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *event = (const ip_event_got_ip_t *)data;
        atomic_store(&g_connected, true);
        atomic_store(&g_connecting, false);
        atomic_store(&g_reconnect_attempts, 0U);
        atomic_store(&g_offline_since_us, 0);
        const int slot = atomic_load(&g_active_slot);
        if (slot >= 0) config_store_mark_wifi_success((uint8_t)slot);
        ESP_LOGI(g_tag, "station connected: " IPSTR, IP2STR(&event->ip_info.ip));
    }
}

/**
 * @brief 使用给定凭据启动 STA。
 */
static esp_err_t apply_station_profile(uint8_t slot, const wifi_profile_t *profile) {
    wifi_config_t config = {0};
    memcpy(config.sta.ssid, profile->ssid, strlen(profile->ssid));
    memcpy(config.sta.password, profile->password, strlen(profile->password));
    config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    config.sta.threshold.authmode = profile->password[0] == '\0' ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &config), g_tag, "station config");
    atomic_store(&g_active_slot, slot);
    ESP_LOGI(g_tag, "connecting Wi-Fi profile slot %u, SSID '%s'", (unsigned)slot, profile->ssid);
    const esp_err_t error = esp_wifi_connect();
    atomic_store(&g_connecting, error == ESP_OK);
    return error;
}

/** @brief 按最近成功优先的顺序选取第 N 个凭据槽位。 */
static int ordered_profile_slot(const wifi_profile_t profiles[APP_MAX_WIFI_PROFILES],
                                uint8_t preferred, unsigned ordinal) {
    if (preferred < APP_MAX_WIFI_PROFILES && profiles[preferred].used) {
        if (ordinal == 0U) return preferred;
        --ordinal;
    }
    for (size_t slot = 0U; slot < APP_MAX_WIFI_PROFILES; ++slot) {
        if (!profiles[slot].used || slot == preferred) continue;
        if (ordinal-- == 0U) return (int)slot;
    }
    return -1;
}

/** @brief 成功连网后关闭恢复热点。 */
static void close_recovery_ap(void) {
    atomic_store(&g_provision_state, APP_WIFI_PROVISION_CONNECTED);
    atomic_store(&g_provisioning, false);
    vTaskDelay(pdMS_TO_TICKS(WIFI_PROVISION_REDIRECT_GRACE_MS));
    if (g_dns_server != NULL) captive_dns_stop(g_dns_server);
    g_dns_server = NULL;
    const esp_err_t error = esp_wifi_set_mode(WIFI_MODE_STA);
    if (error != ESP_OK) ESP_LOGE(g_tag, "cannot close recovery AP: %s", esp_err_to_name(error));
}

/** @brief 以退避方式轮询三组凭据，并在长时间离线后开启门户。 */
static void wifi_manager(void *argument) {
    (void)argument;
    static const uint32_t backoff_seconds[] = {1U, 2U, 5U, 10U, 30U};
    unsigned ordinal = 0U;
    int64_t next_attempt_us = 0;
    for (;;) {
        if (atomic_load(&g_connected)) {
            if (atomic_load(&g_provisioning) && !atomic_load(&g_transition_pending)) close_recovery_ap();
            ordinal = 0U;
            next_attempt_us = 0;
            ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000U));
            continue;
        }
        if (atomic_load(&g_offline_since_us) == 0) atomic_store(&g_offline_since_us, esp_timer_get_time());
        const int64_t elapsed = esp_timer_get_time() - atomic_load(&g_offline_since_us);
        if (elapsed >= WIFI_RECOVERY_DELAY_US && !atomic_load(&g_provisioning)) {
            start_provisioning_ap();
        }
        if (atomic_load(&g_transition_pending) || atomic_load(&g_scan_active) ||
            atomic_load(&g_connecting)) {
            ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000U));
            continue;
        }
        {
            wifi_profile_t profiles[APP_MAX_WIFI_PROFILES];
            uint8_t preferred = UINT8_MAX;
            const size_t count = config_store_get_wifi_profiles(profiles, &preferred);
            if (count > 0U) {
                const unsigned attempts = atomic_load(&g_reconnect_attempts);
                if (attempts > 0U) {
                    const size_t backoff_index = (attempts - 1U) <
                        (sizeof(backoff_seconds) / sizeof(backoff_seconds[0]))
                            ? attempts - 1U
                            : (sizeof(backoff_seconds) / sizeof(backoff_seconds[0]) - 1U);
                    if (next_attempt_us == 0) {
                        next_attempt_us = esp_timer_get_time() +
                            (int64_t)backoff_seconds[backoff_index] * 1000000LL;
                    }
                    const int64_t remaining_us = next_attempt_us - esp_timer_get_time();
                    if (remaining_us > 0) {
                        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS((uint32_t)(remaining_us / 1000LL + 1LL)));
                        continue;
                    }
                }
                const int slot = ordered_profile_slot(profiles, preferred, ordinal % count);
                if (slot >= 0) {
                    if (apply_station_profile((uint8_t)slot, &profiles[slot]) == ESP_OK) {
                        atomic_fetch_add(&g_reconnect_attempts, 1U);
                    }
                    ++ordinal;
                    next_attempt_us = 0;
                }
            }
        }
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000U));
    }
}

/**
 * @brief 等待配网 HTTP 响应发送完成，再从 AP 切换到 STA。
 * @param argument 动态分配的 Wi-Fi 凭据，任务退出前释放。
 */
static void delayed_station_transition(void *argument) {
    wifi_transition_request_t *request = (wifi_transition_request_t *)argument;
    wifi_config_t station_config = {0};
    esp_err_t error;
    vTaskDelay(pdMS_TO_TICKS(WIFI_PROVISION_SWITCH_DELAY_MS));
    memcpy(station_config.sta.ssid, request->ssid, strlen(request->ssid));
    memcpy(station_config.sta.password, request->password, strlen(request->password));
    station_config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    station_config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    station_config.sta.threshold.authmode = request->password[0] == '\0'
        ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;
    atomic_store(&g_connected, false);
    atomic_store(&g_connecting, true);
    atomic_store(&g_provision_state, APP_WIFI_PROVISION_CONNECTING);
    error = esp_wifi_set_config(WIFI_IF_STA, &station_config);
    if (error == ESP_OK) error = esp_wifi_connect();
    if (error == ESP_OK) {
        const TickType_t started = xTaskGetTickCount();
        while (!atomic_load(&g_connected) &&
               xTaskGetTickCount() - started < pdMS_TO_TICKS(WIFI_PROVISION_CONNECT_TIMEOUT_MS)) {
            vTaskDelay(pdMS_TO_TICKS(100U));
        }
        error = atomic_load(&g_connected) ? ESP_OK : ESP_ERR_TIMEOUT;
    }
    if (error != ESP_OK) {
        ESP_LOGE(g_tag, "new Wi-Fi credentials were not accepted; portal remains active: %s",
                 esp_err_to_name(error));
        esp_wifi_disconnect();
        atomic_store(&g_connected, false);
        atomic_store(&g_connecting, false);
        atomic_store(&g_provision_state, APP_WIFI_PROVISION_FAILED);
    } else {
        config_store_mark_wifi_success(request->slot);
        ESP_LOGI(g_tag, "new Wi-Fi credentials connected successfully");
        close_recovery_ap();
    }
    memset(request, 0, sizeof(*request));
    free(request);
    atomic_store(&g_transition_pending, false);
    vTaskDelete(NULL);
}

/**
 * @brief 启动无需密码的 AP、DHCP、门户公告和 DNS 劫持。
 */
static esp_err_t start_provisioning_ap(void) {
    uint8_t mac[6] = {0};
    char ssid[APP_WIFI_SSID_SIZE];
    wifi_config_t config = {0};
    esp_err_t dhcp_error;
    uint8_t offer_dns = 1U;
    esp_netif_ip_info_t ip_info = {0};
    esp_netif_dns_info_t dns_info = {0};
    /** DHCP Option 114 公告的门户地址，必须在 DHCP 服务期间保持有效。 */
    static char portal_uri[] = "http://192.168.4.1";
    atomic_store(&g_provisioning, true);
    atomic_store(&g_connected, false);
    if (g_ap_netif == NULL) g_ap_netif = esp_netif_create_default_wifi_ap();
    if (g_ap_netif == NULL) return ESP_ERR_NO_MEM;
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    wifi_profile_t profiles[APP_MAX_WIFI_PROFILES];
    const bool recovery = config_store_get_wifi_profiles(profiles, NULL) > 0U;
    snprintf(ssid, sizeof(ssid), recovery ? "SMS-Recovery-%02X%02X" : "SMS-Setup-%02X%02X",
             mac[4], mac[5]);
    memcpy(config.ap.ssid, ssid, strlen(ssid));
    config.ap.ssid_len = strlen(ssid);
    config.ap.max_connection = 4U;
    config.ap.authmode = WIFI_AUTH_OPEN;
    /* STA 接口只用于扫描；SoftAP 继续承载门户和 DHCP。 */
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_APSTA), g_tag, "AP+STA portal mode");
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_AP, &config), g_tag, "AP config");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), g_tag, "AP start");

    /*
     * 严格按 ESP-IDF 5.5.2 captive_portal 示例的时序：先启动 SoftAP，
     * 再停止 DHCP 写入 Option 6/114，避免 AP_START 事件重置 DHCP 选项。
     */
    dhcp_error = esp_netif_dhcps_stop(g_ap_netif);
    if (dhcp_error != ESP_OK && dhcp_error != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) return dhcp_error;
    ESP_RETURN_ON_ERROR(esp_netif_get_ip_info(g_ap_netif, &ip_info), g_tag, "read AP address");
    dns_info.ip.u_addr.ip4.addr = ip_info.ip.addr;
    dns_info.ip.type = ESP_IPADDR_TYPE_V4;
    ESP_RETURN_ON_ERROR(esp_netif_set_dns_info(g_ap_netif, ESP_NETIF_DNS_MAIN, &dns_info),
                        g_tag, "set captive DNS address");
    ESP_RETURN_ON_ERROR(esp_netif_dhcps_option(g_ap_netif, ESP_NETIF_OP_SET,
                                               ESP_NETIF_DOMAIN_NAME_SERVER, &offer_dns,
                                               sizeof(offer_dns)), g_tag, "advertise captive DNS");
    ESP_RETURN_ON_ERROR(esp_netif_dhcps_option(g_ap_netif, ESP_NETIF_OP_SET,
                                               ESP_NETIF_CAPTIVEPORTAL_URI, portal_uri,
                                               strlen(portal_uri)), g_tag, "advertise captive portal URI");
    ESP_RETURN_ON_ERROR(esp_netif_dhcps_start(g_ap_netif), g_tag, "start AP DHCP server");
    if (g_dns_server == NULL) g_dns_server = captive_dns_start("WIFI_AP_DEF");
    if (g_dns_server == NULL) return ESP_ERR_NO_MEM;
    ESP_LOGW(g_tag, "open provisioning AP '%s' started; captive portal: http://192.168.4.1/", ssid);
    return ESP_OK;
}

esp_err_t wifi_service_start(void) {
    wifi_profile_t profiles[APP_MAX_WIFI_PROFILES];
    uint8_t preferred = UINT8_MAX;
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t event_error;
    ESP_RETURN_ON_ERROR(esp_netif_init(), g_tag, "netif init");
    event_error = esp_event_loop_create_default();
    if (event_error != ESP_OK && event_error != ESP_ERR_INVALID_STATE) return event_error;
    g_sta_netif = esp_netif_create_default_wifi_sta();
    if (g_sta_netif == NULL) return ESP_ERR_NO_MEM;
    ESP_RETURN_ON_ERROR(esp_wifi_init(&init), g_tag, "wifi init");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                   wifi_event_handler, NULL), g_tag,
                        "wifi event handler");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                   wifi_event_handler, NULL), g_tag,
                        "ip event handler");
    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_RAM), g_tag, "wifi storage");
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), g_tag, "station mode");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), g_tag, "wifi start");
    ESP_RETURN_ON_ERROR(esp_wifi_set_ps(WIFI_PS_NONE), g_tag, "disable wifi power save");
    const size_t count = config_store_get_wifi_profiles(profiles, &preferred);
    esp_err_t error = ESP_OK;
    if (count == 0U) error = start_provisioning_ap();
    else {
        const int slot = ordered_profile_slot(profiles, preferred, 0U);
        error = apply_station_profile((uint8_t)slot, &profiles[slot]);
    }
    if (error == ESP_OK && xTaskCreate(wifi_manager, "wifi_manager", 4096U, NULL, 5U,
                                       &g_manager_task) != pdPASS) return ESP_ERR_NO_MEM;
    return error;
}

esp_err_t wifi_service_update_credentials(const char *ssid, const char *password, int replace_slot) {
    const size_t ssid_length = ssid != NULL ? strlen(ssid) : 0U;
    const size_t password_length = password != NULL ? strlen(password) : 0U;
    wifi_transition_request_t *request;
    if (ssid_length == 0U || ssid_length > 32U || password_length > 63U ||
        (password_length != 0U && password_length < 8U)) return ESP_ERR_INVALID_ARG;
    if (!atomic_load(&g_provisioning) || atomic_exchange(&g_transition_pending, true)) return ESP_ERR_INVALID_STATE;
    atomic_store(&g_provision_state, APP_WIFI_PROVISION_CONNECTING);
    request = calloc(1U, sizeof(*request));
    if (request == NULL) {
        atomic_store(&g_transition_pending, false);
        return ESP_ERR_NO_MEM;
    }
    snprintf(request->ssid, sizeof(request->ssid), "%s", ssid);
    snprintf(request->password, sizeof(request->password), "%s", password);
    wifi_profile_t profiles[APP_MAX_WIFI_PROFILES];
    config_store_get_wifi_profiles(profiles, NULL);
    for (size_t slot = 0U; slot < APP_MAX_WIFI_PROFILES; ++slot) {
        if (profiles[slot].used && strcmp(profiles[slot].ssid, ssid) == 0) {
            replace_slot = (int)slot;
            break;
        }
    }
    esp_err_t save_error = config_store_save_wifi_profile(replace_slot, ssid, password, false,
                                                          &request->slot);
    if (save_error != ESP_OK) {
        free(request);
        atomic_store(&g_transition_pending, false);
        return save_error;
    }
    atomic_store(&g_active_slot, request->slot);
    if (xTaskCreate(delayed_station_transition, "wifi_transition", 4096U, request, 6U, NULL) != pdPASS) {
        memset(request, 0, sizeof(*request));
        free(request);
        atomic_store(&g_transition_pending, false);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t wifi_service_reconnect(void) {
    wifi_profile_t profiles[APP_MAX_WIFI_PROFILES];
    esp_wifi_disconnect();
    atomic_store(&g_reconnect_attempts, 0U);
    atomic_store(&g_offline_since_us, config_store_get_wifi_profiles(profiles, NULL) == 0U
        ? esp_timer_get_time() - WIFI_RECOVERY_DELAY_US : esp_timer_get_time());
    if (g_manager_task != NULL) xTaskNotifyGive(g_manager_task);
    return ESP_OK;
}

esp_err_t wifi_service_scan(app_wifi_network_t *networks, size_t capacity, size_t *count) {
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0U,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
    };
    wifi_ap_record_t *records;
    uint16_t record_count;
    size_t output_count = 0U;
    esp_err_t error;
    if (networks == NULL || count == NULL || capacity == 0U) return ESP_ERR_INVALID_ARG;
    *count = 0U;
    if (!atomic_load(&g_provisioning) || atomic_load(&g_transition_pending)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (atomic_exchange(&g_scan_active, true)) return ESP_ERR_INVALID_STATE;
    error = esp_wifi_scan_start(&scan_config, true);
    if (error != ESP_OK) {
        atomic_store(&g_scan_active, false);
        return error;
    }
    record_count = capacity < APP_WIFI_SCAN_MAX_RESULTS
        ? (uint16_t)capacity : (uint16_t)APP_WIFI_SCAN_MAX_RESULTS;
    records = calloc(record_count, sizeof(*records));
    if (records == NULL) {
        atomic_store(&g_scan_active, false);
        return ESP_ERR_NO_MEM;
    }
    error = esp_wifi_scan_get_ap_records(&record_count, records);
    if (error == ESP_OK) {
        for (uint16_t index = 0U; index < record_count; ++index) {
            const size_t ssid_length = strnlen((const char *)records[index].ssid,
                                               sizeof(records[index].ssid));
            bool duplicate = false;
            if (ssid_length == 0U) continue;
            for (size_t existing = 0U; existing < output_count; ++existing) {
                if (strncmp(networks[existing].ssid, (const char *)records[index].ssid,
                            sizeof(networks[existing].ssid)) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            memcpy(networks[output_count].ssid, records[index].ssid, ssid_length);
            networks[output_count].ssid[ssid_length] = '\0';
            networks[output_count].rssi = records[index].rssi;
            networks[output_count].channel = records[index].primary;
            networks[output_count].secure = records[index].authmode != WIFI_AUTH_OPEN;
            if (++output_count == capacity) break;
        }
    }
    memset(records, 0, record_count * sizeof(*records));
    free(records);
    atomic_store(&g_scan_active, false);
    *count = output_count;
    return error;
}

bool wifi_service_connected(void) { return atomic_load(&g_connected); }

bool wifi_service_provisioning(void) { return atomic_load(&g_provisioning); }

void wifi_service_ip_address(char *output, size_t output_size) {
    esp_netif_ip_info_t info = {0};
    esp_netif_t *netif = wifi_service_provisioning() ? g_ap_netif : g_sta_netif;
    if (output == NULL || output_size == 0U) return;
    if (netif == NULL || esp_netif_get_ip_info(netif, &info) != ESP_OK) {
        snprintf(output, output_size, "0.0.0.0");
        return;
    }
    snprintf(output, output_size, IPSTR, IP2STR(&info.ip));
}

int8_t wifi_service_rssi(void) {
    wifi_ap_record_t record = {0};
    if (!wifi_service_connected()) return -127;
    return esp_wifi_sta_get_ap_info(&record) == ESP_OK ? record.rssi : -127;
}

int wifi_service_active_slot(void) {
    return wifi_service_connected() ? atomic_load(&g_active_slot) : -1;
}

uint32_t wifi_service_outage_seconds(void) {
    const int64_t since = atomic_load(&g_offline_since_us);
    return since == 0 ? 0U : (uint32_t)((esp_timer_get_time() - since) / 1000000LL);
}

uint32_t wifi_service_reconnect_attempts(void) { return atomic_load(&g_reconnect_attempts); }

int32_t wifi_service_last_disconnect_reason(void) { return atomic_load(&g_last_disconnect_reason); }

app_wifi_provision_state_t wifi_service_provision_status(char *ip, size_t ip_size) {
    const app_wifi_provision_state_t state =
        (app_wifi_provision_state_t)atomic_load(&g_provision_state);
    if (ip != NULL && ip_size > 0U) {
        esp_netif_ip_info_t info = {0};
        ip[0] = '\0';
        if (state == APP_WIFI_PROVISION_CONNECTED && g_sta_netif != NULL &&
            esp_netif_get_ip_info(g_sta_netif, &info) == ESP_OK) {
            snprintf(ip, ip_size, IPSTR, IP2STR(&info.ip));
        }
    }
    return state;
}
