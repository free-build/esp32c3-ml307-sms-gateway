#include "config_store.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_sntp.h"
#include "modem_service.h"
#include "notification_service.h"
#include "sms_service.h"
#include "web_server.h"
#include "wifi_service.h"

/** 应用入口日志标签。 */
static const char *const g_tag = "app";

/**
 * @brief 初始化配置、队列、网络、Web 服务、时钟和蜂窝模组。
 */
void app_main(void) {
    ESP_LOGI(g_tag, "starting native ESP-IDF C SMS forwarding firmware");
    ESP_ERROR_CHECK(config_store_init());
    ESP_ERROR_CHECK(sms_service_start());
    ESP_ERROR_CHECK(notification_service_start());
    ESP_ERROR_CHECK(wifi_service_start());
    ESP_ERROR_CHECK(web_server_start());

    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "ntp.ntsc.ac.cn");
    esp_sntp_setservername(1, "ntp.aliyun.com");
    esp_sntp_setservername(2, "pool.ntp.org");
    esp_sntp_init();

    ESP_ERROR_CHECK(modem_service_start());
}
