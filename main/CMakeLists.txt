idf_component_register(
    SRCS
        "app_main.c"
        "config_store.c"
        "modem_service.c"
        "notification_service.c"
        "safety_policy.c"
        "sms_service.c"
        "smtp_client.c"
        "web_server.c"
        "wifi_service.c"
    INCLUDE_DIRS "."
    REQUIRES
        app_update
        captive_dns
        esp_driver_gpio
        esp_driver_uart
        esp_event
        esp_http_client
        esp_http_server
        esp_netif
        esp_timer
        esp_wifi
        json
        lwip
        mbedtls
        nvs_flash
        pdulib
        spiffs
    EMBED_TXTFILES
        "web/management.html"
)

target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror=return-type)
