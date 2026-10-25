idf_component_register(
    SRCS "captive_dns.c" "captive_dns_packet.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_netif lwip
)
