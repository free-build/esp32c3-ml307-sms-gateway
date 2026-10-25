#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @brief 为门户 DNS 查询生成响应。
 *
 * 仅回答 IN 类的 IPv4 A 查询；AAAA 等问题仍保留在响应的问题区，但不生成答案。
 * 输入中的 EDNS/附加记录不会复制到响应，避免把答案追加到附加记录之后形成畸形报文。
 *
 * @param query DNS 查询报文。
 * @param query_length 查询报文长度。
 * @param reply 响应缓冲区。
 * @param reply_size 响应缓冲区大小。
 * @param portal_ipv4_network_order SoftAP IPv4 地址，使用网络字节序。
 * @return 成功时返回响应长度；报文非法或缓冲区不足时返回 -1。
 */
int captive_dns_build_reply(const uint8_t *query, size_t query_length,
                            uint8_t *reply, size_t reply_size,
                            uint32_t portal_ipv4_network_order);
