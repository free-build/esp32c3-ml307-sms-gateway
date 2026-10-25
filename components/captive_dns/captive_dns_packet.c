#include "captive_dns_packet.h"

#include <stdbool.h>
#include <string.h>

/** DNS 报文头长度。 */
#define DNS_HEADER_SIZE 12U
/** DNS 问题尾部长度。 */
#define DNS_QUESTION_TAIL_SIZE 4U
/** DNS 压缩答案长度。 */
#define DNS_ANSWER_SIZE 16U
/** DNS A 记录类型。 */
#define DNS_TYPE_A 1U
/** DNS IN 类。 */
#define DNS_CLASS_IN 1U
/** DNS 响应 TTL，单位秒。 */
#define DNS_TTL_SECONDS 300U
/** DNS 查询响应位。 */
#define DNS_FLAG_QR 0x8000U
/** DNS 操作码掩码。 */
#define DNS_FLAG_OPCODE 0x7800U

/** @brief 从网络字节序缓冲区读取 16 位整数。 */
static uint16_t read_u16(const uint8_t *input) {
    return (uint16_t)(((uint16_t)input[0] << 8U) | input[1]);
}

/** @brief 按网络字节序写入 16 位整数。 */
static void write_u16(uint8_t *output, uint16_t value) {
    output[0] = (uint8_t)(value >> 8U);
    output[1] = (uint8_t)value;
}

/** @brief 按网络字节序写入 32 位整数。 */
static void write_u32(uint8_t *output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24U);
    output[1] = (uint8_t)(value >> 16U);
    output[2] = (uint8_t)(value >> 8U);
    output[3] = (uint8_t)value;
}

/** @brief 跳过未压缩的 DNS 名称并返回问题类型字段偏移。 */
static bool question_tail_offset(const uint8_t *query, size_t query_length,
                                 size_t name_offset, size_t *tail_offset) {
    size_t cursor = name_offset;
    while (cursor < query_length && query[cursor] != 0U) {
        const uint8_t label_length = query[cursor++];
        /* 门户探测查询的问题名不需要压缩；拒绝压缩指针可避免解析环和越界。 */
        if ((label_length & 0xc0U) != 0U || label_length > 63U ||
            (size_t)label_length > query_length - cursor) return false;
        cursor += label_length;
    }
    if (cursor >= query_length || query_length - (cursor + 1U) < DNS_QUESTION_TAIL_SIZE) return false;
    *tail_offset = cursor + 1U;
    return true;
}

int captive_dns_build_reply(const uint8_t *query, size_t query_length,
                            uint8_t *reply, size_t reply_size,
                            uint32_t portal_ipv4_network_order) {
    size_t question_offset = DNS_HEADER_SIZE;
    size_t questions_end;
    size_t reply_length;
    uint16_t answer_count = 0U;
    uint16_t question_count;
    uint16_t flags;
    if (query == NULL || reply == NULL || query_length < DNS_HEADER_SIZE ||
        query_length > reply_size) return -1;
    flags = read_u16(query + 2U);
    if ((flags & (DNS_FLAG_QR | DNS_FLAG_OPCODE)) != 0U) return -1;
    question_count = read_u16(query + 4U);
    if (question_count == 0U) return -1;

    /* 先完整校验问题区，响应只复制到问题区末尾，主动去掉 EDNS 等附加记录。 */
    for (uint16_t index = 0U; index < question_count; ++index) {
        size_t tail_offset;
        if (!question_tail_offset(query, query_length, question_offset, &tail_offset)) return -1;
        question_offset = tail_offset + DNS_QUESTION_TAIL_SIZE;
    }
    questions_end = question_offset;
    if (questions_end > reply_size) return -1;
    memcpy(reply, query, questions_end);
    write_u16(reply + 2U, (uint16_t)(flags | DNS_FLAG_QR));
    write_u16(reply + 6U, 0U);
    write_u16(reply + 8U, 0U);
    write_u16(reply + 10U, 0U);
    reply_length = questions_end;

    question_offset = DNS_HEADER_SIZE;
    for (uint16_t index = 0U; index < question_count; ++index) {
        const size_t name_offset = question_offset;
        size_t tail_offset;
        if (!question_tail_offset(query, questions_end, question_offset, &tail_offset)) return -1;
        question_offset = tail_offset + DNS_QUESTION_TAIL_SIZE;
        if (read_u16(query + tail_offset) != DNS_TYPE_A ||
            read_u16(query + tail_offset + 2U) != DNS_CLASS_IN) continue;
        if (name_offset > 0x3fffU || reply_size - reply_length < DNS_ANSWER_SIZE) return -1;
        write_u16(reply + reply_length, (uint16_t)(0xc000U | name_offset));
        write_u16(reply + reply_length + 2U, DNS_TYPE_A);
        write_u16(reply + reply_length + 4U, DNS_CLASS_IN);
        write_u32(reply + reply_length + 6U, DNS_TTL_SECONDS);
        write_u16(reply + reply_length + 10U, 4U);
        memcpy(reply + reply_length + 12U, &portal_ipv4_network_order, 4U);
        reply_length += DNS_ANSWER_SIZE;
        ++answer_count;
    }
    write_u16(reply + 6U, answer_count);
    return (int)reply_length;
}
