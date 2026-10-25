#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 使用第三方 PDUlib 编码一段短信。
 * @param phone 接收号码。
 * @param text UTF-8 短信正文。
 * @param reference 长短信参考号，单段短信传 0。
 * @param total 长短信总片数，单段短信传 0。
 * @param part 当前片号，单段短信传 0。
 * @param output 接收包含 Ctrl+Z 的 PDU 文本。
 * @param output_size 输出缓冲区长度。
 * @return AT+CMGS 所需的 PDU 长度，失败时返回负数。
 */
int pdu_c_encode(const char *phone, const char *text, uint16_t reference, uint8_t total,
                 uint8_t part, char *output, size_t output_size);

/**
 * @brief 使用第三方 PDUlib 解码收到的 PDU。
 * @param pdu 十六进制 PDU 文本。
 * @param sender 发送号码输出缓冲区。
 * @param sender_size 发送号码缓冲区长度。
 * @param text UTF-8 正文输出缓冲区。
 * @param text_size 正文缓冲区长度。
 * @param timestamp 时间戳输出缓冲区。
 * @param timestamp_size 时间戳缓冲区长度。
 * @param reference 返回长短信参考号。
 * @param part 返回当前片号。
 * @param total 返回总片数。
 * @return 完整解码且没有溢出时返回 true。
 */
bool pdu_c_decode(const char *pdu, char *sender, size_t sender_size, char *text,
                  size_t text_size, char *timestamp, size_t timestamp_size,
                  uint16_t *reference, uint8_t *part, uint8_t *total);

#ifdef __cplusplus
}
#endif
