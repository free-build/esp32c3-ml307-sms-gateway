#include "pdu_c_adapter.h"

#include "pdulib.h"

#include <cstdio>
#include <cstring>

/** 第三方 PDUlib 实例，仅由模组任务串行访问。 */
static PDU g_pdu(4096);

extern "C" int pdu_c_encode(const char *phone, const char *text, uint16_t reference,
                            uint8_t total, uint8_t part, char *output,
                            size_t output_size) {
    g_pdu.setSCAnumber();
    const int length = g_pdu.encodePDU(phone, text, reference, total, part);
    if (length < 0 || g_pdu.getOverflow()) return -1;
    const char *encoded = g_pdu.getSMS();
    if (encoded == nullptr || std::strlen(encoded) + 1U > output_size) return -1;
    std::memcpy(output, encoded, std::strlen(encoded) + 1U);
    return length;
}

extern "C" bool pdu_c_decode(const char *pdu, char *sender, size_t sender_size,
                             char *text, size_t text_size, char *timestamp,
                             size_t timestamp_size, uint16_t *reference,
                             uint8_t *part, uint8_t *total) {
    if (pdu == nullptr || sender == nullptr || text == nullptr || timestamp == nullptr ||
        reference == nullptr || part == nullptr || total == nullptr) return false;
    if (!g_pdu.decodePDU(pdu) || g_pdu.getOverflow()) return false;
    const int *concat = g_pdu.getConcatInfo();
    if (std::strlen(g_pdu.getSender()) + 1U > sender_size ||
        std::strlen(g_pdu.getText()) + 1U > text_size ||
        std::strlen(g_pdu.getTimeStamp()) + 1U > timestamp_size) return false;
    std::snprintf(sender, sender_size, "%s", g_pdu.getSender());
    std::snprintf(text, text_size, "%s", g_pdu.getText());
    std::snprintf(timestamp, timestamp_size, "%s", g_pdu.getTimeStamp());
    *reference = static_cast<uint16_t>(concat[0]);
    *part = static_cast<uint8_t>(concat[1]);
    *total = static_cast<uint8_t>(concat[2]);
    return true;
}
