#include "captive_dns_packet.h"
#include "pdu_c_adapter.h"
#include "safety_policy.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/** @brief 验证蜂窝数据禁用策略和只读白名单。 */
static void test_safety_policy(void) {
    /** 应当允许的内部安全指令。 */
    static const char *const safe[] = {"ATI", " at + csq ", "AT+CEREG?", "AT+CGACT?", "AT+GSN", "AT+CPIN?"};
    /** 必须拒绝的蜂窝数据指令。 */
    static const char *const blocked[] = {"AT+CGACT=1,1", "at + cgact = 1, 1",
        "AT+MPING=\"8.8.8.8\"", "ATD*99#", "AT+CGDATA=PPP,1", "AT+CGATT=1", "AT+CGDCONT=1"};
    for (size_t index = 0U; index < sizeof(safe) / sizeof(safe[0]); ++index) {
        assert(safety_is_safe_at_command(safe[index]));
    }
    for (size_t index = 0U; index < sizeof(blocked) / sizeof(blocked[0]); ++index) {
        assert(safety_is_forbidden_cellular_data_command(blocked[index]));
        assert(!safety_is_safe_at_command(blocked[index]));
    }
    assert(!safety_is_safe_at_command("AT+CFUN=0"));
    assert(!safety_is_safe_at_command("AT+UNKNOWN"));
    assert(safety_is_read_only_at_command("AT+ICCID"));
    assert(safety_is_read_only_at_command("AT+CGACT?"));
    assert(safety_is_read_only_at_command("AT+CPIN?"));
    assert(safety_is_read_only_at_command("AT+MDIALUPCFG?"));
    assert(safety_is_read_only_at_command("AT+MDIALUP?"));
    assert(safety_is_read_only_at_command("AT+MIPCALL?"));
    assert(safety_is_read_only_at_command("AT+CMGF?"));
    assert(safety_is_read_only_at_command("AT+CNMI?"));
    assert(safety_is_read_only_at_command("AT+CPMS?"));
    assert(safety_is_read_only_at_command("AT+CMGL=4"));
    assert(safety_is_read_only_at_command("AT+CSCA?"));
    assert(!safety_is_read_only_at_command("AT+CFUN=1,1"));
    assert(!safety_is_read_only_at_command("AT+CMGF=0"));
    assert(safety_is_pdp_deactivation_command("AT+CGACT=0,1"));
    assert(safety_is_safe_at_command("AT+CGACT=0,1"));
    assert(safety_is_safe_at_command("AT+MIPCALL=0,1"));
    assert(safety_is_safe_at_command("AT+MUECONFIG=\"autoconn\",0"));
    assert(safety_is_safe_at_command("AT+MDIALUPCFG=\"auto\",0"));
    assert(safety_is_safe_at_command("AT+CPMS=\"SM\",\"SM\",\"SM\""));
    assert(safety_is_safe_at_command("AT+CNMI=2,1,0,0,0"));
    assert(!safety_is_safe_at_command("AT+MUECONFIG=\"autoconn\",1"));
    assert(!safety_is_safe_at_command("AT+MDIALUPCFG=\"auto\",1"));
    assert(!safety_is_read_only_at_command("AT+MUECONFIG=\"autoconn\",0"));
    assert(!safety_is_forbidden_cellular_data_command("AT+MIPCALL=0,1"));
    assert(safety_is_pdp_deactivation_command(" at + cgact = 0, 16 "));
    assert(!safety_is_pdp_deactivation_command("AT+CGACT=1,1"));
    assert(!safety_is_pdp_deactivation_command("AT+CGACT=0,0"));
    assert(!safety_is_pdp_deactivation_command("AT+CGACT=0,1;+CGACT=1,1"));
    assert(safety_is_sms_delete_command("AT+CMGD=1"));
    assert(safety_is_safe_at_command("AT+CMGD=1"));
    assert(safety_is_sms_delete_command(" at + cmgd = 50 "));
    assert(!safety_is_sms_delete_command("AT+CMGD=0"));
    assert(!safety_is_sms_delete_command("AT+CMGD=1,4"));
    assert(!safety_is_read_only_at_command("AT+CMGD=1"));
    bool cid_active = true;
    assert(safety_pdp_context_is_active("+CGACT: 1,0\n+CGACT: 8,1\nOK\n", 1, &cid_active));
    assert(!cid_active); /* 兼容 ML307：CID 8 活动不影响短信业务。 */
    assert(safety_pdp_context_is_active("+CGACT: 1,1\n+CGACT: 8,1\nOK\n", 1, &cid_active));
    assert(cid_active);
    assert(!safety_pdp_context_is_active("+CGACT: invalid\n", 1, &cid_active));
    assert(!safety_pdp_context_is_active("OK\n", 1, &cid_active));
}

/** @brief 验证 C 接口输出的 PDU 终止符及长短信参数。 */
static void test_pdu_adapter(void) {
    char encoded[4096];
    int length = pdu_c_encode("+8613800138000", "hello", 0U, 0U, 0U, encoded, sizeof(encoded));
    assert(length > 0);
    const size_t bytes = strlen(encoded);
    assert(bytes > 1U);
    assert((unsigned char)encoded[bytes - 1U] == 0x1aU);
    size_t delimiter_count = 0U;
    for (size_t index = 0U; index < bytes; ++index) if ((unsigned char)encoded[index] == 0x1aU) ++delimiter_count;
    assert(delimiter_count == 1U);
    length = pdu_c_encode("+8613800138000", "multipart segment", 42U, 2U, 1U,
                          encoded, sizeof(encoded));
    assert(length > 0);
}

/** @brief 验证门户 DNS A 响应和 EDNS 附加记录剥离。 */
static void test_captive_dns(void) {
    /* connectivitycheck.gstatic.com A 查询，末尾包含一个最小 EDNS OPT 附加记录。 */
    static const uint8_t query[] = {
        0x12, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x11, 'c','o','n','n','e','c','t','i','v','i','t','y','c','h','e','c','k',
        0x07, 'g','s','t','a','t','i','c', 0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t reply[256] = {0};
    const uint32_t portal_ip = 0x0104a8c0U; /* 内存字节为 192.168.4.1。 */
    const int length = captive_dns_build_reply(query, sizeof(query), reply, sizeof(reply), portal_ip);
    assert(length == (int)(sizeof(query) - 11U + 16U));
    assert(reply[2] == 0x81U && reply[3] == 0x20U);
    assert(reply[6] == 0x00U && reply[7] == 0x01U);
    assert(reply[10] == 0x00U && reply[11] == 0x00U);
    assert(memcmp(reply + length - 4, &portal_ip, 4U) == 0);

    uint8_t malformed[sizeof(query)];
    memcpy(malformed, query, sizeof(query));
    malformed[12] = 0xc0U; /* 问题名称压缩指针在此实现中被安全拒绝。 */
    assert(captive_dns_build_reply(malformed, sizeof(malformed), reply, sizeof(reply), portal_ip) < 0);
    assert(captive_dns_build_reply(query, 10U, reply, sizeof(reply), portal_ip) < 0);
}

/** @brief 运行全部主机侧单元测试。 */
int main(void) {
    test_safety_policy();
    test_pdu_adapter();
    test_captive_dns();
    puts("host tests passed");
    return 0;
}
