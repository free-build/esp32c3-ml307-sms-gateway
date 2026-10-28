#include "safety_policy.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/** 规范化 AT 指令时使用的最大缓冲区长度。 */
#define SAFETY_COMMAND_SIZE 160U

typedef struct {
    const char *command;
    bool web_read_only;
} allowed_command_t;

/** 单一白名单同时描述内部命令和 Web 只读权限。 */
static const allowed_command_t g_commands[] = {
    {"AT", true}, {"ATE0", false}, {"ATI", true}, {"AT+CSQ", true},
    {"AT+CESQ", true}, {"AT+CREG?", true}, {"AT+CGREG?", true},
    {"AT+CEREG?", true}, {"AT+CIREG?", true}, {"AT+CGACT?", true},
    {"AT+CCID", true}, {"AT+ICCID", true}, {"AT+GSN", true},
    {"AT+COPS?", true}, {"AT+CPIN?", true}, {"AT+CNUM", true},
    {"AT+CSMS?", true}, {"AT+CFUN?", true},
    {"AT+MDIALUPCFG?", true}, {"AT+MDIALUP?", true}, {"AT+MIPCALL?", true},
    {"AT+CMGF?", true}, {"AT+CNMI?", true}, {"AT+CPMS?", true},
    {"AT+CMGL=4", true}, {"AT+CSCA?", true}, {"AT+MIPCALL=0,1", false},
    {"AT+CMGF=0", false}, {"AT+MUECONFIG=\"AUTOCONN\",0", false},
    {"AT+MDIALUPCFG=\"AUTO\",0", false}, {"AT+CNMI=2,2,0,0,0", false},
    {"AT+CPMS=\"SM\",\"SM\",\"SM\"", false},
    {"AT+CNMI=2,1,0,0,0", false},
    {"AT+CFUN=1,1", false},
};

/**
 * @brief 删除空白并把指令转换为大写。
 * @param input 原始指令。
 * @param output 规范化结果缓冲区。
 * @param output_size 结果缓冲区长度。
 * @return 输入完整装入缓冲区时返回 true。
 */
static bool normalize_command(const char *input, char *output, size_t output_size) {
    size_t written = 0;
    if (input == NULL || output == NULL || output_size == 0U) return false;
    while (*input != '\0') {
        const unsigned char value = (unsigned char)*input++;
        if (isspace(value)) continue;
        if (written + 1U >= output_size) return false;
        output[written++] = (char)toupper(value);
    }
    output[written] = '\0';
    return true;
}

/**
 * @brief 在固定白名单内查找规范化指令。
 * @param command 已规范化的指令。
 * @param list 白名单数组。
 * @param count 白名单元素数量。
 * @return 完全匹配时返回 true。
 */
static bool command_allowed(const char *command, bool web_only) {
    for (size_t index = 0; index < sizeof(g_commands) / sizeof(g_commands[0]); ++index) {
        if ((!web_only || g_commands[index].web_read_only) &&
            strcmp(command, g_commands[index].command) == 0) return true;
    }
    return false;
}

bool safety_is_forbidden_cellular_data_command(const char *command) {
    char normalized[SAFETY_COMMAND_SIZE];
    if (!normalize_command(command, normalized, sizeof(normalized))) return true;
    return strstr(normalized, "CGACT=1") != NULL || strstr(normalized, "CGDATA") != NULL ||
           strstr(normalized, "ATD*99") != NULL || strstr(normalized, "MPING") != NULL ||
           strstr(normalized, "CGATT=1") != NULL || strstr(normalized, "CGDCONT=") != NULL;
}

bool safety_is_pdp_deactivation_command(const char *command) {
    /** PDP 去激活指令的固定前缀。 */
    static const char prefix[] = "AT+CGACT=0,";
    char normalized[SAFETY_COMMAND_SIZE];
    char *end = NULL;
    long cid;
    if (!normalize_command(command, normalized, sizeof(normalized))) return false;
    if (strncmp(normalized, prefix, sizeof(prefix) - 1U) != 0) return false;
    cid = strtol(normalized + sizeof(prefix) - 1U, &end, 10);
    return end != normalized + sizeof(prefix) - 1U && *end == '\0' && cid > 0L && cid <= 255L;
}

bool safety_is_sms_delete_command(const char *command) {
    static const char prefix[] = "AT+CMGD=";
    char normalized[SAFETY_COMMAND_SIZE];
    char *end = NULL;
    long index;
    if (!normalize_command(command, normalized, sizeof(normalized))) return false;
    if (strncmp(normalized, prefix, sizeof(prefix) - 1U) != 0) return false;
    index = strtol(normalized + sizeof(prefix) - 1U, &end, 10);
    return end != normalized + sizeof(prefix) - 1U && *end == '\0' &&
           index > 0L && index <= 255L;
}

bool safety_pdp_context_is_active(const char *response, int cid, bool *is_active) {
    const char *cursor = response;
    bool saw_context = false;
    if (response == NULL || cid <= 0 || cid > 255 || is_active == NULL) return false;
    *is_active = false;
    while ((cursor = strstr(cursor, "+CGACT:")) != NULL) {
        char *end = NULL;
        long found_cid;
        long state;
        cursor += 7;
        found_cid = strtol(cursor, &end, 10);
        if (end == cursor) return false;
        while (*end == ' ' || *end == '\t') ++end;
        if (*end++ != ',') return false;
        cursor = end;
        state = strtol(cursor, &end, 10);
        if (end == cursor || found_cid <= 0L || found_cid > 255L ||
            (state != 0L && state != 1L)) return false;
        saw_context = true;
        if (found_cid == cid) *is_active = state == 1L;
        cursor = end;
    }
    return saw_context;
}

bool safety_is_safe_at_command(const char *command) {
    char normalized[SAFETY_COMMAND_SIZE];
    if (!normalize_command(command, normalized, sizeof(normalized))) return false;
    return !safety_is_forbidden_cellular_data_command(normalized) &&
           (command_allowed(normalized, false) ||
            safety_is_pdp_deactivation_command(normalized) ||
            safety_is_sms_delete_command(normalized));
}

bool safety_is_read_only_at_command(const char *command) {
    char normalized[SAFETY_COMMAND_SIZE];
    if (!normalize_command(command, normalized, sizeof(normalized))) return false;
    return !safety_is_forbidden_cellular_data_command(normalized) &&
           command_allowed(normalized, true);
}
