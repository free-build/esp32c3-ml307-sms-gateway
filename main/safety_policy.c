#include "safety_policy.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/** 规范化 AT 指令时使用的最大缓冲区长度。 */
#define SAFETY_COMMAND_SIZE 160U

/** 内部允许执行的 AT 指令白名单。 */
static const char *const g_safe_commands[] = {
    "AT",       "ATE0",       "ATI",        "AT+CSQ",    "AT+CESQ",
    "AT+CEREG?", "AT+CGACT?",  "AT+CCID",    "AT+ICCID",  "AT+GSN",
    "AT+COPS?", "AT+CPIN?",   "AT+CFUN?",   "AT+CMGF=0",
    "AT+CNMI=2,2,0,0,0", "AT+CFUN=1,1"};

/** Web API 允许执行的只读 AT 指令白名单。 */
static const char *const g_read_only_commands[] = {
    "AT", "ATI", "AT+CSQ", "AT+CESQ", "AT+CEREG?", "AT+CGACT?",
    "AT+CCID", "AT+ICCID", "AT+GSN", "AT+COPS?", "AT+CPIN?", "AT+CFUN?"};

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
static bool command_in_list(const char *command, const char *const *list, size_t count) {
    for (size_t index = 0; index < count; ++index) {
        if (strcmp(command, list[index]) == 0) return true;
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

bool safety_parse_active_pdp_contexts(const char *response, int *active, size_t capacity,
                                      size_t *active_count) {
    const char *cursor = response;
    bool saw_context = false;
    size_t count = 0;
    if (response == NULL || active_count == NULL) return false;
    *active_count = 0;
    while ((cursor = strstr(cursor, "+CGACT:")) != NULL) {
        char *end = NULL;
        long cid;
        long state;
        cursor += 7;
        cid = strtol(cursor, &end, 10);
        if (end == cursor) return false;
        while (*end == ' ' || *end == '\t') ++end;
        if (*end++ != ',') return false;
        cursor = end;
        state = strtol(cursor, &end, 10);
        if (end == cursor || cid <= 0L || cid > 255L || (state != 0L && state != 1L)) return false;
        saw_context = true;
        if (state == 1L) {
            if (active == NULL || count >= capacity) return false;
            active[count++] = (int)cid;
        }
        cursor = end;
    }
    *active_count = count;
    return saw_context;
}

bool safety_pdp_context_is_active(const char *response, int cid, bool *is_active) {
    int active[32];
    size_t active_count = 0U;
    if (cid <= 0 || cid > 255 || is_active == NULL ||
        !safety_parse_active_pdp_contexts(response, active,
                                          sizeof(active) / sizeof(active[0]), &active_count)) {
        return false;
    }
    *is_active = false;
    for (size_t index = 0U; index < active_count; ++index) {
        if (active[index] == cid) {
            *is_active = true;
            break;
        }
    }
    return true;
}

bool safety_is_safe_at_command(const char *command) {
    char normalized[SAFETY_COMMAND_SIZE];
    if (!normalize_command(command, normalized, sizeof(normalized))) return false;
    return !safety_is_forbidden_cellular_data_command(normalized) &&
           command_in_list(normalized, g_safe_commands,
                           sizeof(g_safe_commands) / sizeof(g_safe_commands[0]));
}

bool safety_is_read_only_at_command(const char *command) {
    char normalized[SAFETY_COMMAND_SIZE];
    if (!normalize_command(command, normalized, sizeof(normalized))) return false;
    return !safety_is_forbidden_cellular_data_command(normalized) &&
           command_in_list(normalized, g_read_only_commands,
                           sizeof(g_read_only_commands) / sizeof(g_read_only_commands[0]));
}
