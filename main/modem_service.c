#include "modem_service.h"

#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "pdu_c_adapter.h"
#include "safety_policy.h"
#include "sms_service.h"

#include <ctype.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** 模组 UART 端口。 */
#define MODEM_UART UART_NUM_1
/** ESP32-C3 到模组的 UART TX 引脚。 */
#define MODEM_TX_PIN GPIO_NUM_3
/** ESP32-C3 从模组接收的 UART RX 引脚。 */
#define MODEM_RX_PIN GPIO_NUM_4
/** 模组电源使能引脚。 */
#define MODEM_ENABLE_PIN GPIO_NUM_5
/** 模组命令队列深度。 */
#define MODEM_QUEUE_DEPTH 16U
/** AT 响应及 UART 单行最大长度。 */
#define MODEM_MAX_RESPONSE 4096U
/** 允许发送的 UTF-8 短信最大字节数。 */
#define MODEM_MAX_SMS_BYTES 2048U
/** PDP 安全状态周期复核间隔。 */
#define MODEM_DATA_GUARD_TICKS pdMS_TO_TICKS(60000U)
/** 首页蜂窝状态缓存刷新间隔。 */
#define MODEM_STATUS_REFRESH_TICKS pdMS_TO_TICKS(30000U)
/** 保存的异步任务状态数量。 */
#define MODEM_JOB_CAPACITY 32U
/** 内部命令参数缓冲区长度。 */
#define MODEM_COMMAND_ARGUMENT_SIZE APP_SMS_TEXT_SIZE
/** PDUlib 输出缓冲区长度。 */
#define MODEM_PDU_SIZE 4096U
/** 单个 UTF-8 分片缓冲区长度。 */
#define MODEM_SMS_PART_SIZE 273U

/** 模组任务命令类型。 */
typedef enum {
    MODEM_COMMAND_QUERY = 0,
    MODEM_COMMAND_SEND_SMS,
    MODEM_COMMAND_SOFT_RESET,
    MODEM_COMMAND_HARD_RESET
} modem_command_type_t;

/** 模组队列中的单个命令。 */
typedef struct {
    uint32_t id;
    modem_command_type_t type;
    char arg1[MODEM_COMMAND_ARGUMENT_SIZE];
    char arg2[MODEM_COMMAND_ARGUMENT_SIZE];
} modem_command_t;

/** 模块日志标签。 */
static const char *const g_tag = "modem";
/** 模组命令队列。 */
static QueueHandle_t g_command_queue;
/** 保护型号和任务状态数组的互斥锁。 */
static SemaphoreHandle_t g_state_mutex;
/** 模组是否处于可用状态。 */
static atomic_bool g_ready;
/** 是否已确认应用数据 CID 1 关闭。 */
static atomic_bool g_data_disabled;
/** 下一个异步任务编号。 */
static atomic_uint g_next_job_id = 1U;
/** 模组型号响应文本。 */
static char g_model[APP_JOB_MESSAGE_SIZE];
/** 最近一次安全查询得到的首页状态。 */
static modem_status_t g_status;
/** 最近一次状态更新的单调时钟毫秒数。 */
static int64_t g_status_updated_ms;
/** 最近的异步任务状态。 */
static job_status_t g_jobs[MODEM_JOB_CAPACITY];
/** 下次覆盖的任务状态槽位。 */
static size_t g_next_job_slot;
/** 是否正在等待 +CMT 后的 PDU 行。 */
static bool g_waiting_for_pdu;
/** 跨调用保存的 UART 行缓冲区。 */
static char g_uart_line[MODEM_MAX_RESPONSE + 1U];
/** UART 行缓冲区当前长度。 */
static size_t g_uart_line_length;
/** 模组任务串行复用的完整行工作缓冲区。 */
static char g_modem_work_line[MODEM_MAX_RESPONSE + 1U];
/** 模组任务串行复用的 AT 响应缓冲区。 */
static char g_modem_response[MODEM_MAX_RESPONSE + 1U];
/** 模组任务串行复用的 PDU 编码输出缓冲区。 */
static char g_pdu_encoded[MODEM_PDU_SIZE];

/** @brief 从 +CSQ 响应更新信号 dBm 和五格强度。 */
static void parse_signal_status(const char *response, modem_status_t *status) {
    const char *value = response != NULL ? strstr(response, "+CSQ:") : NULL;
    int code = value != NULL ? atoi(value + 5U) : 99;
    if (code < 0 || code > 31) {
        status->signal_dbm = INT16_MIN;
        status->signal_bars = 0U;
        return;
    }
    status->signal_dbm = (int16_t)(-113 + code * 2);
    status->signal_bars = code >= 24 ? 5U : code >= 18 ? 4U : code >= 12 ? 3U : code >= 7 ? 2U : 1U;
}

/** @brief 从 +CEREG 响应更新注册和漫游状态。 */
static void parse_registration_status(const char *response, modem_status_t *status) {
    const char *value = response != NULL ? strstr(response, "+CEREG:") : NULL;
    const char *comma = value != NULL ? strchr(value, ',') : NULL;
    int state = comma != NULL ? atoi(comma + 1U) : (value != NULL ? atoi(value + 7U) : 0);
    status->registered = state == 1 || state == 5;
    status->roaming = state == 5;
}

/** @brief 从 +COPS 响应提取运营商名称。 */
static void parse_operator_status(const char *response, modem_status_t *status) {
    const char *begin = response != NULL ? strchr(response, '"') : NULL;
    const char *end = begin != NULL ? strchr(begin + 1U, '"') : NULL;
    status->operator_name[0] = '\0';
    if (begin != NULL && end != NULL && end > begin + 1U) {
        size_t length = (size_t)(end - begin - 1U);
        if (length >= sizeof(status->operator_name)) length = sizeof(status->operator_name) - 1U;
        memcpy(status->operator_name, begin + 1U, length);
        status->operator_name[length] = '\0';
    }
}

/** @brief 去除字符串两端的 ASCII 空白。 */
static void trim_in_place(char *value) {
    char *start = value;
    size_t length;
    while (*start != '\0' && isspace((unsigned char)*start)) ++start;
    if (start != value) memmove(value, start, strlen(start) + 1U);
    length = strlen(value);
    while (length > 0U && isspace((unsigned char)value[length - 1U])) value[--length] = '\0';
}

/** @brief 校验号码只包含可选加号和数字。 */
static bool valid_phone(const char *phone) {
    const size_t length = phone != NULL ? strlen(phone) : 0U;
    size_t index = length > 0U && phone[0] == '+' ? 1U : 0U;
    if (length < 3U || length > 20U || index == length) return false;
    for (; index < length; ++index) if (!isdigit((unsigned char)phone[index])) return false;
    return true;
}

/** @brief 返回 UTF-8 文本是否全部为 ASCII。 */
static bool all_ascii(const char *text) {
    for (; *text != '\0'; ++text) if ((unsigned char)*text >= 0x80U) return false;
    return true;
}

/** @brief 返回一个 UTF-8 字符占用的字节数，非法尾部按单字节处理。 */
static size_t utf8_character_bytes(const char *text, size_t remaining) {
    const unsigned char lead = (unsigned char)text[0];
    size_t bytes = lead < 0x80U ? 1U : (lead < 0xe0U ? 2U : (lead < 0xf0U ? 3U : 4U));
    return bytes <= remaining ? bytes : 1U;
}

/** @brief 统计 UTF-8 字符数量。 */
static size_t utf8_count(const char *text) {
    const size_t length = strlen(text);
    size_t cursor = 0U;
    size_t count = 0U;
    while (cursor < length) {
        cursor += utf8_character_bytes(text + cursor, length - cursor);
        ++count;
    }
    return count;
}

/** @brief 按字符编号复制一个 UTF-8 短信分片。 */
static bool utf8_slice(const char *text, size_t first_character, size_t character_count,
                       char *output, size_t output_size) {
    const size_t length = strlen(text);
    size_t cursor = 0U;
    size_t character = 0U;
    size_t written = 0U;
    while (cursor < length && character < first_character) {
        cursor += utf8_character_bytes(text + cursor, length - cursor);
        ++character;
    }
    while (cursor < length && character < first_character + character_count) {
        const size_t bytes = utf8_character_bytes(text + cursor, length - cursor);
        if (written + bytes + 1U > output_size) return false;
        memcpy(output + written, text + cursor, bytes);
        written += bytes;
        cursor += bytes;
        ++character;
    }
    output[written] = '\0';
    return true;
}

/** @brief 更新或插入一个异步任务状态。 */
static void update_job(uint32_t id, job_state_t state, const char *message) {
    size_t slot = MODEM_JOB_CAPACITY;
    xSemaphoreTake(g_state_mutex, portMAX_DELAY);
    for (size_t index = 0U; index < MODEM_JOB_CAPACITY; ++index) {
        if (g_jobs[index].id == id) { slot = index; break; }
    }
    if (slot == MODEM_JOB_CAPACITY) {
        slot = g_next_job_slot++ % MODEM_JOB_CAPACITY;
    }
    g_jobs[slot].id = id;
    g_jobs[slot].state = state;
    snprintf(g_jobs[slot].message, sizeof(g_jobs[slot].message), "%s", message != NULL ? message : "");
    xSemaphoreGive(g_state_mutex);
}

/** @brief 从 UART 读取一行非空文本。 */
static bool read_line(char *output, size_t output_size, uint32_t timeout_ms) {
    uint8_t byte = 0U;
    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    while (xTaskGetTickCount() <= deadline) {
        if (uart_read_bytes(MODEM_UART, &byte, 1U, pdMS_TO_TICKS(10U)) <= 0) continue;
        if (byte == '\n') {
            g_uart_line[g_uart_line_length] = '\0';
            snprintf(output, output_size, "%s", g_uart_line);
            g_uart_line_length = 0U;
            trim_in_place(output);
            return output[0] != '\0';
        }
        if (byte != '\r') {
            if (g_uart_line_length < MODEM_MAX_RESPONSE) {
                g_uart_line[g_uart_line_length++] = (char)byte;
            } else {
                ESP_LOGE(g_tag, "UART line exceeded safe bound and was discarded");
                g_uart_line_length = 0U;
            }
        }
    }
    return false;
}

/** @brief 解码一行 PDU 并提交给短信处理服务。 */
static void handle_pdu_line(const char *line) {
    decoded_sms_t sms = {0};
    if (line == NULL || line[0] == '\0') return;
    for (const char *cursor = line; *cursor != '\0'; ++cursor) {
        if (!isxdigit((unsigned char)*cursor)) {
            ESP_LOGW(g_tag, "invalid PDU line rejected");
            return;
        }
    }
    if (!pdu_c_decode(line, sms.message.sender, sizeof(sms.message.sender), sms.message.text,
                      sizeof(sms.message.text), sms.message.timestamp,
                      sizeof(sms.message.timestamp), &sms.concat_reference, &sms.part_number,
                      &sms.total_parts)) {
        ESP_LOGE(g_tag, "PDU decode failed or overflowed");
        return;
    }
    sms_service_enqueue(&sms);
}

/** @brief 处理模组主动上报的单行数据。 */
static void handle_line(const char *line) {
    if (strncmp(line, "+CMT:", 5U) == 0) {
        g_waiting_for_pdu = true;
    } else if (g_waiting_for_pdu) {
        handle_pdu_line(line);
        g_waiting_for_pdu = false;
    }
}

/** @brief 发送受安全策略约束的 AT 指令并收集响应。 */
static bool send_at(const char *command, uint32_t timeout_ms, char *response, size_t response_size) {
    char wire[192];
    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    if (!safety_is_pdp_deactivation_command(command) && !safety_is_safe_at_command(command)) {
        snprintf(response, response_size, "blocked by cellular-data safety policy");
        ESP_LOGE(g_tag, "blocked unsafe AT command");
        return false;
    }
    snprintf(wire, sizeof(wire), "%s\r\n", command);
    uart_write_bytes(MODEM_UART, wire, strlen(wire));
    response[0] = '\0';
    while (xTaskGetTickCount() < deadline) {
        size_t used;
        if (!read_line(g_modem_work_line, sizeof(g_modem_work_line), 100U)) continue;
        if (g_modem_work_line[0] == '\0' || strcmp(g_modem_work_line, command) == 0) continue;
        if (strcmp(g_modem_work_line, "OK") == 0) return true;
        if (strcmp(g_modem_work_line, "ERROR") == 0 || strncmp(g_modem_work_line, "+CME ERROR", 10U) == 0 ||
            strncmp(g_modem_work_line, "+CMS ERROR", 10U) == 0) {
            snprintf(response, response_size, "%s", g_modem_work_line);
            return false;
        }
        if (strncmp(g_modem_work_line, "+CMT:", 5U) == 0) { g_waiting_for_pdu = true; continue; }
        if (g_waiting_for_pdu) {
            handle_pdu_line(g_modem_work_line);
            g_waiting_for_pdu = false;
            continue;
        }
        used = strlen(response);
        if (used + strlen(g_modem_work_line) + 2U <= response_size) {
            snprintf(response + used, response_size - used, "%s\n", g_modem_work_line);
        }
    }
    return false;
}

/** @brief 使用只读 AT 查询刷新首页所需蜂窝状态。 */
static void refresh_status(void) {
    modem_status_t status = {0};
    status.ready = modem_service_ready();
    status.data_safely_disabled = modem_service_data_safely_disabled();
    status.signal_dbm = INT16_MIN;
    xSemaphoreTake(g_state_mutex, portMAX_DELAY);
    snprintf(status.model, sizeof(status.model), "%s", g_model);
    xSemaphoreGive(g_state_mutex);
    if (status.ready) {
        if (send_at("AT+CPIN?", 2000U, g_modem_response, sizeof(g_modem_response))) {
            status.sim_ready = strstr(g_modem_response, "READY") != NULL;
        }
        if (send_at("AT+CSQ", 2000U, g_modem_response, sizeof(g_modem_response))) {
            parse_signal_status(g_modem_response, &status);
        }
        if (send_at("AT+CEREG?", 2000U, g_modem_response, sizeof(g_modem_response))) {
            parse_registration_status(g_modem_response, &status);
        }
        if (send_at("AT+COPS?", 3000U, g_modem_response, sizeof(g_modem_response))) {
            parse_operator_status(g_modem_response, &status);
        }
    }
    xSemaphoreTake(g_state_mutex, portMAX_DELAY);
    memcpy(&g_status, &status, sizeof(status));
    g_status_updated_ms = esp_timer_get_time() / 1000LL;
    xSemaphoreGive(g_state_mutex);
}

/** @brief 通过使能引脚对模组执行有界电源重启。 */
static bool power_cycle(void) {
    gpio_config_t io = {0};
    io.pin_bit_mask = 1ULL << MODEM_ENABLE_PIN;
    io.mode = GPIO_MODE_OUTPUT;
    if (gpio_config(&io) != ESP_OK) return false;
    gpio_set_level(MODEM_ENABLE_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(1200U));
    gpio_set_level(MODEM_ENABLE_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(6000U));
    return true;
}

/** @brief 仅确认并关闭应用数据 CID 1；模组内部 CID 由模组自行维护。 */
static bool enforce_data_disabled(void) {
    bool cid1_active = false;
    bool safe = send_at("AT+CGACT?", 3000U, g_modem_response, sizeof(g_modem_response)) &&
                safety_pdp_context_is_active(g_modem_response, 1, &cid1_active);
    if (safe && cid1_active) {
        safe = send_at("AT+CGACT=0,1", 5000U, g_modem_response, sizeof(g_modem_response));
    }
    cid1_active = true;
    safe = safe && send_at("AT+CGACT?", 3000U, g_modem_response, sizeof(g_modem_response)) &&
           safety_pdp_context_is_active(g_modem_response, 1, &cid1_active) && !cid1_active;
    atomic_store(&g_data_disabled, safe);
    if (!safe) {
        ESP_LOGW(g_tag, "CID 1 verification response: %s",
                 g_modem_response[0] != '\0' ? g_modem_response : "<empty>");
        ESP_LOGE(g_tag, "cannot prove PDP CID 1 is inactive; powering the modem off");
        gpio_set_level(MODEM_ENABLE_PIN, 0);
        atomic_store(&g_ready, false);
    } else {
        ESP_LOGI(g_tag, "PDP CID 1 is inactive; modem-managed CIDs are left unchanged");
    }
    return safe;
}

/** @brief 启动模组、应用安全策略并配置短信 PDU 上报。 */
static bool initialize_modem(void) {
    bool responsive = false;
    bool registered = false;
    atomic_store(&g_ready, false);
    atomic_store(&g_data_disabled, false);
    if (!power_cycle()) return false;
    for (int attempt = 0; attempt < 10 && !responsive; ++attempt) {
        responsive = send_at("AT", 1000U, g_modem_response, sizeof(g_modem_response));
        if (!responsive) vTaskDelay(pdMS_TO_TICKS(500U));
    }
    if (!responsive) {
        ESP_LOGE(g_tag, "modem did not respond after bounded retries");
        return false;
    }
    send_at("ATE0", 1000U, g_modem_response, sizeof(g_modem_response));
    if (send_at("ATI", 2000U, g_modem_response, sizeof(g_modem_response))) {
        trim_in_place(g_modem_response);
        xSemaphoreTake(g_state_mutex, portMAX_DELAY);
        snprintf(g_model, sizeof(g_model), "%.*s", (int)sizeof(g_model) - 1, g_modem_response);
        xSemaphoreGive(g_state_mutex);
    }
    if (!enforce_data_disabled()) return false;
    if (!send_at("AT+CNMI=2,2,0,0,0", 2000U, g_modem_response, sizeof(g_modem_response))) return false;
    if (!send_at("AT+CMGF=0", 2000U, g_modem_response, sizeof(g_modem_response))) return false;
    for (int attempt = 0; attempt < 30; ++attempt) {
        if (send_at("AT+CEREG?", 2000U, g_modem_response, sizeof(g_modem_response)) &&
            (strstr(g_modem_response, ",1") != NULL || strstr(g_modem_response, ",5") != NULL)) {
            registered = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(500U));
    }
    if (!registered) ESP_LOGW(g_tag, "network registration timed out; receive service remains degraded");
    ESP_LOGI(g_tag, "modem initialized; application data CID 1 is confirmed inactive");
    return true;
}

/** @brief 等待模组短信发送提示符。 */
static bool wait_for_prompt(uint32_t timeout_ms) {
    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    uint8_t byte = 0U;
    while (xTaskGetTickCount() < deadline) {
        if (uart_read_bytes(MODEM_UART, &byte, 1U, pdMS_TO_TICKS(20U)) == 1 && byte == '>') return true;
    }
    return false;
}

/** @brief 编码并发送一个 PDU 短信分片。 */
static bool send_sms_part(const char *phone, const char *text, uint16_t reference,
                          uint8_t total, uint8_t part, char *result, size_t result_size) {
    char command[40];
    const int length = pdu_c_encode(phone, text, reference, total, part,
                                    g_pdu_encoded, sizeof(g_pdu_encoded));
    if (length < 0) {
        snprintf(result, result_size, "PDU encode failed");
        return false;
    }
    snprintf(command, sizeof(command), "AT+CMGS=%d\r\n", length);
    uart_write_bytes(MODEM_UART, command, strlen(command));
    if (!wait_for_prompt(5000U)) {
        snprintf(result, result_size, "modem did not provide SMS prompt");
        return false;
    }
    uart_write_bytes(MODEM_UART, g_pdu_encoded, strlen(g_pdu_encoded));
    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(30000U);
    while (xTaskGetTickCount() < deadline) {
        if (!read_line(g_modem_work_line, sizeof(g_modem_work_line), 100U)) continue;
        if (strcmp(g_modem_work_line, "OK") == 0) { snprintf(result, result_size, "sent"); return true; }
        if (strcmp(g_modem_work_line, "ERROR") == 0 || strncmp(g_modem_work_line, "+CMS ERROR", 10U) == 0) {
            snprintf(result, result_size, "%s", g_modem_work_line);
            return false;
        }
        handle_line(g_modem_work_line);
    }
    snprintf(result, result_size, "SMS send timed out");
    return false;
}

/** @brief 校验、分片并发送完整短信。 */
static bool send_sms(const char *phone, const char *text, char *result, size_t result_size) {
    size_t maximum_characters;
    size_t characters;
    size_t total_parts;
    uint16_t reference;
    if (!modem_service_ready() || !modem_service_data_safely_disabled()) {
        snprintf(result, result_size, "modem is not in a safe ready state");
        return false;
    }
    if (!valid_phone(phone) || text == NULL || text[0] == '\0' || strlen(text) > MODEM_MAX_SMS_BYTES) {
        snprintf(result, result_size, "invalid phone or message length");
        return false;
    }
    maximum_characters = all_ascii(text) ? 153U : 67U;
    characters = utf8_count(text);
    total_parts = characters == 0U ? 0U : (characters + maximum_characters - 1U) / maximum_characters;
    reference = (uint16_t)((esp_random() % 65535U) + 1U);
    if (total_parts == 0U || total_parts > APP_MAX_CONCAT_PARTS) {
        snprintf(result, result_size, "message exceeds 10 SMS parts");
        return false;
    }
    for (size_t index = 0U; index < total_parts; ++index) {
        char part_text[MODEM_SMS_PART_SIZE];
        if (!utf8_slice(text, index * maximum_characters, maximum_characters,
                        part_text, sizeof(part_text)) ||
            !send_sms_part(phone, part_text, total_parts > 1U ? reference : 0U,
                           total_parts > 1U ? (uint8_t)total_parts : 0U,
                           total_parts > 1U ? (uint8_t)(index + 1U) : 0U,
                           result, result_size)) return false;
    }
    snprintf(result, result_size, "sent %u part(s)", (unsigned)total_parts);
    return true;
}

/** @brief 执行一个队列命令。 */
static bool execute_command(const modem_command_t *command, char *result, size_t result_size) {
    switch (command->type) {
        case MODEM_COMMAND_QUERY:
            return send_at(command->arg1, 5000U, result, result_size);
        case MODEM_COMMAND_SEND_SMS:
            return send_sms(command->arg1, command->arg2, result, result_size);
        case MODEM_COMMAND_SOFT_RESET: {
            bool ok = send_at("AT+CFUN=1,1", 15000U, result, result_size);
            if (ok) { vTaskDelay(pdMS_TO_TICKS(6000U)); ok = initialize_modem(); }
            return ok;
        }
        case MODEM_COMMAND_HARD_RESET:
            return initialize_modem();
        default:
            return false;
    }
}

/** @brief 模组管理任务主循环。 */
static void modem_task(void *argument) {
    TickType_t last_data_guard;
    TickType_t last_status_refresh;
    (void)argument;
    atomic_store(&g_ready, initialize_modem());
    last_data_guard = xTaskGetTickCount();
    refresh_status();
    last_status_refresh = xTaskGetTickCount();
    while (true) {
        modem_command_t *command = NULL;
        if (xQueueReceive(g_command_queue, &command, pdMS_TO_TICKS(20U)) == pdTRUE) {
            char result[APP_JOB_MESSAGE_SIZE];
            update_job(command->id, JOB_STATE_RUNNING, "running");
            const bool ok = execute_command(command, result, sizeof(result));
            update_job(command->id, ok ? JOB_STATE_SUCCEEDED : JOB_STATE_FAILED, result);
            free(command);
        }
        if (read_line(g_modem_work_line, sizeof(g_modem_work_line), 10U)) handle_line(g_modem_work_line);
        const TickType_t now = xTaskGetTickCount();
        if (modem_service_ready() && now - last_data_guard >= MODEM_DATA_GUARD_TICKS) {
            if (!enforce_data_disabled()) atomic_store(&g_ready, false);
            last_data_guard = now;
        }
        if (now - last_status_refresh >= MODEM_STATUS_REFRESH_TICKS) {
            refresh_status();
            last_status_refresh = xTaskGetTickCount();
        }
    }
}

/** @brief 分配并提交一个模组命令。 */
static uint32_t enqueue_command(modem_command_type_t type, const char *arg1, const char *arg2) {
    modem_command_t *command = calloc(1U, sizeof(*command));
    uint32_t id;
    if (command == NULL || g_command_queue == NULL) { free(command); return 0U; }
    command->id = atomic_fetch_add(&g_next_job_id, 1U);
    command->type = type;
    snprintf(command->arg1, sizeof(command->arg1), "%s", arg1 != NULL ? arg1 : "");
    snprintf(command->arg2, sizeof(command->arg2), "%s", arg2 != NULL ? arg2 : "");
    id = command->id;
    update_job(id, JOB_STATE_QUEUED, "queued");
    if (xQueueSend(g_command_queue, &command, 0U) != pdTRUE) {
        update_job(id, JOB_STATE_FAILED, "modem queue full");
        free(command);
    }
    return id;
}

esp_err_t modem_service_start(void) {
    uart_config_t config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT};
    g_state_mutex = xSemaphoreCreateMutex();
    if (g_state_mutex == NULL) return ESP_ERR_NO_MEM;
    ESP_RETURN_ON_ERROR(uart_param_config(MODEM_UART, &config), g_tag, "uart config");
    ESP_RETURN_ON_ERROR(uart_set_pin(MODEM_UART, MODEM_TX_PIN, MODEM_RX_PIN,
                                     UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE), g_tag, "uart pins");
    ESP_RETURN_ON_ERROR(uart_driver_install(MODEM_UART, 4096U, 1024U, 20U, NULL, 0U),
                        g_tag, "uart install");
    g_command_queue = xQueueCreate(MODEM_QUEUE_DEPTH, sizeof(modem_command_t *));
    if (g_command_queue == NULL) return ESP_ERR_NO_MEM;
    return xTaskCreate(modem_task, "modem_task", 8192U, NULL, 12U, NULL) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}

bool modem_service_ready(void) { return atomic_load(&g_ready); }

bool modem_service_data_safely_disabled(void) { return atomic_load(&g_data_disabled); }

void modem_service_model(char *output, size_t output_size) {
    if (output == NULL || output_size == 0U || g_state_mutex == NULL) return;
    xSemaphoreTake(g_state_mutex, portMAX_DELAY);
    snprintf(output, output_size, "%s", g_model);
    xSemaphoreGive(g_state_mutex);
}

uint32_t modem_service_submit_safe_query(const char *command) {
    return safety_is_read_only_at_command(command) ? enqueue_command(MODEM_COMMAND_QUERY, command, NULL) : 0U;
}

uint32_t modem_service_submit_sms(const char *phone, const char *text) {
    return enqueue_command(MODEM_COMMAND_SEND_SMS, phone, text);
}

uint32_t modem_service_submit_soft_reset(void) {
    return enqueue_command(MODEM_COMMAND_SOFT_RESET, NULL, NULL);
}

uint32_t modem_service_submit_hard_reset(void) {
    return enqueue_command(MODEM_COMMAND_HARD_RESET, NULL, NULL);
}

bool modem_service_job_status(uint32_t id, job_status_t *status) {
    bool found = false;
    if (status == NULL || g_state_mutex == NULL) return false;
    xSemaphoreTake(g_state_mutex, portMAX_DELAY);
    for (size_t index = 0U; index < MODEM_JOB_CAPACITY; ++index) {
        if (g_jobs[index].id == id) { memcpy(status, &g_jobs[index], sizeof(*status)); found = true; break; }
    }
    xSemaphoreGive(g_state_mutex);
    return found;
}

void modem_service_status(modem_status_t *status) {
    int64_t updated_ms;
    if (status == NULL) return;
    memset(status, 0, sizeof(*status));
    status->signal_dbm = INT16_MIN;
    if (g_state_mutex == NULL) return;
    xSemaphoreTake(g_state_mutex, portMAX_DELAY);
    memcpy(status, &g_status, sizeof(*status));
    updated_ms = g_status_updated_ms;
    xSemaphoreGive(g_state_mutex);
    status->ready = modem_service_ready();
    status->data_safely_disabled = modem_service_data_safely_disabled();
    if (!status->ready) {
        status->sim_ready = false;
        status->registered = false;
        status->roaming = false;
        status->signal_dbm = INT16_MIN;
        status->signal_bars = 0U;
        status->operator_name[0] = '\0';
    }
    if (updated_ms > 0LL) {
        const int64_t age_ms = esp_timer_get_time() / 1000LL - updated_ms;
        status->age_seconds = age_ms > 0LL ? (uint32_t)(age_ms / 1000LL) : 0U;
    }
}
