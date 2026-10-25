#pragma once

#include "app_types.h"
#include "esp_err.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** 首页展示的模组与蜂窝网络状态快照。 */
typedef struct {
    bool ready;
    /** 已确认应用数据 CID 1 未激活。 */
    bool data_safely_disabled;
    bool sim_ready;
    bool registered;
    bool roaming;
    int16_t signal_dbm;
    uint8_t signal_bars;
    uint32_t age_seconds;
    char operator_name[64];
    char model[APP_JOB_MESSAGE_SIZE];
} modem_status_t;

/** @brief 初始化 UART 并启动模组管理任务。 */
esp_err_t modem_service_start(void);

/** @brief 返回模组是否处于可用状态。 */
bool modem_service_ready(void);

/** @brief 返回是否已确认应用数据 CID 1 未激活。 */
bool modem_service_data_safely_disabled(void);

/** @brief 复制已识别的模组型号文本。 */
void modem_service_model(char *output, size_t output_size);

/** @brief 提交只读 AT 查询任务，失败时返回 0。 */
uint32_t modem_service_submit_safe_query(const char *command);

/** @brief 提交短信发送任务，失败时返回 0。 */
uint32_t modem_service_submit_sms(const char *phone, const char *text);

/** @brief 提交模组软重启任务。 */
uint32_t modem_service_submit_soft_reset(void);

/** @brief 提交模组硬重启任务。 */
uint32_t modem_service_submit_hard_reset(void);

/** @brief 查询异步任务状态。 */
bool modem_service_job_status(uint32_t id, job_status_t *status);

/** @brief 复制供 Web 首页使用的模组状态快照。 */
void modem_service_status(modem_status_t *status);
