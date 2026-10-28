#pragma once

#include "app_types.h"
#include "esp_err.h"

/** @brief 创建通知队列和后台任务。 */
esp_err_t notification_service_start(void);

/** @brief 把已持久化的短信 ID 加入通知队列。 */
bool notification_service_enqueue_inbox(uint32_t inbox_id);

/** @brief 加入一条不写入短信箱的测试通知。 */
bool notification_service_enqueue_test(void);
