#pragma once

#include "app_types.h"
#include "esp_err.h"

/** @brief 创建通知队列和后台任务。 */
esp_err_t notification_service_start(void);

/** @brief 复制短信并加入通知队列。 */
bool notification_service_enqueue_sms(const sms_message_t *sms);
