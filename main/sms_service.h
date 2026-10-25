#pragma once

#include "app_types.h"
#include "esp_err.h"

#include <stddef.h>
#include <stdint.h>

/** Web 收件箱保留的最近短信数量。 */
#define SMS_INBOX_CAPACITY 10U

/** 已解码短信及其长短信分片元数据。 */
typedef struct {
    sms_message_t message;
    uint16_t concat_reference;
    uint8_t part_number;
    uint8_t total_parts;
} decoded_sms_t;

/** 收件箱中的一条短信；内容同步保存到专用 flash 文件系统。 */
typedef struct {
    uint32_t id;
    sms_message_t message;
} sms_inbox_entry_t;

/** @brief 创建短信处理队列和任务。 */
esp_err_t sms_service_start(void);

/** @brief 把解码短信复制到处理队列。 */
bool sms_service_enqueue(const decoded_sms_t *sms);

/** @brief 忽略空白和 +86 前缀后比较两个号码。 */
bool sms_service_phone_equal(const char *left, const char *right);

/** @brief 按新到旧顺序复制最近收到的短信。 */
size_t sms_service_inbox_copy(sms_inbox_entry_t *entries, size_t capacity);

/** @brief 返回当前短信箱条目数量。 */
size_t sms_service_inbox_count(void);

/** @brief 按新到旧顺序读取指定位置的一条短信。 */
bool sms_service_inbox_get(size_t newest_index, sms_inbox_entry_t *entry);
