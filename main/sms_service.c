#include "sms_service.h"

#include "config_store.h"
#include "esp_rom_crc.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "modem_service.h"
#include "notification_service.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/** 短信处理队列深度。 */
#define SMS_QUEUE_DEPTH 8U
/** 单个长短信分片的最大 UTF-8 字节数。 */
#define SMS_PART_TEXT_SIZE 300U
/** 持久化收件箱文件格式标识 "SMSB"。 */
#define SMS_INBOX_FILE_MAGIC 0x534d5342U
/** 持久化收件箱文件格式版本。 */
#define SMS_INBOX_FILE_VERSION 1U
/** 收件箱文件系统挂载点。 */
#define SMS_INBOX_MOUNT_POINT "/smsdata"
/** 收件箱文件系统分区标签。 */
#define SMS_INBOX_PARTITION "sms_data"

/** 持久化文件头；正文紧随其后保存固定十条环形槽位。 */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t generation;
    uint32_t crc32;
    uint32_t head;
    uint32_t count;
    uint32_t next_id;
} inbox_file_header_t;

/** 长短信的一个分片。 */
typedef struct {
    bool valid;
    char text[SMS_PART_TEXT_SIZE];
} sms_part_t;

/** 正在等待后续分片的长短信槽位。 */
typedef struct {
    bool used;
    uint16_t reference;
    char sender[APP_PHONE_SIZE];
    char timestamp[APP_TIMESTAMP_SIZE];
    uint8_t total;
    uint8_t received;
    int64_t first_seen_us;
    sms_part_t parts[APP_MAX_CONCAT_PARTS];
} concat_slot_t;

/** 模块日志标签。 */
static const char *const g_tag = "sms";
/** 待处理短信指针队列。 */
static QueueHandle_t g_sms_queue;
/** 长短信并发缓存。 */
static concat_slot_t g_concat_slots[APP_MAX_CONCAT_MESSAGES];
/** 保护最近短信收件箱的互斥锁。 */
static SemaphoreHandle_t g_inbox_mutex;
/** 最近收到的十条短信环形缓冲区。 */
static sms_inbox_entry_t g_inbox[SMS_INBOX_CAPACITY];
/** 环形缓冲区中最旧短信的位置。 */
static size_t g_inbox_head;
/** 当前收件箱短信数量。 */
static size_t g_inbox_count;
/** 下一条短信的内存序号。 */
static uint32_t g_inbox_next_id = 1U;
/** 最近一次成功恢复或写入的持久化代数。 */
static uint32_t g_inbox_generation;
/** 专用收件箱文件系统是否可用。 */
static bool g_inbox_storage_ready;

/** @brief 计算文件头和十个环形槽位的 CRC32。 */
static uint32_t inbox_crc(inbox_file_header_t header, const sms_inbox_entry_t *entries) {
    header.crc32 = 0U;
    uint32_t crc = esp_rom_crc32_le(UINT32_MAX, (const uint8_t *)&header, sizeof(header));
    return esp_rom_crc32_le(crc, (const uint8_t *)entries,
                            sizeof(sms_inbox_entry_t) * SMS_INBOX_CAPACITY);
}

/** @brief 校验一个持久化槽位并返回文件头，不修改当前收件箱。 */
static bool inbox_validate_file(const char *path, inbox_file_header_t *output) {
    FILE *file = fopen(path, "rb");
    inbox_file_header_t header;
    sms_inbox_entry_t entry;
    uint32_t crc;
    if (file == NULL || fread(&header, sizeof(header), 1U, file) != 1U ||
        header.magic != SMS_INBOX_FILE_MAGIC || header.version != SMS_INBOX_FILE_VERSION ||
        header.head >= SMS_INBOX_CAPACITY || header.count > SMS_INBOX_CAPACITY ||
        header.next_id == 0U) {
        if (file != NULL) fclose(file);
        return false;
    }
    const uint32_t expected = header.crc32;
    header.crc32 = 0U;
    crc = esp_rom_crc32_le(UINT32_MAX, (const uint8_t *)&header, sizeof(header));
    for (size_t index = 0U; index < SMS_INBOX_CAPACITY; ++index) {
        if (fread(&entry, sizeof(entry), 1U, file) != 1U) {
            fclose(file);
            return false;
        }
        crc = esp_rom_crc32_le(crc, (const uint8_t *)&entry, sizeof(entry));
    }
    const int trailing = fgetc(file);
    fclose(file);
    if (trailing != EOF || crc != expected) return false;
    header.crc32 = expected;
    *output = header;
    return true;
}

/** @brief 从两个轮换文件中恢复代数较新的有效收件箱。 */
static void inbox_restore(void) {
    const char *paths[2] = {SMS_INBOX_MOUNT_POINT "/inbox0.bin",
                            SMS_INBOX_MOUNT_POINT "/inbox1.bin"};
    inbox_file_header_t headers[2];
    const bool valid[2] = {inbox_validate_file(paths[0], &headers[0]),
                           inbox_validate_file(paths[1], &headers[1])};
    int selected = valid[1] && (!valid[0] || (int32_t)(headers[1].generation - headers[0].generation) > 0)
        ? 1 : valid[0] ? 0 : -1;
    if (selected < 0) {
        ESP_LOGI(g_tag, "no valid persisted SMS inbox found; starting empty");
        return;
    }
    FILE *file = fopen(paths[selected], "rb");
    if (file == NULL || fseek(file, (long)sizeof(inbox_file_header_t), SEEK_SET) != 0 ||
        fread(g_inbox, sizeof(g_inbox), 1U, file) != 1U) {
        if (file != NULL) fclose(file);
        memset(g_inbox, 0, sizeof(g_inbox));
        ESP_LOGE(g_tag, "failed to restore validated SMS inbox");
        return;
    }
    fclose(file);
    for (size_t index = 0U; index < SMS_INBOX_CAPACITY; ++index) {
        if (memchr(g_inbox[index].message.sender, '\0', sizeof(g_inbox[index].message.sender)) == NULL ||
            memchr(g_inbox[index].message.text, '\0', sizeof(g_inbox[index].message.text)) == NULL ||
            memchr(g_inbox[index].message.timestamp, '\0', sizeof(g_inbox[index].message.timestamp)) == NULL) {
            memset(g_inbox, 0, sizeof(g_inbox));
            ESP_LOGE(g_tag, "persisted SMS inbox contains invalid text fields");
            return;
        }
    }
    g_inbox_head = headers[selected].head;
    g_inbox_count = headers[selected].count;
    g_inbox_next_id = headers[selected].next_id;
    g_inbox_generation = headers[selected].generation;
    ESP_LOGI(g_tag, "restored %u SMS inbox entries from flash", (unsigned)g_inbox_count);
}

/** @brief 把当前环形收件箱写入下一轮换文件。调用方须持有互斥锁。 */
static void inbox_persist_locked(void) {
    if (!g_inbox_storage_ready) return;
    inbox_file_header_t header = {
        .magic = SMS_INBOX_FILE_MAGIC,
        .version = SMS_INBOX_FILE_VERSION,
        .generation = g_inbox_generation + 1U,
        .head = (uint32_t)g_inbox_head,
        .count = (uint32_t)g_inbox_count,
        .next_id = g_inbox_next_id,
    };
    header.crc32 = inbox_crc(header, g_inbox);
    const char *target = (header.generation & 1U) != 0U
        ? SMS_INBOX_MOUNT_POINT "/inbox1.bin" : SMS_INBOX_MOUNT_POINT "/inbox0.bin";
    const char *temporary = SMS_INBOX_MOUNT_POINT "/inbox.tmp";
    FILE *file = fopen(temporary, "wb");
    bool success = file != NULL && fwrite(&header, sizeof(header), 1U, file) == 1U &&
                   fwrite(g_inbox, sizeof(g_inbox), 1U, file) == 1U && fflush(file) == 0 &&
                   fsync(fileno(file)) == 0;
    if (file != NULL && fclose(file) != 0) success = false;
    if (success) {
        remove(target);
        if (rename(temporary, target) == 0) {
            g_inbox_generation = header.generation;
            return;
        }
    }
    remove(temporary);
    ESP_LOGE(g_tag, "failed to persist SMS inbox: errno=%d", errno);
}

/** @brief 挂载专用 flash 文件系统并恢复收件箱。 */
static esp_err_t inbox_storage_start(void) {
    const esp_vfs_spiffs_conf_t config = {
        .base_path = SMS_INBOX_MOUNT_POINT,
        .partition_label = SMS_INBOX_PARTITION,
        .max_files = 4,
        .format_if_mount_failed = true,
    };
    const esp_err_t error = esp_vfs_spiffs_register(&config);
    if (error != ESP_OK) {
        ESP_LOGE(g_tag, "mount SMS inbox storage: %s", esp_err_to_name(error));
        return error;
    }
    g_inbox_storage_ready = true;
    inbox_restore();
    return ESP_OK;
}

/** @brief 将一条已接受短信保存到环形收件箱并持久化。 */
static uint32_t inbox_store(const sms_message_t *sms) {
    size_t slot;
    uint32_t id = 0U;
    if (sms == NULL || g_inbox_mutex == NULL) return 0U;
    xSemaphoreTake(g_inbox_mutex, portMAX_DELAY);
    slot = (g_inbox_head + g_inbox_count) % SMS_INBOX_CAPACITY;
    if (g_inbox_count == SMS_INBOX_CAPACITY) {
        slot = g_inbox_head;
        g_inbox_head = (g_inbox_head + 1U) % SMS_INBOX_CAPACITY;
    } else {
        ++g_inbox_count;
    }
    id = g_inbox_next_id++;
    g_inbox[slot].id = id;
    memcpy(&g_inbox[slot].message, sms, sizeof(*sms));
    inbox_persist_locked();
    xSemaphoreGive(g_inbox_mutex);
    return id;
}

/** @brief 去除字符串两端空白并复制到输出缓冲区。 */
static void trim_copy(const char *input, char *output, size_t output_size) {
    const char *start = input;
    const char *end;
    size_t length;
    while (*start != '\0' && isspace((unsigned char)*start)) ++start;
    end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) --end;
    length = (size_t)(end - start);
    if (length >= output_size) length = output_size - 1U;
    memcpy(output, start, length);
    output[length] = '\0';
}

/** @brief 判断号码是否存在于按行分隔的黑名单。 */
static bool blacklisted(const char *sender, const char *list) {
    const char *cursor = list;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, '\n');
        const size_t length = end != NULL ? (size_t)(end - cursor) : strlen(cursor);
        char line[APP_PHONE_SIZE];
        size_t copied = length < sizeof(line) - 1U ? length : sizeof(line) - 1U;
        memcpy(line, cursor, copied);
        line[copied] = '\0';
        if (sms_service_phone_equal(sender, line)) return true;
        if (end == NULL) break;
        cursor = end + 1U;
    }
    return false;
}

/** @brief 延迟一秒后重启系统，确保当前短信处理路径先返回。 */
static void delayed_system_restart(void *argument) {
    (void)argument;
    vTaskDelay(pdMS_TO_TICKS(1000U));
    esp_restart();
}

/** @brief 查找匹配的长短信槽位，或分配一个空槽位。 */
static concat_slot_t *find_or_allocate(const decoded_sms_t *sms) {
    for (size_t index = 0U; index < APP_MAX_CONCAT_MESSAGES; ++index) {
        concat_slot_t *slot = &g_concat_slots[index];
        if (slot->used && slot->reference == sms->concat_reference &&
            strcmp(slot->sender, sms->message.sender) == 0 && slot->total == sms->total_parts) {
            return slot;
        }
    }
    for (size_t index = 0U; index < APP_MAX_CONCAT_MESSAGES; ++index) {
        concat_slot_t *slot = &g_concat_slots[index];
        if (!slot->used) {
            memset(slot, 0, sizeof(*slot));
            slot->used = true;
            slot->reference = sms->concat_reference;
            snprintf(slot->sender, sizeof(slot->sender), "%s", sms->message.sender);
            snprintf(slot->timestamp, sizeof(slot->timestamp), "%s", sms->message.timestamp);
            slot->total = sms->total_parts;
            slot->first_seen_us = esp_timer_get_time();
            return slot;
        }
    }
    return NULL;
}

/** @brief 执行黑名单、管理员命令和通知分发。 */
static void deliver(const sms_message_t *sms) {
    config_sms_policy_t policy;
    char command[APP_SMS_TEXT_SIZE];
    /* 收件箱是短信接收的主记录，不得受通知配置内存分配影响。 */
    const uint32_t inbox_id = inbox_store(sms);
    config_store_get_sms_policy(&policy);
    if (blacklisted(sms->sender, policy.number_blacklist)) {
        ESP_LOGI(g_tag, "SMS saved; notification ignored by sender blacklist");
        return;
    }
    trim_copy(sms->text, command, sizeof(command));
    if (policy.admin_commands_enabled && sms_service_phone_equal(sms->sender, policy.admin_phone)) {
        if (strcmp(command, "RESET") == 0) {
            ESP_LOGW(g_tag, "authorized administrator reset command received");
            xTaskCreate(delayed_system_restart, "admin_restart", 2048U, NULL, 10U, NULL);
            return;
        }
        if (strncmp(command, "SMS:", 4U) == 0) {
            char *separator = strchr(command + 4U, ':');
            if (separator != NULL) {
                *separator = '\0';
                modem_service_submit_sms(command + 4U, separator + 1U);
                return;
            }
        }
    }
    if (inbox_id == 0U || !notification_service_enqueue_inbox(inbox_id)) {
        ESP_LOGE(g_tag, "SMS saved, but notification queue rejected inbox id %lu",
                 (unsigned long)inbox_id);
    }
    char masked[4] = {0};
    snprintf(masked, sizeof(masked), "%.3s", sms->sender);
    ESP_LOGI(g_tag, "SMS accepted from %s******", masked);
}

/** @brief 合并或直接投递一条解码短信。 */
static void process_sms(const decoded_sms_t *sms) {
    if (sms->total_parts <= 1U || sms->part_number == 0U) {
        deliver(&sms->message);
        return;
    }
    if (sms->total_parts > APP_MAX_CONCAT_PARTS || sms->part_number > sms->total_parts ||
        strlen(sms->message.text) >= SMS_PART_TEXT_SIZE) {
        ESP_LOGE(g_tag, "multipart SMS rejected: part=%u total=%u exceeds safe limit",
                 sms->part_number, sms->total_parts);
        return;
    }
    concat_slot_t *slot = find_or_allocate(sms);
    if (slot == NULL) {
        ESP_LOGE(g_tag, "multipart cache full; message rejected without overwriting active data");
        return;
    }
    sms_part_t *part = &slot->parts[sms->part_number - 1U];
    if (!part->valid) {
        part->valid = true;
        memcpy(part->text, sms->message.text, strlen(sms->message.text) + 1U);
        ++slot->received;
    }
    if (slot->received == slot->total) {
        sms_message_t complete = {0};
        size_t used = 0U;
        snprintf(complete.sender, sizeof(complete.sender), "%s", slot->sender);
        snprintf(complete.timestamp, sizeof(complete.timestamp), "%s", slot->timestamp);
        for (size_t index = 0U; index < slot->total; ++index) {
            const size_t length = strlen(slot->parts[index].text);
            if (used + length >= sizeof(complete.text)) {
                ESP_LOGE(g_tag, "multipart SMS rejected because combined text exceeds safe limit");
                memset(slot, 0, sizeof(*slot));
                return;
            }
            memcpy(complete.text + used, slot->parts[index].text, length);
            used += length;
            complete.text[used] = '\0';
        }
        memset(slot, 0, sizeof(*slot));
        deliver(&complete);
    }
}

/** @brief 投递超时的长短信，并标出缺失分片。 */
static void expire_concat(void) {
    const int64_t now = esp_timer_get_time();
    for (size_t slot_index = 0U; slot_index < APP_MAX_CONCAT_MESSAGES; ++slot_index) {
        concat_slot_t *slot = &g_concat_slots[slot_index];
        if (!slot->used || now - slot->first_seen_us < (int64_t)APP_CONCAT_TIMEOUT_MS * 1000LL) continue;
        sms_message_t partial = {0};
        size_t used = 0U;
        snprintf(partial.sender, sizeof(partial.sender), "%s", slot->sender);
        snprintf(partial.timestamp, sizeof(partial.timestamp), "%s", slot->timestamp);
        for (size_t index = 0U; index < slot->total; ++index) {
            char missing[32];
            const char *piece = slot->parts[index].text;
            if (!slot->parts[index].valid) {
                snprintf(missing, sizeof(missing), "[missing part %u]", (unsigned)(index + 1U));
                piece = missing;
            }
            const size_t length = strlen(piece);
            if (used + length >= sizeof(partial.text)) break;
            memcpy(partial.text + used, piece, length);
            used += length;
            partial.text[used] = '\0';
        }
        ESP_LOGW(g_tag, "multipart SMS timed out (%u/%u parts)", slot->received, slot->total);
        memset(slot, 0, sizeof(*slot));
        deliver(&partial);
    }
}

/** @brief 短信处理任务主循环。 */
static void sms_task(void *argument) {
    (void)argument;
    while (true) {
        decoded_sms_t *incoming = NULL;
        if (xQueueReceive(g_sms_queue, &incoming, pdMS_TO_TICKS(1000U)) == pdTRUE && incoming != NULL) {
            process_sms(incoming);
            free(incoming);
        }
        expire_concat();
    }
}

esp_err_t sms_service_start(void) {
    g_inbox_mutex = xSemaphoreCreateMutex();
    if (g_inbox_mutex == NULL) return ESP_ERR_NO_MEM;
    esp_err_t storage_error = inbox_storage_start();
    if (storage_error != ESP_OK) return storage_error;
    g_sms_queue = xQueueCreate(SMS_QUEUE_DEPTH, sizeof(decoded_sms_t *));
    if (g_sms_queue == NULL) return ESP_ERR_NO_MEM;
    return xTaskCreate(sms_task, "sms_task", 8192U, NULL, 9U, NULL) == pdPASS
        ? ESP_OK : ESP_ERR_NO_MEM;
}

size_t sms_service_inbox_copy(sms_inbox_entry_t *entries, size_t capacity) {
    size_t copied;
    if (entries == NULL || capacity == 0U || g_inbox_mutex == NULL) return 0U;
    xSemaphoreTake(g_inbox_mutex, portMAX_DELAY);
    copied = g_inbox_count < capacity ? g_inbox_count : capacity;
    for (size_t index = 0U; index < copied; ++index) {
        const size_t slot = (g_inbox_head + g_inbox_count - 1U - index) % SMS_INBOX_CAPACITY;
        memcpy(&entries[index], &g_inbox[slot], sizeof(entries[index]));
    }
    xSemaphoreGive(g_inbox_mutex);
    return copied;
}

size_t sms_service_inbox_count(void) {
    size_t count;
    if (g_inbox_mutex == NULL) return 0U;
    xSemaphoreTake(g_inbox_mutex, portMAX_DELAY);
    count = g_inbox_count;
    xSemaphoreGive(g_inbox_mutex);
    return count;
}

bool sms_service_inbox_get(size_t newest_index, sms_inbox_entry_t *entry) {
    bool found = false;
    if (entry == NULL || g_inbox_mutex == NULL) return false;
    xSemaphoreTake(g_inbox_mutex, portMAX_DELAY);
    if (newest_index < g_inbox_count) {
        const size_t slot = (g_inbox_head + g_inbox_count - 1U - newest_index) % SMS_INBOX_CAPACITY;
        memcpy(entry, &g_inbox[slot], sizeof(*entry));
        found = true;
    }
    xSemaphoreGive(g_inbox_mutex);
    return found;
}

bool sms_service_inbox_find(uint32_t id, sms_inbox_entry_t *entry) {
    bool found = false;
    if (id == 0U || entry == NULL || g_inbox_mutex == NULL) return false;
    xSemaphoreTake(g_inbox_mutex, portMAX_DELAY);
    for (size_t index = 0U; index < g_inbox_count; ++index) {
        const size_t slot = (g_inbox_head + index) % SMS_INBOX_CAPACITY;
        if (g_inbox[slot].id == id) {
            memcpy(entry, &g_inbox[slot], sizeof(*entry));
            found = true;
            break;
        }
    }
    xSemaphoreGive(g_inbox_mutex);
    return found;
}

bool sms_service_inbox_delete(uint32_t id) {
    bool found = false;
    if (id == 0U || g_inbox_mutex == NULL) return false;
    xSemaphoreTake(g_inbox_mutex, portMAX_DELAY);
    for (size_t index = 0U; index < g_inbox_count; ++index) {
        const size_t slot = (g_inbox_head + index) % SMS_INBOX_CAPACITY;
        if (g_inbox[slot].id == id) {
            found = true;
            for (size_t move = index; move + 1U < g_inbox_count; ++move) {
                const size_t destination = (g_inbox_head + move) % SMS_INBOX_CAPACITY;
                const size_t source = (g_inbox_head + move + 1U) % SMS_INBOX_CAPACITY;
                memcpy(&g_inbox[destination], &g_inbox[source], sizeof(g_inbox[0]));
            }
            const size_t last = (g_inbox_head + g_inbox_count - 1U) % SMS_INBOX_CAPACITY;
            memset(&g_inbox[last], 0, sizeof(g_inbox[last]));
            --g_inbox_count;
            if (g_inbox_count == 0U) g_inbox_head = 0U;
            break;
        }
    }
    if (found) {
        inbox_persist_locked();
    }
    xSemaphoreGive(g_inbox_mutex);
    return found;
}

bool sms_service_enqueue(const decoded_sms_t *sms) {
    decoded_sms_t *copy;
    if (sms == NULL || g_sms_queue == NULL) return false;
    copy = malloc(sizeof(*copy));
    if (copy == NULL) return false;
    memcpy(copy, sms, sizeof(*copy));
    if (xQueueSend(g_sms_queue, &copy, 0U) != pdTRUE) {
        free(copy);
        ESP_LOGE(g_tag, "SMS queue full; message rejected safely");
        return false;
    }
    return true;
}

bool sms_service_phone_equal(const char *left, const char *right) {
    char normalized_left[APP_PHONE_SIZE];
    char normalized_right[APP_PHONE_SIZE];
    trim_copy(left != NULL ? left : "", normalized_left, sizeof(normalized_left));
    trim_copy(right != NULL ? right : "", normalized_right, sizeof(normalized_right));
    const char *left_number = strncmp(normalized_left, "+86", 3U) == 0 ? normalized_left + 3U : normalized_left;
    const char *right_number = strncmp(normalized_right, "+86", 3U) == 0 ? normalized_right + 3U : normalized_right;
    return left_number[0] != '\0' && strcmp(left_number, right_number) == 0;
}
