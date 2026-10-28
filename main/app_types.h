#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** 推送通道数量上限。 */
#define APP_MAX_PUSH_CHANNELS 5U
/** 长短信并发缓存数量上限。 */
#define APP_MAX_CONCAT_MESSAGES 5U
/** 单条长短信分片数量上限。 */
#define APP_MAX_CONCAT_PARTS 10U
/** 长短信分片等待超时时间，单位为毫秒。 */
#define APP_CONCAT_TIMEOUT_MS 30000U
/** Wi-Fi SSID 缓冲区长度，包含字符串结束符。 */
#define APP_WIFI_SSID_SIZE 33U
/** Wi-Fi 密码缓冲区长度，包含字符串结束符。 */
#define APP_WIFI_PASSWORD_SIZE 64U
/** 可保存的 Wi-Fi 凭据数量。 */
#define APP_MAX_WIFI_PROFILES 3U
/** SMTP 主机名缓冲区长度。 */
#define APP_SMTP_HOST_SIZE 128U
/** SMTP 用户名、密码及收件地址缓冲区长度。 */
#define APP_SMTP_FIELD_SIZE 193U
/** 电话号码缓冲区长度。 */
#define APP_PHONE_SIZE 24U
/** 黑名单文本缓冲区长度。 */
#define APP_BLACKLIST_SIZE 1024U
/** 推送通道名称缓冲区长度。 */
#define APP_CHANNEL_NAME_SIZE 64U
/** 推送 URL 缓冲区长度。 */
#define APP_CHANNEL_URL_SIZE 512U
/** 推送密钥缓冲区长度。 */
#define APP_CHANNEL_KEY_SIZE 257U
/** 自定义推送请求体缓冲区长度。 */
#define APP_CHANNEL_BODY_SIZE 2049U
/** 短信正文缓冲区长度。 */
#define APP_SMS_TEXT_SIZE 2049U
/** 短信时间戳缓冲区长度。 */
#define APP_TIMESTAMP_SIZE 40U
/** 异步任务结果文本缓冲区长度。 */
#define APP_JOB_MESSAGE_SIZE 256U

/** 推送通道类型。 */
typedef enum {
    PUSH_TYPE_NONE = 0,
    PUSH_TYPE_POST_JSON = 1,
    PUSH_TYPE_BARK = 2,
    PUSH_TYPE_GET = 3,
    PUSH_TYPE_DINGTALK = 4,
    PUSH_TYPE_PUSHPLUS = 5,
    PUSH_TYPE_SERVERCHAN = 6,
    PUSH_TYPE_CUSTOM = 7,
    PUSH_TYPE_FEISHU = 8,
    PUSH_TYPE_GOTIFY = 9,
    PUSH_TYPE_TELEGRAM = 10
} push_type_t;

/** 单个推送通道的持久化配置。 */
typedef struct {
    bool enabled;
    push_type_t type;
    char name[APP_CHANNEL_NAME_SIZE];
    char url[APP_CHANNEL_URL_SIZE];
    char key1[APP_CHANNEL_KEY_SIZE];
    char key2[APP_CHANNEL_KEY_SIZE];
    char custom_body[APP_CHANNEL_BODY_SIZE];
} push_channel_t;

/** 一组持久化 Wi-Fi 凭据。 */
typedef struct {
    bool used;
    char ssid[APP_WIFI_SSID_SIZE];
    char password[APP_WIFI_PASSWORD_SIZE];
} wifi_profile_t;

/** 应用的完整持久化配置。 */
typedef struct {
    uint32_t schema_version;
    wifi_profile_t wifi_profiles[APP_MAX_WIFI_PROFILES];
    uint8_t last_successful_wifi;
    char smtp_server[APP_SMTP_HOST_SIZE];
    uint16_t smtp_port;
    char smtp_user[APP_SMTP_FIELD_SIZE];
    char smtp_password[APP_SMTP_FIELD_SIZE];
    char smtp_recipient[APP_SMTP_FIELD_SIZE];
    char admin_phone[APP_PHONE_SIZE];
    bool admin_commands_enabled;
    char number_blacklist[APP_BLACKLIST_SIZE];
    push_channel_t push_channels[APP_MAX_PUSH_CHANNELS];
} app_config_t;

/** 解码后的短信。 */
typedef struct {
    char sender[APP_PHONE_SIZE];
    char text[APP_SMS_TEXT_SIZE];
    char timestamp[APP_TIMESTAMP_SIZE];
} sms_message_t;

/** 异步任务状态。 */
typedef enum {
    JOB_STATE_QUEUED = 0,
    JOB_STATE_RUNNING,
    JOB_STATE_SUCCEEDED,
    JOB_STATE_FAILED
} job_state_t;

/** 异步任务的可查询结果。 */
typedef struct {
    uint32_t id;
    job_state_t state;
    char message[APP_JOB_MESSAGE_SIZE];
} job_status_t;
