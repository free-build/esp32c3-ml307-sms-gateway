#pragma once

#include "app_types.h"

#include <stdbool.h>
#include <stddef.h>

/** SMTP 客户端实际需要的精简配置，避免 TLS 握手期间持有完整应用配置。 */
typedef struct {
    char server[APP_SMTP_HOST_SIZE];
    uint16_t port;
    char user[APP_SMTP_FIELD_SIZE];
    char password[APP_SMTP_FIELD_SIZE];
    char recipient[APP_SMTP_FIELD_SIZE];
} smtp_client_config_t;

/**
 * @brief 通过证书校验的 SMTPS 或 STARTTLS 发送邮件。
 * @param config SMTP 精简配置。
 * @param subject 邮件主题。
 * @param body 邮件正文。
 * @param error 错误文本输出缓冲区。
 * @param error_size 错误文本缓冲区长度。
 * @return 服务器接受邮件时返回 true。
 */
bool smtp_client_send(const smtp_client_config_t *config, const char *subject, const char *body,
                      char *error, size_t error_size);
