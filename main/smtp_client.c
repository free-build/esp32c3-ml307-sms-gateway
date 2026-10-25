#include "smtp_client.h"

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** SMTP 单行响应最大长度。 */
#define SMTP_LINE_SIZE 1025U
/** SMTP Base64 临时缓冲区长度。 */
#define SMTP_BASE64_SIZE 4096U

/** SMTP 日志标签。 */
static const char *const g_tag = "smtp";

/** SMTP TCP/TLS 传输上下文。 */
typedef struct {
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    bool tls;
} smtp_transport_t;

/** @brief 将错误说明复制到调用者缓冲区。 */
static void set_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size > 0U) snprintf(error, error_size, "%s", message);
}

/** @brief 记录并返回带 Mbed TLS 错误码的阶段说明。 */
static void set_tls_error(char *error, size_t error_size, const char *stage, int result) {
    char detail[96];
    mbedtls_strerror(result, detail, sizeof(detail));
    if (error != NULL && error_size > 0U) {
        snprintf(error, error_size, "%s failed: -0x%04X (%s)", stage,
                 (unsigned)(result < 0 ? -result : result), detail);
    }
    ESP_LOGE(g_tag, "%s failed: -0x%04X (%s)", stage,
             (unsigned)(result < 0 ? -result : result), detail);
}

/** @brief 初始化 SMTP 传输上下文。 */
static void transport_init(smtp_transport_t *transport) {
    memset(transport, 0, sizeof(*transport));
    mbedtls_net_init(&transport->net);
    mbedtls_ssl_init(&transport->ssl);
    mbedtls_ssl_config_init(&transport->config);
}

/** @brief 释放 SMTP 传输上下文中的全部资源。 */
static void transport_free(smtp_transport_t *transport) {
    if (transport->tls) mbedtls_ssl_close_notify(&transport->ssl);
    mbedtls_ssl_free(&transport->ssl);
    mbedtls_ssl_config_free(&transport->config);
    mbedtls_net_free(&transport->net);
}

/** @brief 为 TLS 提供 ESP32 硬件随机数。 */
static int tls_random(void *context, unsigned char *output, size_t length) {
    (void)context;
    esp_fill_random(output, length);
    return 0;
}

/** @brief 在现有 TCP 连接上启动并校验证书的 TLS。 */
static bool transport_start_tls(smtp_transport_t *transport, const char *host,
                                char *error, size_t error_size) {
    int result;
    result = mbedtls_ssl_config_defaults(&transport->config, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0) {
        set_tls_error(error, error_size, "SMTP TLS defaults", result);
        return false;
    }
    mbedtls_ssl_conf_authmode(&transport->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&transport->config, tls_random, NULL);
    mbedtls_ssl_conf_read_timeout(&transport->config, 10000U);
    const esp_err_t bundle_error = esp_crt_bundle_attach(&transport->config);
    if (bundle_error != ESP_OK) {
        if (error != NULL && error_size > 0U) {
            snprintf(error, error_size, "SMTP certificate bundle failed: %s",
                     esp_err_to_name(bundle_error));
        }
        ESP_LOGE(g_tag, "certificate bundle attach failed: %s", esp_err_to_name(bundle_error));
        return false;
    }
    result = mbedtls_ssl_setup(&transport->ssl, &transport->config);
    if (result != 0) {
        set_tls_error(error, error_size, "SMTP TLS context setup", result);
        return false;
    }
    result = mbedtls_ssl_set_hostname(&transport->ssl, host);
    if (result != 0) {
        set_tls_error(error, error_size, "SMTP TLS hostname setup", result);
        return false;
    }
    mbedtls_ssl_set_bio(&transport->ssl, &transport->net, mbedtls_net_send,
                        mbedtls_net_recv, mbedtls_net_recv_timeout);
    do {
        result = mbedtls_ssl_handshake(&transport->ssl);
    } while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (result != 0) {
        set_tls_error(error, error_size, "SMTP TLS handshake", result);
        return false;
    }
    const uint32_t verify_result = mbedtls_ssl_get_verify_result(&transport->ssl);
    if (verify_result != 0U) {
        if (error != NULL && error_size > 0U) {
            snprintf(error, error_size, "SMTP certificate verification failed: 0x%08lX",
                     (unsigned long)verify_result);
        }
        ESP_LOGE(g_tag, "certificate verification failed: 0x%08lX",
                 (unsigned long)verify_result);
        return false;
    }
    transport->tls = true;
    return true;
}

/** @brief 建立 SMTP TCP 连接，并按需立即启动 TLS。 */
static bool transport_connect(smtp_transport_t *transport, const char *host, uint16_t port,
                              bool immediate_tls, char *error, size_t error_size) {
    char port_text[8];
    snprintf(port_text, sizeof(port_text), "%u", port);
    if (mbedtls_net_connect(&transport->net, host, port_text, MBEDTLS_NET_PROTO_TCP) != 0) {
        set_error(error, error_size, "SMTP TCP connection failed");
        return false;
    }
    return !immediate_tls || transport_start_tls(transport, host, error, error_size);
}

/** @brief 完整发送指定长度的数据。 */
static bool transport_write_all(smtp_transport_t *transport, const char *data, size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        const int result = transport->tls
            ? mbedtls_ssl_write(&transport->ssl, (const unsigned char *)data + offset, length - offset)
            : mbedtls_net_send(&transport->net, (const unsigned char *)data + offset, length - offset);
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (result <= 0) return false;
        offset += (size_t)result;
    }
    return true;
}

/** @brief 从 SMTP 连接读取一行响应。 */
static bool transport_read_line(smtp_transport_t *transport, char *line, size_t line_size) {
    size_t length = 0U;
    while (length + 1U < line_size) {
        unsigned char byte = 0U;
        const int result = transport->tls
            ? mbedtls_ssl_read(&transport->ssl, &byte, 1U)
            : mbedtls_net_recv_timeout(&transport->net, &byte, 1U, 10000U);
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (result <= 0) return false;
        if (byte == '\n') { line[length] = '\0'; return true; }
        if (byte != '\r') line[length++] = (char)byte;
    }
    line[line_size - 1U] = '\0';
    return false;
}

/** @brief 等待 SMTP 指定状态码，并处理多行响应。 */
static bool expect_response(smtp_transport_t *transport, int expected, char *error,
                            size_t error_size) {
    char line[SMTP_LINE_SIZE];
    do {
        if (!transport_read_line(transport, line, sizeof(line))) {
            set_error(error, error_size, "SMTP response timeout");
            return false;
        }
    } while (strlen(line) >= 4U && line[3] == '-');
    if (strlen(line) < 3U || atoi(line) != expected) {
        set_error(error, error_size, line[0] != '\0' ? line : "empty SMTP response");
        return false;
    }
    return true;
}

/** @brief 发送一条 SMTP 命令并校验响应码。 */
static bool send_command(smtp_transport_t *transport, const char *command, int expected,
                         char *error, size_t error_size) {
    const size_t length = strlen(command);
    return transport_write_all(transport, command, length) &&
           transport_write_all(transport, "\r\n", 2U) &&
           expect_response(transport, expected, error, error_size);
}

/** @brief 将短文本编码为 Base64。 */
static bool encode_text(const char *input, char *output, size_t output_size) {
    size_t written = 0U;
    const size_t length = strlen(input);
    if (length > 2800U || mbedtls_base64_encode((unsigned char *)output, output_size - 1U,
                                                &written, (const unsigned char *)input,
                                                length) != 0) return false;
    output[written] = '\0';
    return true;
}

/** @brief 写入 SMTP DATA 正文并执行点透明和换行规范化。 */
static bool write_dot_stuffed_body(smtp_transport_t *transport, const char *body) {
    bool line_start = true;
    for (const char *cursor = body; *cursor != '\0'; ++cursor) {
        if (line_start && *cursor == '.' && !transport_write_all(transport, ".", 1U)) return false;
        if (*cursor == '\n') {
            if (!transport_write_all(transport, "\r\n", 2U)) return false;
            line_start = true;
        } else {
            if (!transport_write_all(transport, cursor, 1U)) return false;
            line_start = false;
        }
    }
    return true;
}

bool smtp_client_send(const smtp_client_config_t *config, const char *subject, const char *body,
                      char *error, size_t error_size) {
    smtp_transport_t transport;
    bool success = false;
    char encoded[SMTP_BASE64_SIZE];
    char command[512];
    const bool starttls = config != NULL && config->port == 587U;
    if (config == NULL || config->server[0] == '\0' || config->user[0] == '\0' ||
        config->password[0] == '\0' || config->recipient[0] == '\0') {
        set_error(error, error_size, "SMTP configuration incomplete");
        return false;
    }
    if (!starttls && config->port != 465U) {
        set_error(error, error_size, "only certificate-verified SMTPS 465 and STARTTLS 587 are supported");
        return false;
    }
    transport_init(&transport);
    if (!transport_connect(&transport, config->server, config->port, !starttls,
                           error, error_size) ||
        !expect_response(&transport, 220, error, error_size) ||
        !send_command(&transport, "EHLO esp32-c3", 250, error, error_size)) goto cleanup;
    if (starttls && (!send_command(&transport, "STARTTLS", 220, error, error_size) ||
                     !transport_start_tls(&transport, config->server, error, error_size) ||
                     !send_command(&transport, "EHLO esp32-c3", 250, error, error_size))) goto cleanup;
    if (!send_command(&transport, "AUTH LOGIN", 334, error, error_size) ||
        !encode_text(config->user, encoded, sizeof(encoded)) ||
        !send_command(&transport, encoded, 334, error, error_size) ||
        !encode_text(config->password, encoded, sizeof(encoded)) ||
        !send_command(&transport, encoded, 235, error, error_size)) goto cleanup;
    snprintf(command, sizeof(command), "MAIL FROM:<%s>", config->user);
    if (!send_command(&transport, command, 250, error, error_size)) goto cleanup;
    snprintf(command, sizeof(command), "RCPT TO:<%s>", config->recipient);
    if (!send_command(&transport, command, 250, error, error_size) ||
        !send_command(&transport, "DATA", 354, error, error_size) ||
        !encode_text(subject, encoded, sizeof(encoded))) goto cleanup;
    const int header_length = snprintf(NULL, 0U,
        "From: <%s>\r\nTo: <%s>\r\nSubject: =?UTF-8?B?%s?=\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\n",
        config->user, config->recipient, encoded);
    char *headers = header_length >= 0 ? malloc((size_t)header_length + 1U) : NULL;
    if (headers == NULL) { set_error(error, error_size, "SMTP header allocation failed"); goto cleanup; }
    snprintf(headers, (size_t)header_length + 1U,
        "From: <%s>\r\nTo: <%s>\r\nSubject: =?UTF-8?B?%s?=\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\n",
        config->user, config->recipient, encoded);
    const bool headers_written = transport_write_all(&transport, headers, (size_t)header_length);
    free(headers);
    if (!headers_written ||
        !write_dot_stuffed_body(&transport, body) ||
        !transport_write_all(&transport, "\r\n.\r\n", 5U) ||
        !expect_response(&transport, 250, error, error_size)) goto cleanup;
    success = true;
    send_command(&transport, "QUIT", 221, error, error_size);

cleanup:
    transport_free(&transport);
    return success;
}
