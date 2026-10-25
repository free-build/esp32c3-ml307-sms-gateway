#pragma once

#include "esp_err.h"

/** @brief 启动带会话鉴权和 CSRF 防护的 HTTP 管理服务。 */
esp_err_t web_server_start(void);

/** @brief 停止 HTTP 管理服务。 */
void web_server_stop(void);
