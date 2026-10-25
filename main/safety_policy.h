#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief 判断 AT 指令是否尝试启用蜂窝数据功能。
 * @param command 待检查的 AT 指令。
 * @return 命中禁止规则时返回 true。
 */
bool safety_is_forbidden_cellular_data_command(const char *command);

/**
 * @brief 判断 AT 指令是否为合法的 PDP 去激活指令。
 * @param command 待检查的 AT 指令。
 * @return 指令仅关闭一个合法 CID 时返回 true。
 */
bool safety_is_pdp_deactivation_command(const char *command);

/**
 * @brief 从 CGACT 查询结果提取所有活动 CID。
 * @param response 模组响应文本。
 * @param active 保存活动 CID 的数组。
 * @param capacity active 数组容量。
 * @param active_count 返回活动 CID 数量。
 * @return 响应至少包含一个格式正确的上下文时返回 true。
 */
bool safety_parse_active_pdp_contexts(const char *response, int *active, size_t capacity,
                                      size_t *active_count);

/**
 * @brief 查询指定 CID 是否处于活动状态。
 * @param response 模组的 CGACT 查询响应。
 * @param cid 需要检查的 CID。
 * @param is_active 返回该 CID 是否活动；响应中未列出时视为未活动。
 * @return 响应格式有效时返回 true。
 */
bool safety_pdp_context_is_active(const char *response, int cid, bool *is_active);

/**
 * @brief 判断指令是否在固件内部安全白名单中。
 * @param command 待检查的 AT 指令。
 * @return 允许内部执行时返回 true。
 */
bool safety_is_safe_at_command(const char *command);

/**
 * @brief 判断指令是否属于 Web API 可执行的只读白名单。
 * @param command 待检查的 AT 指令。
 * @return 允许从 Web API 查询时返回 true。
 */
bool safety_is_read_only_at_command(const char *command);
