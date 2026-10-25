# 从 Arduino 固件迁移到 ESP-IDF 5.5.2

## 迁移原则

- 先备份、后烧录；没有可验证的完整 flash 镜像就不迁移。
- 不擦除 NVS；新固件只读旧 `sms_config`，写入独立的 `sms_idf` 命名空间。
- 不通过 SIM 使用数据业务。Wi-Fi 是所有 HTTP/SMTP 通知的唯一 IP 出口。
- 第一轮采用原位迁移，确认运行稳定前保留旧镜像和 SHA-256。
- 应用层统一采用 C11，并为函数、全局变量和宏定义提供中文注释；第三方 PDUlib 通过 C ABI 隔离。

## 1. 记录现状

保存以下信息：设备现有 Web 地址、硬件接线、flash 容量、当前固件版本、现有推送与 SMTP 配置。旧固件的 Wi-Fi SSID/密码来自编译期 `code/wifi_config.h`，不在 NVS 中，因此不能自动迁移。

不要为了检查设备而执行蜂窝 Ping，也不要发送 `AT+CGACT=1`、`AT+CGATT=1`、`AT+CGDATA`、`ATD*99`、`AT+CGDCONT` 或任何等价命令。

## 2. 完整备份

先停止任何可能占用串口的监视器，然后执行：

```bash
./tools/backup_device.sh /dev/ttyACM0 4MB backups/device-YYYYMMDD-HHMMSS
```

检查输出目录至少包含：

- `full_flash.bin`
- `chip_id.txt`
- `flash_id.txt`
- `SHA256SUMS`

把 `full_flash.bin` 和 `SHA256SUMS` 复制到仓库之外的安全位置。脚本参数中的容量必须来自 `flash_id`/硬件资料，不应猜测。

## 3. 构建并审查产物

```bash
git submodule update --init --recursive
. "$IDF_PATH/export.sh"
idf.py set-target esp32c3
idf.py build
idf.py size
bash tests/host/run.sh
```

核对 `build/flash_args`，确认目标为 ESP32-C3、flash 为 4 MB，并确认分区：

| 分区 | 偏移 | 大小 | 迁移用途 |
|---|---:|---:|---|
| nvs | `0x9000` | `0x5000` | 保留并读取旧配置 |
| factory | `0x10000` | `0x280000` | 新原生 IDF 应用 |
| sms_data | `0x290000` | `0x80000` | 最近十条短信的双副本持久化存储 |
| legacy_data | `0x310000` | `0xE0000` | 保留旧 SPIFFS 区域 |
| coredump | `0x3F0000` | `0x10000` | 崩溃记录 |

## 4. 原位烧录

只有完整备份已经校验并另存后才执行：

```bash
idf.py -p /dev/ttyACM0 flash monitor
```

不得执行整片擦除。普通 `idf.py flash` 写入 bootloader、partition table 和 app，不应写入 NVS 数据内容。

## 5. 首次启动与配置导入

新固件第一次启动时：

1. 从旧 `sms_config` 导入 SMTP、管理员号码、黑名单和 5 个推送通道。
2. 兼容导入更早版本的 `httpUrl`/`barkMode` 到第一个推送通道。
3. 不继承旧明文 Web 密码；新装设备默认免密码访问。启用登录保护时必须设置 10–72 字符的新密码，密码只以 PBKDF2-HMAC-SHA256 哈希形式保存。
4. 管理员短信命令即使旧版曾可用，迁移后仍默认关闭。
5. 因 Wi-Fi 原先是编译期配置，设备创建无需密码的开放热点 `SMS-Setup-XXXX`；手机通常会自动打开门户，也可访问 `http://192.168.4.1/`。默认免密码进入配网，若已启用后台登录保护则使用自行设置的密码。

### 门户实现基线

- 以 ESP-IDF v5.5.2 `examples/protocols/http_server/captive_portal` 为基线，而不是自行假设某个手机厂商的固定探测 URL。
- DHCP Option 114 公告门户 URI；DHCP Option 6 把 SoftAP 地址公告为 DNS；通配 DNS 把所有 IPv4 A 查询解析到 SoftAP。
- `/` 返回配网页，其他 HTTP 路径在配网模式下用 `303 See Other` 重定向到 `/`，并保留非空正文以兼容 iOS。
- SoftAP 使用 AP+STA 模式：AP 承载门户，STA 仅在登录后扫描附近网络；扫描结果按信号强度显示 SSID、RSSI 和加密状态，隐藏网络保留手动输入入口。
- DNS 解析器在官方示例工作方式上增加长度、标签、类型和类检查，并剥离 EDNS 附加记录后再生成答案，避免畸形响应。
- 门户提交的新凭据先在 RAM 中试连；30 秒内获得地址才写入 `sms_idf` NVS。失败则恢复热点，错误凭据不会跨重启锁死设备。
- 成功后门户返回 STA 的准确局域网 IP 和后台 URL，页面自动跳转；SoftAP 延迟 15 秒关闭，确保手机已经取得后台地址。
- 关闭配网热点后同时停止通配 DNS；正常 STA 管理模式的未知路径恢复为普通 404，不劫持局域网请求。

开放式热点上的门户 HTTP 不具备链路保密性，因此这里只完成首次 Wi-Fi 配置；短信正文、Token、SMTP
授权码等业务配置必须在设备加入可信局域网后再填写。门户仍要求管理账号登录与 CSRF Token，防止同一热点内的
无授权提交，但这不能替代链路加密。

## 6. 验收清单

- USB 启动日志无循环复位、NVS 错误或 UART 溢出。
- 状态页显示 `packet_data_disabled=true`；该字段只表示应用数据 CID 1 已关闭，否则模组必须处于 EN 低电平断电状态。
- `AT+CGACT?` 只读查询显示 CID 1 为 0。兼容旧版时允许 ML307 自行维护 CID 8，固件既不关闭 CID 8，也不主动激活任何 PDP 上下文。
- Web 页面无法提交不在白名单中的 AT 指令。
- 修改默认管理密码后，分别验证单段短信、中文短信、长短信和黑名单。
- 用 Wi-Fi 路由器日志确认 HTTP/SMTP 流量来自 ESP32-C3 Wi-Fi，而不是蜂窝模组。
- 分别测试启用的通知通道，确认 TLS 证书校验及服务端返回码。
- 管理员短信命令保持关闭，除非确有需要并已确认管理员号码。

验收时不要测试蜂窝 Ping 或任何分组数据功能。

## 回滚

若新固件不能稳定运行，先保存故障串口日志，再用完整备份恢复整片 flash：

```bash
esptool.py --chip esp32c3 --port /dev/ttyACM0 write_flash 0x0 backups/device-YYYYMMDD-HHMMSS/full_flash.bin
```

恢复前再次核对目标串口、备份容量和 SHA-256。整片恢复会覆盖当前 flash，是有意的回滚操作；不要把示例路径原样执行。
