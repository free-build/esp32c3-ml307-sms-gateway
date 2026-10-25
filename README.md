# ESP32-C3 + ML307 短信网关（原生 ESP-IDF 5.5.2）

这是一个可独立构建、测试和发布的 ESP-IDF 5.5.2 工程。固件入口位于 `main/`，应用层使用 C11 编写；第三方 PDUlib 本体是独立的 C++ 依赖，通过 `pdu_c_adapter.h` 的 C ABI 与应用隔离。旧 Arduino 实现暂时保留在 `code/`，不参与 ESP-IDF 构建。

> **蜂窝数据安全约束：** 固件不提供蜂窝 Ping、PDP 激活、数据拨号或 APN 配置功能。启动时只关闭并核验应用数据 CID 1；ML307 自行维护的 CID（包括 CID 8）保持不变。无法证明 CID 1 已关闭时，固件会拉低模组 EN，使模组断电。HTTP、SMTP 等通知只通过 ESP32-C3 的 Wi-Fi 网络发送。

## 已实现功能

- ML307R-DC PDU 短信接收、发送及最多 10 段长短信合并
- 持久化短信箱保存最近 10 条已接受短信，设备重启后自动恢复
- SMTP（SMTPS 465、STARTTLS 587）和 5 个并行推送通道
- POST JSON、Bark、GET、钉钉、PushPlus、Server酱、自定义、飞书、Gotify、Telegram
- 号码黑名单；管理员 `SMS:号码:内容` 和 `RESET` 命令（默认关闭）
- 基于 ESP-IDF 官方 captive portal 示例的 SoftAP 门户配网及 Wi-Fi 自动重连
- 响应式正式管理后台：首页、通知、短信、诊断和设置五个功能区
- 默认局域网免密访问，可选管理员密码保护；写操作始终使用会话 Cookie 和 CSRF
- 首页展示 Wi-Fi、SIM、运营商、注册状态、信号强度和通知配置摘要
- 只读 AT 白名单、异步任务状态和内存日志
- 旧 `sms_config` NVS 配置只读导入，不修改旧命名空间

## 硬件连接

| ESP32-C3 | ML307R-DC |
|---|---|
| GPIO3 (TX) | RX |
| GPIO4 (RX) | TX |
| GPIO5 | EN |
| GND | GND |
| 5V | VCC |

## 构建

要求使用固定版本 ESP-IDF v5.5.2：

```bash
git submodule update --init --recursive
. "$IDF_PATH/export.sh"
idf.py set-target esp32c3
idf.py build
idf.py size
```

本地不依赖 Arduino Core。`main/` 中的应用源码全部为 `.c/.h`；PDUlib 以固定 Git submodule 引入，并由极薄的 C ABI 适配层封装。CI 同样固定使用 `espressif/idf:v5.5.2`。

主机侧安全与 PDU 回归测试：

```bash
bash tests/host/run.sh
```

## 固件下载与烧录

仓库中的 [`firmware/latest/`](firmware/latest/) 保存已经通过实机验证的 ESP32-C3 固件：

- `factory-install.bin`：新设备首次安装使用的合并镜像，从 `0x0` 烧录；会清空已有 NVS 配置和短信箱。
- `bootloader.bin`、`partition-table.bin`、`ota_data_initial.bin`、`sms_forwarding_idf.bin`：分地址升级镜像；按文档命令烧录不会覆盖 NVS 和 `sms_data` 短信分区。
- `SHA256SUMS`：所有二进制文件的 SHA-256 校验值。

详细命令、偏移和安全说明见 [`firmware/latest/README.md`](firmware/latest/README.md)。已有设备需要保留 Wi-Fi、SMTP 和短信箱时，必须使用分地址升级方式，不能烧录合并镜像。

## 烧录前必须备份

不要直接执行 `erase-flash` 或 `idf.py erase-flash`。先确认实际 flash 容量，再做完整备份：

```bash
./tools/backup_device.sh /dev/ttyACM0 4MB backups/device-YYYYMMDD-HHMMSS
```

脚本拒绝覆盖已有目录，并核对镜像字节数、生成 SHA-256。备份完成且哈希另行保存后，才可按迁移说明烧录。`idf.py flash` 不会主动写 NVS 分区；本工程分区偏移也保持与旧 `huge_app` 布局一致，以便原位导入配置。

完整步骤见 [ESP-IDF 迁移与回滚](docs/ESP_IDF_MIGRATION.md)。

## 首次启动

1. 如果 NVS 中没有 Wi-Fi 凭据，设备创建无需 Wi-Fi 密码的开放热点 `SMS-Setup-XXXX`。
2. 手机连接热点后通常会自动打开门户；也可手动访问 `http://192.168.4.1/`。页面会自动扫描附近 2.4 GHz Wi-Fi，选择名称并输入密码即可；隐藏网络仍可手动输入 SSID。
3. 在设备新的局域网地址打开正式管理后台。新装和升级设备默认免密；如需保护，可在“设置 → 访问安全”启用 10–72 字符的管理员密码，固定账号为 `admin`。
4. 核对状态页中的 `packet_data_disabled=true`。该字段表示应用数据 CID 1 已关闭；ML307 自行维护的 CID 8 可以保持活动，固件不会修改它。若为 false，模组应已由固件断电，不能继续短信业务，先排查串口和模组响应。

兼容旧版的安全策略只执行或核验 `AT+CGACT=0,1`，不会主动激活任何 PDP 上下文，也不会对 CID 8 执行关闭操作。CID 8 属于模组内部维护范围，因此 `packet_data_disabled=true` 不代表所有 CID 都为 0。

门户同时使用两种官方机制：DHCP Option 114 向支持 RFC 8910 的客户端公告
`http://192.168.4.1`，通配 DNS 与 HTTP 303 重定向兼容 Android、iOS 和 Windows 的传统联网探测。
提交凭据后，设备先试连 30 秒；只有成功获得 IP 才写入 NVS。密码错误或连接超时时会自动恢复
`SMS-Setup-XXXX`，避免错误凭据导致设备失联。连接成功后页面会显示取得的局域网 IP，并自动跳转到
后台管理页面；开放热点延迟 15 秒关闭，为手机切换到目标 Wi-Fi 留出时间。门户只能接管 HTTP 探测，无法也不应拦截 HTTPS。

管理页使用局域网 HTTP，而不是设备端 HTTPS；因此应仅放在可信 Wi-Fi/VLAN 中，禁止从公网端口映射。对外推送和 SMTP 使用证书校验 TLS（用户明确配置 HTTP URL 的自定义通道除外）。
免密模式下，同一局域网中的用户可查看短信并执行管理操作；不满足这一信任条件时必须启用管理员密码。

## 仓库发布

工程根目录即 Git 仓库根目录，不依赖父目录中的文件。发布到 GitHub 前应检查：

```bash
git submodule update --init --recursive
bash tests/host/run.sh
. "$IDF_PATH/export.sh"
idf.py build
git diff --check
```

`build/`、`sdkconfig`、设备备份和短信内容不会纳入版本控制；仅 `firmware/latest/` 中经过校验的通用固件发布文件纳入仓库。

## 硬件与运行边界

- 目标：ESP32-C3，4 MB flash，USB Serial/JTAG 控制台
- 模组串口：UART1，115200，GPIO3/4；EN 为 GPIO5
- 管理员短信命令默认关闭，必须在 Web 中显式启用
- Web AT 页面只允许信息查询，无法提交任意 AT 命令
- 第一版未启用 OTA、Secure Boot、Flash Encryption 或 NVS Encryption

本仓库中的备份和烧录均为显式人工步骤；构建或运行测试不会自动访问已连接设备。

## 参考项目

- [chenxuuu/sms_forwarding](https://github.com/chenxuuu/sms_forwarding) — 短信接收、PDU 解码、长短信合并及多通道转发实现参考
- [短信转发配置演示](https://sms.j2.cx/) — 原项目后台功能和界面参考
