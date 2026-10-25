# ESP32-C3 + ML307 固件烧录说明

本目录中的固件由 ESP-IDF v5.5.2 构建，目标芯片为 ESP32-C3、flash 容量为 4 MB、flash mode 为 DIO、频率为 80 MHz。

## 已有设备升级（保留配置和短信箱）

使用分地址镜像。下面的命令只写 bootloader、分区表、OTA 初始化数据和应用，不写 `0x9000` 的 NVS，也不写 `0x290000` 的 `sms_data` 分区：

```bash
esptool.py --chip esp32c3 --port /dev/ttyACM0 --baud 460800 \
  --before default_reset --after hard_reset write_flash \
  --flash_mode dio --flash_freq 80m --flash_size 4MB \
  0x0 bootloader.bin \
  0x8000 partition-table.bin \
  0xe000 ota_data_initial.bin \
  0x10000 sms_forwarding_idf.bin
```

Windows 用户把 `/dev/ttyACM0` 换成实际串口，例如 `COM4`。

## 新设备首次安装

`factory-install.bin` 是从 `0x0` 开始的连续合并镜像，适合无须保留数据的新设备：

```bash
esptool.py --chip esp32c3 --port /dev/ttyACM0 --baud 460800 \
  --before default_reset --after hard_reset write_flash 0x0 factory-install.bin
```

**警告：** 合并镜像覆盖范围包含 NVS 间隙，因此会清除已有 Wi-Fi、SMTP、推送配置和持久化短信。升级现有设备必须使用上一节的分地址命令。

## 文件用途

| 文件 | 偏移 | 用途 |
|---|---:|---|
| `bootloader.bin` | `0x0` | ESP32-C3 二级引导程序 |
| `partition-table.bin` | `0x8000` | 4 MB flash 分区表 |
| `ota_data_initial.bin` | `0xe000` | OTA 数据初始化区 |
| `sms_forwarding_idf.bin` | `0x10000` | 主应用固件 |
| `factory-install.bin` | `0x0` | 上述内容的连续首次安装镜像 |

`flash_args.txt` 同时提供了 ESP-IDF/esptool 可读取的分地址参数清单。

烧录前执行 `sha256sum -c SHA256SUMS` 校验下载文件。不要执行 `erase-flash`；如需迁移或回滚，请先参照仓库的设备备份文档制作完整 4 MB 备份。
