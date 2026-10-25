#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 PORT FLASH_SIZE OUTPUT_DIR" >&2
  echo "Example: $0 /dev/ttyACM0 4MB backups/device-2026-10-13" >&2
  exit 2
fi

port="$1"
flash_size="$2"
output_dir="$3"

case "$port" in /dev/ttyACM*|/dev/ttyUSB*) ;; *) echo "Refusing unexpected serial path: $port" >&2; exit 2;; esac
case "$flash_size" in 2MB) bytes=0x200000;; 4MB) bytes=0x400000;; 8MB) bytes=0x800000;; 16MB) bytes=0x1000000;; *) echo "Unsupported flash size" >&2; exit 2;; esac

if [[ -e "$output_dir" ]]; then
  echo "Refusing to overwrite existing backup directory: $output_dir" >&2
  exit 2
fi
mkdir -p "$output_dir"

esptool.py --chip esp32c3 --port "$port" chip_id | tee "$output_dir/chip_id.txt"
esptool.py --chip esp32c3 --port "$port" flash_id | tee "$output_dir/flash_id.txt"
esptool.py --chip esp32c3 --port "$port" read_flash 0 "$bytes" "$output_dir/full_flash.bin"
sha256sum "$output_dir/full_flash.bin" | tee "$output_dir/SHA256SUMS"

actual="$(stat -c '%s' "$output_dir/full_flash.bin")"
expected="$((bytes))"
[[ "$actual" -eq "$expected" ]] || { echo "Backup size mismatch" >&2; exit 1; }
echo "Backup complete and size-checked. Do not flash until SHA-256 is stored separately."
