#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/../.." && pwd)"
build_dir="${TMPDIR:-/tmp}/sms-forwarding-host-tests"
mkdir -p "$build_dir"

common_include_flags=(
  -Wall
  -Wextra
  -DDESKTOP_PDU
  -I"$repo_dir/main"
  -I"$repo_dir/components/captive_dns/include"
  -I"$repo_dir/components/pdulib"
  -I"$repo_dir/components/pdulib/upstream/src"
)

# 项目自有的 C 代码启用严格警告。
gcc -std=c11 "${common_include_flags[@]}" -Werror -c \
  "$repo_dir/tests/host/test_main.c" \
  -o "$build_dir/test_main.o"

gcc -std=c11 "${common_include_flags[@]}" -Werror -c \
  "$repo_dir/main/safety_policy.c" \
  -o "$build_dir/safety_policy.o"

gcc -std=c11 "${common_include_flags[@]}" -Werror -c \
  "$repo_dir/components/captive_dns/captive_dns_packet.c" \
  -o "$build_dir/captive_dns_packet.o"

# 第三方 PDUlib 仍由 C++ 编译器构建，只通过 C ABI 暴露给应用。
g++ -std=c++17 "${common_include_flags[@]}" \
  -Wno-unused-parameter -Wno-implicit-fallthrough -c \
  "$repo_dir/components/pdulib/upstream/src/pdulib.cpp" \
  -o "$build_dir/pdulib.o"

g++ -std=c++17 "${common_include_flags[@]}" -Werror -c \
  "$repo_dir/components/pdulib/pdu_c_adapter.cpp" \
  -o "$build_dir/pdu_c_adapter.o"

g++ "$build_dir/test_main.o" "$build_dir/safety_policy.o" "$build_dir/captive_dns_packet.o" \
  "$build_dir/pdu_c_adapter.o" "$build_dir/pdulib.o" \
  -o "$build_dir/test_main"

"$build_dir/test_main"
