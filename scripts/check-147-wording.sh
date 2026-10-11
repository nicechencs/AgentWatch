#!/usr/bin/env bash
# #147 approved launch-error wording. Run from the repository root.
set -euo pipefail

cd "${1:-.}"
sources=(crates app ui)

# These combined launch explanations lose the actual failing input. They must
# not exist even in tests or output tables: every path uses one of the four
# reviewed program/cwd sentences instead.
if rg -n '程序或工作目录|运行它或进入|运行这个程序或进入|找不到这个程序或工作目录|没有权限运行这个程序或进入工作目录' "${sources[@]}"; then
  echo '【不该出现】合并的程序/工作目录启动错误'
  exit 1
fi

echo 'UI-147 启动错误措辞检查通过'
