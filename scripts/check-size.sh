#!/bin/sh
# 逐个检查目录下产物的大小（P4-CI-06 / NFR-04）。
# 与 scripts/check-size.ps1 行为一致：超过限额非零退出；
# 达到限额的 90%（可用 -w 覆盖）但未超限额时退出码 0 并打印警告；
# 路径不存在、不是目录、或目录里没有普通文件时非零退出。
#
# 用法：
#   scripts/check-size.sh [-l LIMIT_MB] [-w WARN_PERCENT] PATH
#   scripts/check-size.sh PATH LIMIT_MB
#
# LIMIT_MB 默认 25。1 MB = 1000 * 1000 字节。

set -eu

limit_mb=25
warn_percent=90
path=

usage() {
    printf '%s\n' "用法：check-size.sh [-l LIMIT_MB] [-w WARN_PERCENT] PATH" >&2
    printf '%s\n' "      check-size.sh PATH LIMIT_MB" >&2
    exit 2
}

is_number() {
    # 正数，允许小数。拒绝 0、负数、空串和科学计数法。
    printf '%s\n' "$1" | grep -Eq '^[0-9]+([.][0-9]+)?$'
}

while [ $# -gt 0 ]; do
    case "$1" in
        -l)
            [ $# -ge 2 ] || usage
            limit_mb=$2
            shift 2
            ;;
        -w)
            [ $# -ge 2 ] || usage
            warn_percent=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            printf '%s\n' "未知参数：$1" >&2
            usage
            ;;
        *)
            break
            ;;
    esac
done

if [ $# -eq 1 ]; then
    path=$1
elif [ $# -eq 2 ]; then
    path=$1
    limit_mb=$2
else
    usage
fi

if ! is_number "$limit_mb"; then
    printf '%s\n' "限额必须是大于 0 的数字（MB），实际为 $limit_mb" >&2
    exit 2
fi
if ! is_number "$warn_percent"; then
    printf '%s\n' "警告百分比必须是 (0, 100] 内的数字，实际为 $warn_percent" >&2
    exit 2
fi

# awk 做浮点比较与换算，避免依赖 bash / bc。
eval "$(awk -v limit="$limit_mb" -v warn="$warn_percent" 'BEGIN {
    if (limit + 0 <= 0) { print "bad_limit=1"; exit }
    if (warn + 0 <= 0 || warn + 0 > 100) { print "bad_warn=1"; exit }
    limit_bytes = int(limit * 1000000)
    if (limit_bytes < 1) { print "bad_limit_bytes=1"; exit }
    warn_bytes = int(limit_bytes * warn / 100)
    printf "limit_bytes=%d\nwarn_bytes=%d\n", limit_bytes, warn_bytes
}')" || true

if [ "${bad_limit:-0}" = 1 ]; then
    printf '%s\n' "限额必须大于 0 MB，实际为 $limit_mb" >&2
    exit 2
fi
if [ "${bad_warn:-0}" = 1 ]; then
    printf '%s\n' "警告百分比必须在 (0, 100] 内，实际为 $warn_percent" >&2
    exit 2
fi
if [ "${bad_limit_bytes:-0}" = 1 ]; then
    printf '%s\n' "限额换算后不足 1 字节：$limit_mb MB" >&2
    exit 2
fi

if [ ! -e "$path" ]; then
    printf '%s\n' "路径不存在：$path" >&2
    exit 2
fi
if [ ! -d "$path" ]; then
    printf '%s\n' "路径不是目录：$path" >&2
    exit 2
fi

# 只看目录本身的普通文件，不递归。按文件名排序，和 PowerShell 的 Sort-Object Name 对齐。
found=0
over=0
warned=0
# 用换行分隔的清单，文件名不含换行（产物名不会）。
list=$(find "$path" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort) || {
    printf '%s\n' "无法读取目录：$path" >&2
    exit 2
}

if [ -z "$list" ]; then
    printf '%s\n' "目录为空（没有普通文件）：$path" >&2
    exit 2
fi

# POSIX sh 没有数组；用换行读回已排序的文件名。
OLD_IFS=$IFS
IFS='
'
for name in $list; do
    IFS=$OLD_IFS
    [ -n "$name" ] || continue
    file="$path/$name"
    size=$(wc -c < "$file" | tr -d '[:space:]')
    size_mb=$(awk -v s="$size" 'BEGIN { printf "%.3f", s / 1000000 }')
    limit_mb_text=$(awk -v b="$limit_bytes" 'BEGIN { printf "%.3f", b / 1000000 }')
    found=$((found + 1))
    if [ "$size" -gt "$limit_bytes" ]; then
        printf '%s\n' "超过限额：$file  实际 ${size} 字节（${size_mb} MB），限额 ${limit_bytes} 字节（${limit_mb_text} MB）" >&2
        over=$((over + 1))
    elif [ "$size" -ge "$warn_bytes" ]; then
        warn_mb_text=$(awk -v b="$warn_bytes" 'BEGIN { printf "%.3f", b / 1000000 }')
        printf '%s\n' "警告: 接近限额（≥${warn_percent}%）：$file  实际 ${size} 字节（${size_mb} MB），限额 ${limit_bytes} 字节（${limit_mb_text} MB），警告线 ${warn_bytes} 字节（${warn_mb_text} MB）" >&2
        warned=$((warned + 1))
    else
        printf '%s\n' "通过：$name  ${size} 字节（${size_mb} MB）"
    fi
    IFS='
'
done
IFS=$OLD_IFS

if [ "$over" -gt 0 ]; then
    printf '%s\n' "失败：${over} 个文件超过限额 ${limit_mb} MB" >&2
    exit 1
fi

if [ "$warned" -gt 0 ]; then
    printf '%s\n' "完成：${found} 个文件，${warned} 个达到警告线（限额的 ${warn_percent}%），均未超过限额 ${limit_mb} MB"
else
    printf '%s\n' "完成：${found} 个文件均低于限额 ${limit_mb} MB"
fi
exit 0
