#!/bin/bash
# 构建后台前端并放进 public/assets/admin。
# 后台前端源码在 https://github.com/codeman857/v2board-admin（React），本仓库只保存构建产物，
# 用户 update.sh 拉取后直接可用，服务器上不需要 Node。
#
# 用法：./build-admin.sh [v2board-admin 源码目录]   默认 ../v2board-admin
# 需要：Node >= 22.22、pnpm 11（npm i -g pnpm@11）
# 流程：先在 v2board-admin 提交并推送，再跑本脚本，然后把 public/assets/admin 的变化和后端改动一起提交。
set -euo pipefail
cd "$(dirname "$0")"

SRC="${1:-../v2board-admin}"
DEST="public/assets/admin"

if [ ! -f "$SRC/package.json" ]; then
  echo "未找到 v2board-admin 源码：$SRC" >&2
  exit 1
fi
if ! git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1; then
  echo "$SRC 不是 git 仓库，无法记录产物来源" >&2
  exit 1
fi

# 产物必须来自已提交的源码，否则 SOURCE 里记录的 commit 在仓库里找不到；本地联调可用 ALLOW_DIRTY=1 跳过
DIRTY=$(git -C "$SRC" status --porcelain)
if [ -n "$DIRTY" ] && [ "${ALLOW_DIRTY:-0}" != "1" ]; then
  echo "v2board-admin 有未提交的改动，请先提交（本地联调可加 ALLOW_DIRTY=1）" >&2
  exit 1
fi

# V2B_EMBED=1：入口固定为 assets/admin.js、assets/admin.css（resources/views/admin.blade.php 引用）
(cd "$SRC" && pnpm install --frozen-lockfile && V2B_EMBED=1 pnpm build)
for f in assets/admin.js assets/admin.css favicon.png; do
  if [ ! -f "$SRC/dist/$f" ]; then
    echo "构建产物缺少 $f，请检查 v2board-admin 的 vite.config.ts 是否支持 V2B_EMBED" >&2
    exit 1
  fi
done

# 清掉旧产物；custom.css 是各站点自己的样式覆盖（已 gitignore），保留
mkdir -p "$DEST"
find "$DEST" -mindepth 1 -maxdepth 1 ! -name custom.css -exec rm -rf {} +
cp -R "$SRC/dist/assets" "$DEST/assets"
cp "$SRC/dist/favicon.png" "$DEST/favicon.png"

# 记录产物来自哪个仓库、哪个提交，便于对照源码
COMMIT=$(git -C "$SRC" rev-parse HEAD)
[ -n "$DIRTY" ] && COMMIT="$COMMIT-dirty"
{
  echo "source: $(git -C "$SRC" remote get-url origin 2>/dev/null || echo unknown)"
  echo "commit: $COMMIT"
  echo "built:  $(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$DEST/SOURCE"

echo "已更新 ${DEST}（v2board-admin ${COMMIT:0:7}${DIRTY:+-dirty}），请检查后提交"
if [ -n "$DIRTY" ]; then
  echo "注意：产物来自未提交的源码（SOURCE 带 -dirty），只用于本地联调，不要提交" >&2
fi
