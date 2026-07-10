#!/usr/bin/env bash
# 服务器上:load 镜像 + 起服务。随 build-and-export.sh 的 prod/ 包一起 scp 到服务器后运行。
# 用法:./import-images.sh [镜像包路径]  (省略则自动找本目录最新的 baserust_images_*.tar*)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

ARCHIVE="${1:-}"
if [ -z "$ARCHIVE" ]; then
  ARCHIVE=$(find "$DIR" -maxdepth 1 -type f -name 'baserust_images_*.tar*' | sort -r | head -1)
fi
if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
  echo "❌ 找不到镜像包(baserust_images_*.tar.xz / .tar)"; exit 1
fi

echo "═══ baserust 部署 ═══"
echo "📦 镜像包: $(basename "$ARCHIVE")"
echo ""

# .env 存在性 + CHANGE-ME 未改的告警
if [ ! -f "$DIR/.env" ]; then
  echo "❌ 缺 .env(应随包带来)"; exit 1
fi
if grep -q "CHANGE-ME" "$DIR/.env"; then
  echo "⚠️ .env 里仍有 CHANGE-ME 未改(DB/minio 密码等)。继续? [y/N]"
  read -r ans; [ "$ans" = "y" ] || { echo "已中止,先改 .env"; exit 1; }
fi

# seed.prod.toml 存在性(compose bind-mount 它;缺文件会被 docker 建成目录 → idm 启动崩)。
# 不建 = idm 不 seed 任何账号(不落 pwd 弱默认);要建就得填真密码。
if [ ! -f "$DIR/seed.prod.toml" ]; then
  echo "⚠️ 缺 seed.prod.toml —— idm 启动不会建超管账号。"
  echo "   要建号:cp seed.prod.toml.example seed.prod.toml 并填强密码,再重跑本脚本。"
  echo "   确认无账号继续起服务? [y/N]"
  read -r ans; [ "$ans" = "y" ] || { echo "已中止"; exit 1; }
  # 占位空文件,避免 bind mount 把路径建成目录(idm 读它 = 空账号列表,不建号)。
  : > "$DIR/seed.prod.toml"
elif grep -q "CHANGE_ME" "$DIR/seed.prod.toml"; then
  echo "⚠️ seed.prod.toml 仍有 CHANGE_ME 占位密码(弱凭据)。继续? [y/N]"
  read -r ans; [ "$ans" = "y" ] || { echo "已中止,先填真密码"; exit 1; }
fi

echo "📥 load 镜像..."
# docker load 原生支持压缩包;失败再回退 xz 解流
if ! docker load -i "$ARCHIVE"; then
  case "$ARCHIVE" in
    *.tar.xz) xz -dc "$ARCHIVE" | docker load ;;
    *) echo "❌ docker load 失败"; exit 1 ;;
  esac
fi
echo "  ✓ 镜像已 load"
echo ""

echo "🚀 起服务..."
docker compose -f docker-compose.prod.yml up -d
echo ""
docker image prune -f >/dev/null 2>&1 || true

echo "═══ 完成 ═══"
echo "状态: docker compose -f docker-compose.prod.yml ps"
echo "日志: docker compose -f docker-compose.prod.yml logs -f app idm"
echo ""
echo "⚠️ 首启后立刻登录改 superadmin 密码(seed 默认 superadmin/pwd 是弱凭据)。"
