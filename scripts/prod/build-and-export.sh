#!/usr/bin/env bash
# 本机构建生产镜像 + 打包成离线部署包(照 go-tw 形态)。
# 产出 prod/ 目录:镜像 tar + compose + .env + nginx.conf + prod 密钥 + initdb + import 脚本。
# 用法:./scripts/prod/build-and-export.sh [-f] [-n]
#   -f  强制无缓存重建(--no-cache)
#   -n  不压缩,导出 .tar(默认 .tar.xz)
# 平台:默认 linux/amd64(多数服务器);override: TARGET_PLATFORM=linux/arm64 ./...
set -euo pipefail

FORCE_BUILD=false
NO_COMPRESS=false
while getopts "fn" opt; do
  case $opt in
    f) FORCE_BUILD=true ;;
    n) NO_COMPRESS=true ;;
    *) echo "用法: $0 [-f 无缓存] [-n 不压缩]"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROD_DIR="$ROOT/prod"
PLATFORM="${TARGET_PLATFORM:-linux/amd64}"
TS=$(date +%Y%m%d_%H%M%S)
RUNTIME_IMG="baserust-runtime:latest"
MIGRATE_IMG="baserust-migrate:latest"
if [ "$NO_COMPRESS" = true ]; then
  ARCHIVE="$PROD_DIR/baserust_images_${TS}.tar"
else
  ARCHIVE="$PROD_DIR/baserust_images_${TS}.tar.xz"
fi

cd "$ROOT"

if [ "$NO_COMPRESS" = false ] && ! command -v xz >/dev/null 2>&1; then
  echo "❌ 需要 xz(或用 -n 出非压缩 tar)"; exit 1
fi

echo "═══ baserust 生产打包 ═══"
echo "平台: $PLATFORM  |  压缩: $([ "$NO_COMPRESS" = true ] && echo 无 || echo xz)  |  缓存: $([ "$FORCE_BUILD" = true ] && echo 无 || echo 用)"
echo ""

# ── 1/4 生产 JWT 密钥(缺则生成;私钥永不入库,只进本包)──
echo "🔑 1/4 生产 Ed25519 密钥..."
if [ ! -f "$ROOT/keys/prod-ed25519.pem" ]; then
  openssl genpkey -algorithm ed25519 -out "$ROOT/keys/prod-ed25519.pem"
  openssl pkey -in "$ROOT/keys/prod-ed25519.pem" -pubout -out "$ROOT/keys/prod-ed25519.pub.pem"
  echo "  ✓ 已生成 keys/prod-ed25519.{pem,pub.pem}(.gitignore 已挡,不会入库)"
else
  echo "  ✓ 复用已存在的 keys/prod-ed25519.*"
fi
echo ""

# ── 2/4 构建镜像(runtime = app+idm 二进制;migrate = sqlx+迁移)──
BUILD_FLAGS=""
[ "$FORCE_BUILD" = true ] && BUILD_FLAGS="--no-cache"
echo "📦 2/4 构建镜像($PLATFORM)..."
docker build --platform "$PLATFORM" $BUILD_FLAGS --target runtime -t "$RUNTIME_IMG" .
docker build --platform "$PLATFORM" $BUILD_FLAGS --target migrate -t "$MIGRATE_IMG" .
echo "  ✓ $RUNTIME_IMG + $MIGRATE_IMG"
echo ""

# ── 3/4 导出镜像 ──
echo "💾 3/4 导出镜像 → $(basename "$ARCHIVE")..."
mkdir -p "$PROD_DIR"
# 保留 data/(服务器数据),清其余旧包内容
find "$PROD_DIR" -mindepth 1 -maxdepth 1 ! -name 'data' -exec rm -rf {} + 2>/dev/null || true
if [ "$NO_COMPRESS" = true ]; then
  docker save "$RUNTIME_IMG" "$MIGRATE_IMG" > "$ARCHIVE"
else
  docker save "$RUNTIME_IMG" "$MIGRATE_IMG" | xz "${XZ_PRESET:--6}" -c > "$ARCHIVE"
fi
du -h "$ARCHIVE" | awk '{print "  ✓ 包大小:", $1}'
echo ""

# ── 4/4 拢齐部署包 ──
echo "📁 4/4 拢齐部署文件..."
cp docker-compose.prod.yml "$PROD_DIR/"
cp .env.prod "$PROD_DIR/.env"
cp nginx.conf "$PROD_DIR/"
mkdir -p "$PROD_DIR/keys" "$PROD_DIR/scripts"
cp keys/prod-ed25519.pem keys/prod-ed25519.pub.pem "$PROD_DIR/keys/"
chmod 600 "$PROD_DIR/keys/prod-ed25519.pem"
cp -r scripts/initdb "$PROD_DIR/scripts/"
cp scripts/prod/import-images.sh "$PROD_DIR/"
chmod +x "$PROD_DIR/import-images.sh"
echo "  ✓ docker-compose.prod.yml · .env · nginx.conf · keys/ · scripts/initdb · import-images.sh"
echo ""

echo "═══ 完成 ═══"
echo "部署包: $PROD_DIR"
echo ""
echo "下一步:"
echo "  1. 改 prod/.env 里所有 CHANGE-ME(DB/minio 密码、CORS 域)"
echo "  2. scp -r $PROD_DIR user@server:/opt/baserust"
echo "  3. 服务器上:cd /opt/baserust/prod && ./import-images.sh"
echo ""
echo "⚠️ prod/keys/prod-ed25519.pem 是私钥,scp 用加密通道;上线后立刻改 superadmin 密码。"
