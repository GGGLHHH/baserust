# 生产部署(离线 tar 包)

无 registry、服务器不碰源码的一键部署:本机 build + 打包 → scp → 服务器 load + up。

## 本机(打包)

```bash
./scripts/prod/build-and-export.sh          # 构建 + 打包到 prod/
./scripts/prod/build-and-export.sh -f       # 强制无缓存重建
./scripts/prod/build-and-export.sh -n        # 不压缩(快,包大)
TARGET_PLATFORM=linux/arm64 ./scripts/prod/build-and-export.sh   # 改目标架构
```

产出 `prod/`:

| 文件 | 是什么 |
|---|---|
| `baserust_images_<ts>.tar.xz` | runtime(app+idm) + migrate 两镜像 |
| `docker-compose.prod.yml` | 纯镜像消费 compose(无 build) |
| `.env` | 由 `.env.prod` 生成 —— **改所有 CHANGE-ME** |
| `nginx.conf` | 反代分流(auth→idm / 其余→app) |
| `keys/prod-ed25519.{pem,pub.pem}` | 生产 JWT 密钥(私钥,`.gitignore` 挡着不入库) |
| `scripts/initdb/` | pg 首启建 role/schema |
| `import-images.sh` | 服务器部署脚本 |

## 服务器(部署)

```bash
scp -r prod/ user@server:/opt/baserust      # 私钥在包里,scp 加密通道
ssh user@server
cd /opt/baserust/prod
vim .env                                     # 改 CHANGE-ME(DB/minio 密码、CORS 域)
./import-images.sh                           # load 镜像 + compose up -d
```

## 拓扑

```
                    ┌─ nginx:80 (SSL 由外层 LB/面板终止)
   浏览器 ─HTTPS→ LB ─┤
                    └→ /api/v1/{public,frontend,admin}/auth/ → idm 进程(私钥签发)
                       /api/*                                → app 进程(公钥验签)
   app / idm → pg(app/idm/content 三 schema role 隔离) + minio(字节) + nats(事件)
```

- **非对称 JWT**:idm 持私钥签、app 只持公钥验 —— app 被攻破铸不出 token。密钥打包时生成、随包带。
- **数据**:`prod/data/{postgres,minio}` 绑定挂载,备份 = tar 这个目录。

## 上线必做

1. `.env` 全部 CHANGE-ME 改成真密码 / 真前端域
2. 外层 LB 配 HTTPS(prod cookie 带 Secure,HTTP 下浏览器不回传)
3. 首启后立刻登录改 `superadmin` 密码(seed 默认 `superadmin/pwd` 是弱凭据),或部署前 `SEED_FILE` 挂自定义账号
4. `prod/keys/prod-ed25519.pem` 权限 600,别泄露

## 常用

```bash
docker compose -f docker-compose.prod.yml ps          # 状态
docker compose -f docker-compose.prod.yml logs -f app idm
docker compose -f docker-compose.prod.yml down         # 停(留数据)
docker compose -f docker-compose.prod.yml down -v      # 停 + 删卷(慎:清数据)
```
