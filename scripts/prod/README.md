# 生产部署

一键部署脚本在总仓库 **baserust-stack** 的 `scripts/prod/`(前端 + 后端 + nginx 一起打包,离线部署包、
只导出变化的镜像、国内源、数据迁移脚本),用法见那边的 `scripts/prod/README.md`。

本仓库提供被它复用的部分:

| 文件 | 作用 |
|---|---|
| `docker-compose.prod.yml` | 后端生产 compose(纯镜像,无 build);stack 的部署包原样带上它,再叠加前端 |
| `.env.prod` | 生产环境变量**模板**(`CHANGE-ME` 占位);stack 的 `init.sh` 用它生成带随机密码的 `.env.prod` |
| `seed.prod.toml.example` | 首个超管账号模板 |
| `scripts/initdb/00-roles-schemas.sh` | 各 schema 的 role + schema;可重复执行,每次部署都跑一遍补齐 |
| `Dockerfile` | `runtime`(app + idm 二进制)/ `migrate`(sqlx + 迁移)两个镜像;国内源、本地 git 依赖都是可选 build arg |
