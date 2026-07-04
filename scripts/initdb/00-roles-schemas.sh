#!/bin/bash
# 多 schema 隔离:role 名 = schema 名,role 的 search_path 指向同名 schema。
# 连该 role 即默认操作对应 schema(代码/迁移都不写 schema 前缀),权限天然隔离。
# role 名与密码都从环境变量读 —— 每个 schema 一对独立变量(密码暂时都是 pwd)。
# 由 pg 首次初始化空卷时执行(superuser 身份);改了要 `docker compose down -v` 重建卷才生效。
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  create role ${APP_DB_USER} login password '${APP_DB_PASSWORD}';
  create schema ${APP_DB_USER} authorization ${APP_DB_USER};
  alter role ${APP_DB_USER} set search_path to ${APP_DB_USER};

  create role ${IDM_DB_USER} login password '${IDM_DB_PASSWORD}';
  create schema ${IDM_DB_USER} authorization ${IDM_DB_USER};
  alter role ${IDM_DB_USER} set search_path to ${IDM_DB_USER};

  create role ${CONTENT_DB_USER} login password '${CONTENT_DB_PASSWORD}';
  create schema ${CONTENT_DB_USER} authorization ${CONTENT_DB_USER};
  alter role ${CONTENT_DB_USER} set search_path to ${CONTENT_DB_USER};
EOSQL
