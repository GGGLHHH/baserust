#!/bin/sh
# migrate 容器入口:按 schema 迁移,每个 schema 用**同名 role** 连接
# (role 的 search_path 落到自己 schema,_sqlx_migrations 也各自独立 → 互不冲突)。
# 只有 .gitkeep 的空 schema 自动跳过。role 名/密码由 compose 注入。
# ponytail: 显式列 schema,加新 schema 加一行;回滚/查看用本地 `just migrate-<schema>-revert`。
set -eu
host="${PG_HOST:-pg}"
port="${PG_PORT:-5432}"
db="${POSTGRES_DB:-xchangeai}"

migrate_schema() { # $1=schema目录 $2=role $3=password
  if ! ls "migrations/$1"/*.sql >/dev/null 2>&1; then
    echo "schema '$1': 无迁移,跳过"
    return
  fi
  echo "schema '$1': 以 role '$2' 迁移"
  sqlx migrate run --source "migrations/$1" \
    --database-url "postgres://$2:$3@$host:$port/$db?sslmode=disable"
}

migrate_schema app "${APP_DB_USER:-app}" "${APP_DB_PASSWORD:-pwd}"
migrate_schema idm "${IDM_DB_USER:-idm}" "${IDM_DB_PASSWORD:-pwd}"
migrate_schema content "${CONTENT_DB_USER:-content}" "${CONTENT_DB_PASSWORD:-pwd}"
