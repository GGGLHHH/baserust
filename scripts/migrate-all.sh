#!/bin/sh
# migrate 容器入口:按 schema 迁移,各 schema 各自独立的 _sqlx_migrations(连接账号的 search_path 落到该 schema)。
# app / content / search 拆了账号(spec §4.4):迁移用 **<schema>_owner**(拥有表;运行时账号只有 DML、建不了表);
# idm / ops 不拆,仍用同名 role。只有 .gitkeep 的空 schema 自动跳过。账号名 / 密码由 compose 注入
# (owner 账号名缺省 = 运行时账号名 + _owner,和 scripts/initdb/10-tenancy-roles.sh 同一套缺省)。
# ponytail: 显式列 schema,加新 schema 加一行;回滚/查看用本地 `just migrate-<schema>-revert`。
set -eu
host="${PG_HOST:-pg}"
port="${PG_PORT:-5432}"
db="${POSTGRES_DB:-baserust}"

migrate_schema() { # $1=schema目录 $2=role $3=password
  if ! ls "migrations/$1"/*.sql >/dev/null 2>&1; then
    echo "schema '$1': 无迁移,跳过"
    return
  fi
  echo "schema '$1': 以 role '$2' 迁移"
  sqlx migrate run --source "migrations/$1" \
    --database-url "postgres://$2:$3@$host:$port/$db?sslmode=disable"
}

migrate_schema app "${APP_DB_OWNER_USER:-${APP_DB_USER:-app}_owner}" "${APP_DB_OWNER_PASSWORD:-pwd}"
migrate_schema idm "${IDM_DB_USER:-idm}" "${IDM_DB_PASSWORD:-pwd}"
migrate_schema content "${CONTENT_DB_OWNER_USER:-${CONTENT_DB_USER:-content}_owner}" "${CONTENT_DB_OWNER_PASSWORD:-pwd}"
migrate_schema search "${SEARCH_DB_OWNER_USER:-${SEARCH_DB_USER:-search}_owner}" "${SEARCH_DB_OWNER_PASSWORD:-pwd}"
migrate_schema ops "${OPS_DB_USER:-ops}" "${OPS_DB_PASSWORD:-pwd}"
