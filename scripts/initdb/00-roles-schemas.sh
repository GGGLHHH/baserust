#!/bin/bash
# 多 schema 隔离:role 名 = schema 名,role 的 search_path 指向同名 schema。
# 连该 role 即默认操作对应 schema(代码/迁移都不写 schema 前缀),权限天然隔离。
# role 名与密码都从环境变量读 —— 每个 schema 一对独立变量。
#
# 这里建的是**运行时账号**。app / content / search 随后由 10-tenancy-roles.sh 拆成 owner / 运行时 / system
# 三个账号(schema 和表转给 <schema>_owner,运行时账号只留 DML);idm、ops 不拆,这里建的 role 就是 owner。
# 本脚本只在 schema 不存在时才以运行时账号建它,不会把已转给 owner 的 schema 改回来。
#
# 两处调用,所以必须**可重复执行**(已有的跳过,密码按环境变量重设):
#   1. pg 首次初始化空卷时,docker-entrypoint-initdb.d 以 superuser 执行;
#   2. 每次部署(baserust-stack 的 scripts/prod/deploy.sh、本仓库 just db-ensure-roles)对**已有的卷**再跑一遍(之后跑 10)
#      —— initdb 只在空卷跑一次,后来新加的 schema(如 ops)靠这一步补上,不用重建卷。
# `-u`:少一个 *_DB_USER/PASSWORD 就当场炸,不留半初始化的状态。
set -eu

ensure() { # $1=role(= schema 名) $2=password
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v role="$1" -v pw="$2" <<-'EOSQL'
	select format('create role %I login password %L', :'role', :'pw')
	  where not exists (select 1 from pg_roles where rolname = :'role') \gexec
	select format('alter role %I with login password %L', :'role', :'pw') \gexec
	select format('create schema if not exists %I authorization %I', :'role', :'role') \gexec
	select format('alter role %I set search_path to %I', :'role', :'role') \gexec
EOSQL
}

ensure "${APP_DB_USER}" "${APP_DB_PASSWORD}"
ensure "${IDM_DB_USER}" "${IDM_DB_PASSWORD}"
ensure "${CONTENT_DB_USER}" "${CONTENT_DB_PASSWORD}"
ensure "${SEARCH_DB_USER}" "${SEARCH_DB_PASSWORD}"
ensure "${OPS_DB_USER}" "${OPS_DB_PASSWORD}"
echo "roles/schemas 就绪:${APP_DB_USER} ${IDM_DB_USER} ${CONTENT_DB_USER} ${SEARCH_DB_USER} ${OPS_DB_USER}"
