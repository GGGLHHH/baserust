#!/usr/bin/env bash
# scripts/initdb/10-tenancy-roles.sh 的回归测试(在真 PG 上跑两遍脚本,查授权结果)。
#
# 要一个能建库、建账号的 PG 超级用户。会建临时库 roles_verify / roles_verify_old 和 rv_* 账号,结束时(含失败)删掉;
# 不碰别的库和账号。连接走 libpq 的环境变量:
#   PGHOST=127.0.0.1 PGPORT=5821 PGUSER=baserust PGPASSWORD=baserust bash scripts/tests/tenancy-roles.test.sh
# 本机没有 psql:在 postgres 镜像里跑,挂到 pg 容器的网络上(容器里连 127.0.0.1:5432):
#   docker run --rm --network container:<pg 容器> -v "$PWD:/w" -w /w \
#     -e PGHOST=127.0.0.1 -e PGUSER=baserust -e PGPASSWORD=baserust postgres:17-alpine bash scripts/tests/tenancy-roles.test.sh
#
# 覆盖:
#   1. 全新库:跑两遍,中间项目迁移(owner)收紧了某表的权限 → 第二遍之后仍是收紧的(脚本不按「全部表」重授 DML)。
#   2. search 的 schema 名是 SEARCH_DB_USER(这里故意不叫 search):account_index / auth_event 的写权限照样收回;
#      别的 schema 里同名的表不受影响。
#   3. 老库(多租户之前:表、序列、迁移台账都归运行时账号)跑一遍:全部转给 owner,运行时 / system 账号拿到 DML、
#      序列 usage,迁移台账只读,数据不动;之后再收紧、再跑,仍是收紧的。
#   4. 老库第一次拆分在「第 3 步转完属主、第 4 步授权之前」失败(事件触发器拦下第一条 GRANT):每个 schema 是一个
#      事务,整段回滚(表、schema 仍归运行时账号);去掉故障再跑一遍,运行时账号照样拿到老表的 DML(上面第 3 条)。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INITDB="${INITDB_DIR:-$HERE/../initdb}"
: "${PGUSER:?要 PG 超级用户(PGUSER / PGPASSWORD / PGHOST / PGPORT)}"

export POSTGRES_USER="$PGUSER"
export APP_DB_USER=rv_app APP_DB_PASSWORD=pwd IDM_DB_USER=rv_idm IDM_DB_PASSWORD=pwd
export CONTENT_DB_USER=rv_content CONTENT_DB_PASSWORD=pwd OPS_DB_USER=rv_ops OPS_DB_PASSWORD=pwd
export SEARCH_DB_USER=rv_srch SEARCH_DB_PASSWORD=pwd   # search 的 schema 名可配:故意不叫 search
export APP_DB_OWNER_PASSWORD=pwd APP_DB_SYSTEM_PASSWORD=pwd CONTENT_DB_OWNER_PASSWORD=pwd
export CONTENT_DB_SYSTEM_PASSWORD=pwd SEARCH_DB_OWNER_PASSWORD=pwd SEARCH_DB_SYSTEM_PASSWORD=pwd
DBS=(roles_verify roles_verify_old)
ROLES=(rv_app rv_app_owner rv_app_system rv_idm rv_content rv_content_owner rv_content_system
       rv_srch rv_srch_owner rv_srch_system rv_ops)

LOG="$(mktemp)"
psql_q() { psql -X -v ON_ERROR_STOP=1 -qAt "$@"; }
cleanup() {
  for db in "${DBS[@]}"; do psql_q -d postgres -c "drop database if exists $db with (force)" 2>/dev/null || true; done
  for r in "${ROLES[@]}"; do psql_q -d postgres -c "drop role if exists $r" 2>/dev/null || true; done
  rm -f "$LOG"
}
trap cleanup EXIT
cleanup; LOG="$(mktemp)"

fails=0
check() { # $1=说明 $2=期望 $3=实际
  if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1:期望 $2,实际 $3"; fails=$((fails + 1)); fi
}
q() { psql_q -d "$1" -c "$2"; }               # 超级用户查一个值
priv() { q "$1" "select has_table_privilege('$2', '$3', '$4')"; }
run() { # $1=库 $2..=要跑的脚本(00 / 10)
  local db="$1"; shift
  for s in "$@"; do
    POSTGRES_DB="$db" bash "$INITDB/$s" >>"$LOG" 2>&1 || { cat "$LOG"; echo "FAIL $s 在 $db 上失败"; exit 1; }
  done
}

echo "▶ 全新库:建账号 → owner 建表(相当于迁移)→ 再跑一遍"
q postgres "create database roles_verify"
run roles_verify 00-roles-schemas.sh 10-tenancy-roles.sh
q roles_verify "set role rv_app_owner;
  create table rv_app.widgets (id serial primary key, name text);
  create table rv_app.account_index (id int);
  set role rv_srch_owner;
  create table rv_srch.account_index (id int);
  create table rv_srch.auth_event (id int);
  create table rv_srch.admin_user_index (id int);"
check "新表经 default privileges 给运行时账号 INSERT" t "$(priv roles_verify rv_app rv_app.widgets INSERT)"
run roles_verify 00-roles-schemas.sh 10-tenancy-roles.sh
check "运行时账号对 widgets 有 INSERT" t "$(priv roles_verify rv_app rv_app.widgets INSERT)"
check "运行时账号能用 widgets 的序列" t "$(q roles_verify "select has_sequence_privilege('rv_app', 'rv_app.widgets_id_seq', 'USAGE')")"
check "search 运行时账号对 account_index 没有 INSERT(schema 名 = SEARCH_DB_USER)" f "$(priv roles_verify rv_srch rv_srch.account_index INSERT)"
check "search 运行时账号对 account_index 有 SELECT" t "$(priv roles_verify rv_srch rv_srch.account_index SELECT)"
check "search 运行时账号对 auth_event 没有 UPDATE" f "$(priv roles_verify rv_srch rv_srch.auth_event UPDATE)"
check "search 运行时账号对 admin_user_index 有 INSERT" t "$(priv roles_verify rv_srch rv_srch.admin_user_index INSERT)"
check "search system 账号对 account_index 有 INSERT" t "$(priv roles_verify rv_srch_system rv_srch.account_index INSERT)"
check "app schema 里同名的 account_index 不受影响" t "$(priv roles_verify rv_app rv_app.account_index INSERT)"
check "迁移台账运行时账号只读(INSERT)" f "$(priv roles_verify rv_app rv_app._sqlx_migrations INSERT)"
check "迁移台账运行时账号只读(SELECT)" t "$(priv roles_verify rv_app rv_app._sqlx_migrations SELECT)"
check "迁移台账归 owner" rv_app_owner "$(q roles_verify "select tableowner from pg_tables where schemaname = 'rv_app' and tablename = '_sqlx_migrations'")"

echo "▶ 全新库:项目迁移收紧 widgets(revoke insert)→ 再跑一遍"
q roles_verify "set role rv_app_owner; revoke insert on rv_app.widgets from rv_app;"
run roles_verify 00-roles-schemas.sh 10-tenancy-roles.sh
check "收紧的 INSERT 没被还原" f "$(priv roles_verify rv_app rv_app.widgets INSERT)"
check "没收紧的 SELECT 还在" t "$(priv roles_verify rv_app rv_app.widgets SELECT)"
check "system 账号不受影响" t "$(priv roles_verify rv_app_system rv_app.widgets INSERT)"

echo "▶ 老库:表 / 序列 / 迁移台账归运行时账号(多租户之前的结构)→ 跑一遍"
q postgres "create database roles_verify_old"
run roles_verify_old 00-roles-schemas.sh
q roles_verify_old "set role rv_app;
  create table rv_app._sqlx_migrations (version bigint primary key, description text not null,
    installed_on timestamptz not null default now(), success boolean not null, checksum bytea not null,
    execution_time bigint not null);
  create table rv_app.widgets (id serial primary key, name text);
  insert into rv_app.widgets (name) values ('old');
  create sequence rv_app.standalone_seq;
  create view rv_app.widget_names as select name from rv_app.widgets;
  set role rv_content;
  create table rv_content.content (id int);
  set role rv_srch;
  create table rv_srch.account_index (id int);
  create table rv_srch.auth_event (id int);"
echo "▶ 老库:第一次拆分在转属主之后、授权之前失败 → 整段回滚"
q roles_verify_old "create function public.rv_fail_grant() returns event_trigger language plpgsql
    as \$f\$ begin raise exception 'rv: 注入的失败(第 4 步第一条 GRANT)'; end \$f\$;
  create event trigger rv_fail_grant on ddl_command_start when tag in ('GRANT') execute function public.rv_fail_grant();"
if POSTGRES_DB=roles_verify_old bash "$INITDB/10-tenancy-roles.sh" >>"$LOG" 2>&1; then failed=no; else failed=yes; fi
check "注入故障时脚本失败" yes "$failed"
check "失败的确是注入的那个(第 4 步)" yes "$(grep -q 'rv: 注入的失败' "$LOG" && echo yes || echo no)"
check "回滚:widgets 仍归运行时账号" rv_app "$(q roles_verify_old "select tableowner from pg_tables where schemaname = 'rv_app' and tablename = 'widgets'")"
check "回滚:serial 序列仍归运行时账号" rv_app "$(q roles_verify_old "select pg_get_userbyid(relowner) from pg_class where oid = 'rv_app.widgets_id_seq'::regclass")"
check "回滚:迁移台账仍归运行时账号" rv_app "$(q roles_verify_old "select tableowner from pg_tables where schemaname = 'rv_app' and tablename = '_sqlx_migrations'")"
check "回滚:schema 仍归运行时账号" rv_app "$(q roles_verify_old "select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'rv_app'")"
q roles_verify_old "drop event trigger rv_fail_grant; drop function public.rv_fail_grant();"

echo "▶ 老库:去掉故障后正常跑一遍"
run roles_verify_old 00-roles-schemas.sh 10-tenancy-roles.sh
check "widgets 转给 owner" rv_app_owner "$(q roles_verify_old "select tableowner from pg_tables where schemaname = 'rv_app' and tablename = 'widgets'")"
check "serial 序列跟着转" rv_app_owner "$(q roles_verify_old "select pg_get_userbyid(relowner) from pg_class where oid = 'rv_app.widgets_id_seq'::regclass")"
check "独立序列转给 owner" rv_app_owner "$(q roles_verify_old "select pg_get_userbyid(relowner) from pg_class where oid = 'rv_app.standalone_seq'::regclass")"
check "视图转给 owner" rv_app_owner "$(q roles_verify_old "select viewowner from pg_views where schemaname = 'rv_app' and viewname = 'widget_names'")"
check "schema 转给 owner" rv_app_owner "$(q roles_verify_old "select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'rv_app'")"
for p in SELECT INSERT UPDATE DELETE; do
  check "运行时账号对 widgets 有 $p" t "$(priv roles_verify_old rv_app rv_app.widgets "$p")"
  check "system 账号对 widgets 有 $p" t "$(priv roles_verify_old rv_app_system rv_app.widgets "$p")"
done
check "运行时账号没有 TRUNCATE" f "$(priv roles_verify_old rv_app rv_app.widgets TRUNCATE)"
check "运行时账号能读视图" t "$(priv roles_verify_old rv_app rv_app.widget_names SELECT)"
check "运行时账号能用 serial 序列" t "$(q roles_verify_old "select has_sequence_privilege('rv_app', 'rv_app.widgets_id_seq', 'USAGE')")"
check "运行时账号能用独立序列" t "$(q roles_verify_old "select has_sequence_privilege('rv_app', 'rv_app.standalone_seq', 'USAGE')")"
check "运行时账号读得到旧数据" 1 "$(q roles_verify_old "set role rv_app; select count(*) from rv_app.widgets")"
check "运行时账号写得进去" 1 "$(q roles_verify_old "set role rv_app; with i as (insert into rv_app.widgets (name) values ('new') returning 1) select count(*) from i")"
check "迁移台账转给 owner" rv_app_owner "$(q roles_verify_old "select tableowner from pg_tables where schemaname = 'rv_app' and tablename = '_sqlx_migrations'")"
check "迁移台账运行时账号只读" f "$(priv roles_verify_old rv_app rv_app._sqlx_migrations INSERT)"
check "content 运行时账号有 INSERT" t "$(priv roles_verify_old rv_content rv_content.content INSERT)"
check "search 运行时账号对 account_index 没有 INSERT" f "$(priv roles_verify_old rv_srch rv_srch.account_index INSERT)"
check "search 运行时账号对 account_index 有 SELECT" t "$(priv roles_verify_old rv_srch rv_srch.account_index SELECT)"
check "search system 账号对 auth_event 有 INSERT" t "$(priv roles_verify_old rv_srch_system rv_srch.auth_event INSERT)"
check "运行时账号 NOBYPASSRLS" f "$(q roles_verify_old "select rolbypassrls from pg_roles where rolname = 'rv_app'")"
check "owner BYPASSRLS" t "$(q roles_verify_old "select rolbypassrls from pg_roles where rolname = 'rv_app_owner'")"

echo "▶ 老库升级之后:收紧 → 再跑一遍"
q roles_verify_old "set role rv_app_owner; revoke insert, delete on rv_app.widgets from rv_app;"
run roles_verify_old 00-roles-schemas.sh 10-tenancy-roles.sh
check "收紧的 INSERT 没被还原" f "$(priv roles_verify_old rv_app rv_app.widgets INSERT)"
check "收紧的 DELETE 没被还原" f "$(priv roles_verify_old rv_app rv_app.widgets DELETE)"
check "UPDATE 还在" t "$(priv roles_verify_old rv_app rv_app.widgets UPDATE)"

echo
if [ "$fails" -gt 0 ]; then echo "❌ $fails 项不通过"; exit 1; fi
echo "✅ 全部通过"
