#!/bin/bash
# 多租户的 PG 账号拆分(spec §4.4):app / content / search 三个 schema 各拆成三个账号 ——
#
#   <schema>_owner   跑迁移、拥有 schema 与表;BYPASSRLS;运行时不用。  *_DB_OWNER_USER / *_DB_OWNER_PASSWORD
#   <schema>         运行时请求:只有 DML、非 owner、NOBYPASSRLS。   *_DB_USER / *_DB_PASSWORD(00 建)
#   <schema>_system  后台任务 / 平台级跨租户读:BYPASSRLS,单独连接池。 *_DB_SYSTEM_USER / *_DB_SYSTEM_PASSWORD
#
# 运行时账号不是 owner,表上的 FORCE ROW LEVEL SECURITY 才真的约束得住它。idm、ops 不拆。
# owner 给 BYPASSRLS:它只跑迁移,本来就能 ALTER TABLE 关掉 RLS,不给反而让以后「修数据」的迁移
# 在 FORCE RLS 的表上静默改 0 行(没设 app.tenant_id 时策略谁都看不见)。
# 各 schema 的 _sqlx_migrations(迁移台账)只有 owner 能写:运行时 / system 账号只留 SELECT。
#
# **幂等**,两处调用(和 00-roles-schemas.sh 一样,并且总在它之后):
#   1. pg 首次初始化空卷:docker-entrypoint-initdb.d 按文件名顺序以 superuser 执行(00 → 10);
#      这时还没有表,只建账号、把 schema 转给 owner、设好 ALTER DEFAULT PRIVILEGES,之后迁移(owner)建的表自动授权。
#   2. 每次部署 / 升级已有的库(baserust-stack 的 scripts/prod/deploy.sh、本仓库 just db-ensure-roles),
#      **在迁移之前**:旧结构的库里表归运行时账号,这里转给 owner,再给运行时 / system 账号授 DML。
#      已有数据不动。重复执行只会把密码按环境变量重设一遍。
#
# owner / system 账号名缺省 = 运行时账号名加 _owner / _system 后缀;密码必须给(`-u`:少一个当场炸)。
set -eu
# 先把要的变量都检查一遍:缺一个就什么都不做(别拆了 app 才发现 search 的密码没给)。
: "${APP_DB_USER:?}" "${APP_DB_OWNER_PASSWORD:?}" "${APP_DB_SYSTEM_PASSWORD:?}"
: "${CONTENT_DB_USER:?}" "${CONTENT_DB_OWNER_PASSWORD:?}" "${CONTENT_DB_SYSTEM_PASSWORD:?}"
: "${SEARCH_DB_USER:?}" "${SEARCH_DB_OWNER_PASSWORD:?}" "${SEARCH_DB_SYSTEM_PASSWORD:?}"

split() { # $1=schema(= 运行时账号名) $2=owner 名 $3=owner 密码 $4=system 名 $5=system 密码
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v schema="$1" -v rt="$1" -v owner="$2" -v owner_pw="$3" -v sys="$4" -v sys_pw="$5" <<-'EOSQL'
	-- 0) 运行时账号由 00-roles-schemas.sh 建;没有就是顺序错了,当场失败。
	select format('do $x$ begin raise exception %L; end $x$', '运行时账号 ' || :'rt' || ' 不存在:先跑 00-roles-schemas.sh')
	  where not exists (select 1 from pg_roles where rolname = :'rt') \gexec

	-- 1) 账号:owner(迁移、拥有表,BYPASSRLS —— 迁移里的数据修复不能被 FORCE RLS 静默过滤成 0 行)/
	--    system(BYPASSRLS);运行时账号收紧成 NOBYPASSRLS。密码每次按环境变量重设。
	select format('create role %I login password %L', :'owner', :'owner_pw')
	  where not exists (select 1 from pg_roles where rolname = :'owner') \gexec
	select format('alter role %I with login nosuperuser bypassrls password %L', :'owner', :'owner_pw') \gexec
	select format('create role %I login password %L', :'sys', :'sys_pw')
	  where not exists (select 1 from pg_roles where rolname = :'sys') \gexec
	select format('alter role %I with login nosuperuser bypassrls password %L', :'sys', :'sys_pw') \gexec
	select format('alter role %I with nosuperuser nobypassrls', :'rt') \gexec
	select format('alter role %I set search_path to %I', :'owner', :'schema') \gexec
	select format('alter role %I set search_path to %I', :'sys', :'schema') \gexec

	-- 2) schema 归 owner(00 建的时候归运行时账号;老库里也是)。
	select format('create schema if not exists %I authorization %I', :'schema', :'owner') \gexec
	select format('alter schema %I owner to %I', :'schema', :'owner') \gexec

	-- 2b) 迁移台账 _sqlx_migrations 在这里先建好(DDL 与 sqlx 0.8 / 0.9 的 ensure_migrations_table 逐字一致,
	--     sqlx 迁移时 CREATE TABLE IF NOT EXISTS 直接复用)。不先建的话,全新库上它要等迁移时才出现、经
	--     ALTER DEFAULT PRIVILEGES 拿到运行时账号的写权限,要到下次跑本脚本才被收回。
	--     **升级 sqlx 时核对**:新版 sqlx 的 ensure_migrations_table(sqlx-postgres 的 migrate.rs)若改了这张表的
	--     结构,这里要同步改 —— 它的 CREATE TABLE IF NOT EXISTS 会直接复用这里先建好的旧结构,不会替你改表。
	select format('create table if not exists %I._sqlx_migrations (
	    version BIGINT PRIMARY KEY,
	    description TEXT NOT NULL,
	    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
	    success BOOLEAN NOT NULL,
	    checksum BYTEA NOT NULL,
	    execution_time BIGINT NOT NULL
	)', :'schema') \gexec

	-- 3) schema 里的对象全部转给 owner。表连带它的索引、serial / identity 序列一起转;
	--    独立序列、视图、函数、类型单独转。已经归 owner 的跳过(幂等)。
	select format('alter %s %I.%I owner to %I',
	              case c.relkind when 'v' then 'view' when 'm' then 'materialized view'
	                             when 'f' then 'foreign table' when 'S' then 'sequence' else 'table' end,
	              n.nspname, c.relname, :'owner')
	  from pg_class c join pg_namespace n on n.oid = c.relnamespace
	 where n.nspname = :'schema'
	   and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
	   and c.relowner <> (select oid from pg_roles where rolname = :'owner')
	   and not (c.relkind = 'S' and exists (
	         select 1 from pg_depend d
	          where d.classid = 'pg_class'::regclass and d.objid = c.oid and d.deptype in ('a', 'i')))
	 order by c.relkind = 'S', c.oid \gexec
	select format('alter routine %s owner to %I', p.oid::regprocedure, :'owner')
	  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
	 where n.nspname = :'schema' and p.prokind in ('f', 'p')
	   and p.proowner <> (select oid from pg_roles where rolname = :'owner') \gexec
	select format('alter %s %s owner to %I', case t.typtype when 'd' then 'domain' else 'type' end,
	              t.oid::regtype, :'owner')
	  from pg_type t join pg_namespace n on n.oid = t.typnamespace
	 where n.nspname = :'schema' and t.typtype in ('e', 'd', 'r', 'c')
	   and (t.typtype <> 'c' or (select c.relkind from pg_class c where c.oid = t.typrelid) = 'c')
	   and t.typowner <> (select oid from pg_roles where rolname = :'owner') \gexec

	-- 4) 运行时 / system 账号:只有 DML(不能建表、不能 truncate);owner 以后建的表自动授同样的权限。
	select format('grant usage on schema %I to %I, %I', :'schema', :'rt', :'sys') \gexec
	select format('revoke create on schema %I from %I, %I', :'schema', :'rt', :'sys') \gexec
	select format('grant select, insert, update, delete on all tables in schema %I to %I, %I', :'schema', :'rt', :'sys') \gexec
	select format('revoke truncate, references, trigger on all tables in schema %I from %I, %I', :'schema', :'rt', :'sys') \gexec
	select format('grant usage, select on all sequences in schema %I to %I, %I', :'schema', :'rt', :'sys') \gexec
	select format('alter default privileges for role %I in schema %I grant select, insert, update, delete on tables to %I, %I',
	              :'owner', :'schema', :'rt', :'sys') \gexec
	select format('alter default privileges for role %I in schema %I grant usage, select on sequences to %I, %I',
	              :'owner', :'schema', :'rt', :'sys') \gexec

	-- 5) 迁移台账只有 owner 能写:运行时 / system 账号对 _sqlx_migrations 只留 SELECT(第 4 步按「全部表」授过 DML)。
	select format('revoke insert, update, delete on %I._sqlx_migrations from %I, %I', :'schema', :'rt', :'sys') \gexec

	-- 6) 只许 system 账号写的全局读模型(运行时账号只读;第 4 步按「全部表」授过 DML,这里收回):
	--    search.account_index(账号目录投影,投影器 / rebuild_search 用 search_system 写)、
	--    search.auth_event(平台级认证审计,投影器 / 清理任务用 search_system 写)。表不在(老库 / 别的 schema)就跳过。
	select format('revoke insert, update, delete on %I.%I from %I', n.nspname, c.relname, :'rt')
	  from pg_class c join pg_namespace n on n.oid = c.relnamespace
	 where n.nspname = :'schema' and (n.nspname, c.relname) in (('search', 'account_index'), ('search', 'auth_event')) \gexec
EOSQL
}

split "${APP_DB_USER}" "${APP_DB_OWNER_USER:-${APP_DB_USER}_owner}" "${APP_DB_OWNER_PASSWORD}" \
  "${APP_DB_SYSTEM_USER:-${APP_DB_USER}_system}" "${APP_DB_SYSTEM_PASSWORD}"
split "${CONTENT_DB_USER}" "${CONTENT_DB_OWNER_USER:-${CONTENT_DB_USER}_owner}" "${CONTENT_DB_OWNER_PASSWORD}" \
  "${CONTENT_DB_SYSTEM_USER:-${CONTENT_DB_USER}_system}" "${CONTENT_DB_SYSTEM_PASSWORD}"
split "${SEARCH_DB_USER}" "${SEARCH_DB_OWNER_USER:-${SEARCH_DB_USER}_owner}" "${SEARCH_DB_OWNER_PASSWORD}" \
  "${SEARCH_DB_SYSTEM_USER:-${SEARCH_DB_USER}_system}" "${SEARCH_DB_SYSTEM_PASSWORD}"
echo "账号拆分就绪(owner / 运行时 / system):${APP_DB_USER} ${CONTENT_DB_USER} ${SEARCH_DB_USER}"
