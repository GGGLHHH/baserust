#!/bin/sh
# 给**已经初始化过的** pg 卷补建 ops role + schema(initdb 只在空卷首次启动时跑,老卷不会自动补)。
# 幂等:role / schema 已存在就跳过。以 pg 超级用户身份执行,用法见 justfile 的 `ops-db-init`。
set -eu
: "${OPS_DB_USER:=ops}"
: "${OPS_DB_PASSWORD:=pwd}"
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-baserust}" --dbname "${POSTGRES_DB:-baserust}" <<EOSQL
do \$\$
begin
  if not exists (select 1 from pg_roles where rolname = '${OPS_DB_USER}') then
    create role ${OPS_DB_USER} login password '${OPS_DB_PASSWORD}';
  end if;
end
\$\$;
create schema if not exists ${OPS_DB_USER} authorization ${OPS_DB_USER};
alter role ${OPS_DB_USER} set search_path to ${OPS_DB_USER};
EOSQL
echo "ops role/schema 就绪"
