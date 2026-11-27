//! **OpenAPI 规范快照**:整份规范(路径、参数、schema、权限 security、描述)存成快照
//! `tests/snapshots/openapi_snapshot__openapi.snap`。它就是前端 `pnpm generate` 生成类型的契约 ——
//! 任何接口变化(哪怕只是重构时误改了 DTO 字段名 / 可选性 / 枚举值)都会让本测试变红。
//!
//! 有意改了接口:`cargo insta review`(装了 cargo-insta)逐处审过再接受,
//! 或 `just openapi-snapshot-accept`(= `INSTA_UPDATE=always cargo test --test openapi_snapshot`)直接接受;
//! 然后把 .snap 的 diff 跟代码一起提交,评审时一眼看到接口变了什么。

use baserust::app::router;

#[test]
fn openapi_spec_snapshot() {
    let spec = serde_json::to_value(router::api_spec()).expect("规范可序列化");
    insta::assert_json_snapshot!("openapi", spec);
}
