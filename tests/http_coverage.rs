//! **黑盒验收覆盖率守卫**:OpenAPI 里的每个接口(method + path),都必须出现在某个 `tests/http_*.rs`
//! 文件头的 `//! covers: METHOD /path` 清单里;清单里写的也必须是真实存在的接口(防过期)。
//!
//! 意义:黑盒测试是换 web 底座(或任何 HTTP 层重构)时的验收标准 —— 加了新接口却没写黑盒测试,
//! 这道门就会红。清单是测试作者的声明(不是运行时统计),评审时看对应测试是否真的打到了它。

use std::collections::BTreeSet;
use std::path::Path;

const METHODS: [&str; 5] = ["get", "post", "put", "delete", "patch"];

fn spec_operations() -> BTreeSet<String> {
    let spec = serde_json::to_value(baserust::app::router::api_spec()).unwrap();
    let mut ops = BTreeSet::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        for m in METHODS {
            if item.get(m).is_some() {
                ops.insert(format!("{} {path}", m.to_uppercase()));
            }
        }
    }
    ops
}

/// 各 http_*.rs 声明的覆盖清单:(接口, 声明它的文件)。
fn declared() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !(name.starts_with("http_") && name.ends_with(".rs")) || name == "http_coverage.rs" {
            continue;
        }
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            if let Some(op) = line.trim().strip_prefix("//! covers:") {
                out.push((op.trim().to_owned(), name.clone()));
            }
        }
    }
    out
}

#[test]
fn every_operation_has_a_black_box_test() {
    let spec = spec_operations();
    let declared = declared();
    let covered: BTreeSet<String> = declared.iter().map(|(op, _)| op.clone()).collect();

    let missing: Vec<_> = spec.difference(&covered).collect();
    let stale: Vec<_> = declared
        .iter()
        .filter(|(op, _)| !spec.contains(op))
        .map(|(op, f)| format!("{op}({f})"))
        .collect();

    assert!(
        spec.len() >= 50,
        "只从规范里取到 {} 个接口 —— 取法坏了?",
        spec.len()
    );
    assert!(
        missing.is_empty(),
        "这些接口没有黑盒测试(在某个 tests/http_*.rs 写测试,并在文件头加 `//! covers: METHOD /path`):\n{}",
        missing.iter().map(|s| format!("  {s}")).collect::<Vec<_>>().join("\n")
    );
    assert!(
        stale.is_empty(),
        "covers 清单里有规范中不存在的接口(改名 / 删了?):\n  {}",
        stale.join("\n  ")
    );
}
