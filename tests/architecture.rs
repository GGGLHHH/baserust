//! **六边形架构的依赖规则**(端口与适配器):核心不依赖框架、数据库、HTTP;依赖只向内指。
//!
//! 核心是独立 crate `baserust-core`(`crates/core`):共享内核 + 各业务模块的领域模型 / 端口 / 用例 +
//! 纯 Rust 的内存适配器。**主要防线是编译器** —— 核心的 `Cargo.toml` 里没有 axum / sqlx / … ,
//! 核心代码想用也 import 不到。本测试守编译器管不到的三条:
//! 1. 核心的依赖清单不许加回框架 / 数据库 / HTTP / 消息 / 对象存储 / JWT 依赖([`FORBIDDEN_PACKAGES`]);
//! 2. 核心里的业务模块之间不许直接 import(`crate::features::<别的模块>`)—— 协作走端口,
//!    实现在主 crate 的组合根 `app/adapters/`;
//! 3. 主 crate 的 `src/features/<m>/` 下除 `adapters/` 外只许有 `mod.rs`(重新导出核心),
//!    不许把模型 / 端口 / 用例写回主 crate;也不许再出现 `src/kernel/`。
//!
//! 另外保留源码扫描([`FORBIDDEN_CRATES`]):`[dev-dependencies]` 或传递依赖不该被核心源码直接点名。

use std::fs;
use std::path::{Path, PathBuf};

/// 核心 crate 的 Cargo.toml 里禁止出现的包(按 Cargo 包名)。
const FORBIDDEN_PACKAGES: &[&str] = &[
    "axum",
    "axum-extra",
    "tower",
    "tower-http",
    "http",
    "hyper",
    "actix-web",
    "utoipa",
    "utoipa-axum",
    "utoipa-scalar",
    "sqlx",
    "sea-query",
    "sea-query-sqlx",
    "async-nats",
    "aws-sdk-s3",
    "aws-config",
    "reqwest",
    "jsonwebtoken",
];

/// 核心源码里禁止出现的路径前缀(按 Rust crate 名,如 `axum::`、`use sqlx`)。
const FORBIDDEN_CRATES: &[&str] = &[
    "axum",
    "axum_extra",
    "tower",
    "tower_http",
    "http",
    "hyper",
    "actix_web",
    "utoipa",
    "utoipa_axum",
    "utoipa_scalar",
    "sqlx",
    "sea_query",
    "sea_query_sqlx",
    "async_nats",
    "aws_sdk_s3",
    "aws_config",
    "reqwest",
    "jsonwebtoken",
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("读目录 {}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// 去掉行注释(含 `///` / `//!` 文档注释)后的代码部分。
fn code_of(line: &str) -> &str {
    line.find("//").map_or(line, |i| &line[..i])
}

/// `text` 里是否以"路径段"的形式引用了 `krate`:前一个字符不是标识符字符,后面紧跟 `::`
/// (`axum::Json`、`use axum::`、`sqlx::FromRow`),或是 `use krate;` / `use krate as …`。
fn mentions_crate(text: &str, krate: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(pos) = text[from..].find(krate) {
        let start = from + pos;
        let end = start + krate.len();
        let before_ok = start == 0 || {
            let c = bytes[start - 1] as char;
            !(c.is_alphanumeric() || c == '_' || c == ':')
        };
        let rest = &text[end..];
        let after_ok = rest.starts_with("::")
            || (text[..start].trim_end().ends_with("use")
                && (rest.starts_with(';') || rest.starts_with(" as ")));
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// 一个核心源文件的违规清单(`文件:行: 原因`)。`module` = 所属业务模块名(kernel 为 None)。
fn violations(path: &Path, module: Option<&str>) -> Vec<String> {
    let src = fs::read_to_string(path).unwrap();
    let mut out = Vec::new();
    for (i, raw) in src.lines().enumerate() {
        let line = code_of(raw);
        let at = || format!("{}:{}", path.display(), i + 1);
        for krate in FORBIDDEN_CRATES {
            if mentions_crate(line, krate) {
                out.push(format!("{}: 核心依赖了 `{krate}` → {}", at(), raw.trim()));
            }
        }
        for outward in ["crate::infra", "crate::app"] {
            if line.contains(outward) {
                out.push(format!(
                    "{}: 核心向外依赖 `{outward}` → {}",
                    at(),
                    raw.trim()
                ));
            }
        }
        if let Some(m) = module {
            // crate::features::<x>:x 必须是本模块
            let mut rest = line;
            while let Some(p) = rest.find("crate::features::") {
                let tail = &rest[p + "crate::features::".len()..];
                let other: String = tail
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !other.is_empty() && other != m {
                    out.push(format!(
                        "{}: 核心直接依赖了别的业务模块 `{other}`(应走端口)→ {}",
                        at(),
                        raw.trim()
                    ));
                }
                rest = tail;
            }
        }
    }
    out
}

/// 某个 TOML 段(如 `[dependencies]`)里声明的包名。够用的极简解析:段内每行 `name = …` / `name.workspace = true`。
fn packages_in_section(toml: &str, section: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in toml.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == section;
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            let name = name
                .trim()
                .split('.')
                .next()
                .unwrap()
                .trim()
                .trim_matches('"');
            out.push(name.to_owned());
        }
    }
    out
}

#[test]
fn core_crate_manifest_has_no_framework_dependencies() {
    let toml = fs::read_to_string(manifest_dir().join("crates/core/Cargo.toml")).unwrap();
    let deps = packages_in_section(&toml, "[dependencies]");
    assert!(
        deps.contains(&"serde".to_owned()),
        "依赖段解析坏了?读到:{deps:?}"
    );
    let bad: Vec<_> = deps
        .iter()
        .filter(|d| FORBIDDEN_PACKAGES.contains(&d.as_str()))
        .collect();
    assert!(
        bad.is_empty(),
        "核心 crate 依赖了框架 / 数据库 / HTTP 类包 {bad:?} —— 这类代码属于主 crate 的适配器"
    );
}

#[test]
fn core_sources_respect_dependency_rules() {
    let core_src = manifest_dir().join("crates/core/src");
    let mut files = Vec::new();
    rs_files(&core_src, &mut files);
    let mut problems = Vec::new();
    for f in &files {
        // crates/core/src/features/<m>/… → 所属模块 m;kernel / lib.rs → None
        let rel = f.strip_prefix(&core_src).unwrap();
        let mut parts = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned());
        let module = match (parts.next().as_deref(), parts.next()) {
            (Some("features"), Some(m)) if !m.ends_with(".rs") => Some(m),
            _ => None,
        };
        problems.extend(violations(f, module.as_deref()));
    }
    assert!(
        files.len() >= 30,
        "只扫到 {} 个核心文件 —— 目录结构变了?",
        files.len()
    );
    assert!(
        problems.is_empty(),
        "核心违反依赖规则 {} 处:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn main_crate_holds_no_core_code() {
    let src = manifest_dir().join("src");
    assert!(
        !src.join("kernel").exists(),
        "src/kernel/ 又出现了 —— 共享内核在 crates/core/src/kernel"
    );
    let mut misplaced = Vec::new();
    for entry in fs::read_dir(src.join("features")).unwrap() {
        let dir = entry.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        rs_files(&dir, &mut files);
        for f in files {
            let rel = f.strip_prefix(&dir).unwrap();
            if rel.starts_with("adapters") || rel == Path::new("mod.rs") {
                continue;
            }
            misplaced.push(f.display().to_string());
        }
    }
    assert!(
        misplaced.is_empty(),
        "主 crate 的业务模块里只该有 mod.rs + adapters/;模型 / 端口 / 用例放 crates/core:\n{}",
        misplaced.join("\n")
    );
}

/// 规则自检:扫描器认得出各种引用写法,也不会把注释 / 相似标识符误判成依赖。
#[test]
fn scanner_detects_crate_paths_but_not_lookalikes() {
    assert!(mentions_crate("use axum::Json;", "axum"));
    assert!(mentions_crate("#[derive(sqlx::FromRow)]", "sqlx"));
    assert!(mentions_crate("use utoipa;", "utoipa"));
    assert!(!mentions_crate("use axum_extra::extract::Query;", "axum"));
    assert!(mentions_crate(
        "use axum_extra::extract::Query;",
        "axum_extra"
    ));
    assert!(!mentions_crate("let http_status = 1;", "http"));
    assert!(!mentions_crate("fn my_sqlx_helper() {}", "sqlx"));
    assert_eq!(code_of("let a = 1; // axum::Json 只是注释"), "let a = 1; ");
    let toml = "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\nidm.workspace = true\n[dev-dependencies]\ntokio = \"1\"\n";
    assert_eq!(
        packages_in_section(toml, "[dependencies]"),
        vec!["serde", "idm"]
    );
}
