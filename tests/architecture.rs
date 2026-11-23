//! **六边形架构的依赖规则,扫源码钉死**(端口与适配器):核心不依赖框架、数据库、HTTP;依赖只向内指。
//!
//! "核心" = `src/kernel/**`(共享内核)+ 每个业务模块 `src/features/<m>/` 下**除 `adapters/` 以外**的文件
//! (领域模型、端口、用例)。这些文件里不许出现:
//! - 框架 / 数据库 / HTTP / 消息 / 对象存储 / JWT 的 crate(见 [`FORBIDDEN_CRATES`]);
//! - 向外的依赖:`crate::infra`(适配器侧横切件)、`crate::app`(组合根);
//! - 别的业务模块(`crate::features::<其他>`)—— 模块间协作走端口,实现在组合根 `app/adapters/`。
//!
//! 允许:`crate::kernel`、本模块、领域库(idm / content,零 HTTP)、serde / garde / uuid / time /
//! thiserror / anyhow / async-trait / tokio / tracing 这类不属于框架、数据库、HTTP 的基础库。
//! 适配器(`adapters/`)、`infra`、`app` 不受限 —— 它们就是用这些依赖去实现端口、驱动核心的那一层。

use std::fs;
use std::path::{Path, PathBuf};

/// 核心里禁止出现的 crate(按路径前缀匹配,如 `axum::`、`use axum`)。
const FORBIDDEN_CRATES: &[&str] = &[
    "axum",
    "axum_extra",
    "tower",
    "tower_http",
    "http",
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

/// 一个核心文件的违规清单(`文件:行: 原因`)。`module` = 所属业务模块名(kernel 为 None)。
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

#[test]
fn core_depends_on_no_framework_database_or_http() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0;
    let mut problems = Vec::new();

    // 共享内核:整个目录都是核心。
    let mut kernel = Vec::new();
    rs_files(&root.join("kernel"), &mut kernel);
    for f in &kernel {
        problems.extend(violations(f, None));
        checked += 1;
    }

    // 业务模块:adapters/ 以外的文件是核心。
    for entry in fs::read_dir(root.join("features")).unwrap() {
        let dir = entry.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        let module = dir.file_name().unwrap().to_string_lossy().into_owned();
        let mut files = Vec::new();
        rs_files(&dir, &mut files);
        for f in files {
            if f.strip_prefix(&dir).unwrap().starts_with("adapters") {
                continue;
            }
            problems.extend(violations(&f, Some(&module)));
            checked += 1;
        }
    }

    assert!(
        checked >= 30,
        "只扫到 {checked} 个核心文件 —— 目录结构变了?检查本测试的路径约定"
    );
    assert!(
        problems.is_empty(),
        "核心(kernel + features/*/ 除 adapters/)违反依赖规则 {} 处:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// 规则自检:扫描器认得出各种引用写法,也不会把注释 / 相似标识符误判成依赖。
#[test]
fn scanner_detects_crate_paths_but_not_lookalikes() {
    assert!(mentions_crate("use axum::Json;", "axum"));
    assert!(mentions_crate("#[derive(sqlx::FromRow)]", "sqlx"));
    assert!(mentions_crate("use utoipa;", "utoipa"));
    assert!(!mentions_crate("use axum_extra::extract::Query;", "axum")); // 交给 axum_extra 自己那条
    assert!(mentions_crate(
        "use axum_extra::extract::Query;",
        "axum_extra"
    ));
    assert!(!mentions_crate("let http_status = 1;", "http"));
    assert!(!mentions_crate("fn my_sqlx_helper() {}", "sqlx"));
    assert_eq!(code_of("let a = 1; // axum::Json 只是注释"), "let a = 1; ");
}
