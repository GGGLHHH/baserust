//! app 进程入口。开发默认 `Both`(单进程含 idm);生产设 `IDM_EMBEDDED=false` → 只挂 app,
//! idm 由 `idm` bin 独立进程承载(nginx 按 `/api/v1/{public,frontend,admin}/auth/` 与 `/api/v1/admin/platform/` 前缀分流)。
//! 业务逻辑都在 lib(见 lib.rs)。

// Google Rust 风格指南:必须 panic 时用 expect("原因") 说明不变量,不用 unwrap。
#![warn(clippy::unwrap_used)]

use baserust::app::{self, Mount};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // mount 依赖配置(Config.idm_embedded),经回调在 run 内 Config::try_new 之后决定。
    app::run(|config| {
        if config.idm_embedded {
            Mount::Both
        } else {
            Mount::App
        }
    })
    .await
}
