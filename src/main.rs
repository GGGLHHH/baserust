//! app 进程入口。开发默认 `Both`(单进程含 idm);生产设 `IDM_EMBEDDED=false` → 只挂 app,
//! idm 由 `idm` bin 独立进程承载(nginx 按 /api/v1/auth 前缀分流)。业务逻辑都在 lib(见 lib.rs)。

use xchangeai::app::{run, Mount};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mount = if std::env::var("IDM_EMBEDDED")
        .map(|v| v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
    {
        Mount::App
    } else {
        Mount::Both
    };
    run(mount).await
}
