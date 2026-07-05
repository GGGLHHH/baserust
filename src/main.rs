//! app 进程入口。开发默认 `Both`(单进程含 idm);生产设 `IDM_EMBEDDED=false` → 只挂 app,
//! idm 由 `idm` bin 独立进程承载(nginx 按 `/api/v1/{public,frontend,admin}/auth` 前缀分流)。
//! 业务逻辑都在 lib(见 lib.rs)。

use xchangeai::app::{run, Mount};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // mount 依赖配置(Config.idm_embedded),经回调在 run 内 Config::load 之后决定。
    run(|config| {
        if config.idm_embedded {
            Mount::Both
        } else {
            Mount::App
        }
    })
    .await
}
