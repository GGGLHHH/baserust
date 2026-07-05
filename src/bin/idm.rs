//! idm 进程入口 —— 生产分进程,只挂 idm(auth 端点分散在 public/frontend/admin 三组下);
//! nginx 按 `/api/v1/{public,frontend,admin}/auth` 前缀分流到此。
//! 本地开发用 app 进程(Both 已含 idm)即可,不必单跑它。对应 Go 的 cmd/realestate-login。

use xchangeai::app::{run, Mount};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(|_| Mount::Idm).await
}
