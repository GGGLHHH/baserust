//! 业务模块层:每个子模块是一个业务域,薄分层 routes->service->repo(trait)->types。
//! 加业务:在此 `pub mod xxx;`,照抄 widget/ 的结构。

pub mod idm;
pub mod widget;
