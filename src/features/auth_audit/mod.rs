pub mod projector;
pub mod repo;
pub mod retention;
pub mod routes;
pub mod types;

pub use repo::{AuthEventRepo, InMemoryAuthEventRepo, PgAuthEventRepo};
pub use retention::AuthRetentionJob;
pub use types::{AuthEventQuery, AuthEventRow, NewAuthEvent};

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

/// admin 组(组闸「admin:login」由 composition root 上;端点内再 gate「users:admin」)。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_user_auth_events))
        .routes(routes!(routes::list_auth_events))
}
