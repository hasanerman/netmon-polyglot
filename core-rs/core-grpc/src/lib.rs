mod link;

pub mod proto {
    tonic::include_proto!("netmon.analytics.v1");
}

pub use link::{AnalyticsLink, LinkError, LinkState, INITIAL_BACKOFF, MAX_BACKOFF};
