//! rustbgpd-policy — Minimal policy engine
//!
//! Prefix allow/deny lists, max-prefix enforcement, simple attribute
//! set/clear. Enough to be operationally useful.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod prefix_list;

pub use prefix_list::{
    CommunityMatch, PolicyAction, PrefixList, PrefixListEntry, check_prefix_list,
    parse_community_match,
};
