//! Application-level GlobalProtect networking; no virtual interface or OS route management.
#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod control;
pub mod control_local;
pub mod credentials;
pub mod deployment;
pub mod deployment_store;
pub mod dns;
pub mod gp;
mod launchd;
mod lease;
mod local_file;
mod log_store;
pub mod logging;
#[cfg(target_os = "macos")]
mod managed_candidate;
mod managed_child;
pub mod managed_io;
mod managed_lifecycle;
mod managed_plist;
pub mod managed_protocol;
pub mod managed_release;
pub mod managed_runtime;
mod owned_snapshot;
pub mod pac_history;
pub mod policy;
mod private_fs;
pub mod probe;
pub mod proxy;
mod secret_file;
pub mod service;
pub mod session;
pub mod session_file;
pub mod stack;
pub mod status;
pub mod terminal;
pub mod tls;
