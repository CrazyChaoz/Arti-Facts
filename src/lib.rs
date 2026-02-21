//! Library entry points extracted from `main.rs` so the core functionality can be used
//! programmatically (for example from uniffi).
//!
//! This module exposes a small set of helpers:
//! - `create_tor_client` - create and bootstrap an arti Tor client for a given config directory
//! - `start_onion_service_async` - start a single onion service (the previous "onion_http_server" path)
//! - `run_managed_service_async` - run the management HTTP UI (previously in `main.rs` -> `management` branch)
//! - `start_service_blocking` - convenience function which mirrors the behaviour of the original binary
//! - `start_service_ffi` - a single FFI-friendly blocking entrypoint that accepts strings and starts the service
//!
//! The library intentionally re-uses the existing `management`, `onion_http_server` and `utils`
//! modules that live in the crate so the main logic remains in those modules and this file
//! only provides a small, ergonomic API surface.

mod management;
mod onion_http_server;
mod utils;

pub use utils::{generate_key, get_onion_address};

use arti_client::TorClient;
use arti_client::config::TorClientConfigBuilder;
use log::info;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use tor_rtcompat::{PreferredRuntime, ToplevelBlockOn};

/// Create and bootstrap an arti `TorClient` using directories under `config_directory`.
///
/// This mirrors the configuration used in the binary: arti-config and arti-cache are created
/// inside the provided `config_directory`.
///
/// On success returns a bootstrapped `TorClient<PreferredRuntime>`.
pub async fn create_tor_client(
    config_directory: PathBuf,
) -> Result<TorClient<PreferredRuntime>, Box<dyn Error + Send + Sync>> {
    // Build the Tor client configuration (same directories layout as the binary)
    let mut config = TorClientConfigBuilder::from_directories(
        config_directory.join("arti-config"),
        config_directory.join("arti-cache"),
    );
    config.address_filter().allow_onion_addrs(true);

    let config = config.build()?;

    // Select or create a runtime
    let rt = if let Ok(runtime) = PreferredRuntime::current() {
        runtime
    } else {
        PreferredRuntime::create()?
    };

    let binding = TorClient::with_runtime(rt.clone()).config(config);
    let client_future = binding.create_bootstrapped();

    // Await the bootstrap on the runtime we selected/created
    let client = client_future.await?;
    Ok(client)
}

/// Start an onion service (non-managed mode) using an already bootstrapped `TorClient`.
///
/// This is an async, non-blocking function: the called `onion_http_server::onion_service_from_sk`
/// will spawn background tasks and manage the service lifetime itself. Awaiting this function
/// will await the inner startup process, but in the common case the inner routines keep running
/// forever (so this future will not return unless the service terminates).
pub async fn start_onion_service_async(
    client: TorClient<PreferredRuntime>,
    data_directory: PathBuf,
    config_directory: PathBuf,
    secret_key: Option<[u8; 32]>,
    custom_css: Option<String>,
    forward_proxy: Option<(u16, SocketAddr)>,
    visitor_tracking: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Starting onion service (async)");
    onion_http_server::onion_service_from_sk(
        client,
        data_directory,
        config_directory,
        secret_key,
        custom_css,
        forward_proxy,
        visitor_tracking,
    )
    .await;
    Ok(())
}

/// Run the managed service (management UI) using an already bootstrapped `TorClient`.
///
/// This function awaits the management service; the implementation will accept connections
/// and normally does not return unless the runtime or listener stops.
pub async fn run_managed_service_async(
    client: TorClient<PreferredRuntime>,
    config_directory: PathBuf,
    custom_css: Option<String>,
    visitor_tracking: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Starting managed service (async)");
    management::run_managed_service(client, config_directory, custom_css, visitor_tracking).await;
    Ok(())
}

/// Convenience blocking entry point which mirrors the behaviour of the original binary.
///
/// This function will:
///  - create or reuse a runtime
///  - build and bootstrap a Tor client using `config_directory`
///  - either run the management UI (if `managed == true`) or start a single onion service
///    that serves `data_directory`
///
/// The blocking variant uses `PreferredRuntime::block_on` to await the async flows. It returns
/// when the inner service future returns (in typical usage these run forever).
pub fn start_service_blocking(
    data_directory: PathBuf,
    config_directory: PathBuf,
    secret_key: Option<[u8; 32]>,
    custom_css: Option<String>,
    forward_proxy: Option<(u16, SocketAddr)>,
    visitor_tracking: bool,
    managed: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Prepare a runtime (match behaviour of the binary)
    let rt = if let Ok(runtime) = PreferredRuntime::current() {
        runtime
    } else {
        PreferredRuntime::create()?
    };

    // Build tor config (same as create_tor_client)
    let mut cfg_builder = TorClientConfigBuilder::from_directories(
        config_directory.join("arti-config"),
        config_directory.join("arti-cache"),
    );
    cfg_builder.address_filter().allow_onion_addrs(true);
    let cfg = cfg_builder.build()?;

    let binding = TorClient::with_runtime(rt.clone()).config(cfg);
    let client_future = binding.create_bootstrapped();

    rt.block_on(async {
        let client = client_future.await?;
        info!("Tor client started (blocking entry)");

        if managed {
            management::run_managed_service(client, config_directory, custom_css, visitor_tracking)
                .await;
            // run_managed_service doesn't return until it stops
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        } else {
            onion_http_server::onion_service_from_sk(
                client,
                data_directory,
                config_directory,
                secret_key,
                custom_css,
                forward_proxy,
                visitor_tracking,
            )
            .await;
            // The onion service path similarly runs until shutdown
            Ok(())
        }
    })?;
    Ok(())
}

/// FFI-friendly blocking wrapper that starts the service with string arguments.
///
/// - `data_dir` and `config_dir` are file system paths.
///
/// Returns Ok(\"started\") on success (the service normally runs indefinitely), or Err with an error message.
pub fn start_service_ffi(data_dir: &str, config_dir: &str) -> Result<String, String> {
    // Convert paths
    let data_directory = PathBuf::from(data_dir);
    let config_directory = PathBuf::from(config_dir);


    // Call the blocking entry
    match start_service_blocking(
        data_directory,
        config_directory,
        None,
        None,
        None,
        false,
        false,
    ) {
        Ok(_) => Ok("started".to_string()),
        Err(e) => Err(format!("{}", e)),
    }
}
