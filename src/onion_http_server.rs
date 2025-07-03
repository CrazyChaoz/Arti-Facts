use arti_client::TorClient;
use async_zip::{tokio::write::ZipFileWriter, Compression};
use async_zip::{ZipEntryBuilder, ZipString};
use futures::task::SpawnExt;
use futures::{AsyncWriteExt, TryStreamExt};
use futures::{Stream, StreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use log::{error, info};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;

use crate::utils;
use crate::utils::get_onion_address;
use tor_hsrproxy::{
    config::{Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr},
    OnionServiceReverseProxy,
};
use uuid::Uuid;

lazy_static! {
    pub(crate) static ref VISIT_COUNTS: Arc<Mutex<HashMap<String, HashMap<String, Vec<String>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    pub(crate) static ref RUNNING_ONION_SERVICES: Arc<Mutex<HashMap<String, CancellationToken>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

const INDEX_TEMPLATE: &str = include_str!("index.html");
const DEFAULT_CSS: &str = include_str!("default.css");

pub(crate) fn load_visit_log(config_directory: &Path) {
    let log_file = config_directory.join("visit_log.json");
    if let Ok(content) = fs::read_to_string(&log_file) {
        if let Ok(visits) =
            serde_json::from_str::<HashMap<String, HashMap<String, Vec<String>>>>(&content)
        {
            *VISIT_COUNTS.lock().unwrap() = visits;
        }
    }
}

fn save_visit_log(config_directory: &Path) {
    let log_file = config_directory.join("visit_log.json");
    let visits = VISIT_COUNTS.lock().unwrap();
    if let Ok(json) = serde_json::to_string(&*visits) {
        let _ = fs::write(&log_file, json);
    }
}

fn get_or_create_session_id(request: &Request<Incoming>) -> String {
    for header in request.headers().get_all("cookie") {
        if let Ok(cookie_str) = header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(session_id) = cookie.strip_prefix("session=") {
                    return session_id.to_string();
                }
            }
        }
    }
    Uuid::new_v4().to_string()
}

pub(crate) async fn onion_service_from_sk(
    tor_client: TorClient<PreferredRuntime>,
    data_directory: PathBuf,
    config_directory: PathBuf,
    secret_key: Option<[u8; 32]>,
    custom_css: Option<String>,
    forward_proxy: Option<(u16, SocketAddr)>,
    visitor_tracking: bool,
) {
    let nickname = if secret_key.is_some() {
        format!(
            "arti-facts-service-{}",
            get_onion_address(
                utils::keypair_from_sk(secret_key.unwrap())
                    .public()
                    .as_bytes()
            )
        )
    } else {
        "arti-facts-service".into()
    };

    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname(nickname.parse().unwrap())
        .build()
        .unwrap();

    let (onion_service, request_stream): (
        _,
        Pin<Box<dyn Stream<Item = tor_hsservice::RendRequest> + Send>>,
    ) = if secret_key.is_none() {
        // We are trying to reuse an old instance
        let (service, stream) = tor_client
            .launch_onion_service(svc_cfg)
            .expect("error creating onion service");
        (service, Box::pin(stream))
    } else {
        let secret_key = secret_key.unwrap();

        let expanded_key_pair = utils::keypair_from_sk(secret_key);

        let encodable_key = tor_hscrypto::pk::HsIdKeypair::from(expanded_key_pair);

        if let Ok((service, stream)) =
            tor_client.launch_onion_service_with_hsid(svc_cfg.clone(), encodable_key)
        {
            (service, Box::pin(stream))
        } else {
            // This key exists; reuse it
            let (service, stream) = tor_client
                .launch_onion_service(svc_cfg)
                .expect("error creating onion service");
            (service, Box::pin(stream))
        }
    };

    info!("onion service status: {:?}", onion_service.status());
    let clone_onion_service = onion_service.clone();

    let cancel_token = CancellationToken::new();
    let _ = tor_client.clone().runtime().spawn(async move {
        while let Some(status_event) = clone_onion_service.status_events().next().await {
            if status_event.state().is_fully_reachable() {
                break;
            }
        }
        println!(
            "This directory is now available at: {}",
            clone_onion_service.onion_address().unwrap()
        );
        info!("onion service status: {:?}", clone_onion_service.status());
    });

    let _ = tor_client.clone().runtime().spawn(async move {
        let clone_running_onion_services = RUNNING_ONION_SERVICES.clone();
        clone_running_onion_services.lock().unwrap().insert(
            onion_service
                .clone()
                .onion_address()
                .unwrap()
                .to_string()
                .trim_end_matches(".onion")
                .into(),
            cancel_token.clone(),
        );

        if let Some(forward_proxy) = forward_proxy {
            let (local_port, listeners) = forward_proxy;

            let proxy_rule = ProxyRule::new(
                ProxyPattern::one_port(local_port)
                    .map_err(|e| println!("Not a valid port: {e}"))
                    .unwrap(),
                ProxyAction::Forward(Encapsulation::Simple, TargetAddr::Inet(listeners)),
            );

            let mut proxy_config = ProxyConfigBuilder::default();
            proxy_config.set_proxy_ports(vec![proxy_rule]);
            let proxy = OnionServiceReverseProxy::new(
                proxy_config
                    .build()
                    .expect("Unreachable, all fields have been set"),
            );

            tokio::select! {
                result = proxy.handle_requests(
                    tor_client.runtime().clone(),
                    nickname.parse().unwrap(),
                    request_stream,
                ) => {
                    match result {
                        Ok(_) => info!("Proxy handling completed normally"),
                        Err(e) => error!("Error handling requests: {}", e),
                    }
                }
                _ = cancel_token.cancelled() => {
                    info!("Shutting down onion service via cancellation token");
                }
            }
        } else {
            let accepted_streams = tor_hsservice::handle_rend_requests(request_stream);

            tokio::pin!(accepted_streams);

            loop {
                tokio::select! {
                Some(stream_request) = accepted_streams.next() => {
                        info!("new incoming stream");
                        let request = stream_request.request().clone();
                        match request {
                            IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
                                let onion_service_stream =
                                    stream_request.accept(Connected::new_empty()).await.unwrap();
                                let io = TokioIo::new(onion_service_stream);

                                http1::Builder::new()
                                    .serve_connection(
                                        io,
                                        service_fn(|request| {
                                            service_function(
                                                request,
                                                onion_service.onion_address().unwrap().to_string(),
                                                data_directory.clone(),
                                                config_directory.clone(),
                                                custom_css.clone(),
                                                visitor_tracking,
                                            )
                                        }),
                                    )
                                    .await
                                    .unwrap_or_else(|_| {
                                        info!("error serving connection");
                                    });
                            }
                            _ => {
                                stream_request.shutdown_circuit().unwrap();
                            }
                        };
                    }
                        _ = cancel_token.cancelled() => {
                            info!("Shutting down onion service");
                            return;
                        }
                    }
            }
        }
    });
}

/// Handles an HTTP request by serving files or directory listings from the specified data directory,
/// while restricting access to the configuration directory and supporting ZIP downloads.
///
/// # Arguments
///
/// * `request` - The incoming HTTP request.
/// * `data_dir` - The base directory from which files and directories are served.
/// * `config_directory` - The directory containing configuration files, which must not be accessible.
/// * `custom_css` - Optional custom CSS for the index page.
/// * `visitor_tracking` - Whether to enable visit tracking.
///
/// # Returns
///
/// Returns a `Result` containing either a `Response<BoxBody<Bytes, std::io::Error>>` with the requested file contents,
/// directory listing, or ZIP archive, or an error if access is forbidden or the resource is not found.
///
/// # Behavior
///
/// - Prevents access to files outside `data_dir` or within `config_directory`.
/// - If the requested path is a directory or root, returns an HTML index of its contents.
/// - If the requested path is a file, streams its contents.
/// - If the `?download` query is present on a directory, streams a ZIP archive of its contents.
/// - Returns 404 Not Found if the file or directory does not exist.
async fn service_function(
    request: Request<Incoming>,
    onion_address: String,
    data_dir: PathBuf,
    config_directory: PathBuf,
    custom_css: Option<String>,
    visitor_tracking: bool,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>, std::io::Error> {
    let path = request.uri().path().trim_start_matches('/').to_string();
    let mut file_path = data_dir.join(&path);

    // Prevent access to config_directory or its subdirectories
    let config_directory = config_directory.canonicalize()?;
    file_path = if file_path
        .canonicalize()
        .map(|p| p.starts_with(&config_directory))
        .unwrap_or(false)
    {
        // If the requested path is within the config directory, try one directory above the config directory
        config_directory
            .parent()
            .unwrap_or(&config_directory)
            .to_path_buf()
    } else {
        file_path
    };

    // Prevent access to any file outside of data_dir or to config_directory
    let data_dir_canon = data_dir.canonicalize()?;
    let file_path_canon = file_path.canonicalize().unwrap_or(data_dir_canon.clone());
    if !file_path_canon.starts_with(&data_dir_canon)
        || file_path_canon.starts_with(&config_directory)
    {
        file_path = data_dir_canon;
    }

    info!("Visit: {}", onion_address);

    let response = if visitor_tracking {
        // Get or create session ID
        let session_id = get_or_create_session_id(&request);

        // Record visit
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        {
            let mut visits = VISIT_COUNTS.lock().unwrap();
            visits
                .entry(onion_address.clone())
                .or_default()
                .entry(session_id.clone())
                .or_default()
                .push(timestamp);
        }

        // Save visit log
        save_visit_log(&config_directory);

        Response::builder().header(
            "Set-Cookie",
            format!("session={session_id}; Path=/; HttpOnly"),
        )
    } else {
        Response::builder()
    };

    if request.uri().query() == Some("download") && file_path.is_dir() {
        // Create a pipe with large buffer
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);

        let file_path = file_path.clone();
        let config_directory = config_directory.clone();

        // Spawn async task to write ZIP
        tokio::spawn(async move {
            let mut zip = ZipFileWriter::with_tokio(&mut writer);

            let walker = walkdir::WalkDir::new(&file_path).follow_links(true);
            for entry in walker {
                let Ok(entry) = entry else { continue };
                let path = entry.path();

                // Skip config directory
                if path
                    .canonicalize()
                    .map(|p| p.starts_with(&config_directory))
                    .unwrap_or(false)
                {
                    continue;
                }

                if path.is_file() {
                    let name = match path.strip_prefix(&file_path) {
                        Ok(n) => n.to_string_lossy(),
                        Err(_) => continue,
                    };

                    if let Ok(data) = tokio::fs::read(&path).await {
                        let builder = ZipEntryBuilder::new(
                            ZipString::from(name.as_ref()),
                            Compression::Deflate,
                        );
                        let mut entry_writer = zip.write_entry_stream(builder).await.unwrap();
                        entry_writer
                            .write_all(&data)
                            .await
                            .expect("error writing to zip entry");

                        entry_writer.close().await.unwrap();
                    }
                }
            }

            let _ = zip.close().await;
        });

        // Stream the ZIP file
        let reader_stream = ReaderStream::new(reader);
        let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
        let boxed_body = BodyExt::boxed(stream_body);

        return Ok(response
            .status(StatusCode::OK)
            .header("Content-Type", "application/zip")
            .header(
                "Content-Disposition",
                "attachment; filename=\"download.zip\"",
            )
            .body(boxed_body)
            .unwrap());
    }

    // If path is a directory or root, list files
    if file_path.is_dir() || path.is_empty() {
        let mut entries_vec: Vec<_> = fs::read_dir(&file_path)?
            .filter_map(Result::ok)
            .filter(|entry| {
                let entry_path = entry.path();
                // Skip config_dir and its contents
                !entry_path
                    .canonicalize()
                    .map(|p| p.starts_with(&config_directory))
                    .unwrap_or(false)
            })
            .collect();

        // Sort entries by file type and then file name (case-insensitive)
        entries_vec.sort_by_key(|entry| {
            let entry_path = entry.path();
            let file_type = !entry_path.is_dir();
            let name = entry.file_name().to_string_lossy().to_lowercase();
            (file_type, name)
        });

        let mut table_rows = Vec::new();
        for entry in entries_vec {
            let entry_path = entry.path();
            let name = entry.file_name().into_string().unwrap_or_default();
            let metadata = entry.metadata()?;
            let file_type = if entry_path.is_dir() { "📁" } else { "📄" };
            let size = if entry_path.is_file() {
                let len = metadata.len();
                if len >= 1 << 30 {
                    format!("{:.2} GiB", len as f64 / f64::from(1 << 30))
                } else if len >= 1 << 20 {
                    format!("{:.2} MiB", len as f64 / f64::from(1 << 20))
                } else if len >= 1 << 10 {
                    format!("{:.2} KiB", len as f64 / f64::from(1 << 10))
                } else {
                    format!("{len} bytes")
                }
            } else {
                String::from("-")
            };
            let modified = metadata.modified().ok().map_or("-".to_string(), |m| {
                let datetime: chrono::DateTime<chrono::Local> = m.into();
                datetime.format("%H:%M | %Y-%m-%d").to_string()
            });

            table_rows.push(format!(
                "<tr><td>{}</td><td><a href=\"/{href}\">{}</a></td><td>{}</td><td>{}</td><td><a href=\"/{href}?download\" class=\"download-button\">⬇️</a></td></tr>",
                file_type,
                name,
                size,
                modified,
                href = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                }
            ));
        }
        let go_back = if path.is_empty() || file_path.eq(&data_dir) {
            "<span class=\"left\"></span>".to_string()
        } else {
            let parent = file_path
                .parent()
                .and_then(|p| p.strip_prefix(&data_dir).ok())
                .and_then(|p| p.to_str())
                .unwrap_or("<span class=\"left\"></span>");
            format!("<a href=\"/{parent}\" class=\"button left\">⬆️ Parent directory</a>")
        };

        let css = if let Some(css) = custom_css {
            css
        } else {
            DEFAULT_CSS.to_string()
        };

        let body = INDEX_TEMPLATE
            .replace("{0}", &path)
            .replace("{1}", &table_rows.join(""))
            .replace("{css_structure}", &css)
            .replace("{parent_dir}", &go_back);

        return Ok(response
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::<Bytes>::from(body).map_err(|e| match e {}).boxed())
            .unwrap());
    }

    // If path is a file, return its contents
    if file_path.is_file() {
        let file = tokio::fs::File::open(&file_path).await?;

        // Wrap to a tokio_util::io::ReaderStream
        let reader_stream = ReaderStream::new(file);

        // Convert to http_body_util::BoxBody
        let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
        let boxed_body = BodyExt::boxed(stream_body);

        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download");

        let mut response_builder = response.status(StatusCode::OK);

        if request.uri().query() == Some("download") {
            response_builder = response_builder.header(
                "Content-Disposition",
                format!("attachment; filename=\"{file_name}\""),
            );
        }

        // Send response
        return Ok(response_builder.body(boxed_body).unwrap());
    }

    // Not found
    Ok(response
        .status(StatusCode::NOT_FOUND)
        .body(
            Full::<Bytes>::from("File or directory not found")
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap())
}
