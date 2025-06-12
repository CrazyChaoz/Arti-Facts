use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use async_zip::{tokio::write::ZipFileWriter, Compression};
use async_zip::{ZipEntryBuilder, ZipString};
use clap::{Arg, Command};
use futures::task::SpawnExt;
use futures::{AsyncWriteExt, TryStreamExt};
use futures::{Stream, StreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use log::info;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio_util::io::ReaderStream;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::{PreferredRuntime, ToplevelBlockOn};
use uuid::Uuid;

lazy_static! {
    static ref VISIT_COUNTS: Mutex<HashMap<String, Vec<String>>> = Mutex::new(HashMap::new());
}

const INDEX_TEMPLATE: &str = include_str!("index.html");
const DEFAULT_CSS: &str = include_str!("default.css");

fn load_visit_log(config_directory: &Path) {
    let log_file = config_directory.join("visit_log.json");
    if let Ok(content) = fs::read_to_string(&log_file) {
        if let Ok(visits) = serde_json::from_str::<HashMap<String, Vec<String>>>(&content) {
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

fn keypair_from_sk(secret_key: [u8; 32]) -> ExpandedKeypair {
    let sk = secret_key as ed25519_dalek::SecretKey;
    let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(&sk);
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&esk.scalar.to_bytes());
    bytes[32..].copy_from_slice(&esk.hash_prefix);
    ExpandedKeypair::from_secret_key_bytes(bytes).expect("error converting to ExpandedKeypair")
}

async fn onion_service_from_sk(
    tor_client: TorClient<PreferredRuntime>,
    data_directory: PathBuf,
    config_directory: PathBuf,
    secret_key: Option<[u8; 32]>,
    custom_css: Option<String>,
    visitor_tracking: bool,
) {
    let nickname = "arti-facts-service";

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

        let expanded_key_pair = keypair_from_sk(secret_key);

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

    while let Some(status_event) = onion_service.status_events().next().await {
        if status_event.state().is_fully_reachable() {
            break;
        }
    }
    println!(
        "This directory is now available at: {}",
        onion_service.onion_address().unwrap()
    );
    info!("onion service status: {:?}", onion_service.status());

    let _ = tor_client.clone().runtime().spawn(async move {
        let accepted_streams = tor_hsservice::handle_rend_requests(request_stream);

        tokio::pin!(accepted_streams);

        while let Some(stream_request) = accepted_streams.next().await {
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
        drop(onion_service);
        info!("onion service dropped");
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

    let response = if visitor_tracking {
        // Get or create session ID
        let session_id = get_or_create_session_id(&request);

        // Record visit
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        {
            let mut visits = VISIT_COUNTS.lock().unwrap();
            visits
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

/// Generates a random 32-byte secret key using a cryptographically secure random number generator.
///
/// # Returns
///
/// A `[u8; 32]` array containing the generated secret key.
///
/// # Examples
///
/// ```
/// let key = generate_key();
/// assert_eq!(key.len(), 32);
/// ```
///
/// # Notes
///
/// The `#[must_use]` attribute ensures that the returned key is not ignored.
#[must_use]
pub fn generate_key() -> [u8; 32] {
    let mut rng = rand::rng();
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    sk
}
#[must_use]
pub fn get_onion_address(public_key: &[u8]) -> String {
    let pub_key = <[u8; 32]>::try_from(public_key).expect("could not convert to [u8; 32]");
    let mut buf = [0u8; 35];
    pub_key.iter().copied().enumerate().for_each(|(i, b)| {
        buf[i] = b;
    });

    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pub_key);
    h.update(b"\x03");

    let res_vec = h.finalize().to_vec();
    buf[32] = res_vec[0];
    buf[33] = res_vec[1];
    buf[34] = 3;

    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf).to_ascii_lowercase()
}

async fn run_managed_service(
    client: TorClient<PreferredRuntime>,
    config_directory: PathBuf,
    custom_css: Option<String>,
    visitor_tracking: bool,
) {
    // Run a simple HTTP server for management page
    let mgmt_addr = "127.0.0.1:8080";
    println!("Management page available at http://{}/", mgmt_addr);

    let secret_keys_to_directory_mapping: Arc<Mutex<HashMap<[u8; 32], String>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mgmt_service = service_fn(move |req: Request<Incoming>| {
        let value = secret_keys_to_directory_mapping.clone();
        let client = client.clone();
        let method = req.method().clone();
        let uri = req.uri().clone();
        let config_directory = config_directory.clone();

        info!("Incoming request: {req:?}");
        
        async {
            let body = String::from_utf8(
                req.into_body()
                    .collect()
                    .await
                    .expect("Error while awaiting incoming request")
                    .to_bytes()
                    .into(),
            )
            .expect("Failed to parse body as UTF-8");
            info!("Request body: {body:?}");
            async move {
                match (method, uri.path()) {
                    (Method::POST, "/add-onion-service") => {
                        let params: HashMap<_, _> = form_urlencoded::parse(body.as_bytes())
                            .into_owned()
                            .collect();
                        
                        info!("Adding onion service: {params:?}");

                        if let (Some(secret_key), Some(share_dir)) = (params.get("secret_key"), params.get("share_dir")) {
                            let mut sk = [0u8; 32];
                            if hex::decode_to_slice(secret_key, &mut sk).is_ok() {
                                let share_dir = PathBuf::from(share_dir);
                                if share_dir.exists() && share_dir.is_dir() {
                                    value.lock().unwrap().insert(sk, share_dir.to_string_lossy().into_owned());

                                    let config_dir = config_directory.clone();
                                    tokio::spawn(async move {
                                        onion_service_from_sk(
                                            client,
                                            share_dir,
                                            config_dir,
                                            Some(sk),
                                            None,
                                            false,
                                        ).await;
                                    });

                                    return Ok(Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Full::<Bytes>::from("").boxed())
                                        .unwrap());
                                }
                            }
                        }

                        Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Full::<Bytes>::from("Invalid form data").boxed())
                            .unwrap())
                    }
                    (Method::GET, "/generate-random-key") => {
                        let random_key = generate_key();
                        let hex_key = hex::encode(random_key);
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::<Bytes>::from(hex_key).boxed())
                            .unwrap())
                    }
                    _ => {
                        let html = include_str!("management_page.html").replace("{existing_onion_services}",
                                                                                &*value.clone().lock().unwrap()
                                                                                    .iter()
                                                                                    .map(|(sk, dir)| {
                                                                                        format!(
                                                                                            "<tr><td class=\"onion\">{}</td><td class=\"dir\">{}</td><td><button onclick=\"deleteOnionService('{}')\" class=\"delete-button\">🗑️</button></td></tr>",
                                                                                            get_onion_address(keypair_from_sk(*sk).public().as_bytes()),
                                                                                            dir,
                                                                                            hex::encode(sk)
                                                                                        )
                                                                                    })
                                                                                    .collect::<Vec<_>>()
                                                                                    .join("\n"),
                        );
                        Ok::<_, std::io::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "text/html; charset=utf-8")
                                .body(Full::<Bytes>::from(html).map_err(|e| match e {}).boxed())
                                .unwrap()
                        )
                    }
                }
            }.await
        }
    });

    let listener = tokio::net::TcpListener::bind(mgmt_addr).await.unwrap();
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        tokio::spawn(http1::Builder::new().serve_connection(io, mgmt_service.clone()));
    }
}

fn cli_args() -> clap::ArgMatches {
    Command::new("arti-facts")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A simple file sharing service over Tor onion services")
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIR")
                .help("Sets the working directory, you need read permissions on it"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file, you need read and write permissions on it"),
        )
        .arg(
            Arg::new("key")
                .short('k')
                .long("key")
                .value_name("HEX")
                .help("Provide a 32-byte secret key in hexadecimal format"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::Count)
                .help("Increase verbosity level"),
        )
        .arg(
            Arg::new("css")
                .short('s')
                .long("css")
                .value_name("FILE")
                .help("Path to a custom CSS file for the index page, defaults to built-in style"),
        )
        .arg(
            Arg::new("tracking")
                .short('t')
                .long("tracking")
                .action(clap::ArgAction::SetTrue)
                .help("Enable visit tracking (saves visit counts in config directory)"),
        ).arg(
        Arg::new("managed")
            .long("managed")
            .action(clap::ArgAction::SetTrue)
            .help("Run the service in managed mode, where it serves a static HTML page with management page to manage shared folders and its onion address"),
    )
        .get_matches()
}

fn main() {
    let matches = cli_args();

    // Initialize logging based on verbosity level
    let log_level = match matches.get_count("verbose") {
        0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    let current_directory = std::env::current_dir().unwrap();

    let data_directory = if let Some(dir) = matches.get_one::<String>("directory") {
        info!("Working directory: {dir}");
        Path::new(dir).canonicalize().unwrap_or_else(|_| {
            info!("Invalid directory specified, using current directory instead.");
            current_directory.clone()
        })
    } else {
        info!("No directory specified, using default.");
        current_directory.clone()
    };

    println!("Sharing directory: {data_directory:?}");

    let mut secret_key = if let Some(hex_key) = matches.get_one::<String>("key") {
        assert_eq!(
            hex_key.len(),
            64,
            "Secret key must be a 32-byte hexadecimal string (64 characters)."
        );
        let mut sk = [0u8; 32];
        hex::decode_to_slice(hex_key, &mut sk).expect("Invalid hex string for secret key");
        Some(sk)
    } else {
        None
    };

    let config_directory = if let Some(cfg) = matches.get_one::<String>("config") {
        let config_path = Path::new(cfg);
        if config_path.exists() && config_path.is_dir() {
            config_path.canonicalize().unwrap()
        } else {
            current_directory.clone()
        }
    } else {
        info!("No config file specified, using default.");
        std::env::current_dir().unwrap()
    };
    // If a key is provided, create a directory for the config with onion service name from the key.
    // If that directory does not exist, create it, if it does, use it.
    // If no key is provided, check if any directory exists that starts with .arti-fact-config.
    // If no such directory exists, create one.
    // If exactly one such directory exists, use it.
    // If multiple such directories exist, make the user choose one in the CLI.

    let config_directory = if let Some(sk) = secret_key {
        // Use onion address as config dir name
        let onion_addr = get_onion_address(
            &ed25519_dalek::SigningKey::from_bytes(&sk)
                .verifying_key()
                .to_bytes(),
        );
        let dir_name = format!(".arti-fact-config-{onion_addr}");
        let dir_path = config_directory.join(dir_name.clone()).clone();
        if !dir_path.exists() {
            fs::create_dir_all(&dir_path).expect("Failed to create config directory");
        }
        dir_path.canonicalize().unwrap()
    } else {
        // Find all dirs starting with .arti-fact-config
        let mut config_dirs: Vec<_> = fs::read_dir(config_directory.clone())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".arti-fact-config")
            })
            .collect();

        match config_dirs.len() {
            0 => {
                // Create new
                secret_key = Some(generate_key());
                let onion_addr = get_onion_address(
                    &ed25519_dalek::SigningKey::from_bytes(&secret_key.unwrap())
                        .verifying_key()
                        .to_bytes(),
                );
                let dir_name = format!(".arti-fact-config-{onion_addr}");
                let dir_path = config_directory.join(dir_name).clone();
                fs::create_dir_all(&dir_path).expect("Failed to create config directory");
                dir_path.canonicalize().unwrap()
            }
            1 => config_dirs.pop().unwrap().path().canonicalize().unwrap(),
            _ => {
                // Ask user to choose
                println!("Multiple config directories found:");
                println!("  [0] Create a new directory");
                for (i, entry) in config_dirs.iter().enumerate() {
                    println!("  [{}] {}", i + 1, entry.path().display());
                }
                println!("Select a config directory by number:");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                let idx: usize = input.trim().parse().expect("Invalid input");
                if idx == 0 {
                    // Create new
                    secret_key = Some(generate_key());
                    let onion_addr = get_onion_address(
                        &ed25519_dalek::SigningKey::from_bytes(&secret_key.unwrap())
                            .verifying_key()
                            .to_bytes(),
                    );
                    let dir_name = format!(".arti-fact-config-{onion_addr}");
                    let dir_path = config_directory.join(dir_name).clone();
                    fs::create_dir_all(&dir_path).expect("Failed to create config directory");
                    dir_path.canonicalize().unwrap()
                } else {
                    config_dirs
                        .get(idx - 1)
                        .expect("Invalid selection")
                        .path()
                        .canonicalize()
                        .unwrap()
                }
            }
        }
    };

    println!("Using config directory: {config_directory:?}");

    // if secret_key is Some, print it in hex format
    if let Some(sk) = secret_key {
        println!("Using secret key: {}", hex::encode(sk));
    }

    let custom_css = if let Some(css_file) = matches.get_one::<String>("css") {
        let css_path = PathBuf::from(css_file);
        if css_path.exists() && css_path.is_file() {
            println!("Using custom CSS from: {css_file}");
            Some(fs::read_to_string(css_path).expect("Failed to read CSS file"))
        } else {
            panic!("CSS file does not exist or is not a file: {css_file}");
        }
    } else {
        None
    };

    let visitor_tracking = if matches.get_flag("tracking") {
        info!("Visit tracking enabled, saving visit counts in config directory");
        load_visit_log(&config_directory);
        true
    } else {
        info!("Visit tracking disabled");
        false
    };

    info!("Starting Tor client");

    let rt = if let Ok(runtime) = PreferredRuntime::current() {
        runtime
    } else {
        PreferredRuntime::create().expect("could not create async runtime")
    };

    let mut config = TorClientConfigBuilder::from_directories(
        config_directory.join("arti-config"),
        config_directory.join("arti-cache"),
    );
    config.address_filter().allow_onion_addrs(true);

    let config = config.build().expect("error building tor config");

    let binding = TorClient::with_runtime(rt.clone()).config(config);
    let client_future = binding.create_bootstrapped();

    rt.block_on(async {
        let client = client_future.await.unwrap();

        info!("Tor client started");

        if matches.get_flag("managed") {
            run_managed_service(
                client.clone(),
                config_directory,
                custom_css,
                visitor_tracking,
            )
            .await;
        } else {
            onion_service_from_sk(
                client.clone(),
                data_directory,
                config_directory,
                secret_key,
                custom_css,
                visitor_tracking,
            )
            .await;
            loop {}
        }
    });
}
