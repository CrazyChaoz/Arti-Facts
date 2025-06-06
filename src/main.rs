use clap::{Arg, Command};
use futures::{AsyncWriteExt, TryStreamExt};
use std::fs;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use async_zip::{ZipEntryBuilder, ZipString};
use futures::{Stream, StreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::info;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;
use std::pin::Pin;
use tokio_util::io::ReaderStream;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::{PreferredRuntime, ToplevelBlockOn};

use async_zip::{tokio::write::ZipFileWriter, Compression};

const INDEX_TEMPLATE: &str = include_str!("index.html");

fn new(
    data_directory: PathBuf,
    config_directory: PathBuf,
    onion_address_secret_key: Option<[u8; 32]>,
) -> TorClient<PreferredRuntime> {
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

        onion_service_from_sk(
            client.clone(),
            data_directory,
            config_directory,
            onion_address_secret_key,
        )
        .await;
        client
    })
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

                let data_dir = data_directory.clone();

                http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|request| {
                            service_function(request, data_dir.clone(), config_directory.clone())
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
}

/// Handles an HTTP request by serving files or directory listings from the specified data directory,
/// while restricting access to the configuration directory.
///
/// # Arguments
///
/// * `request` - The incoming HTTP request.
/// * `data_dir` - The base directory from which files and directories are served.
/// * `config_directory` - The directory containing configuration files, which must not be accessible.
///
/// # Returns
///
/// Returns a `Result` containing either a `Response<String>` with the requested file contents or directory listing,
/// or an error if access is forbidden or the resource is not found.
///
/// # Behavior
///
/// - Prevents access to files outside `data_dir` or within `config_directory`.
/// - If the requested path is a directory or root, returns an HTML index of its contents.
/// - If the requested path is a file, returns its contents.
/// - Returns 403 Forbidden if access to the config directory is attempted.
/// - Returns 404 Not Found if the file or directory does not exist.
async fn service_function(
    request: Request<Incoming>,
    data_dir: PathBuf,
    config_directory: PathBuf,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>, std::io::Error> {
    let path = request.uri().path().trim_start_matches('/').to_string();
    let mut file_path = data_dir.join(&path);

    // Prevent access to any file outside of data_dir or to config_directory
    let data_dir_canon = data_dir.canonicalize()?;
    let file_path_canon = file_path.canonicalize().unwrap_or(data_dir_canon.clone());
    if !file_path_canon.starts_with(&data_dir_canon)
        || file_path_canon.starts_with(&config_directory)
    {
        file_path = data_dir_canon;
    }

    // Prevent access to config_directory or its subdirectories
    let config_directory = config_directory.canonicalize()?;
    if file_path
        .canonicalize()
        .map(|p| p.starts_with(&config_directory))
        .unwrap_or(false)
    {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(
                Full::new("Access to config directory is forbidden".as_bytes().into())
                    .map_err(|e| match e {})
                    .boxed(),
            )
            .unwrap());
    }
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
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
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

        return Ok(Response::builder()
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
        let mut entries = Vec::new();
        for entry in fs::read_dir(&file_path)? {
            let entry = entry?;
            let entry_path = entry.path();
            // Skip config_dir and its contents
            if entry_path
                .canonicalize()
                .map(|p| p.starts_with(&config_directory))
                .unwrap_or(false)
            {
                continue;
            }
            let name = entry.file_name().into_string().unwrap_or_default();
            let metadata = entry.metadata()?;
            let file_type = if entry_path.is_dir() { "📁" } else { "📄" };
            let size = if entry_path.is_file() {
                let len = metadata.len();
                if len >= 1 << 30 {
                    format!("{:.2} GiB", len as f64 / (1 << 30) as f64)
                } else if len >= 1 << 20 {
                    format!("{:.2} MiB", len as f64 / (1 << 20) as f64)
                } else if len >= 1 << 10 {
                    format!("{:.2} KiB", len as f64 / (1 << 10) as f64)
                } else {
                    format!("{} bytes", len)
                }
            } else {
                String::from("-")
            };
            let modified = metadata
                .modified()
                .ok()
                .map(|m| {
                    let datetime: chrono::DateTime<chrono::Local> = m.into();
                    datetime.format("%H:%M | %Y-%m-%d").to_string()
                })
                .unwrap_or_else(|| "-".to_string());

            entries.push(format!(
                "<tr><td>{}</td><td><a href=\"/{href}\">{}</a></td><td>{}</td><td>{}</td></tr>",
                file_type,
                name,
                size,
                modified,
                href = if path.is_empty() {
                    format!("{}", name)
                } else {
                    format!("{}/{}", path, name)
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
            format!(
                "<a href=\"/{}\" class=\"button left\">⬆️ Parent directory</a>",
                parent
            )
        };
        let body = INDEX_TEMPLATE
            .replace("{0}", &path)
            .replace("{1}", &entries.join(""))
            .replace("{parent_dir}", &go_back);

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::<Bytes>::from(body).map_err(|e| match e {}).boxed())
            .unwrap());
    }

    // If path is a file, return its contents
    if file_path.is_file() {
        let file = tokio::fs::File::open(&file_path).await.unwrap();

        // Wrap to a tokio_util::io::ReaderStream
        let reader_stream = tokio_util::io::ReaderStream::new(file);

        // Convert to http_body_util::BoxBody
        let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
        let boxed_body = BodyExt::boxed(stream_body);

        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download");

        let mut response_builder = Response::builder().status(StatusCode::OK);

        if request.uri().query() == Some("download") {
            response_builder = response_builder.header(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", file_name),
            );
        }

        // Send response
        return Ok(response_builder.body(boxed_body).unwrap());
    }

    // Not found
    Ok(Response::builder()
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

fn main() {
    let matches = Command::new("arti-facts")
        .version("2.0.1")
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
        .get_matches();

    let current_directory = std::env::current_dir().unwrap();

    let directory = if let Some(dir) = matches.get_one::<String>("directory") {
        info!("Working directory: {}", dir);
        std::path::Path::new(dir)
            .canonicalize()
            .unwrap_or_else(|_| {
                info!("Invalid directory specified, using current directory instead.");
                current_directory.clone()
            })
    } else {
        info!("No directory specified, using default.");
        current_directory.clone()
    };

    println!("Sharing directory: {:?}", directory);

    let mut secret_key = if let Some(hex_key) = matches.get_one::<String>("key") {
        if hex_key.len() != 64 {
            panic!("Secret key must be a 32-byte hexadecimal string (64 characters).");
        }
        let mut sk = [0u8; 32];
        hex::decode_to_slice(hex_key, &mut sk).expect("Invalid hex string for secret key");
        Some(sk)
    } else {
        None
    };

    let config_directory = if let Some(cfg) = matches.get_one::<String>("config") {
        let config_path = std::path::Path::new(cfg);
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
        let dir_name = format!(".arti-fact-config-{}", onion_addr);
        let dir_path = config_directory.join(dir_name.clone()).clone();
        if !dir_path.exists() {
            fs::create_dir_all(&dir_path).expect("Failed to create config directory");
        }
        dir_path.canonicalize().unwrap()
    } else {
        // Find all dirs starting with .arti-fact-config
        let mut config_dirs: Vec<_> = fs::read_dir(config_directory.clone())
            .unwrap()
            .filter_map(|e| e.ok())
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
                let dir_name = format!(".arti-fact-config-{}", onion_addr);
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
                    let dir_name = format!(".arti-fact-config-{}", onion_addr);
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

    println!("Using config directory: {:?}", config_directory);

    // if secret_key is Some, print it in hex format
    if let Some(sk) = secret_key {
        println!("Using secret key: {}", hex::encode(sk));
    }

    new(directory.clone(), config_directory.clone(), secret_key);
}
