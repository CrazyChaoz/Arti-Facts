use clap::{Arg, Command};

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::{Stream, StreamExt};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::pin::Pin;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::{PreferredRuntime, ToplevelBlockOn};

fn new(
    data_directory: PathBuf,
    config_directory: PathBuf,
    onion_address_secret_key: [u8; 32],
) -> TorClient<PreferredRuntime> {
    eprintln!("Starting Tor client");

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

        println!("Tor client started");

        onion_service_from_sk(
            client.clone(),
            data_directory,
            config_directory,
            &onion_address_secret_key,
        )
        .await;
        client
    })
}

async fn onion_service_from_sk(
    tor_client: TorClient<PreferredRuntime>,
    data_directory: PathBuf,
    config_directory: PathBuf,
    secret_key: &[u8],
) -> String {
    let sk = <[u8; 32]>::try_from(secret_key).expect("could not convert to [u8; 32]");
    let sk = sk as ed25519_dalek::SecretKey;
    let expanded_secret_key = ed25519_dalek::hazmat::ExpandedSecretKey::from(&sk);
    let esk = <[u8; 64]>::try_from(
        [
            expanded_secret_key.scalar.to_bytes(),
            expanded_secret_key.hash_prefix,
        ]
        .concat()
        .as_slice(),
    )
    .unwrap();
    let expanded_key_pair =
        ExpandedKeypair::from_secret_key_bytes(esk).expect("error converting to ExpandedKeypair");
    let pk = expanded_key_pair.public();

    let onion_address = get_onion_address(&pk.to_bytes());
    let clone_onion_address = onion_address.clone();
    let nickname = format!(
        "arti-facts-{}",
        onion_address.clone().chars().take(16).collect::<String>()
    );

    let encodable_key = tor_hscrypto::pk::HsIdKeypair::from(expanded_key_pair);

    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname(nickname.clone().parse().unwrap())
        .build()
        .unwrap();

    let (onion_service, request_stream): (
        _,
        Pin<Box<dyn Stream<Item = tor_hsservice::RendRequest> + Send>>,
    ) = if let Ok((service, stream)) =
        tor_client.launch_onion_service_with_hsid(svc_cfg.clone(), encodable_key)
    {
        (service, Box::pin(stream))
    } else {
        // This key exists; reuse it
        let (service, stream) = tor_client
            .launch_onion_service(svc_cfg)
            .expect("error creating onion service");
        (service, Box::pin(stream))
    };
    println!(
        "onion service created: {}",
        onion_service.onion_address().unwrap()
    );
    println!("status: {:?}", onion_service.status());

    while let Some(status_event) = onion_service.status_events().next().await {
        if status_event.state().is_fully_reachable() {
            break;
        }
    }
    println!("status: {:?}", onion_service.status());

    let accepted_streams = tor_hsservice::handle_rend_requests(request_stream);

    tokio::pin!(accepted_streams);

    while let Some(stream_request) = accepted_streams.next().await {
        println!("new stream");
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
                    .unwrap();
            }
            _ => {
                stream_request.shutdown_circuit().unwrap();
            }
        };
    }
    drop(onion_service);
    println!("onion service dropped");

    clone_onion_address
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
) -> Result<Response<String>, anyhow::Error> {
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
            .body("Access to cache directory is forbidden".to_string())?);
    }

    // If path is a directory or root, list files
    if file_path.is_dir() || path.is_empty() {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&file_path)? {
            let entry = entry?;
            let entry_path = entry.path();
            // Skip cache_dir and its contents
            if entry_path
                .canonicalize()
                .map(|p| p.starts_with(&config_directory))
                .unwrap_or(false)
            {
                continue;
            }
            let name = entry.file_name().into_string().unwrap_or_default();
            if entry_path.is_dir() {
                entries.push(format!("{}/", name));
            } else {
                entries.push(name);
            }
        }
        let body = format!(
            "<!DOCTYPE html><html><head><title>Index of /{0}</title></head><body><h1>Index of /{0}</h1><ul>{1}</ul></body></html>",
            path,
            entries
                .iter()
                .map(|e| {
                    let href = if path.is_empty() {
                        format!("{}", e)
                    } else {
                        format!("{}/{}", path, e)
                    };
                    format!("<li><a href=\"/{href}\">{}</a></li>", e)
                })
                .collect::<String>()
        );
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(body)?);
    }

    // If path is a file, return its contents
    if file_path.is_file() {
        let mut file = fs::File::open(&file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        return Ok(Response::builder().status(StatusCode::OK).body(contents)?);
    }

    // Not found
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("File or directory not found".to_string())?)
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
        .version("0.1.0")
        .about("A CLI tool")
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
        .get_matches();

    let current_directory = std::env::current_dir().unwrap();

    let directory = if let Some(dir) = matches.get_one::<String>("directory") {
        println!("Working directory: {}", dir);
        std::path::Path::new(dir)
            .canonicalize()
            .unwrap_or_else(|_| {
                println!("Invalid directory specified, using current directory instead.");
                current_directory.clone()
            })
    } else {
        println!("No directory specified, using default.");
        current_directory.clone()
    };

    println!("Sharing directory: {:?}", directory);

    let config_directory = if let Some(cfg) = matches.get_one::<String>("config") {
        let config_path = std::path::Path::new(cfg);
        let target_dir = if config_path.exists() && config_path.is_dir() {
            config_path
        } else {
            current_directory.as_path()
        };
        let arti_fact_dir = target_dir.join(".arti-fact-config");
        match std::fs::create_dir_all(&arti_fact_dir) {
            Ok(_) => println!("Created directory: {:?}", arti_fact_dir),
            Err(e) => eprintln!("Failed to create directory: {:?} ({})", arti_fact_dir, e),
        }
        arti_fact_dir
    } else {
        println!("No config file specified, using default.");
        std::env::current_dir().unwrap().join(".arti-fact-config")
    };

    println!("Using config directory: {:?}", config_directory);

    let secret_key = generate_key();

    new(directory.clone(), config_directory.clone(), secret_key);
}
