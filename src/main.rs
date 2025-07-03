mod management;
mod onion_http_server;
mod utils;

use crate::onion_http_server::load_visit_log;
use crate::utils::{generate_key, get_onion_address};
use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use clap::{Arg, Command};
use log::info;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tor_rtcompat::{PreferredRuntime, ToplevelBlockOn};

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
        ).arg(
            Arg::new("proxy")
                .short('p')
                .long("proxy")
                .value_name("URL")
                .help("Sets a forwarding URL.\n\
                       Sample: 127.0.0.1:54321\n\
                       e.g. asdfasdfasdf.onion:80 -> 127.0.0.1:54321")
        ).arg(
            Arg::new("extended-proxy")
                .long("extended-proxy")
                .value_name("(PORT, URL)")
                .help("Sets an extended forwarding URL for the Tor client.\n\
                    Example: (12345, 127.0.0.1:54321)\n\
                    This maps asdfasdfasdf.onion:12345 -> 127.0.0.1:54321",
                )
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

    let mut proxy_url = if matches.get_one::<String>("proxy").is_some() {
        let sock_addr: SocketAddr = matches
            .get_one::<String>("proxy")
            .map(|s| s.to_string())
            .unwrap()
            .parse()
            .expect("Invalid proxy URL format");
        Some((80, sock_addr))
    } else {
        None
    };

    proxy_url = if let Some(ext_proxy) = matches.get_one::<String>("extended-proxy") {
        // Remove possible parentheses and whitespace, then split
        let trimmed = ext_proxy
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')');
        let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            panic!("Invalid extended proxy format, expected (PORT, URL)");
        }
        let port: u16 = parts[0]
            .parse()
            .expect("Invalid port number in extended proxy");
        let sock_addr: SocketAddr = parts[1].parse().expect("Invalid URL in extended proxy");
        Some((port, sock_addr))
    } else {
        proxy_url
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
            management::run_managed_service(
                client.clone(),
                config_directory,
                custom_css,
                visitor_tracking,
            )
            .await;
        } else {
            onion_http_server::onion_service_from_sk(
                client.clone(),
                data_directory,
                config_directory,
                secret_key,
                custom_css,
                proxy_url,
                visitor_tracking,
            )
            .await;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    });
}
