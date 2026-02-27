use arti_facts::start_service_blocking;
use clap::{Arg, Command};
use log::error;
use log::info;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
    prelude::*,
};


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
        )
        .arg(
            Arg::new("managed")
                .long("managed")
                .action(clap::ArgAction::SetTrue)
                .help("Run the service in managed mode, serving the management UI"),
        )
        .arg(
            Arg::new("proxy")
                .short('p')
                .long("proxy")
                .value_name("URL")
                .help("Sets a forwarding URL, e.g. 127.0.0.1:54321"),
        )
        .arg(
            Arg::new("extended-proxy")
                .long("extended-proxy")
                .value_name("(PORT, URL)")
                .help("Sets an extended forwarding URL for the Tor client.\nExample: (12345, 127.0.0.1:54321)"),
        )
        .get_matches()
}

fn init_logging(cli_loglevel:u8) {
    // Start with: default=info, arti crates=error
    
    let log_level = match cli_loglevel {
        0 => LevelFilter::ERROR,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let mut filter = EnvFilter::builder()
        .parse_lossy(format!("arti_facts={log_level},arti_client=error,tor_hsservice=error,tor_dirmgr=error,tor_guardmgr=error,tor_circmgr=error"));

    // If ARTI_LOG is set, override the arti crate levels with whatever it says.
    // e.g. ARTI_LOG=debug  → sets both arti crates to debug
    // e.g. ARTI_LOG=arti_client=warn,tor_stuff=trace  → fine-grained control
    if let Ok(arti_log) = std::env::var("ARTI_LOG") {
        for directive in arti_log.split(',') {
            let directive = directive.trim();
            if directive.is_empty() { continue; }

            // If it's a bare level like "debug", apply it to all arti crates
            if let Ok(level) = directive.parse::<LevelFilter>() {
                filter = filter
                    .add_directive(format!("arti_client={level}").parse().unwrap())
                    .add_directive(format!("tor_hsservice={level}").parse().unwrap())
                    .add_directive(format!("tor_dirmgr={level}").parse().unwrap())
                    .add_directive(format!("tor_guardmgr={level}").parse().unwrap())
                    .add_directive(format!("tor_circmgr={level}").parse().unwrap());
            } else {
                // Otherwise treat it as a full directive like "arti_client=warn"
                if let Ok(d) = directive.parse() {
                    filter = filter.add_directive(d);
                }
            }
        }
    }

    // Also respect RUST_LOG for your own crate's level, if set.
    // Directives added later override earlier ones for the same target,
    // so RUST_LOG can still override everything if you want.
    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        for directive in rust_log.split(',') {
            if let Ok(d) = directive.trim().parse() {
                filter = filter.add_directive(d);
            }
        }
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = cli_args();

    // Initialize logging based on verbosity level
    init_logging(matches.get_count("verbose"));    

    let current_directory = std::env::current_dir().expect("failed to determine current directory");
    
    // Determine data_directory (what to share)
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

    info!("Sharing directory: {}", data_directory.display());

    // Secret key as hex if provided
    let secret_key_hex = matches.get_one::<String>("key").map(|s| s.to_string());

    // Determine config_directory (pass-through; the library will create its own subi-dirs)
    let config_directory = if let Some(cfg) = matches.get_one::<String>("config") {
        let config_path = PathBuf::from(cfg);
        if config_path.exists() && config_path.is_dir() {
            config_path.canonicalize().unwrap_or(config_path)
        } else {
            current_directory.clone()
        }
    } else {
        info!("No config file specified, using default.");
        current_directory.clone()
    };

    info!("Using config directory: {}", config_directory.display());

    // Read custom CSS file if provided (we pass the content to the library)
    let custom_css_content = if let Some(css_file) = matches.get_one::<String>("css") {
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

    // Build a proxy string to pass to the FFI-friendly function.
    // We accept either `proxy` or `extended-proxy`. For extended-proxy we strip surrounding parens.
    let proxy_param = if let Some(p) = matches.get_one::<String>("proxy") {
        Some(p.to_string())
    } else if let Some(ext) = matches.get_one::<String>("extended-proxy") {
        // remove possible parentheses and pass the inner string (e.g. "12345, 127.0.0.1:54321")
        let trimmed = ext.trim().trim_start_matches('(').trim_end_matches(')');
        Some(trimmed.to_string())
    } else {
        None
    };

    let visitor_tracking = matches.get_flag("tracking");
    let managed = matches.get_flag("managed");

    // Convert paths
    let data_directory = PathBuf::from(data_directory);
    let config_directory = PathBuf::from(config_directory);

    // Parse secret key if provided
    let secret_key = if let Some(hex_key) = secret_key_hex {        
        if hex_key.len() != 64 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "secret_key_hex must be 64 hex characters (32 bytes)",
            )));
        }
        let mut sk = [0u8; 32];
        if let Err(e) = hex::decode_to_slice(&hex_key, &mut sk) {
            error!("invalid hex string for secret key: {}", e);
            return Err(Box::new(e));
        }
        Some(sk)
    } else {
        None
    };

    // Parse proxy if provided
    let forward_proxy: Option<(u16, SocketAddr)> = if let Some(proxy_str) = proxy_param {
        let trimmed = proxy_str.trim();
        // If contains comma, treat as (PORT,ADDR)
        if trimmed.contains(',') {
            let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
            if parts.len() != 2 {                
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "proxy must be in format \"PORT,ADDR\" or \"ADDR\"",
                )));
            }
            let port: u16 = parts[0].parse().map_err(|_| "invalid port in proxy")?;
            let addr: SocketAddr = parts[1].parse().map_err(|_| "invalid address in proxy")?;
            Some((port, addr))
        } else {
            // Single address: assume port 80
            let addr: SocketAddr = trimmed.parse().map_err(|_| "invalid address in proxy")?;
            Some((80, addr))
        }
    } else {
        None
    };

    // Call the blocking entry
    match start_service_blocking(
        data_directory,
        config_directory,
        secret_key,
        custom_css_content,
        forward_proxy,
        visitor_tracking,
        managed,
    ) {
        Ok(_) => {
            println!("Service finished successfully");
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to start service: {e}");
            Err(e)
        }
    }
}
