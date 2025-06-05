use clap::{Arg, Command};
use log::info;




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
}
