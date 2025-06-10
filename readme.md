# arti-facts

arti-facts is a command-line tool and webserver that lets you securely share files and directories over the Tor network using an onion service. Built in Rust, it leverages the arti Tor client libraries for privacy and security.

## 🚀 Quick Start: Download a Release

**No need to build from source!**

- Pre-built binaries for **Windows** and **Linux** are available on the [GitHub Releases page](https://github.com/CrazyChaoz/Arti-Facts/releases). Just download and run!
- No installation required—get started in seconds.

## Why Use arti-facts?
- **Share Anything, Privately:** Share any folder or file with anyone, anywhere, without exposing your IP address.
- **Zero Setup for Recipients:** Recipients only need Tor Browser to access your files—no extra software required.
- **Simple & Fast:** Start sharing in seconds with a single command. No accounts, no cloud, no hassle.
- **You’re in Control:** You choose what to share, and only those with your onion address can access it.

## Features
- **Secure File Sharing:** Serve files and directories from any folder over a Tor onion service (v3).
- **Access Control:** Blocks access to configuration and cache directories for your safety.
- **Beautiful Directory Listing:** Clean, modern HTML index for browsing and downloading files.
- **Instant ZIP Download:** Download entire folders as .zip archives with one click.
- **Configurable:** Choose the data directory to share and a custom configuration directory.
- 
## Building from Source (Optional)

1. **Install Rust** (if you haven’t already):
   https://rustup.rs/

2. **Build arti-facts:**
   ```sh
   cargo build --release
   ```

3. **Run arti-facts:**
   ```sh
   ./target/release/arti-facts --directory /path/to/share
   ```
   Or just run without arguments to share your current folder!

4. **Share the Onion Address:**
   arti-facts will print a .onion address. Anyone with Tor Browser can visit it and browse/download your files.

## Command-Line Options
- `-d, --directory <DIR>`: Sets the working directory to share (default: current directory).
- `-c, --config <FILE>`: Sets a custom config directory (default: `.arti-fact-config` in the current directory).
- `-k, --key <HEX>`: Provide a 32-byte secret key in hexadecimal format (for persistent onion addresses).

## How It Works
1. **Tor Client Initialization:** Starts a Tor client in the background.
2. **Onion Service Creation:** Generates a new onion service (or reuses a persistent one if you provide a key).
3. **Webserver:** Listens for HTTP requests on the onion service and serves files/directories from your chosen folder.
4. **Security:** Blocks access to the config/cache directory and prevents directory traversal outside the shared folder.

## Example

```sh
arti-facts --directory /path/to/share --config /path/to/config
```

After running, arti-facts will print the onion address. You (or others) can access the shared files using Tor Browser or a compatible client by visiting:

```
http://<onion-address>.onion/
```

## Requirements
- Rust (for building from source)
- Internet access (for Tor network connectivity)

## Ready to Share Securely?
Try arti-facts today and experience effortless, private file sharing over Tor. Your files, your rules—no middleman, no tracking, just privacy.

## License

This project is licensed under the EUPL License. See the [LICENSE](LICENSE) file for details.
