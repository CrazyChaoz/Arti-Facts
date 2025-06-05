# arti-facts

arti-facts is a command-line tool and webserver that allows you to securely share files and directories over the Tor network using an onion service. It is written in Rust and leverages the arti Tor client libraries.

## Features
- **Secure File Sharing:** Serves files and directories from a specified folder over a Tor onion service (v3).
- **Access Control:** Prevents access to configuration and cache directories.
- **Directory Listing:** Provides a simple HTML index for browsing shared directories.
- **Configurable:** Allows you to specify the data directory to share and a custom configuration directory.

## Usage

```
arti-facts [OPTIONS]
```

### Options
- `-d, --directory <DIR>`: Sets the working directory to share (default: current directory).
- `-c, --config <FILE>`: Sets a custom config directory (default: `.arti-fact-config` in the current directory).

## How It Works
1. **Tor Client Initialization:** Starts a Tor client in the background.
2. **Onion Service Creation:** Generates a new onion service using a random key.
3. **Webserver:** Listens for HTTP requests on the onion service and serves files/directories from the specified data directory.
4. **Security:** Blocks access to the config/cache directory and prevents directory traversal outside the shared folder.

## Example

```
arti-facts --directory /path/to/share --config /path/to/config
```

After running, arti-facts will print the onion address. You (or others) can access the shared files using Tor Browser or a compatible client by visiting:

```
http://<onion-address>.onion/
```

## Requirements
- Rust (for building from source)
- Internet access (for Tor network connectivity)

## License

This project is licensed under the EUPL License. See the [LICENSE](LICENSE) file for details.
