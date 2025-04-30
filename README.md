# microdns

[![Crates.io](https://img.shields.io/crates/v/microdns.svg)](https://crates.io/crates/microdns)
[![Documentation](https://docs.rs/microdns/badge.svg)](https://docs.rs/microdns)
[![License: MIT](https://img.shields.io/crates/l/microdns.svg)](https://github.com/fschutt/microdns#license)

A minimal DNS resolver library with zero dependencies, using only the Rust standard library.

## Features

- **Zero dependencies**: Uses only Rust standard library
- **Simple API**: Easy to use with sensible defaults
- **Configurable**: Customize DNS servers and timeouts
- **Multiple record types**: Supports MX, A, and AAAA records
- **Error handling**: Comprehensive error types with descriptive messages
- **No unsafe code**: 100% safe Rust

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
microdns = "0.1.0"
```

## Usage

### Basic MX Record Lookup

```rust
use microdns::{lookup_mx_records, Error};

fn main() -> Result<(), Error> {
    let mx_records = lookup_mx_records("example.com")?;
    
    for mx in mx_records {
        println!("Priority: {}, Server: {}", mx.priority, mx.server);
    }
    
    Ok(())
}
```

### Resolving IP Addresses

```rust
use microdns::{lookup_ip_addresses, Error};

fn main() -> Result<(), Error> {
    let ips = lookup_ip_addresses("example.com")?;
    
    for ip in ips {
        println!("IP: {}", ip);
    }
    
    Ok(())
}
```

### Complete Mail Server Resolution

```rust
use microdns::{resolve_mx_server_ips, Error};

fn main() -> Result<(), Error> {
    let server_ips = resolve_mx_server_ips("example.com")?;
    
    for server in server_ips {
        println!("Server: {}", server.server);
        for ip in server.ip_addresses {
            println!("  IP: {}", ip);
        }
    }
    
    Ok(())
}
```

### Custom DNS Configuration

```rust
use microdns::{lookup_ip_addresses_with_config, DnsConfig, Error};

fn main() -> Result<(), Error> {
    // Use custom DNS servers and timeout
    let config = DnsConfig {
        servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        timeout: 3,
    };
    
    let ips = lookup_ip_addresses_with_config("example.com", Some(config))?;
    
    for ip in ips {
        println!("IP: {}", ip);
    }
    
    Ok(())
}
```

## Default DNS Servers

The library defaults to using these DNS servers in order:

1. 1.1.1.1 (Cloudflare primary)
2. 1.0.0.1 (Cloudflare secondary)
3. 8.8.8.8 (Google primary)
4. 8.8.4.4 (Google secondary)

## License

MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
