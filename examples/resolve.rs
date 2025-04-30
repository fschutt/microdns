use microdns::{resolve_mx_server_ips_with_config, DnsConfig, Error};

fn main() -> Result<(), Error> {
    let domain = std::env::args().nth(1).unwrap_or_else(|| "example.com".to_string());
    
    // Custom DNS config with shorter timeout
    let config = DnsConfig {
        servers: vec![
            "1.1.1.1".to_string(),         // Cloudflare
            "1.0.0.1".to_string(),         // Cloudflare secondary
            "8.8.8.8".to_string(),         // Google
            "8.8.4.4".to_string(),         // Google secondary
            "9.9.9.9".to_string(),         // Quad9
            "149.112.112.112".to_string(), // Quad9 secondary
        ],
        timeout: 3,
    };
    
    println!("Resolving mail servers for {}", domain);
    
    let server_ips = resolve_mx_server_ips_with_config(&domain, Some(config))?;
    
    println!("\nMail servers and their IP addresses:");
    for server in server_ips {
        println!("\nServer: {} ({} IPs)", server.server, server.ip_addresses.len());
        for ip in server.ip_addresses {
            println!("  {}", ip);
        }
    }
    
    Ok(())
}
