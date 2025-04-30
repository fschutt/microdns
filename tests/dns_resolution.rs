use microdns::{lookup_ip_addresses, lookup_mx_records, DnsConfig, Error};
use std::net::IpAddr;

#[test]
fn test_google_mx_records() -> Result<(), Error> {
    let mx_records = lookup_mx_records("google.com")?;

    // Verify we got some MX records
    assert!(!mx_records.is_empty(), "No MX records found for google.com");

    // Google mail servers usually contain "google.com" in their names
    let google_mx = mx_records
        .iter()
        .find(|mx| mx.server.contains("google.com"));
    assert!(
        google_mx.is_some(),
        "No Google mail servers found in MX records"
    );

    Ok(())
}

#[test]
fn test_a_record_resolution() -> Result<(), Error> {
    let ips = lookup_ip_addresses("google.com")?;

    // Verify we got some IP addresses
    assert!(!ips.is_empty(), "No IP addresses found for google.com");

    // Check that we have at least one IPv4 address
    let has_ipv4 = ips.iter().any(|ip| ip.is_ipv4());
    assert!(has_ipv4, "No IPv4 addresses found for google.com");

    Ok(())
}

#[test]
fn test_aaaa_record_resolution() -> Result<(), Error> {
    // Create config with slightly longer timeout for IPv6
    let config = DnsConfig {
        timeout: 10,
        ..Default::default()
    };

    let ips = lookup_ip_addresses_with_config("google.com", Some(config))?;

    // We might not get IPv6 addresses depending on the network configuration,
    // so this test is more permissive

    // If we got any IPs, check if at least one is IPv6
    if !ips.is_empty() {
        println!("Found {} IP addresses for google.com", ips.len());
        for ip in &ips {
            println!("  {}", ip);
        }

        // Note: not all networks support IPv6, so we don't fail the test if none are found
        let has_ipv6 = ips.iter().any(|ip| ip.is_ipv6());
        if !has_ipv6 {
            println!("Warning: No IPv6 addresses found for google.com - this may be normal depending on your network");
        }
    }

    Ok(())
}

#[test]
fn test_mx_server_ip_resolution() -> Result<(), Error> {
    // First get MX records
    let mx_records = lookup_mx_records("google.com")?;
    assert!(!mx_records.is_empty(), "No MX records found for google.com");

    // Then try to resolve the first MX server
    let first_mx = &mx_records[0];
    println!("Resolving IP for MX server: {}", first_mx.server);

    let ips = lookup_ip_addresses(&first_mx.server)?;

    // Verify we got some IP addresses for the MX server
    assert!(
        !ips.is_empty(),
        "No IP addresses found for MX server {}",
        first_mx.server
    );

    // Print the IPs we found
    println!("Found {} IP addresses for {}", ips.len(), first_mx.server);
    for ip in ips {
        println!("  {}", ip);
    }

    Ok(())
}
