//! # microdns
//!
//! A minimal DNS resolver library using only the Rust standard library.
//!
//! This crate provides functionality to resolve various DNS record types,
//! including MX records for mail servers and A/AAAA records for IP addresses.
//!
//! ## Example
//!
//! ```rust
//! use microdns::{lookup_mx_records, lookup_ip_addresses, resolve_mx_server_ips};
//!
//! fn main() -> Result<(), microdns::Error> {
//!     let domain = "example.com";
//!     
//!     // Get MX records
//!     let mx_records = lookup_mx_records(domain)?;
//!     
//!     // Get IP addresses for a specific hostname
//!     let ips = lookup_ip_addresses("mail.example.com")?;
//!     
//!     // Or resolve all MX servers to their IPs
//!     let server_ips = resolve_mx_server_ips(domain)?;
//!     
//!     Ok(())
//! }
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;
use std::io;
use std::error;

/// Default DNS servers to try (in order)
pub const DEFAULT_DNS_SERVERS: &[&str] = &[
    "1.1.1.1",   // Cloudflare primary (fastest)
    "1.0.0.1",   // Cloudflare secondary
    "8.8.8.8",   // Google primary
    "8.8.4.4",   // Google secondary
];

/// DNS record type constants
pub const DNS_TYPE_A: u16 = 1;     // A record (IPv4 address)
pub const DNS_TYPE_MX: u16 = 15;   // MX record (mail exchange)
pub const DNS_TYPE_AAAA: u16 = 28; // AAAA record (IPv6 address)

/// Error type for DNS operations
#[derive(Debug)]
pub enum Error {
    /// An IO error occurred
    Io(io::Error),
    /// DNS query timed out
    Timeout,
    /// DNS server returned an error code
    ServerError(u16),
    /// No records found for the requested domain/type
    NoRecordsFound,
    /// Malformed DNS packet
    MalformedPacket,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "IO error: {}", err),
            Error::Timeout => write!(f, "DNS query timed out"),
            Error::ServerError(code) => write!(f, "DNS server returned error code: {}", code),
            Error::NoRecordsFound => write!(f, "No DNS records found"),
            Error::MalformedPacket => write!(f, "Malformed DNS packet"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

/// DNS header structure
#[derive(Debug)]
pub struct DnsHeader {
    /// Transaction ID
    pub id: u16,
    /// Flags field 
    pub flags: u16,
    /// Number of questions
    pub questions: u16,
    /// Number of answer records
    pub answers: u16,
    /// Number of authority records
    pub authorities: u16,
    /// Number of additional records
    pub additionals: u16,
}

/// Parse DNS header from buffer
pub fn parse_dns_header(buffer: &[u8]) -> Result<DnsHeader, Error> {
    if buffer.len() < 12 {
        return Err(Error::MalformedPacket);
    }

    let header = DnsHeader {
        id: u16::from_be_bytes([buffer[0], buffer[1]]),
        flags: u16::from_be_bytes([buffer[2], buffer[3]]),
        questions: u16::from_be_bytes([buffer[4], buffer[5]]),
        answers: u16::from_be_bytes([buffer[6], buffer[7]]),
        authorities: u16::from_be_bytes([buffer[8], buffer[9]]),
        additionals: u16::from_be_bytes([buffer[10], buffer[11]]),
    };
    
    // Check response code (lower 4 bits of flags)
    let rcode = header.flags & 0x0F;
    if rcode != 0 {
        return Err(Error::ServerError(rcode));
    }
    
    Ok(header)
}

/// Skip DNS question section
pub fn skip_question(buffer: &[u8], mut pos: usize) -> Result<usize, Error> {
    if pos >= buffer.len() {
        return Err(Error::MalformedPacket);
    }

    // Skip name
    while pos < buffer.len() {
        let len = buffer[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        
        // Handle compression pointers (0xC0 mask)
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        
        pos += len + 1;
        
        if pos >= buffer.len() {
            return Err(Error::MalformedPacket);
        }
    }
    
    // Skip type and class (4 bytes)
    if pos + 4 > buffer.len() {
        return Err(Error::MalformedPacket);
    }
    
    Ok(pos + 4)
}

/// DNS record data variants
#[derive(Debug, Clone)]
pub enum RecordData {
    /// MX record with priority and server hostname
    MX {
        /// Priority value (lower is preferred)
        priority: u16,
        /// Server hostname
        server: String
    },
    /// A record with IPv4 address
    A(Ipv4Addr),
    /// AAAA record with IPv6 address
    AAAA(Ipv6Addr),
    /// Unknown record type
    Unknown,
}

/// DNS record structure
#[derive(Debug)]
pub struct DnsRecord {
    /// DNS record type
    pub record_type: u16,
    /// Record data based on type
    pub data: RecordData,
}

/// Parse DNS answer record
pub fn parse_answer(buffer: &[u8], mut pos: usize) -> Result<(DnsRecord, usize), Error> {
    if pos >= buffer.len() {
        return Err(Error::MalformedPacket);
    }

    // Skip name field
    while pos < buffer.len() {
        let len = buffer[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        
        // Handle compression pointers
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        
        pos += len + 1;
        
        if pos >= buffer.len() {
            return Err(Error::MalformedPacket);
        }
    }
    
    // Ensure we have enough bytes for the record header
    if pos + 10 > buffer.len() {
        return Err(Error::MalformedPacket);
    }
    
    // Parse record type and class
    let record_type = u16::from_be_bytes([buffer[pos], buffer[pos+1]]);
    pos += 4; // Skip type and class
    
    // Skip TTL (4 bytes)
    pos += 4;
    
    // Get data length
    let data_len = u16::from_be_bytes([buffer[pos], buffer[pos+1]]) as usize;
    pos += 2;
    
    // Ensure we have enough bytes for the record data
    if pos + data_len > buffer.len() {
        return Err(Error::MalformedPacket);
    }
    
    let data = match record_type {
        DNS_TYPE_MX => {
            if data_len < 2 {
                return Err(Error::MalformedPacket);
            }
            
            let priority = u16::from_be_bytes([buffer[pos], buffer[pos+1]]);
            pos += 2;
            
            // Extract hostname (rest of data)
            let server = parse_dns_name(buffer, pos)?;
            pos += data_len - 2; // -2 because we already processed priority
            
            RecordData::MX { priority, server }
        },
        DNS_TYPE_A => {
            if data_len != 4 {
                return Err(Error::MalformedPacket);
            }
            
            let ipv4 = Ipv4Addr::new(buffer[pos], buffer[pos+1], buffer[pos+2], buffer[pos+3]);
            pos += 4;
            RecordData::A(ipv4)
        },
        DNS_TYPE_AAAA => {
            if data_len != 16 {
                return Err(Error::MalformedPacket);
            }
            
            let mut ipv6_bytes = [0u8; 16];
            ipv6_bytes.copy_from_slice(&buffer[pos..pos+16]);
            let ipv6 = Ipv6Addr::from(ipv6_bytes);
            pos += 16;
            RecordData::AAAA(ipv6)
        },
        _ => {
            // Skip unknown record types
            pos += data_len;
            RecordData::Unknown
        }
    };
    
    Ok((DnsRecord { record_type, data }, pos))
}

/// Parse DNS name from buffer
pub fn parse_dns_name(buffer: &[u8], mut pos: usize) -> Result<String, Error> {
    if pos >= buffer.len() {
        return Err(Error::MalformedPacket);
    }

    let mut name = String::new();
    let mut first = true;
    
    // Detect compression loops
    let mut jumps = 0;
    const MAX_JUMPS: usize = 10; // Prevent infinite loops
    
    loop {
        if pos >= buffer.len() {
            return Err(Error::MalformedPacket);
        }
        
        let len = buffer[pos] as usize;
        pos += 1;
        
        // End of name
        if len == 0 {
            break;
        }
        
        // Handle compression pointers
        if len & 0xC0 == 0xC0 {
            if pos >= buffer.len() {
                return Err(Error::MalformedPacket);
            }
            
            jumps += 1;
            if jumps > MAX_JUMPS {
                return Err(Error::MalformedPacket);
            }
            
            let offset = (((len & 0x3F) as usize) << 8) | buffer[pos] as usize;
            
            // If this is not the first part, add a dot
            if !first {
                name.push('.');
            }
            
            // Append the name from the offset position
            let remainder = parse_dns_name(buffer, offset)?;
            name.push_str(&remainder);
            pos += 1;
            break;
        }
        
        // Regular label
        if pos + len > buffer.len() {
            return Err(Error::MalformedPacket);
        }
        
        // If this is not the first part, add a dot
        if !first {
            name.push('.');
        }
        first = false;
        
        // Append this part
        name.push_str(&String::from_utf8_lossy(&buffer[pos..pos+len]));
        pos += len;
    }
    
    Ok(name)
}

/// MX record structure
#[derive(Debug, Clone, PartialEq)]
pub struct MxRecord {
    /// Priority value (lower is preferred)
    pub priority: u16,
    /// Server hostname
    pub server: String,
}

/// Server with resolved IP addresses
#[derive(Debug, Clone, PartialEq)]
pub struct ServerIpRecord {
    /// Server hostname
    pub server: String,
    /// List of IP addresses (v4 and v6)
    pub ip_addresses: Vec<IpAddr>,
}

/// DNS query configuration
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// List of DNS servers to try
    pub servers: Vec<String>,
    /// Query timeout in seconds
    pub timeout: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: DEFAULT_DNS_SERVERS.iter().map(|s| s.to_string()).collect(),
            timeout: 5,
        }
    }
}

/// Build DNS query packet
pub fn build_dns_query(domain: &str, record_type: u16) -> Result<Vec<u8>, Error> {
    let mut packet = Vec::new();
    
    // DNS header (12 bytes)
    let id = 1_i16;
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
    packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0
    
    // Encode domain name in DNS format
    for part in domain.split('.') {
        if part.is_empty() {
            continue;
        }
        
        if part.len() > 63 {
            return Err(Error::MalformedPacket);
        }
        
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0); // Terminating zero byte
    
    // Query type and class (IN = 1)
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]); // Class: IN
    
    Ok(packet)
}

/// Parse MX records from DNS response
pub fn parse_mx_records(buffer: &[u8]) -> Result<Vec<MxRecord>, Error> {
    let mut records = Vec::new();
    let header = parse_dns_header(buffer)?;
    
    if header.answers == 0 {
        return Err(Error::NoRecordsFound);
    }
    
    // Skip question section
    let mut pos = 12; // Header size
    for _ in 0..header.questions {
        pos = skip_question(buffer, pos)?;
    }
    
    // Parse answer section
    for _ in 0..header.answers {
        let (record, new_pos) = parse_answer(buffer, pos)?;
        pos = new_pos;
        
        if record.record_type == DNS_TYPE_MX {
            if let RecordData::MX { priority, server } = record.data {
                records.push(MxRecord {
                    priority,
                    server
                });
            }
        }
    }
    
    if records.is_empty() {
        return Err(Error::NoRecordsFound);
    }
    
    // Sort by priority (lower is preferred)
    records.sort_by_key(|r| r.priority);
    Ok(records)
}

/// Parse IP records from DNS response
pub fn parse_ip_records(buffer: &[u8]) -> Result<Vec<IpAddr>, Error> {
    let mut ips = Vec::new();
    let header = parse_dns_header(buffer)?;
    
    // Skip question section
    let mut pos = 12; // Header size
    for _ in 0..header.questions {
        pos = skip_question(buffer, pos)?;
    }
    
    // Parse answer section
    for _ in 0..header.answers {
        let (record, new_pos) = parse_answer(buffer, pos)?;
        pos = new_pos;
        
        match record.data {
            RecordData::A(ipv4) => ips.push(IpAddr::V4(ipv4)),
            RecordData::AAAA(ipv6) => ips.push(IpAddr::V6(ipv6)),
            _ => {}
        }
    }
    
    if ips.is_empty() {
        return Err(Error::NoRecordsFound);
    }
    
    Ok(ips)
}

/// Send DNS query and get response using the specified configuration
pub fn lookup_dns_records(domain: &str, record_type: u16, config: Option<DnsConfig>) -> Result<Vec<u8>, Error> {
    let config = config.unwrap_or_default();
    
    // Build DNS query packet
    let query = build_dns_query(domain, record_type)?;
    
    // Try each DNS server until we get a response
    for server in &config.servers {
        let server_addr = format!("{}:53", server);
        
        match try_dns_query(&server_addr, &query, config.timeout) {
            Ok(response) => return Ok(response),
            Err(Error::Timeout) | Err(Error::Io(_)) => continue, // Try next server
            Err(e) => return Err(e),
        }
    }
    
    Err(Error::Timeout)
}

/// Try a DNS query against a specific server
fn try_dns_query(server: &str, query: &[u8], timeout: u64) -> Result<Vec<u8>, Error> {
    // Create DNS socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(timeout)))?;
    
    // Connect to DNS server
    socket.connect(server)?;
    
    // Send query
    socket.send(query)?;
    
    // Receive response
    let mut buffer = [0; 512];
    let size = socket.recv(&mut buffer)?;
    
    Ok(buffer[..size].to_vec())
}

/// Lookup MX records for a domain
pub fn lookup_mx_records(domain: &str) -> Result<Vec<MxRecord>, Error> {
    lookup_mx_records_with_config(domain, None)
}

/// Lookup MX records for a domain with custom configuration
pub fn lookup_mx_records_with_config(domain: &str, config: Option<DnsConfig>) -> Result<Vec<MxRecord>, Error> {
    let response = lookup_dns_records(domain, DNS_TYPE_MX, config)?;
    parse_mx_records(&response)
}

/// Lookup IP addresses for a hostname
pub fn lookup_ip_addresses(hostname: &str) -> Result<Vec<IpAddr>, Error> {
    lookup_ip_addresses_with_config(hostname, None)
}

/// Lookup IP addresses for a hostname with custom configuration
pub fn lookup_ip_addresses_with_config(hostname: &str, config: Option<DnsConfig>) -> Result<Vec<IpAddr>, Error> {
    let mut ips = Vec::new();
    
    // Get A records (IPv4)
    match lookup_dns_records(hostname, DNS_TYPE_A, config.clone()) {
        Ok(response) => match parse_ip_records(&response) {
            Ok(v4_ips) => ips.extend(v4_ips),
            Err(Error::NoRecordsFound) => {}, // Ignore if no records found
            Err(e) => return Err(e),
        },
        Err(Error::NoRecordsFound) => {}, // Ignore if no records found
        Err(e) => return Err(e),
    }
    
    // Get AAAA records (IPv6)
    match lookup_dns_records(hostname, DNS_TYPE_AAAA, config) {
        Ok(response) => match parse_ip_records(&response) {
            Ok(v6_ips) => ips.extend(v6_ips),
            Err(Error::NoRecordsFound) => {}, // Ignore if no records found
            Err(e) => return Err(e),
        },
        Err(Error::NoRecordsFound) => {}, // Ignore if no records found
        Err(e) => return Err(e),
    }
    
    if ips.is_empty() {
        return Err(Error::NoRecordsFound);
    }
    
    Ok(ips)
}

/// Resolve MX records to their IP addresses
pub fn resolve_mx_server_ips(domain: &str) -> Result<Vec<ServerIpRecord>, Error> {
    resolve_mx_server_ips_with_config(domain, None)
}

/// Resolve MX records to their IP addresses with custom configuration
pub fn resolve_mx_server_ips_with_config(domain: &str, config: Option<DnsConfig>) -> Result<Vec<ServerIpRecord>, Error> {
    let mx_records = lookup_mx_records_with_config(domain, config.clone())?;
    
    let mut server_ips = Vec::new();
    for mx in mx_records {
        match lookup_ip_addresses_with_config(&mx.server, config.clone()) {
            Ok(ips) => {
                server_ips.push(ServerIpRecord {
                    server: mx.server,
                    ip_addresses: ips,
                });
            },
            Err(Error::NoRecordsFound) => {}, // Skip servers with no IP records
            Err(e) => return Err(e),
        }
    }
    
    if server_ips.is_empty() {
        return Err(Error::NoRecordsFound);
    }
    
    Ok(server_ips)
}