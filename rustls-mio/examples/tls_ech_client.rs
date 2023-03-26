use rustls::internal::msgs::ech::EncryptedClientHello;
 use rustls::{ClientConnection, ConfigBuilder, Connection, RootCertStore, ServerName, OwnedTrustAnchor, ClientConfig};
 use trust_dns_resolver::config::*;
 use trust_dns_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
 use trust_dns_resolver::proto::rr::record_type::RecordType::HTTPS;
 use trust_dns_resolver::proto::rr::{RData, RecordType};
 use trust_dns_resolver::proto::serialize::binary::BinEncodable;
 use trust_dns_resolver::Resolver;

 use std::io::{stdout, Read, Write};
 use std::net::TcpStream;
 use std::sync::Arc;
use std::thread;
use std::time::Duration;

 fn main() {
     let dnsdomain = "crypto.cloudflare.com"; // we use this to get an ECH Config
     let domain = "REPLACEME.gluonhq.net";
     let dns_config = ResolverConfig::cloudflare_https();
     let opts = ResolverOpts::default();
     let resolver = Resolver::new(dns_config, opts).unwrap();
     let (_key, value) = lookup(&resolver, dnsdomain).unwrap();

     let config = match value {
         SvcParamValue::EchConfig(e) => e,
         _ => unreachable!(),
     };
println!("We have an echconfig: {:?}", config);
     let dns_name = webpki::DnsNameRef::try_from_ascii(domain.as_bytes()).unwrap();
     let ech =
         EncryptedClientHello::with_host_and_config_list(dns_name, &config.to_bytes().unwrap())
             .unwrap();

     
     let mut roots = RootCertStore::empty();
     roots.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );
     let client_config = ClientConfig::builder()
         .with_safe_defaults()
         .with_root_certificates(roots)
         .with_no_client_auth();

println!("waiting A");
    thread::sleep(Duration::from_secs(1));
println!("waiting A done");

     let mut connection = ClientConnection::new(
         Arc::new(client_config),
         ServerName::EncryptedClientHello(Box::new(ech)),
     )
     .unwrap();

println!("waiting B");
    thread::sleep(Duration::from_secs(1));
println!("waiting B done");

     let mut sock = TcpStream::connect("cloudflare-ech.com:443").unwrap();
     // let mut sock = TcpStream::connect(domain.to_owned() + ":443").unwrap();

println!("waiting C");
    thread::sleep(Duration::from_secs(1));
println!("waiting C done");

     let mut tls = rustls::Stream::new(&mut connection, &mut sock);

println!("waiting D");
    thread::sleep(Duration::from_secs(1));
println!("waiting D done");

     let host_header = format!("Host: {}\r\n", domain);
     let mut headers = String::new();
     headers.push_str("GET / HTTP/1.1\r\n");
     headers.push_str(host_header.as_str());
     headers.push_str("User-Agent: RustlsDemo .01\r\n");
     headers.push_str("Connection: close\r\n");
     headers.push_str("Accept-Encoding: identity\r\n");
     headers.push_str("\r\n");
     match tls.write(headers.as_bytes()) {
         Ok(size) => {
             println!("Received: {} bytes", size);
         }
         Err(e) => {
             println!("Error: {:?}", e);
             return;
         }
     }

println!("waiting E");
    thread::sleep(Duration::from_secs(1));
println!("waiting E done");

     let ciphersuite = tls
         .conn
         .negotiated_cipher_suite()
         .unwrap();
     writeln!(
         &mut std::io::stderr(),
         "\n\nNegotiated ciphersuite: {:?}",
         ciphersuite.suite()
     )
     .unwrap();
     let mut plaintext = Vec::new();
     match tls.read_to_end(&mut plaintext) {
         Ok(success) => {
             println!("read bytes: {}", success);
         }
         Err(e) => {
             stdout().write_all(&plaintext).unwrap();

             println!("failure to read the bytes: {:?}", e);

             return;
         }
     }
     stdout().write_all(&plaintext).unwrap();
 }

 fn lookup(resolver: &Resolver, domain: &str) -> Option<(SvcParamKey, SvcParamValue)> {
     let lookup = resolver
         .lookup(domain, RecordType::HTTPS)
         .unwrap();
     let record = lookup
         .record_iter()
         .find(|r| r.rr_type() == HTTPS)
         .map(|r| {
             if let RData::HTTPS(svcb) = r.rdata() {
                 Some(
                     svcb.svc_params()
                         .iter()
                         .find(|sp| sp.0 == SvcParamKey::EchConfig),
                 )
             } else {
                 None
             }
         })
         .flatten();

     match record {
         Some(Some(record)) => Some(record.clone()),
         _ => None,
     }
 }
