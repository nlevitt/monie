//! Generates RSA private keys and self-signed X509 certificates.
//!
//! Builds `rustls::ServerConfig`s using generated keys and certs, caching the
//! 1000 most recently used.

#![deny(warnings)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

use std::sync::{Arc, Mutex};
use std::env;

use rustls::internal::pemfile;
use std::{fs, io};

use http::uri::Authority;
use lru_cache::LruCache;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};

const MONIE_KEY_FILE: &str = "MONIE_KEY_FILE";
const MONIE_CERT_FILE: &str = "MONIE_CERT_FILE";

lazy_static! {
    static ref TLS_CONFIG_CACHE: Mutex<LruCache<String, Arc<rustls::ServerConfig>>> =
        Mutex::new(LruCache::new(1000));
}

/// Generate a key and self-signed cert for the provided authority.
pub fn gen_key_cert(
    authority: &Authority,
) -> (rustls::PrivateKey, rustls::Certificate) {
    info!(
        "gen_key_cert() generating key/cert for {}",
        authority.host()
    );

    // optimization todo: use a single private key
    let rsa: Rsa<openssl::pkey::Private> = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa.clone()).unwrap();
    let key = rustls::PrivateKey(rsa.private_key_to_der().unwrap());

    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name
        .append_entry_by_text("CN", authority.host())
        .unwrap();
    let x509_name = x509_name.build();

    let mut x509builder = X509Builder::new().unwrap();
    x509builder.set_pubkey(&pkey).unwrap();
    x509builder.set_version(2).unwrap();
    x509builder.set_subject_name(&x509_name).unwrap();
    x509builder.set_issuer_name(&x509_name).unwrap();
    x509builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    x509builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    x509builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let x509 = x509builder.build();

    let cert = rustls::Certificate(x509.to_der().unwrap());

    (key, cert)
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    pemfile::certs(&mut reader).map_err(|_| error("failed to load certificate".into()))
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| error("failed to load private key".into()))?;
    if keys.len() != 1 {
        return Err(error("expected a single private key".into()));
    }
    Ok(keys[0].clone())
}

/// Get a key and self-signed cert for the provided authority, checking to see if a static cert has
/// been provided.
pub fn get_key_certs(
    authority: &Authority,
) -> (rustls::PrivateKey, Vec<rustls::Certificate>) {
    if env::var_os(MONIE_KEY_FILE).is_some() &&
        env::var_os(MONIE_CERT_FILE).is_some() {
        let keyfile = env::var(MONIE_KEY_FILE).unwrap();
        let certfile = env::var(MONIE_CERT_FILE).unwrap();
        let key = load_private_key(&keyfile).expect("Failed loading key");
        let certs = load_certs(&certfile).expect("Failed loading certs");
        (key, certs)
    } else {
        let (key, cert) = gen_key_cert(&authority);
        let certs = vec![cert; 1];
        (key, certs)
    }
}

/// Either load an existing TLS server configuration from cache or build a new
/// one (and cache it) for the provided authority.
pub fn tls_config(authority: &Authority) -> Arc<rustls::ServerConfig> {
    if !TLS_CONFIG_CACHE
        .lock()
        .unwrap()
        .contains_key(authority.host())
    {
        let tls_cfg: Arc<rustls::ServerConfig> = {
            let (key, certs) = get_key_certs(&authority);
            let mut result =
                rustls::ServerConfig::new(rustls::NoClientAuth::new());
            result
                .set_single_cert(certs, key)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{}", e),
                    )
                })
                .unwrap();
            Arc::new(result)
        };

        TLS_CONFIG_CACHE
            .lock()
            .unwrap()
            .insert(authority.host().to_owned(), tls_cfg);
    }

    TLS_CONFIG_CACHE
        .lock()
        .unwrap()
        .get_mut(authority.host())
        .unwrap()
        .clone()
}
