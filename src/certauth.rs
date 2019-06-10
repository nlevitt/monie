#![deny(warnings)]

use std::sync::{Arc, Mutex};

use http::uri::Authority;
use lru_cache::LruCache;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};

lazy_static! {
    static ref TLS_CONFIG_CACHE: Mutex<LruCache<String, Arc<rustls::ServerConfig>>> =
        Mutex::new(LruCache::new(1000));
}

fn gen_key_cert(
    authority: &Authority,
) -> (rustls::PrivateKey, rustls::Certificate) {
    info!(
        "gen_key_cert() generating key/cert for {}",
        authority.host()
    );

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

pub fn tls_config(authority: &Authority) -> Arc<rustls::ServerConfig> {
    if !TLS_CONFIG_CACHE
        .lock()
        .unwrap()
        .contains_key(authority.host())
    {
        let tls_cfg: Arc<rustls::ServerConfig> = {
            let (key, cert) = gen_key_cert(&authority);
            let certs = vec![cert; 1];
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
