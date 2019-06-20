//! A mitm proxy example using monie. Adds via header to each request and
//! response.

#![deny(warnings)]

use futures::future::Future;
use http::header::{HeaderMap, HeaderValue};
use http::uri::Uri;
use hyper::{Body, Chunk, Request, Response, Server};

use monie::{Mitm, MitmProxyService};

#[derive(Debug)]
struct AddsVia;

fn numeric_bytes(version: http::Version) -> &'static [u8] {
    match version {
        http::Version::HTTP_09 => b"0.9",
        http::Version::HTTP_10 => b"1.0",
        http::Version::HTTP_11 => b"1.1",
        http::Version::HTTP_2  => b"2.0",
    }
}

fn set_via(headers: &mut HeaderMap, version: &http::Version) {
    let mut buf = match headers.remove("via") {
        Some(existing_via) => {
            let mut buf = existing_via.as_bytes().to_vec();
            buf.extend_from_slice(b", ");
            buf
        },
        None => {
            Vec::new()
        },
    };
    buf.extend_from_slice(numeric_bytes(*version));
    buf.extend_from_slice(b" monie-add-via-example");
    headers.insert("via", HeaderValue::from_bytes(&buf).unwrap());
}

impl Mitm for AddsVia {
    fn new(uri: Uri) -> AddsVia {
        println!("proxying request for {}", uri);
        AddsVia {}
    }

    fn request_headers(&self, req: Request<Body>) -> Request<Body> {
        let (mut parts, body) = req.into_parts();
        set_via(&mut parts.headers, &parts.version);
        Request::from_parts(parts, body)
    }

    fn response_headers(&self, res: Response<Body>) -> Response<Body> {
        let (mut parts, body) = res.into_parts();
        set_via(&mut parts.headers, &parts.version);
        Response::from_parts(parts, body)
    }

    fn request_body_chunk(&self, chunk: Chunk) -> Chunk {
        chunk
    }

    fn response_body_chunk(&self, chunk: Chunk) -> Chunk {
        chunk
    }
}

fn main() {
    pretty_env_logger::init_timed();
    let addr = ([127, 0, 0, 1], 8000).into();
    let svc = MitmProxyService::<AddsVia>::new();
    let server = Server::bind(&addr)
        .serve(svc)
        .map_err(|e| eprintln!("server error: {}", e));
    println!("add-via mitm proxy listening on http://{}", addr);
    hyper::rt::run(server);
}
