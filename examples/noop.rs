//! A noop mitm proxy example using monie.

#![deny(warnings)]

use futures::future::Future;
use http::uri::Uri;
use hyper::{Body, Chunk, Request, Response, Server};

use monie::{Mitm, MitmProxyService};

#[derive(Debug)]
struct NoopMitm;

impl Mitm for NoopMitm {
    fn new(uri: Uri) -> NoopMitm {
        println!("proxying request for {}", uri);
        NoopMitm {}
    }
    fn request_headers(&self, req: Request<Body>) -> Request<Body> { req }
    fn response_headers(&self, res: Response<Body>) -> Response<Body> { res }
    fn request_body_chunk(&self, chunk: Chunk) -> Chunk { chunk }
    fn response_body_chunk(&self, chunk: Chunk) -> Chunk { chunk }
}

fn main() {
    pretty_env_logger::init_timed();
    let addr = ([127, 0, 0, 1], 8000).into();
    let svc = MitmProxyService::<NoopMitm>::new();
    let server = Server::bind(&addr)
        .serve(svc)
        .map_err(|e| eprintln!("server error: {}", e));
    println!("noop mitm proxy listening on http://{}", addr);
    hyper::rt::run(server);
}
