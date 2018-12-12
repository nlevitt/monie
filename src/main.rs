extern crate hyper;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate mitmprox;

use std::net::SocketAddr;
use hyper::rt::Future;
use hyper::server::Server;
use mitmprox::NewProxyService;

fn main() {
    env_logger::Builder::from_default_env()
        .default_format_module_path(true)
        .default_format_timestamp_nanos(true)
        .init();

    let addr: SocketAddr = ([127, 0, 0, 1], 8000).into();
    let server = Server::bind(&addr).serve(NewProxyService{})
        .map_err(|e| {
            error!("main() server error: {}", e);
        });

    info!("main() listening on {}", addr);

    hyper::rt::run(server);
}

