extern crate actix;
extern crate actix_web;
extern crate env_logger;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_json;

use actix_web::{middleware, server, App, HttpRequest, HttpResponse};
use log::info;
use slog::Drain;
use std::env;
use std::sync::Arc;
use std::sync::Mutex;

/// Application state
struct AppState {
    counter: Arc<Mutex<usize>>,
}

/// simple handle
fn index(req: &HttpRequest<AppState>) -> HttpResponse {
    *(req.state().counter.lock().unwrap()) += 1;

    HttpResponse::Ok().body(format!(
        "Num of requests: {}",
        req.state().counter.lock().unwrap()
    ))
}

fn main() {
    ::std::env::set_var("RUST_LOG", "actix_web=info");
    let root_logger = default_root_logger("culper-server");
    let _guard = slog_scope::set_global_logger(root_logger);
    slog_stdlog::init().unwrap();

    let sys = actix::System::new("culper-server");

    let counter = Arc::new(Mutex::new(0));
    //move is necessary to give closure below ownership of counter
    server::new(move || {
        App::with_state(AppState {
            counter: counter.clone(),
        }) // <- create app with shared state
        // enable logger
        .middleware(middleware::Logger::default())
        // register simple handler, handle all methods
        .resource("/", |r| r.f(index))
    })
    .bind("0.0.0.0:8080")
    .unwrap()
    .start();

    info!("Started http server: 0.0.0.0:8080");
    let _ = sys.run();
}

pub fn default_json_drain() -> slog_async::Async {
    let drain = slog_json::Json::new(std::io::stdout())
        .add_key_value(slog_o!(
           "msg" => slog::PushFnValue(move |record : &slog::Record, ser| {
               ser.emit(record.msg())
           }),
           "tag" => slog::PushFnValue(move |record : &slog::Record, ser| {
               ser.emit(record.tag())
           }),
           "ts" => slog::PushFnValue(move |_ : &slog::Record, ser| {
               ser.emit(chrono::Local::now().to_rfc3339())
           }),
           "level" => slog::FnValue(move |rinfo : &slog::Record| {
               rinfo.level().as_str()
           }),
        ))
        .build()
        .fuse();
    let mut log_builder =
        slog_envlogger::LogBuilder::new(drain).filter(None, slog::FilterLevel::Info);
    if let Ok(s) = env::var("RUST_LOG") {
        log_builder = log_builder.parse(&s);
    }
    slog_async::Async::default(log_builder.build())
}

pub fn default_root_logger(process_name: &'static str) -> slog::Logger {
    let drain = default_json_drain();
    slog::Logger::root(
        drain.fuse(),
        slog_o!(
          "version" => env!("CARGO_PKG_VERSION"),
          "process" => process_name,
        ),
    )
}
