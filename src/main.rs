#![feature(async_closure)]

mod config;

mod vtfheader;
mod web;

use std::env;
use env_logger::Env;
use std::fs::File;
use std::io::BufReader;

use config::Config;

use actix_rt::signal::ctrl_c;


#[actix_rt::main]
async fn main() -> Result<(),Box<dyn std::error::Error>> {
    // Default log level is debug
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let path = env::args().nth(1).unwrap_or("config.yaml".to_string());

    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    let config: Config = serde_yaml::from_reader(reader)?;

    web::2(config.clone());

    ctrl_c().await?;

    Ok(())
}