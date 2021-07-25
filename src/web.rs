
use actix_ratelimit::{RateLimiter, MemoryStore, MemoryStoreActor};
use actix_web::{App, FromRequest, HttpRequest, HttpResponse, HttpServer, Result, web::Bytes, web::{self}};
use rust_tls::internal::pemfile::{certs, rsa_private_keys};
use rust_tls::{NoClientAuth, ServerConfig};
use json;
use log::{info, warn};
use std::{error::Error, fs::File, fs::{self}, io::{BufReader, Cursor, Read, Write}, path::Path, sync::Mutex, time::{SystemTime, UNIX_EPOCH}};

use std::time::Duration;

use serde::Deserialize;

use actix_rt::Arbiter;

use crate::vtfheader::VtfHeader;

use log::error;

use crc32fast::Hasher;

use hmac_sha256::HMAC;

use crate::config::Config;

#[derive(Deserialize, Debug)]
struct Uri {
    key: String
}

#[derive(Deserialize)]
pub struct UpdateParams {
    steamid64: String,
}

#[derive(Deserialize)]
pub struct GetParams {
    steamid64: String,
    filename: String,
}

const UNSAFE_CHARS: &[char] = &['<', '>', ':', '"', '.', '/', '\\', '|', '?', '*'];

fn sanitize_filename(input: &String) -> String {
    String::from(input.as_str().trim_matches(&UNSAFE_CHARS[..]))
}

// https://stackoverflow.com/questions/44691363/how-to-compare-strings-in-constant-time
#[inline(never)]
fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter().zip(b)
        .fold(0, |acc, (a, b)| acc | (a ^ b) ) == 0
}

async fn upload(info: web::Query<Uri>, params: web::Path<UpdateParams>, req: HttpRequest, body: Bytes,mconfig: web::Data<Mutex<Config>>) -> Result<HttpResponse> {
    let conn_info = req.connection_info();

    let result = async || -> Result<HttpResponse, Box<dyn Error>> {
    
    let config = mconfig.lock()?;

    info!("Upload request begin for {}", params.steamid64);

    if body.len() > config.max_size*1048576 {
        info!("File size is too high for {}", params.steamid64);  
        return Ok(HttpResponse::BadRequest().body(format!("File size is too big (max {} MB)",config.max_size)));
    }

    info!("Passed size check for {}", params.steamid64);

    let mut hasher = Hasher::new();
    hasher.update(&body);

    let checksum = hasher.finalize();

    let time = SystemTime::now().duration_since(UNIX_EPOCH)?;

    let round = (time.as_secs() / config.round_interval) as i64;

    let mut succ = false;

    let key = hex::decode(&info.key)?;

    for i in -1..2_i64 {
        // Okay rust compiler i lost to your naughtiness again let's loose some cpu cycles on that crap
        let mac = HMAC::mac(
            format!("{}{}{}{}",params.steamid64,conn_info.realip_remote_addr().unwrap_or(conn_info.host()),round+i,checksum).as_bytes(),
            config.master_key.as_bytes());


        if ct_compare(&mac, key.as_slice()) {
            succ = true;
            break;
        }
    }

    if !succ {
        return Ok(HttpResponse::Forbidden().body("Provided key is invalid for this content or id")); 
    }

    info!("Passed key check for {}", params.steamid64);    

    let vtfh = VtfHeader::load(Cursor::new(&body))?;

    if vtfh.width() > config.max_width || vtfh.height() > config.max_height {
        info!("Spray resolution is too high for {}", params.steamid64);    
        return Ok(HttpResponse::BadRequest().body(format!("VTF Resolution is too high (max {}x{})",config.max_width,config.max_height))); 
    }

    info!("Passed VTFHeader check for {}", params.steamid64);

    let fpath = format!("{}/{}/",config.path,sanitize_filename(&params.steamid64));
    let file = format!("{}/{}.vtf",&fpath,checksum);

    if !Path::new(&fpath.as_str()).exists() {
        let fpath = fpath.clone();
        actix_web::web::block(move || { fs::create_dir_all(&fpath)}).await?;
    }

    let dir = {
    let fpath = fpath.clone();
    actix_web::web::block(move || {
        fs::read_dir(&fpath)
    }).await?
    };

    let mut files= Vec::new();
    let mut futures = Vec::new();

    for entry in dir {
        let entry = entry?.path().into_os_string().into_string().unwrap();
        let fmdata = {
            let entry = entry.clone();
            actix_web::web::block(move || {fs::metadata(&entry.clone())})
        };

        files.push(entry);
        futures.push(fmdata);
    }

    let mut modified = Vec::new();

    for (file,fmdata) in files.into_iter().zip(futures::future::join_all(futures).await) {
        modified.push((file,fmdata?.modified()?))
    }

    modified.sort_by(|(_,a),(_,b)| b.cmp(a));

    modified.drain(0..std::cmp::min(modified.len(),config.max_files));

    let modified = modified.into_iter().map(|(v,_)| {
        info!("Removing old file: {} for {}", v, params.steamid64);
        actix_web::web::block(move || {fs::remove_file(v)})
        }).collect::<Vec<_>>();

    futures::future::join_all(modified).await;

    let filepath = Path::new(file.as_str());

    if !&filepath.exists() {
        let file = file.clone();
        info!("Saving new file: {} for {}", file, params.steamid64);
        actix_web::web::block(move || {
        let mut buffer = File::create(file)?;
        buffer.write_all(&body)
        }).await?;
    }

    info!("Upload success for {}",params.steamid64);

    return Ok(HttpResponse::Ok().body("Successfully saved file on server"))
    }().await;

    match result {
        Ok(a) => return Ok(a),
        Err(err) => {
            error!("Upload: Web request error: {}", err);
            return Ok(HttpResponse::InternalServerError().finish());
        }
    }
}

async fn list(params: web::Path<UpdateParams>,mconfig: web::Data<Mutex<Config>>) -> Result<HttpResponse> {
    let result = async || -> Result<HttpResponse, Box<dyn Error>> {
        let config = mconfig.lock()?;

        info!("Begin listing for {}",sanitize_filename(&params.steamid64));

        let fpath = format!("{}/{}/",config.path,sanitize_filename(&params.steamid64));
        let filepath = Path::new(fpath.as_str());

        if filepath.exists() {

            let mut files = json::JsonValue::new_array();
        
            let dir = {
                let fpath = fpath.clone();
                actix_web::web::block(move || {
                    fs::read_dir(&fpath)
                }).await?
            };

            for entry in dir {
                let filename = entry?.file_name().into_string().unwrap();
            
                files.push(filename)?;
            }

            info!("Found {} files for {}", files.len(),params.steamid64);

            return Ok(HttpResponse::Ok().body(files.dump()));
        }

        warn!("Empty list for {}", sanitize_filename(&params.steamid64));

        return Ok(HttpResponse::NotFound().body("Spray folder doesn't exist yet for this steamid64"));
    }().await;

    match result {
        Ok(a) => return Ok(a),
        Err(err) => {
            error!("Get: Web request error: {}", err);
            return Ok(HttpResponse::InternalServerError().finish());
        }
    }
}

async fn check(params: web::Path<GetParams>,mconfig: web::Data<Mutex<Config>>) -> Result<HttpResponse> {
    let result = || -> Result<HttpResponse, Box<dyn Error>> {
        let config = mconfig.lock()?;

        info!("Begin check for {} {}", sanitize_filename(&params.steamid64),sanitize_filename(&params.filename));

        let file = format!("{}/{}/{}.vtf",config.path,sanitize_filename(&params.steamid64),sanitize_filename(&params.filename));
        let filepath = Path::new(file.as_str());

        if filepath.exists() {

            info!("Found file for {} {}",sanitize_filename(&params.steamid64),sanitize_filename(&params.filename));

            return Ok(HttpResponse::Ok().body(format!("{}.vtf exist",&params.filename)))
        }

        warn!("Checked file not found for {} {}", sanitize_filename(&params.steamid64),sanitize_filename(&params.filename));

        return Ok(HttpResponse::NotFound().body(format!("{}.vtf doesn't exist",sanitize_filename(&params.filename))));
    }();

    match result {
        Ok(a) => return Ok(a),
        Err(err) => {
            error!("Get: Web request error: {}", err);
            return Ok(HttpResponse::InternalServerError().finish());
        }
    }
}

async fn get(params: web::Path<GetParams>,mconfig: web::Data<Mutex<Config>>) -> Result<HttpResponse> {
    let result = || -> Result<HttpResponse, Box<dyn Error>> {
        let config = mconfig.lock()?;

        info!("Begin direct get for {}", sanitize_filename(&params.steamid64));

        let file = format!("{}/{}/{}.vtf",config.path,sanitize_filename(&params.steamid64),sanitize_filename(&params.filename));
        let filepath = Path::new(file.as_str());

        if filepath.exists() {
            let mut file = File::open(filepath)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;

            info!("Got direct file for {}", sanitize_filename(&params.steamid64));

            return Ok(HttpResponse::Ok().body(buffer))
        }

        warn!("Direct file not found for {}", sanitize_filename(&params.steamid64));

        return Ok(HttpResponse::NotFound().body(format!("{}.vtf doesn't exist",&params.filename)));
    }();

    match result {
        Ok(a) => return Ok(a),
        Err(err) => {
            error!("Get: Web request error: {}", err);
            return Ok(HttpResponse::InternalServerError().finish());
        }
    }
}

async fn task(config: Config) -> Result<(),Box<dyn Error>> {
    let mut ssl_config = ServerConfig::new(NoClientAuth::new());

    let ssl = config.web_ssl;

    if ssl {
        let cert_file = &mut BufReader::new(File::open(&config.web_cert)?);
        let key_file = &mut BufReader::new(File::open(&config.web_privkey)?);
        let cert_chain = certs(cert_file).unwrap();
        let mut keys = rsa_private_keys(key_file).unwrap();
        ssl_config.set_single_cert(cert_chain, keys.remove(0))?;
    }

    let addr = format!("{}:{}", &config.web_hostname, &config.web_port);

    info!("Running web thread {}", addr);

    let maxsize = &config.max_size*1048576;

    let data = web::Data::new(Mutex::new(config));

    let store = MemoryStore::new();

    let mut server = HttpServer::new(move || {
        App::new()
            .wrap(
                RateLimiter::new(
                MemoryStoreActor::from(store.clone()).start())
                    .with_interval(Duration::from_secs(30))
                    .with_max_requests(500)
            )
            .app_data(data.clone())
            .app_data(actix_web::web::Bytes::configure(|cfg| {
                cfg.limit(maxsize)
            }))
            .route("/upload/{steamid64}", web::post().to( upload))
            .route("/list/{steamid64}", web::get().to( list))
            .route("/get/{steamid64}/{filename}.vtf", web::get().to( get))
            .route("/check/{steamid64}/{filename}.vtf", web::get().to( check))
    })
    .disable_signals();

    if ssl {
        server = server.bind_rustls(addr, ssl_config)?;
    } else {
        server = server.bind(addr)?;
    }

    server.run().await?;

    Ok(())
}

pub async fn spawn(config: Config) -> Result<()> {
    loop {
        task(config.clone())
            .await
            .unwrap_or_else(|err| warn!("Web task failed: {}", err));
    }
}