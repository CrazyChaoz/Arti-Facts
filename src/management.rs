use crate::onion_http_server::{RUNNING_ONION_SERVICES, VISIT_COUNTS, onion_service_from_sk};
use crate::utils::{generate_key, get_onion_address, keypair_from_sk};
use arti_client::TorClient;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::info;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tor_rtcompat::PreferredRuntime;

fn load_service_list(
    config_directory: &Path,
) -> Result<HashMap<String, ([u8; 32], String, bool)>, serde_json::Error> {
    let log_file = config_directory.join("service_list.json");
    fs::read_to_string(&log_file)
        .map_err(serde_json::Error::io)
        .and_then(|content| {
            serde_json::from_str::<HashMap<String, ([u8; 32], String, bool)>>(&content)
        })
}

fn save_service_list(
    config_directory: &Path,
    services: &HashMap<String, ([u8; 32], String, bool)>,
) {
    let log_file = config_directory.join("service_list.json");
    if let Ok(json) = serde_json::to_string(services) {
        let _ = fs::write(&log_file, json);
    }
}

pub(crate) async fn run_managed_service(
    client: TorClient<PreferredRuntime>,
    config_directory: PathBuf,
    custom_css: Option<String>,
    visitor_tracking: bool,
) {
    // Run a simple HTTP server for management page
    let mgmt_addr = "127.0.0.1:8080";

    println!("Management page available at http://{mgmt_addr}/");

    let secret_keys_to_directory_mapping: Arc<Mutex<HashMap<String, ([u8; 32], String, bool)>>> =
        Arc::new(Mutex::new(
            load_service_list(&config_directory).unwrap_or_default(),
        ));

    if !secret_keys_to_directory_mapping.lock().unwrap().is_empty() {
        for (onion_address, (sk, share_dir, is_proxy)) in
            secret_keys_to_directory_mapping.lock().unwrap().iter()
        {
            let share_path = PathBuf::from(share_dir);
            if share_path.exists() && share_path.is_dir() {
                info!(
                    "Starting existing onion service: {onion_address} with directory {share_dir}"
                );
                tokio::spawn(onion_service_from_sk(
                    client.clone(),
                    share_path,
                    config_directory.clone(),
                    Some(*sk),
                    custom_css.clone(),
                    if *is_proxy {
                        // For proxy, parse share_dir as (u16, std::net::SocketAddr)
                        serde_json::from_str::<(u16, std::net::SocketAddr)>(share_dir).ok()
                    } else {
                        None
                    },
                    visitor_tracking,
                ));
            } else {
                info!("Skipping non-existent directory for onion service: {share_dir}");
            }
        }
    }

    let mgmt_service = service_fn(move |request| {
        service_function(
            request,
            secret_keys_to_directory_mapping.clone(),
            client.clone(),
            config_directory.clone(),
            custom_css.clone(),
            visitor_tracking,
        )
    });

    let listener = tokio::net::TcpListener::bind(mgmt_addr).await.unwrap();
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        tokio::spawn(http1::Builder::new().serve_connection(io, mgmt_service.clone()));
    }
}

fn service_function(
    req: Request<Incoming>,
    secret_keys_to_directory_mapping: Arc<Mutex<HashMap<String, ([u8; 32], String, bool)>>>,
    client: TorClient<PreferredRuntime>,
    config_directory: PathBuf,
    custom_css: Option<String>,
    visitor_tracking: bool,
) -> impl Future<
    Output = Result<
        Response<http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>>,
        std::io::Error,
    >,
> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    info!("Incoming request: {req:?}");

    async move {
        let body = String::from_utf8(
            req.into_body()
                .collect()
                .await
                .expect("Error while awaiting incoming request")
                .to_bytes()
                .into(),
        )
        .expect("Failed to parse body as UTF-8");

        info!("Request body: {body:?}");
        async move {
            match (method, uri.path()) {
                (Method::POST, "/add-onion-service") => {
                    let params: HashMap<_, _> = form_urlencoded::parse(body.as_bytes())
                        .into_owned()
                        .collect();

                    info!("Adding onion service: {params:?}");

                    if let (Some(secret_key), Some(share_dir)) = (params.get("secret_key"), params.get("share_dir")) {
                        let mut sk = [0u8; 32];
                        if hex::decode_to_slice(secret_key, &mut sk).is_ok() {
                            let share_dir = PathBuf::from(share_dir);
                            if share_dir.exists() && share_dir.is_dir() {
                                secret_keys_to_directory_mapping.lock().unwrap().insert(get_onion_address(keypair_from_sk(sk).public().as_bytes()), (sk, share_dir.to_string_lossy().into_owned(),false));

                                let config_dir = config_directory.clone();
                                tokio::spawn(async move {
                                    onion_service_from_sk(
                                        client,
                                        share_dir,
                                        config_dir,
                                        Some(sk),
                                        custom_css,
                                        None,
                                        visitor_tracking,
                                    ).await;
                                });

                                save_service_list(&config_directory, &secret_keys_to_directory_mapping.lock().unwrap());

                                return Ok(Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::<Bytes>::from("").boxed())
                                    .unwrap());
                            }
                        }
                    }

                    Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::<Bytes>::from("Invalid form data").boxed())
                        .unwrap())
                }
                (Method::GET, "/generate-random-key") => {
                    let random_key = generate_key();
                    let hex_key = hex::encode(random_key);
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::<Bytes>::from(hex_key).boxed())
                        .unwrap())
                }
                (Method::DELETE, "/delete-onion-service") => {
                    let params: HashMap<_, _> = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                        .into_owned()
                        .collect();
                    info!("Deleting onion service: {params:?}");

                    if let Some(onion_address) = params.get("onion_address") {
                        let onion_address = onion_address.trim_end_matches(".onion");

                        secret_keys_to_directory_mapping.lock().unwrap().remove(onion_address);

                        let service = RUNNING_ONION_SERVICES
                            .lock()
                            .unwrap()
                            .remove(onion_address);

                        if let Some(service) = service {
                            service.cancel();
                            save_service_list(&config_directory, &secret_keys_to_directory_mapping.lock().unwrap());

                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::<Bytes>::from("").boxed())
                                .unwrap());
                        } else {
                            info!("No running onion service found for address: {}", onion_address);
                            return Ok(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Full::<Bytes>::from("Onion service not found").boxed())
                                .unwrap());
                        }
                    }

                    Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::<Bytes>::from("Invalid form data").boxed())
                        .unwrap())
                }
                _ => {
                    let html = include_str!("management_page.html")
                        .replace("{existing_onion_services}",
                            &secret_keys_to_directory_mapping
                                .clone()
                                .lock()
                                .unwrap()
                                .iter()
                                .map(|(onion_address, (_sk, dir,is_proxy))| {
                                    format!(
                                        "<tr>\
                                        <td class=\"onion\">{}</td>\
                                        <td class=\"{}\">{}</td>\
                                        <td>{}</td>\
                                        <td><button onclick=\"deleteOnionService('{}')\" class=\"delete-button\">🗑️</button></td>\
                                        </tr>",
                                        onion_address,
                                        if *is_proxy { "proxy" } else { "dir" },
                                        dir,
                                        if visitor_tracking {
                                            VISIT_COUNTS
                                                .lock()
                                                .unwrap()
                                                .get(format!("{onion_address}.onion").as_str())
                                                .map_or("0".to_string(), |v| v.len().to_string())
                                        } else {
                                            "N/A".to_string()
                                        },
                                        onion_address
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join("\n"),
                    );
                    Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "text/html; charset=utf-8")
                            .body(Full::<Bytes>::from(html).map_err(|e| match e {}).boxed())
                            .unwrap()
                    )
                }
            }
        }.await
    }
}
