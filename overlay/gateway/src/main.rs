use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{
        DefaultBodyLimit, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::SinkExt;
use isahc::{
    HttpClient,
    config::{RedirectPolicy, VersionNegotiation},
    prelude::*,
};
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    sync::{Mutex, Notify, Semaphore, broadcast},
    task::JoinSet,
};
use uuid::Uuid;
use zedlink_local_ipc::{self as local_ipc, asynchronous as ipc};
use web_push::{
    ContentEncoding, IsahcWebPushClient, SubscriptionInfo, Urgency, VapidSignatureBuilder,
    WebPushClient, WebPushError, WebPushMessageBuilder,
};

const MAX_RPC: usize = 2 * 1024 * 1024;
const MAX_PROBE_RESPONSE: u64 = 4 * 1024 * 1024;
const PAIR_TTL: Duration = Duration::from_secs(300);
const MAX_DEVICES: usize = 32;
const MAX_WEBSOCKETS: usize = 64;
const EVENT_POLL: Duration = Duration::from_secs(1);
const NOTIFICATION_POLL: Duration = Duration::from_secs(2);
const PUSH_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone)]
struct Gateway(Arc<Inner>);
struct Inner {
    directory: PathBuf,
    targets: Vec<ProbeTarget>,
    route_origins: Vec<String>,
    tls_identities: Vec<TlsIdentity>,
    persisted: Mutex<Persisted>,
    pairing: Mutex<Option<Pairing>>,
    pairing_updates: broadcast::Sender<PairingUpdate>,
    probe_limit: Arc<Semaphore>,
    websocket_limit: Arc<Semaphore>,
    shutdown: Arc<Notify>,
    push_client: IsahcWebPushClient,
    apns: Option<ApnsProvider>,
}
struct ApnsProvider {
    team_id: String,
    key_id: String,
    key_pem: String,
    client: HttpClient,
}
#[derive(Clone)]
struct TlsIdentity {
    id: String,
    cert: PathBuf,
    key: PathBuf,
    config: RustlsConfig,
}
#[derive(Clone, Serialize, Deserialize)]
struct Persisted {
    gateway_id: Uuid,
    devices: Vec<Device>,
    #[serde(default)]
    vapid_private_key: String,
    #[serde(default)]
    push_subscriptions: Vec<PushSubscription>,
    #[serde(default)]
    apns_devices: Vec<ApnsDevice>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ApnsDevice {
    device_id: Uuid,
    token: String,
    environment: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Device {
    id: Uuid,
    name: String,
    digest: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PushSubscription {
    device_id: Uuid,
    subscription: SubscriptionInfo,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApnsRegistrationRequest {
    token: String,
    environment: String,
}
struct Pairing {
    id: Uuid,
    digest: [u8; 32],
    watch_digest: [u8; 32],
    kind: PairingKind,
    expires: Instant,
    attempts: u8,
}
#[derive(Clone, Serialize)]
struct PairingUpdate {
    pairing_id: Uuid,
    status: &'static str,
    attempts_remaining: u8,
}
#[derive(Clone, Copy)]
enum PairingKind {
    Hex,
    Decimal,
}
#[derive(Deserialize)]
struct PairRequest {
    code: String,
    device_name: String,
}
#[derive(Deserialize)]
struct EventQuery {
    thread_id: String,
    after_sequence: Option<u64>,
    target_id: Option<String>,
}
#[derive(Deserialize)]
struct PairingEventQuery {
    pairing_id: String,
}
#[derive(Deserialize)]
struct UnsubscribeRequest {
    endpoint: String,
}
#[derive(Deserialize)]
struct NotificationTestRequest {
    endpoint: String,
}

#[derive(Clone, Default)]
struct ThreadObservation {
    status: String,
    approvals: HashSet<String>,
    inputs: HashSet<String>,
    had_error: bool,
    last_sequence: u64,
}

fn thread_notification(
    previous: &ThreadObservation,
    current: &ThreadObservation,
    stop_reason: Option<&str>,
) -> Option<&'static str> {
    if current
        .approvals
        .iter()
        .any(|id| !previous.approvals.contains(id))
    {
        Some("A Zed Agent session needs your approval.")
    } else if current
        .inputs
        .iter()
        .any(|id| !previous.inputs.contains(id))
    {
        Some("A Zed Agent session needs your input.")
    } else if let Some(reason) = stop_reason {
        match reason {
            "completed" if current.had_error => Some("A Zed Agent session failed."),
            "completed" => Some("A Zed Agent session completed."),
            "cancelled" => Some("A Zed Agent session was cancelled."),
            "max_turn_requests" => Some("A Zed Agent session reached its turn request limit."),
            "max_tokens" => Some("A Zed Agent session reached its output limit."),
            "refusal" => Some("A Zed Agent request was refused."),
            "error" => Some("A Zed Agent session stopped with an error."),
            _ => Some("A Zed Agent session stopped. Open it to review the reason."),
        }
    } else if !previous.had_error && current.had_error {
        Some("A Zed Agent session failed.")
    } else if previous.status == "Generating" && current.status == "Idle" {
        Some("A Zed Agent session stopped. Open it to review the result.")
    } else {
        None
    }
}

fn pending_approval_keys(snapshot: &Value) -> HashSet<String> {
    let mut keys = HashSet::new();
    let mut add = |rows: Option<&Vec<Value>>, child: &str| {
        for row in rows.into_iter().flatten() {
            if let Some(id) = row["approval_id"].as_str() {
                keys.insert(format!(
                    "{}:{child}:{}:{id}",
                    snapshot["epoch"], row["turn_id"]
                ));
            }
        }
    };
    add(snapshot["pending_approvals"].as_array(), "");
    for child in snapshot["subagents"].as_array().into_iter().flatten() {
        add(
            child["pending_approvals"].as_array(),
            child["session_id"].as_str().unwrap_or(""),
        );
    }
    keys
}

fn latest_stop_reason(events: &Value, through_sequence: u64) -> Option<&str> {
    events
        .as_array()?
        .iter()
        .rev()
        .find(|event| {
            event["kind"] == "turn.stopped"
                && event["sequence"]
                    .as_u64()
                    .is_some_and(|sequence| sequence <= through_sequence)
        })
        .and_then(|event| event["stop_reason"].as_str())
}

enum PushOutcome {
    Sent,
    Stale,
    Failed,
}

#[derive(Clone, Deserialize)]
struct TlsListenerConfig {
    id: String,
    bind: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize)]
struct ListenerFile {
    version: u8,
    listeners: Vec<TlsListenerConfig>,
}

#[derive(Clone, Deserialize)]
struct ProbeTarget {
    id: String,
    label: String,
    probe: PathBuf,
}

#[derive(Deserialize)]
struct TargetFile {
    version: u8,
    targets: Vec<ProbeTarget>,
}

fn application(state: Gateway) -> Router {
    Router::new()
        .route("/", get(browser_page))
        .route("/app.js", get(browser_script))
        .route("/ui.js", get(browser_ui_bundle))
        .route("/style.css", get(browser_style))
        .route("/manifest.webmanifest", get(browser_manifest))
        .route("/service-worker.js", get(browser_service_worker))
        .route("/fonts/terminal-icons.woff2", get(browser_terminal_font))
        .route("/icons/icon-192.png", get(browser_icon_192))
        .route("/icons/icon-512.png", get(browser_icon_512))
        .route("/v1/gateway", get(info))
        .route("/v1/pair", post(pair))
        .route("/v1/pairing-events", get(pairing_events))
        .route("/v1/rpc", post(rpc))
        .route("/v1/events", get(events))
        .route("/v1/notifications/config", get(notification_config))
        .route("/v1/notifications/subscribe", post(notification_subscribe))
        .route("/v1/notifications/status", post(notification_status))
        .route(
            "/v1/notifications/unsubscribe",
            post(notification_unsubscribe),
        )
        .route("/v1/notifications/test", post(notification_test))
        .route(
            "/v1/notifications/apns",
            get(apns_status).post(apns_register).delete(apns_unregister),
        )
        .route("/v1/notifications/apns/test", post(apns_test))
        .layer(DefaultBodyLimit::max(MAX_RPC))
        .with_state(state)
}

fn validate_listener(listener: &TlsListenerConfig) -> Result<()> {
    if listener.id.trim().is_empty() || listener.id.len() > 64 {
        bail!("listener id must contain 1 to 64 characters");
    }
    if !private_ip(listener.bind.ip()) {
        bail!(
            "listener {} must bind a loopback or private address",
            listener.id
        );
    }
    if !listener.cert.is_absolute() || !listener.key.is_absolute() {
        bail!(
            "listener {} certificate and key paths must be absolute",
            listener.id
        );
    }
    local_ipc::validate_private_file(&listener.key)
        .with_context(|| format!("listener {} TLS private key must be private", listener.id))?;
    if let Some(origin) = &listener.url {
        let parsed = url::Url::parse(origin).context("invalid listener HTTPS origin")?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            bail!(
                "listener {} URL must be a trusted HTTPS origin",
                listener.id
            );
        }
    }
    Ok(())
}

async fn run_gateway(
    listeners: Vec<TlsListenerConfig>,
    targets: Vec<ProbeTarget>,
    directory: PathBuf,
) -> Result<()> {
    if listeners.is_empty() || listeners.len() > 16 {
        bail!("configure between 1 and 16 TLS listeners");
    }
    if !directory.is_absolute() {
        bail!("state path must be absolute");
    }
    local_ipc::create_private_directory(&directory)?;
    // Acquire exclusive ownership before creating or changing pairing state.
    let admin_listener = ipc::Listener::bind(&directory.join("admin.sock"))
        .context("another gateway may already own this state directory")?;
    let mut addresses = HashSet::new();
    for listener in &listeners {
        validate_listener(listener)?;
        if !addresses.insert(listener.bind) {
            bail!("duplicate listener address: {}", listener.bind);
        }
    }

    let mut route_origins = listeners
        .iter()
        .filter_map(|listener| listener.url.clone())
        .collect::<Vec<_>>();
    route_origins.sort();
    route_origins.dedup();
    let mut servers_to_start = Vec::with_capacity(listeners.len());
    let mut tls_identities = Vec::with_capacity(listeners.len());
    for listener in listeners {
        let tls = RustlsConfig::from_pem_file(&listener.cert, &listener.key)
            .await
            .with_context(|| format!("load TLS identity for listener {}", listener.id))?;
        tls_identities.push(TlsIdentity {
            id: listener.id.clone(),
            cert: listener.cert.clone(),
            key: listener.key.clone(),
            config: tls.clone(),
        });
        servers_to_start.push((listener, tls));
    }
    let state = Gateway::load(directory, targets, route_origins, tls_identities)?;
    let admin = state.clone();
    tokio::spawn(async move {
        if let Err(error) = admin.admin_server(admin_listener).await {
            eprintln!("admin socket stopped: {error:#}");
        }
    });
    let notifications = state.clone();
    tokio::spawn(async move { notifications.notification_monitor().await });

    let mut servers = JoinSet::new();
    for (listener, tls) in servers_to_start {
        let app = application(state.clone());
        eprintln!(
            "ZedLink route {} listening on https://{}",
            listener.id, listener.bind
        );
        servers.spawn(async move {
            axum_server::bind_rustls(listener.bind, tls)
                .serve(app.into_make_service())
                .await
                .with_context(|| format!("listener {} stopped", listener.id))
        });
    }
    tokio::select! {
        result = servers.join_next() => match result {
            Some(result) => result.context("gateway listener task failed")??,
            None => bail!("no gateway listener started"),
        },
        _ = state.0.shutdown.notified() => return Ok(()),
    }
    bail!("gateway listener stopped unexpectedly")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("serve") if args.len() == 6 => {
            let address: SocketAddr = args[1].parse().context("invalid listen address")?;
            let probe = PathBuf::from(&args[4]);
            let directory = PathBuf::from(&args[5]);
            run_gateway(
                vec![TlsListenerConfig {
                    id: "primary".into(),
                    bind: address,
                    cert: PathBuf::from(&args[2]),
                    key: PathBuf::from(&args[3]),
                    url: None,
                }],
                vec![ProbeTarget {
                    id: "default".into(),
                    label: "This Zed".into(),
                    probe,
                }],
                directory,
            )
            .await
        }
        Some("serve-routes") if args.len() == 4 => {
            let path = PathBuf::from(&args[1]);
            if !path.is_absolute() {
                bail!("listener configuration path must be absolute");
            }
            local_ipc::validate_private_file(&path)?;
            let config: ListenerFile = serde_json::from_slice(&fs::read(&path)?)
                .context("invalid listener configuration")?;
            if config.version != 1 {
                bail!("unsupported listener configuration version");
            }
            run_gateway(
                config.listeners,
                vec![ProbeTarget {
                    id: "default".into(),
                    label: "This Zed".into(),
                    probe: PathBuf::from(&args[2]),
                }],
                PathBuf::from(&args[3]),
            )
            .await
        }
        Some("serve-targets") if args.len() == 4 => {
            let listeners_path = PathBuf::from(&args[1]);
            let targets_path = PathBuf::from(&args[2]);
            for path in [&listeners_path, &targets_path] {
                if !path.is_absolute() {
                    bail!("configuration paths must be absolute");
                }
                local_ipc::validate_private_file(path)?;
            }
            let listeners: ListenerFile = serde_json::from_slice(&fs::read(listeners_path)?)
                .context("invalid listener configuration")?;
            let targets: TargetFile = serde_json::from_slice(&fs::read(targets_path)?)
                .context("invalid target configuration")?;
            if listeners.version != 1 || targets.version != 1 {
                bail!("unsupported configuration version");
            }
            run_gateway(
                listeners.listeners,
                targets.targets,
                PathBuf::from(&args[3]),
            )
            .await
        }
        Some("admin") if args.len() >= 3 => {
            let command = match args[2].as_str() {
                "pair-code" if args.len() == 3 => json!({"method":"pair-code"}),
                "pair-short-code" if args.len() == 3 => json!({"method":"pair-short-code"}),
                "devices" if args.len() == 3 => json!({"method":"devices"}),
                "reload-tls" if args.len() == 3 => json!({"method":"reload-tls"}),
                "shutdown" if args.len() == 3 => json!({"method":"shutdown"}),
                "revoke" if args.len() == 4 => json!({"method":"revoke","device_id":args[3]}),
                _ => bail!(
                    "admin STATE_DIR pair-code|pair-short-code|devices|reload-tls|shutdown|revoke DEVICE_ID"
                ),
            };
            let mut stream = tokio::time::timeout(Duration::from_secs(3),
                ipc::connect(&Path::new(&args[1]).join("admin.sock"))).await??;
            stream
                .write_all(serde_json::to_string(&command)?.as_bytes())
                .await?;
            stream.write_all(b"\n").await?;
            let mut response = String::new();
            BufReader::new(stream).read_line(&mut response).await?;
            print!("{response}");
            Ok(())
        }
        _ => bail!(
            "serve PRIVATE_IP:PORT CERT_PEM KEY_PEM PROBE_SOCKET STATE_DIR | serve-routes LISTENERS_JSON PROBE_SOCKET STATE_DIR | serve-targets LISTENERS_JSON TARGETS_JSON STATE_DIR | admin STATE_DIR pair-code|pair-short-code|devices|reload-tls|shutdown|revoke DEVICE_ID"
        ),
    }
}
fn static_response(content_type: &'static str, body: &'static str) -> Response {
    let mut response = Response::new(Body::from(body));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    response
}
async fn browser_page() -> Response {
    static_response(
        "text/html; charset=utf-8",
        include_str!("../web/index.html"),
    )
}
async fn browser_script() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../web/app.js"),
    )
}
async fn browser_ui_bundle() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../web/ui.js"),
    )
}
async fn browser_style() -> Response {
    static_response("text/css; charset=utf-8", include_str!("../web/style.css"))
}
async fn browser_manifest() -> Response {
    static_response(
        "application/manifest+json; charset=utf-8",
        include_str!("../web/manifest.webmanifest"),
    )
}
async fn browser_service_worker() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../web/service-worker.js"),
    )
}
fn static_bytes(content_type: &'static str, body: &'static [u8]) -> Response {
    let mut response = Response::new(Body::from(body));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}
async fn browser_terminal_font() -> Response {
    static_bytes(
        "font/woff2",
        include_bytes!("../web/fonts/terminal-icons.woff2"),
    )
}

async fn browser_icon_192() -> Response {
    static_bytes("image/png", include_bytes!("../web/icons/icon-192.png"))
}
async fn browser_icon_512() -> Response {
    static_bytes("image/png", include_bytes!("../web/icons/icon-512.png"))
}
fn private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        }
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00 == 0xfc00),
    }
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ZedLink gateway credential v1\0");
    hash.update(bytes);
    hash.finalize().into()
}
fn new_vapid_private_key() -> String {
    loop {
        let bytes: [u8; 32] = rand::random();
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        if VapidSignatureBuilder::from_base64_no_sub(&encoded).is_ok() {
            return encoded;
        }
    }
}

fn valid_apns_token(token: &str) -> bool {
    (32..=512).contains(&token.len())
        && token.len().is_multiple_of(2)
        && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl ApnsProvider {
    fn from_environment() -> Result<Option<Self>> {
        let key_file = match std::env::var("ZEDLINK_APNS_KEY_FILE") {
            Ok(path) => PathBuf::from(path),
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(_) => bail!("invalid APNs key path"),
        };
        let team_id = std::env::var("ZEDLINK_APNS_TEAM_ID").context("APNs team ID missing")?;
        let key_id = std::env::var("ZEDLINK_APNS_KEY_ID").context("APNs key ID missing")?;
        if ![&team_id, &key_id].iter().all(|id| {
            id.len() == 10
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        }) {
            bail!("invalid APNs team or key ID");
        }
        local_ipc::validate_private_file(&key_file).context("APNs key file must be private")?;
        let key_pem = fs::read_to_string(key_file).context("APNs key file unreadable")?;
        ES256KeyPair::from_pem(&key_pem).context("invalid APNs signing key")?;
        let client = HttpClient::builder()
            .timeout(PUSH_TIMEOUT)
            .redirect_policy(RedirectPolicy::None)
            .version_negotiation(VersionNegotiation::http2())
            .build()
            .context("APNs HTTP/2 client unavailable")?;
        Ok(Some(Self {
            team_id,
            key_id,
            key_pem,
            client,
        }))
    }

    fn provider_token(&self) -> Result<String> {
        let key = ES256KeyPair::from_pem(&self.key_pem)?;
        let mut claims =
            Claims::create(jwt_simple::prelude::Duration::from_mins(50)).with_issuer(&self.team_id);
        claims.expires_at = None;
        claims.invalid_before = None;
        Ok(key.with_key_id(&self.key_id).sign(claims)?)
    }

    async fn send(
        &self,
        registration: &ApnsDevice,
        body: &str,
        gateway_id: &str,
        target_id: Option<&str>,
        thread_id: Option<&str>,
    ) -> PushOutcome {
        if !valid_apns_token(&registration.token) {
            return PushOutcome::Failed;
        }
        let Ok(token) = self.provider_token() else {
            return PushOutcome::Failed;
        };
        let host = if registration.environment == "sandbox" {
            "api.sandbox.push.apple.com"
        } else {
            "api.push.apple.com"
        };
        let payload = json!({"aps": {"alert": {"title": "ZedLink", "body": body},
            "sound": "default", "category": "ZEDLINK_REVIEW"},
            "gateway": gateway_id, "target": target_id, "thread": thread_id,
            "type": if thread_id.is_some() { "push" } else { "push_test" }});
        let request =
            isahc::Request::post(format!("https://{host}/3/device/{}", registration.token))
                .header("authorization", format!("bearer {token}"))
                .header("apns-topic", "dev.zedlink.app")
                .header("apns-push-type", "alert")
                .header("apns-expiration", "0")
                .header("content-type", "application/json")
                .body(payload.to_string());
        let Ok(request) = request else {
            return PushOutcome::Failed;
        };
        match tokio::time::timeout(PUSH_TIMEOUT, self.client.send_async(request)).await {
            Ok(Ok(response)) if response.status().is_success() => PushOutcome::Sent,
            Ok(Ok(response)) if response.status().as_u16() == 410 => PushOutcome::Stale,
            _ => PushOutcome::Failed,
        }
    }
}

fn valid_subscription(subscription: &SubscriptionInfo) -> bool {
    let public_key = URL_SAFE_NO_PAD.decode(subscription.keys.p256dh.as_bytes());
    let auth = URL_SAFE_NO_PAD.decode(subscription.keys.auth.as_bytes());
    let trusted_endpoint = url::Url::parse(&subscription.endpoint)
        .ok()
        .filter(|endpoint| {
            endpoint.scheme() == "https"
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.port_or_known_default() == Some(443)
        })
        .and_then(|endpoint| endpoint.host_str().map(str::to_owned))
        .is_some_and(|host| {
            host == "fcm.googleapis.com"
                || host == "push.apple.com"
                || host.ends_with(".push.apple.com")
                || host == "push.services.mozilla.com"
                || host.ends_with(".push.services.mozilla.com")
        });
    trusted_endpoint
        && subscription.endpoint.len() <= 2048
        && !subscription.keys.p256dh.is_empty()
        && subscription.keys.p256dh.len() <= 256
        && !subscription.keys.auth.is_empty()
        && subscription.keys.auth.len() <= 256
        && matches!(public_key.as_deref(), Ok([4, ..]) if public_key.as_ref().is_ok_and(|key| key.len() == 65))
        && auth.as_ref().is_ok_and(|secret| secret.len() == 16)
}
fn save(directory: &Path, state: &Persisted) -> Result<()> {
    local_ipc::save_private(&directory.join("state.json"), &serde_json::to_vec(state)?)?;
    Ok(())
}
impl Gateway {
    fn load(
        directory: PathBuf,
        targets: Vec<ProbeTarget>,
        route_origins: Vec<String>,
        tls_identities: Vec<TlsIdentity>,
    ) -> Result<Self> {
        if targets.is_empty() || targets.len() > 16 {
            bail!("configure between 1 and 16 Zed targets");
        }
        let mut target_ids = HashSet::new();
        for target in &targets {
            if target.id.is_empty()
                || target.id.len() > 64
                || !target
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                || target.label.trim().is_empty()
                || target.label.len() > 80
                || !target_ids.insert(target.id.clone())
                || !target.probe.is_absolute()
            {
                bail!("invalid or duplicate Zed target");
            }
            local_ipc::validate_endpoint_parent(&target.probe)?;
            if target.probe.exists() {
                validate_probe_socket(&target.probe)?;
            }
        }
        local_ipc::create_private_directory(&directory)?;
        let file = directory.join("state.json");
        let mut persisted: Persisted = if file.exists() {
            local_ipc::validate_private_file(&file)?;
            serde_json::from_slice(&fs::read(file)?)?
        } else {
            let initial = Persisted {
                gateway_id: Uuid::new_v4(),
                devices: vec![],
                vapid_private_key: new_vapid_private_key(),
                push_subscriptions: vec![],
                apns_devices: vec![],
            };
            save(&directory, &initial)?;
            initial
        };
        if persisted.vapid_private_key.is_empty() {
            persisted.vapid_private_key = new_vapid_private_key();
            save(&directory, &persisted)?;
        }
        VapidSignatureBuilder::from_base64_no_sub(&persisted.vapid_private_key)
            .context("invalid saved Web Push key")?;
        let (pairing_updates, _) = broadcast::channel(16);
        Ok(Self(Arc::new(Inner {
            directory,
            targets,
            route_origins,
            tls_identities,
            persisted: Mutex::new(persisted),
            pairing: Mutex::new(None),
            pairing_updates,
            probe_limit: Arc::new(Semaphore::new(16)),
            websocket_limit: Arc::new(Semaphore::new(MAX_WEBSOCKETS)),
            shutdown: Arc::new(Notify::new()),
            push_client: IsahcWebPushClient::new().context("Web Push client unavailable")?,
            apns: ApnsProvider::from_environment()?,
        })))
    }
    async fn authorize(&self, headers: &HeaderMap) -> Option<Uuid> {
        let token = headers
            .get("authorization")?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")?;
        self.authorize_token(token).await
    }
    async fn authorize_token(&self, token: &str) -> Option<Uuid> {
        let bytes = hex::decode(token).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let hash = digest(&bytes);
        self.0
            .persisted
            .lock()
            .await
            .devices
            .iter()
            .find_map(|device| {
                let stored = hex::decode(&device.digest).ok()?;
                (stored.len() == 32 && bool::from(stored.ct_eq(&hash))).then_some(device.id)
            })
    }
    fn target(&self, target_id: Option<&str>) -> Result<&ProbeTarget> {
        match target_id {
            Some(id) => self
                .0
                .targets
                .iter()
                .find(|target| target.id == id)
                .context("unknown Zed target"),
            None => self.0.targets.first().context("no Zed target configured"),
        }
    }

    async fn probe(&self, target_id: Option<&str>, request: &Value) -> Result<Value> {
        let _permit = self
            .0
            .probe_limit
            .clone()
            .try_acquire_owned()
            .context("probe request limit reached")?;
        let encoded = serde_json::to_vec(request)?;
        if encoded.len() > MAX_RPC {
            bail!("oversized probe request");
        }
        let probe = self.target(target_id)?.probe.clone();
        validate_probe_socket(&probe)?;
        let mut stream =
            tokio::time::timeout(Duration::from_secs(3), ipc::connect(&probe)).await??;
        stream.write_all(&encoded).await?;
        stream.write_all(b"\n").await?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(6), async {
            BufReader::new(stream)
                .take(MAX_PROBE_RESPONSE + 1)
                .read_until(b'\n', &mut response)
                .await
        })
        .await??;
        if response.len() as u64 > MAX_PROBE_RESPONSE || !response.ends_with(b"\n") {
            bail!("invalid probe response");
        }
        let response: Value = serde_json::from_slice(&response)?;
        if response["version"] != 1
            || response["request_id"] != request["request_id"]
            || response.get("result").is_some() == response.get("error").is_some()
        {
            bail!("invalid probe response envelope");
        }
        Ok(response)
    }

    async fn instance_list(&self) -> Value {
        let mut targets = Vec::with_capacity(self.0.targets.len());
        for target in &self.0.targets {
            let request = json!({
                "version": 1,
                "request_id": Uuid::new_v4().to_string(),
                "method": "instance.info",
                "params": {},
            });
            let mut item = json!({
                "target_id": target.id,
                "label": target.label,
                "available": false,
            });
            if let Ok(response) = self.probe(Some(&target.id), &request).await
                && let Some(result) = response.get("result")
            {
                item["available"] = json!(true);
                for field in ["instance_id", "epoch", "capabilities", "project"] {
                    if let Some(value) = result.get(field) {
                        item[field] = value.clone();
                    }
                }
            }
            targets.push(item);
        }
        json!({
            "targets": targets,
            "default_target_id": self.0.targets.first().map(|target| target.id.as_str()),
        })
    }
    async fn admin_server(&self, mut listener: ipc::Listener) -> Result<()> {
        loop {
            let stream = listener.accept().await?;
            let state = self.clone();
            tokio::spawn(async move {
                if let Err(error) = state.admin_command(stream).await {
                    eprintln!("admin command failed: {error:#}");
                }
            });
        }
    }
    async fn admin_command(&self, stream: ipc::Stream) -> Result<()> {
        let mut reader = BufReader::new(stream);
        let mut request = Vec::new();
        (&mut reader)
            .take(1025)
            .read_until(b'\n', &mut request)
            .await?;
        if request.len() > 1024 || !request.ends_with(b"\n") {
            bail!("invalid admin request");
        }
        let request: Value = serde_json::from_slice(&request)?;
        let shutdown = request["method"].as_str() == Some("shutdown");
        let response = match request["method"].as_str() {
            Some("pair-code") => {
                let code: [u8; 32] = rand::random();
                let watch_token: [u8; 32] = rand::random();
                let id = Uuid::new_v4();
                let mut pairing = self.0.pairing.lock().await;
                if let Some(previous) = pairing.as_ref() {
                    drop(self.0.pairing_updates.send(PairingUpdate {
                        pairing_id: previous.id,
                        status: "replaced",
                        attempts_remaining: 0,
                    }));
                }
                *pairing = Some(Pairing {
                    id,
                    digest: digest(&code),
                    watch_digest: digest(&watch_token),
                    kind: PairingKind::Hex,
                    expires: Instant::now() + PAIR_TTL,
                    attempts: 0,
                });
                json!({"code":hex::encode(code),"pairing_id":id,
                    "watch_token":hex::encode(watch_token),"expires_seconds":PAIR_TTL.as_secs()})
            }
            Some("pair-short-code") => {
                let code = format!("{:010}", rand::random_range(0..10_000_000_000_u64));
                let watch_token: [u8; 32] = rand::random();
                let id = Uuid::new_v4();
                let mut pairing = self.0.pairing.lock().await;
                if let Some(previous) = pairing.as_ref() {
                    drop(self.0.pairing_updates.send(PairingUpdate {
                        pairing_id: previous.id,
                        status: "replaced",
                        attempts_remaining: 0,
                    }));
                }
                *pairing = Some(Pairing {
                    id,
                    digest: digest(code.as_bytes()),
                    watch_digest: digest(&watch_token),
                    kind: PairingKind::Decimal,
                    expires: Instant::now() + PAIR_TTL,
                    attempts: 0,
                });
                json!({"code":code,"pairing_id":id,
                    "watch_token":hex::encode(watch_token),"expires_seconds":PAIR_TTL.as_secs()})
            }
            Some("devices") => {
                let persisted = self.0.persisted.lock().await;
                json!({"gateway_id":persisted.gateway_id,
                    "devices":persisted.devices.iter().map(|device| json!({
                        "id":device.id,
                        "name":device.name,
                        "notifications":persisted.push_subscriptions.iter().any(|subscription| subscription.device_id == device.id)
                            || persisted.apns_devices.iter().any(|registration| registration.device_id == device.id)
                    })).collect::<Vec<_>>()})
            }
            Some("shutdown") => json!({"stopping":true}),
            Some("reload-tls") => {
                let mut replacements = Vec::with_capacity(self.0.tls_identities.len());
                for identity in &self.0.tls_identities {
                    let replacement = RustlsConfig::from_pem_file(&identity.cert, &identity.key)
                        .await
                        .with_context(|| {
                            format!("reload TLS identity for listener {}", identity.id)
                        })?;
                    replacements.push(replacement);
                }
                let mut listeners = Vec::with_capacity(replacements.len());
                for (identity, replacement) in self.0.tls_identities.iter().zip(replacements) {
                    identity.config.reload_from_config(replacement.get_inner());
                    listeners.push(identity.id.clone());
                }
                json!({"reloaded":true,"listeners":listeners})
            }
            Some("revoke") => {
                let id =
                    Uuid::parse_str(request["device_id"].as_str().context("device ID missing")?)?;
                let mut persisted = self.0.persisted.lock().await;
                let mut next = persisted.clone();
                let before = next.devices.len();
                next.devices.retain(|device| device.id != id);
                next.push_subscriptions
                    .retain(|subscription| subscription.device_id != id);
                next.apns_devices
                    .retain(|registration| registration.device_id != id);
                if next.devices.len() != before {
                    save(&self.0.directory, &next)?;
                    *persisted = next;
                }
                json!({"revoked":persisted.devices.len()!=before})
            }
            _ => json!({"error":"INVALID_REQUEST"}),
        };
        let mut stream = reader.into_inner();
        stream
            .write_all(serde_json::to_string(&response)?.as_bytes())
            .await?;
        stream.write_all(b"\n").await?;
        if shutdown {
            self.0.shutdown.notify_one();
        }
        Ok(())
    }

    fn vapid_public_key(&self, persisted: &Persisted) -> Result<String> {
        let builder = VapidSignatureBuilder::from_base64_no_sub(&persisted.vapid_private_key)?;
        Ok(URL_SAFE_NO_PAD.encode(builder.get_public_key()))
    }

    async fn send_push(
        &self,
        record: &PushSubscription,
        body: &str,
        thread_id: Option<&str>,
        target_id: Option<&str>,
    ) -> PushOutcome {
        let private_key = self.0.persisted.lock().await.vapid_private_key.clone();
        let signature = match VapidSignatureBuilder::from_base64(&private_key, &record.subscription)
            .and_then(|builder| builder.build())
        {
            Ok(signature) => signature,
            Err(_) => return PushOutcome::Failed,
        };
        let payload = json!({
            "title": "ZedLink",
            "body": body,
            "tag": thread_id.map_or_else(|| "zedlink-test".to_owned(), |id| format!("zedlink-thread-{id}")),
            "thread_id": thread_id,
            "target_id": target_id,
            "kind": if body == "A Zed Agent session needs your approval." { "approval" } else { "status" },
        });
        let encoded = match serde_json::to_vec(&payload) {
            Ok(encoded) => encoded,
            Err(_) => return PushOutcome::Failed,
        };
        let mut builder = WebPushMessageBuilder::new(&record.subscription);
        builder.set_payload(ContentEncoding::Aes128Gcm, &encoded);
        builder.set_ttl(300);
        builder.set_urgency(if body == "A Zed Agent session needs your approval." {
            Urgency::High
        } else {
            Urgency::Normal
        });
        builder.set_vapid_signature(signature);
        let message = match builder.build() {
            Ok(message) => message,
            Err(_) => return PushOutcome::Failed,
        };
        match tokio::time::timeout(PUSH_TIMEOUT, self.0.push_client.send(message)).await {
            Ok(Ok(())) => PushOutcome::Sent,
            Ok(Err(WebPushError::EndpointNotFound(_) | WebPushError::EndpointNotValid(_))) => {
                PushOutcome::Stale
            }
            _ => PushOutcome::Failed,
        }
    }

    async fn notify_all(&self, body: &'static str, target_id: &str, thread_id: &str) {
        let persisted = self.0.persisted.lock().await;
        let subscriptions = persisted.push_subscriptions.clone();
        let apns_devices = persisted.apns_devices.clone();
        let gateway_id = persisted.gateway_id.to_string();
        drop(persisted);
        let mut stale = HashSet::new();
        for record in subscriptions {
            if matches!(
                self.send_push(&record, body, Some(thread_id), Some(target_id))
                    .await,
                PushOutcome::Stale
            ) {
                stale.insert(record.subscription.endpoint);
            }
        }
        if !stale.is_empty() {
            let mut persisted = self.0.persisted.lock().await;
            let mut next = persisted.clone();
            next.push_subscriptions
                .retain(|record| !stale.contains(&record.subscription.endpoint));
            if save(&self.0.directory, &next).is_ok() {
                *persisted = next;
            }
        }
        if let Some(provider) = &self.0.apns {
            let mut expired = HashSet::new();
            for registration in apns_devices {
                if matches!(
                    provider
                        .send(
                            &registration,
                            body,
                            &gateway_id,
                            Some(target_id),
                            Some(thread_id)
                        )
                        .await,
                    PushOutcome::Stale
                ) {
                    expired.insert(registration.token);
                }
            }
            if !expired.is_empty() {
                let mut persisted = self.0.persisted.lock().await;
                let mut next = persisted.clone();
                next.apns_devices
                    .retain(|registration| !expired.contains(&registration.token));
                if save(&self.0.directory, &next).is_ok() {
                    *persisted = next;
                }
            }
        }
    }

    async fn notification_monitor(&self) {
        let mut prior = HashMap::<String, ThreadObservation>::new();
        let mut interval = tokio::time::interval(NOTIFICATION_POLL);
        loop {
            interval.tick().await;
            let persisted = self.0.persisted.lock().await;
            let no_subscribers = persisted.push_subscriptions.is_empty()
                && (self.0.apns.is_none() || persisted.apns_devices.is_empty());
            drop(persisted);
            if no_subscribers {
                prior.clear();
                continue;
            }
            let mut current = prior.clone();
            for target in &self.0.targets {
                let request = json!({
                    "version": 1,
                    "request_id": Uuid::new_v4().to_string(),
                    "method": "thread.list",
                    "params": {},
                });
                let Ok(response) = self.probe(Some(&target.id), &request).await else {
                    continue;
                };
                let Some(threads) = response["result"]["threads"].as_array() else {
                    continue;
                };
                let (Some(instance), Some(epoch)) = (
                    response["result"]["instance_id"].as_str(),
                    response["result"]["epoch"].as_str(),
                ) else {
                    continue;
                };
                current.retain(|key, _| !key.starts_with(&format!("{}:", target.id)));
                for thread in threads {
                    let Some(thread_id) = thread["thread_id"].as_str() else {
                        continue;
                    };
                    let snapshot_request = json!({
                        "version": 1,
                        "request_id": Uuid::new_v4().to_string(),
                        "method": "thread.snapshot",
                        "params": {"thread_id": thread_id},
                    });
                    let key = format!("{}:{instance}:{epoch}:{thread_id}", target.id);
                    let (approvals, last_sequence, status, had_error) =
                        match self.probe(Some(&target.id), &snapshot_request).await {
                            Ok(snapshot) => {
                                let Some(result) = snapshot.get("result").filter(|result| {
                                    result["pending_approvals"].is_array()
                                        && result["instance_id"].as_str() == Some(instance)
                                        && result["epoch"].as_str() == Some(epoch)
                                }) else {
                                    if let Some(previous) = prior.get(&key) {
                                        current.insert(key, previous.clone());
                                    }
                                    continue;
                                };
                                (
                                    pending_approval_keys(result),
                                    result["last_sequence"].as_u64().unwrap_or(0),
                                    result["status"].as_str().unwrap_or("Unknown").to_owned(),
                                    result["had_error"].as_bool().unwrap_or(false),
                                )
                            }
                            Err(_) => {
                                if let Some(previous) = prior.get(&key) {
                                    current.insert(key, previous.clone());
                                }
                                continue;
                            }
                        };
                    let inputs = self.probe(Some(&target.id), &json!({
                            "version": 1,
                            "request_id": Uuid::new_v4().to_string(),
                            "method": "thread.elicitations",
                            "params": {"thread_id": thread_id, "instance_id": instance, "epoch": epoch},
                        })).await.ok()
                        .and_then(|response| response["result"]["elicitations"].as_array().map(|rows| rows.iter()
                                .take(128)
                                .filter(|row| row["status"] == "pending")
                                .filter_map(|row| row["elicitation_id"].as_str().map(str::to_owned))
                                .collect::<HashSet<_>>()))
                        .unwrap_or_else(|| prior.get(&key).map(|previous| previous.inputs.clone()).unwrap_or_default());
                    let observation = ThreadObservation {
                        status,
                        approvals,
                        inputs,
                        had_error,
                        last_sequence,
                    };
                    let stop_reason = if let Some(previous) = prior.get(&key) {
                        let events_request = json!({
                            "version": 1,
                            "request_id": Uuid::new_v4().to_string(),
                            "method": "thread.events",
                            "params": {"thread_id": thread_id, "after_sequence": previous.last_sequence},
                        });
                        self.probe(Some(&target.id), &events_request)
                            .await
                            .ok()
                            .filter(|events| {
                                events["result"]["instance_id"].as_str() == Some(instance)
                                    && events["result"]["epoch"].as_str() == Some(epoch)
                            })
                            .and_then(|events| {
                                latest_stop_reason(&events["result"]["events"], last_sequence)
                                    .map(str::to_owned)
                            })
                    } else {
                        None
                    };
                    let initial = ThreadObservation::default();
                    if let Some(body) = thread_notification(
                        prior.get(&key).unwrap_or(&initial),
                        &observation,
                        stop_reason.as_deref(),
                    ) {
                        self.notify_all(body, &target.id, thread_id).await;
                    }
                    current.insert(key, observation);
                }
            }
            prior = current;
        }
    }
}

fn validate_probe_socket(probe: &Path) -> Result<()> {
    local_ipc::validate_endpoint(probe).context("native probe endpoint must be private")?;
    Ok(())
}
async fn info(State(state): State<Gateway>) -> Json<Value> {
    Json(json!({
        "version": 1,
        "gateway_id": state.0.persisted.lock().await.gateway_id,
        "route_origins": state.0.route_origins,
    }))
}
async fn pair(State(state): State<Gateway>, Json(request): Json<PairRequest>) -> impl IntoResponse {
    if request.device_name.trim().is_empty() || request.device_name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_REQUEST"})),
        );
    }
    let mut pairing = state.0.pairing.lock().await;
    let Some(active) = pairing.as_mut() else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"PAIRING_UNAVAILABLE"})),
        );
    };
    if Instant::now() >= active.expires || active.attempts >= 5 {
        drop(state.0.pairing_updates.send(PairingUpdate {
            pairing_id: active.id,
            status: "expired",
            attempts_remaining: 0,
        }));
        *pairing = None;
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"PAIRING_EXPIRED"})),
        );
    }
    active.attempts += 1;
    let valid = match active.kind {
        PairingKind::Hex => {
            let decoded = hex::decode(&request.code).unwrap_or_default();
            decoded.len() == 32 && bool::from(active.digest.ct_eq(&digest(&decoded)))
        }
        PairingKind::Decimal => {
            request.code.len() == 10
                && request.code.bytes().all(|byte| byte.is_ascii_digit())
                && bool::from(active.digest.ct_eq(&digest(request.code.as_bytes())))
        }
    };
    if !valid {
        drop(state.0.pairing_updates.send(PairingUpdate {
            pairing_id: active.id,
            status: "attempt_failed",
            attempts_remaining: 5_u8.saturating_sub(active.attempts),
        }));
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"PAIRING_INVALID"})),
        );
    }
    let mut persisted = state.0.persisted.lock().await;
    if persisted.devices.len() >= MAX_DEVICES {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"RATE_LIMITED"})),
        );
    }
    let token: [u8; 32] = rand::random();
    let id = Uuid::new_v4();
    let mut next = persisted.clone();
    next.devices.push(Device {
        id,
        name: request.device_name,
        digest: hex::encode(digest(&token)),
    });
    if save(&state.0.directory, &next).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"INTERNAL_ERROR"})),
        );
    }
    *persisted = next;
    drop(state.0.pairing_updates.send(PairingUpdate {
        pairing_id: active.id,
        status: "paired",
        attempts_remaining: 5_u8.saturating_sub(active.attempts),
    }));
    *pairing = None;
    (
        StatusCode::OK,
        Json(json!({"device_id":id,"token":hex::encode(token),"gateway_id":persisted.gateway_id})),
    )
}

async fn pairing_events(
    State(state): State<Gateway>,
    headers: HeaderMap,
    Query(query): Query<PairingEventQuery>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let Ok(pairing_id) = Uuid::parse_str(&query.pairing_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let watch_token = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(',').map(str::trim).find_map(|protocol| {
                protocol
                    .strip_prefix("zedlink-pairing-token-")
                    .map(str::to_owned)
            })
        })
        .and_then(|token| hex::decode(token).ok());
    let Some(watch_token) = watch_token.filter(|token| token.len() == 32) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let watch_digest = digest(&watch_token);
    let receiver = state.0.pairing_updates.subscribe();
    let mut pairing = state.0.pairing.lock().await;
    let Some(active) = pairing.as_ref() else {
        return StatusCode::GONE.into_response();
    };
    if active.id != pairing_id || !bool::from(active.watch_digest.ct_eq(&watch_digest)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if Instant::now() >= active.expires {
        drop(state.0.pairing_updates.send(PairingUpdate {
            pairing_id,
            status: "expired",
            attempts_remaining: 0,
        }));
        *pairing = None;
        return StatusCode::GONE.into_response();
    }
    drop(pairing);
    let Ok(permit) = state.0.websocket_limit.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    upgrade
        .protocols(["zedlink-pairing-v1"])
        .on_upgrade(move |socket| pairing_event_stream(socket, state, pairing_id, receiver, permit))
        .into_response()
}

async fn send_pairing_event(socket: &mut WebSocket, event: Value) -> bool {
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(event.to_string().into())),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn pairing_event_stream(
    mut socket: WebSocket,
    state: Gateway,
    pairing_id: Uuid,
    mut receiver: broadcast::Receiver<PairingUpdate>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            update = receiver.recv() => {
                match update {
                    Ok(update) if update.pairing_id == pairing_id => {
                        let terminal = matches!(update.status, "paired" | "expired" | "replaced");
                        if !send_pairing_event(&mut socket, json!({
                            "pairing_id": update.pairing_id,
                            "status": update.status,
                            "attempts_remaining": update.attempts_remaining,
                        })).await || terminal {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = interval.tick() => {
                let (status, expires_seconds, attempts_remaining) = {
                    let mut pairing = state.0.pairing.lock().await;
                    match pairing.as_ref() {
                        Some(active) if active.id == pairing_id && Instant::now() < active.expires => (
                            "active",
                            active.expires.saturating_duration_since(Instant::now()).as_secs(),
                            5_u8.saturating_sub(active.attempts),
                        ),
                        Some(active) if active.id == pairing_id => {
                            *pairing = None;
                            ("expired", 0, 0)
                        }
                        _ => ("replaced", 0, 0),
                    }
                };
                if status == "expired" {
                    drop(state.0.pairing_updates.send(PairingUpdate {
                        pairing_id,
                        status,
                        attempts_remaining,
                    }));
                }
                if !send_pairing_event(&mut socket, json!({
                    "pairing_id": pairing_id,
                    "status": status,
                    "expires_seconds": expires_seconds,
                    "attempts_remaining": attempts_remaining,
                })).await || status != "active" {
                    break;
                }
            }
        }
    }
    if let Err(error) = socket.close().await {
        eprintln!("pairing event stream close failed: {error}");
    }
}

async fn notification_config(
    State(state): State<Gateway>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    let persisted = state.0.persisted.lock().await;
    let public_key = match state.vapid_public_key(&persisted) {
        Ok(public_key) => public_key,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"INTERNAL_ERROR"})),
            );
        }
    };
    let enabled = persisted
        .push_subscriptions
        .iter()
        .any(|subscription| subscription.device_id == device_id);
    (
        StatusCode::OK,
        Json(json!({
            "version": 1,
            "supported": true,
            "enabled": enabled,
            "application_server_key": public_key,
        })),
    )
}

async fn notification_subscribe(
    State(state): State<Gateway>,
    headers: HeaderMap,
    Json(subscription): Json<SubscriptionInfo>,
) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    if !valid_subscription(&subscription) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_SUBSCRIPTION"})),
        );
    }
    let mut persisted = state.0.persisted.lock().await;
    let mut next = persisted.clone();
    next.push_subscriptions
        .retain(|record| record.subscription.endpoint != subscription.endpoint);
    next.push_subscriptions.push(PushSubscription {
        device_id,
        subscription,
    });
    if save(&state.0.directory, &next).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"INTERNAL_ERROR"})),
        );
    }
    *persisted = next;
    (StatusCode::OK, Json(json!({"enabled":true})))
}

async fn notification_unsubscribe(
    State(state): State<Gateway>,
    headers: HeaderMap,
    Json(request): Json<UnsubscribeRequest>,
) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    if request.endpoint.is_empty() || request.endpoint.len() > 2048 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_REQUEST"})),
        );
    }
    let mut persisted = state.0.persisted.lock().await;
    let mut next = persisted.clone();
    next.push_subscriptions.retain(|record| {
        record.device_id != device_id || record.subscription.endpoint != request.endpoint
    });
    if save(&state.0.directory, &next).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"INTERNAL_ERROR"})),
        );
    }
    *persisted = next;
    (StatusCode::OK, Json(json!({"enabled":false})))
}

async fn notification_status(
    State(state): State<Gateway>,
    headers: HeaderMap,
    Json(request): Json<UnsubscribeRequest>,
) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    if request.endpoint.is_empty() || request.endpoint.len() > 2048 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_REQUEST"})),
        );
    }
    let enabled = state
        .0
        .persisted
        .lock()
        .await
        .push_subscriptions
        .iter()
        .any(|record| {
            record.device_id == device_id && record.subscription.endpoint == request.endpoint
        });
    (StatusCode::OK, Json(json!({"enabled":enabled})))
}

async fn notification_test(
    State(state): State<Gateway>,
    headers: HeaderMap,
    Json(request): Json<NotificationTestRequest>,
) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    let subscription = state
        .0
        .persisted
        .lock()
        .await
        .push_subscriptions
        .iter()
        .find(|record| {
            record.device_id == device_id && record.subscription.endpoint == request.endpoint
        })
        .cloned();
    let Some(subscription) = subscription else {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"NOTIFICATIONS_DISABLED"})),
        );
    };
    match state
        .send_push(
            &subscription,
            "Notifications are ready for this device.",
            None,
            None,
        )
        .await
    {
        PushOutcome::Sent => (StatusCode::OK, Json(json!({"delivered":true}))),
        PushOutcome::Stale => (
            StatusCode::GONE,
            Json(json!({"error":"SUBSCRIPTION_EXPIRED"})),
        ),
        PushOutcome::Failed => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":"PUSH_DELIVERY_FAILED"})),
        ),
    }
}

async fn apns_status(State(state): State<Gateway>, headers: HeaderMap) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    let enabled = state
        .0
        .persisted
        .lock()
        .await
        .apns_devices
        .iter()
        .any(|record| record.device_id == device_id);
    (
        StatusCode::OK,
        Json(json!({"supported":state.0.apns.is_some(), "enabled":enabled})),
    )
}

async fn apns_register(
    State(state): State<Gateway>,
    headers: HeaderMap,
    Json(request): Json<ApnsRegistrationRequest>,
) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    if state.0.apns.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"APNS_NOT_CONFIGURED"})),
        );
    }
    if !valid_apns_token(&request.token)
        || !matches!(request.environment.as_str(), "sandbox" | "production")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_REQUEST"})),
        );
    }
    let token = request.token.to_ascii_lowercase();
    let mut persisted = state.0.persisted.lock().await;
    let mut next = persisted.clone();
    next.apns_devices
        .retain(|record| record.device_id != device_id && record.token != token);
    next.apns_devices.push(ApnsDevice {
        device_id,
        token,
        environment: request.environment,
    });
    if save(&state.0.directory, &next).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"INTERNAL_ERROR"})),
        );
    }
    *persisted = next;
    (StatusCode::OK, Json(json!({"enabled":true})))
}

async fn apns_unregister(State(state): State<Gateway>, headers: HeaderMap) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    let mut persisted = state.0.persisted.lock().await;
    let mut next = persisted.clone();
    next.apns_devices
        .retain(|record| record.device_id != device_id);
    if save(&state.0.directory, &next).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"INTERNAL_ERROR"})),
        );
    }
    *persisted = next;
    (StatusCode::OK, Json(json!({"enabled":false})))
}

async fn apns_test(State(state): State<Gateway>, headers: HeaderMap) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    let Some(provider) = &state.0.apns else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"APNS_NOT_CONFIGURED"})),
        );
    };
    let registration = state
        .0
        .persisted
        .lock()
        .await
        .apns_devices
        .iter()
        .find(|record| record.device_id == device_id)
        .cloned();
    let Some(registration) = registration else {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"NOTIFICATIONS_DISABLED"})),
        );
    };
    let gateway_id = state.0.persisted.lock().await.gateway_id.to_string();
    match provider
        .send(
            &registration,
            "Native push is ready for this device.",
            &gateway_id,
            None,
            None,
        )
        .await
    {
        PushOutcome::Sent => (StatusCode::OK, Json(json!({"delivered":true}))),
        PushOutcome::Stale => (
            StatusCode::GONE,
            Json(json!({"error":"SUBSCRIPTION_EXPIRED"})),
        ),
        PushOutcome::Failed => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":"PUSH_FAILED"})),
        ),
    }
}

async fn rpc(State(state): State<Gateway>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    let Some(device_id) = state.authorize(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"UNAUTHENTICATED"})),
        );
    };
    if body.len() > MAX_RPC {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error":"PAYLOAD_TOO_LARGE"})),
        );
    }
    let mut request: Value = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"INVALID_REQUEST"})),
            );
        }
    };
    let Some(method) = request["method"].as_str().map(str::to_owned) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_REQUEST"})),
        );
    };
    if !matches!(
        method.as_str(),
        "instance.list"
            | "session.resume"
            | "instance.info"
            | "thread.list"
            | "thread.create"
            | "thread.create.options"
            | "thread.rename"
            | "thread.unexpose"
            | "thread.snapshot"
            | "thread.history"
            | "thread.events"
            | "thread.commands"
            | "thread.settings"
            | "thread.settings.update"
            | "thread.elicitations"
            | "elicitation.respond"
            | "thread.queue"
            | "thread.queue.clear"
            | "thread.edit_review"
            | "thread.edit_review.respond"
            | "terminal.list"
            | "terminal.snapshot"
            | "clipboard.read"
            | "clipboard.write"
            | "terminal.input"
            | "terminal.create"
            | "terminal.resize"
            | "task.list"
            | "task.stop"
            | "task.catalog"
            | "task.run"
            | "debugger.catalog"
            | "debugger.launch"
            | "debugger.snapshot"
            | "debugger.control"
            | "thread.approvals"
            | "approval.respond"
            | "project.files"
            | "project.directory"
            | "project.file"
            | "project.search"
            | "changes.snapshot"
            | "changes.diff"
            | "changes.stage"
            | "changes.unstage"
            | "thread.send"
            | "thread.cancel"
            | "subagent.cancel"
            | "thread.rewind_image"
            | "thread.rewind"
            | "request.status"
    ) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"UNSUPPORTED_CAPABILITY"})),
        );
    }
    let Some(original_request_id) = request["request_id"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 80)
        .map(str::to_owned)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_REQUEST"})),
        );
    };
    let target_id = request
        .get("target_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if target_id
        .as_ref()
        .is_some_and(|id| id.is_empty() || id.len() > 64)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_REQUEST"})),
        );
    }
    if let Some(object) = request.as_object_mut() {
        object.remove("target_id");
    }
    if method == "instance.list" {
        let result = state.instance_list().await;
        return (
            StatusCode::OK,
            Json(json!({"version":1,"request_id":original_request_id,"result":result})),
        );
    }
    if method == "session.resume" {
        let Some(target_id) = target_id.as_deref() else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"INVALID_REQUEST"})),
            );
        };
        let Ok(target) = state.target(Some(target_id)) else {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"UNKNOWN_TARGET"})),
            );
        };
        let params = &request["params"];
        let thread_id = params["thread_id"].as_str();
        let pending_id = params["pending_request_id"].as_str();
        if thread_id.is_some_and(|id| id.is_empty() || id.len() > 128)
            || pending_id.is_some_and(|id| id.is_empty() || id.len() > 80)
            || params
                .get("thread_id")
                .is_some_and(|value| !value.is_null() && !value.is_string())
            || params
                .get("pending_request_id")
                .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"INVALID_REQUEST"})),
            );
        }
        let native_request = |method: &str, params: Value| {
            json!({
                "version": 1, "request_id": Uuid::new_v4().to_string(), "method": method, "params": params,
            })
        };
        let info_response = state
            .probe(Some(target_id), &native_request("instance.info", json!({})))
            .await;
        let Ok(info_response) = info_response else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"INSTANCE_UNAVAILABLE"})),
            );
        };
        let Some(info) = info_response.get("result") else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"INSTANCE_UNAVAILABLE"})),
            );
        };
        let list_response = state
            .probe(Some(target_id), &native_request("thread.list", json!({})))
            .await;
        let Ok(list_response) = list_response else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"INSTANCE_UNAVAILABLE"})),
            );
        };
        let Some(list) = list_response.get("result") else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"INSTANCE_UNAVAILABLE"})),
            );
        };
        if !info["instance_id"].is_string()
            || !info["epoch"].is_string()
            || !list["threads"].is_array()
            || info["instance_id"] != list["instance_id"]
            || info["epoch"] != list["epoch"]
        {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"INSTANCE_UNAVAILABLE"})),
            );
        }
        let mut snapshot = Value::Null;
        if let Some(thread_id) = thread_id
            && list["threads"].as_array().is_some_and(|threads| {
                threads
                    .iter()
                    .any(|thread| thread["thread_id"] == thread_id)
            })
        {
            let tail_count = if params["instance_id"] == info["instance_id"]
                && params["epoch"] == info["epoch"]
            {
                16
            } else {
                64
            };
            let response = state
                .probe(
                    Some(target_id),
                    &native_request(
                        "thread.snapshot",
                        json!({
                            "thread_id": thread_id, "tail_entry_count": tail_count,
                        }),
                    ),
                )
                .await;
            let Ok(response) = response else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error":"INSTANCE_UNAVAILABLE"})),
                );
            };
            if let Some(result) = response.get("result") {
                if result["instance_id"] != info["instance_id"]
                    || result["epoch"] != info["epoch"]
                    || result["thread_id"] != thread_id
                {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error":"INSTANCE_UNAVAILABLE"})),
                    );
                }
                snapshot = result.clone();
            }
        }
        let mut pending_status = Value::Null;
        if let Some(pending_id) = pending_id {
            let response = state
                .probe(
                    Some(target_id),
                    &native_request(
                        "request.status",
                        json!({
                            "instance_id": info["instance_id"], "epoch": info["epoch"],
                            "original_request_id": format!("{device_id}:{pending_id}"),
                        }),
                    ),
                )
                .await;
            if let Ok(response) = response
                && let Some(result) = response.get("result")
            {
                pending_status = result.clone();
            }
        }
        let mut result = json!({
            "instance_id": info["instance_id"], "epoch": info["epoch"], "capabilities": info["capabilities"],
            "target": {"target_id": target_id, "label": target.label, "available": true},
            "threads": list["threads"], "snapshot": snapshot, "pending_status": pending_status,
        });
        // Leave room for the RPC envelope inside the client's 4 MiB response cap.
        let max_result_size = MAX_PROBE_RESPONSE as usize - 512;
        if serde_json::to_vec(&result).is_ok_and(|body| body.len() > max_result_size) {
            result["snapshot"] = Value::Null;
        }
        if serde_json::to_vec(&result).is_ok_and(|body| body.len() > max_result_size) {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"error":"RESPONSE_TOO_LARGE"})),
            );
        }
        return (
            StatusCode::OK,
            Json(json!({"version":1,"request_id":original_request_id,"result":result})),
        );
    }
    if matches!(
        method.as_str(),
        "thread.send"
            | "thread.create"
            | "thread.rewind_image"
            | "terminal.input"
            | "terminal.create"
            | "terminal.resize"
            | "task.stop"
            | "task.run"
            | "debugger.launch"
            | "debugger.control"
            | "changes.stage"
            | "changes.unstage"
    ) {
        request["request_id"] = json!(format!("{device_id}:{original_request_id}"));
    } else if method == "request.status" {
        let Some(original_send_id) = request["params"]["original_request_id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 80)
            .map(str::to_owned)
        else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"INVALID_REQUEST"})),
            );
        };
        request["params"]["original_request_id"] = json!(format!("{device_id}:{original_send_id}"));
    }
    match state.probe(target_id.as_deref(), &request).await {
        Ok(mut response) => {
            response["request_id"] = json!(original_request_id);
            (StatusCode::OK, Json(response))
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"INSTANCE_UNAVAILABLE"})),
        ),
    }
}
async fn events(
    State(state): State<Gateway>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    let websocket_token = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find_map(|protocol| protocol.strip_prefix("zedlink-token-").map(str::to_owned))
        });
    let device_id = if let Some(device_id) = state.authorize(&headers).await {
        Some(device_id)
    } else if let Some(token) = websocket_token.as_deref() {
        state.authorize_token(token).await
    } else {
        None
    };
    let Some(device_id) = device_id else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if query.thread_id.is_empty() || query.thread_id.len() > 128 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if state.target(query.target_id.as_deref()).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(permit) = state.0.websocket_limit.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    upgrade
        .protocols(["zedlink-v1"])
        .on_upgrade(move |socket| event_stream(socket, state, device_id, query, permit))
        .into_response()
}
async fn event_stream(
    mut socket: WebSocket,
    state: Gateway,
    device_id: Uuid,
    query: EventQuery,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let mut sequence = query.after_sequence.unwrap_or(0);
    let mut interval = tokio::time::interval(EVENT_POLL);
    'stream: loop {
        tokio::select! {
            biased;
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Ping(payload))) => {
                    if !tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Pong(payload)))
                        .await
                        .is_ok_and(|result| result.is_ok())
                    {
                        break;
                    }
                    continue;
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => continue,
            },
            _ = interval.tick() => {}
        }
        if !state
            .0
            .persisted
            .lock()
            .await
            .devices
            .iter()
            .any(|device| device.id == device_id)
        {
            break;
        }
        let request = json!({"version":1,"request_id":Uuid::new_v4().to_string(),
            "method":"thread.events","params":{"thread_id":query.thread_id,"after_sequence":sequence}});
        // The native probe can take six seconds. Keep reading the socket while it
        // is pending so a client heartbeat is answered without waiting for Zed.
        let probe = state.probe(query.target_id.as_deref(), &request);
        tokio::pin!(probe);
        let response = loop {
            tokio::select! {
                incoming = socket.recv() => match incoming {
                    Some(Ok(Message::Ping(payload))) => {
                        if !tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Pong(payload)))
                            .await.is_ok_and(|result| result.is_ok()) {
                            break 'stream;
                        }
                    }
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break 'stream,
                    Some(Ok(_)) => {}
                },
                result = &mut probe => break result,
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(_) => json!({"version":1,"error":{"code":"INSTANCE_UNAVAILABLE"}}),
        };
        // A device may be revoked while the native poll is in flight.
        if !state
            .0
            .persisted
            .lock()
            .await
            .devices
            .iter()
            .any(|device| device.id == device_id)
        {
            break;
        }
        if let Some(next) = response["result"]["last_sequence"].as_u64() {
            sequence = next;
        }
        let stop = response.get("error").is_some();
        if tokio::time::timeout(
            Duration::from_secs(5),
            socket.send(Message::Text(response.to_string().into())),
        )
        .await
        .map_or(true, |result| result.is_err())
            || stop
        {
            break;
        }
    }
    if let Err(error) = socket.close().await {
        eprintln!("event stream close failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_stable_vapid_key_pair() {
        let private_key = new_vapid_private_key();
        let first = VapidSignatureBuilder::from_base64_no_sub(&private_key).unwrap();
        let second = VapidSignatureBuilder::from_base64_no_sub(&private_key).unwrap();
        assert_eq!(first.get_public_key(), second.get_public_key());
        assert_eq!(first.get_public_key().len(), 65);
    }

    #[test]
    fn validates_web_push_subscription_shape() {
        let subscription = SubscriptionInfo::new(
            "https://fcm.googleapis.com/device".to_owned(),
            URL_SAFE_NO_PAD.encode([4_u8].into_iter().chain([7_u8; 64]).collect::<Vec<_>>()),
            URL_SAFE_NO_PAD.encode([9_u8; 16]),
        );
        assert!(valid_subscription(&subscription));

        let mut insecure = subscription.clone();
        insecure.endpoint = "http://push.example.test/device".into();
        assert!(!valid_subscription(&insecure));

        let mut private_endpoint = subscription.clone();
        private_endpoint.endpoint = "https://127.0.0.1/device".into();
        assert!(!valid_subscription(&private_endpoint));

        let mut malformed = subscription;
        malformed.keys.p256dh = URL_SAFE_NO_PAD.encode([4_u8; 32]);
        assert!(!valid_subscription(&malformed));
    }

    #[test]
    fn apns_tokens_are_bounded_and_provider_claims_are_scoped() -> Result<()> {
        assert!(valid_apns_token(&"ab".repeat(32)));
        assert!(!valid_apns_token("ab/../device"));
        assert!(!valid_apns_token(&"ab".repeat(257)));
        let provider = ApnsProvider {
            team_id: "ABCDEFGHIJ".into(),
            key_id: "KLMNOPQRST".into(),
            key_pem: ES256KeyPair::generate().to_pem()?,
            client: HttpClient::new()?,
        };
        let signed = provider.provider_token()?;
        let parts = signed.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KLMNOPQRST");
        assert_eq!(claims["iss"], "ABCDEFGHIJ");
        assert!(claims["iat"].is_number());
        assert!(claims.get("exp").is_none());
        Ok(())
    }

    #[test]
    fn loads_state_from_before_notifications() {
        let gateway_id = Uuid::new_v4();
        let state: Persisted = serde_json::from_value(json!({
            "gateway_id": gateway_id,
            "devices": [],
        }))
        .unwrap();
        assert_eq!(state.gateway_id, gateway_id);
        assert!(state.vapid_private_key.is_empty());
        assert!(state.push_subscriptions.is_empty());
        assert!(state.apns_devices.is_empty());
    }

    #[test]
    fn detects_replaced_and_child_approvals_without_count_changes() {
        let before = json!({"epoch":"a", "pending_approvals":[{"approval_id":"old","turn_id":1}]});
        let after = json!({"epoch":"a", "subagents":[{"session_id":"child","pending_approvals":[{"approval_id":"new","turn_id":2}]}]});
        let previous = ThreadObservation {
            approvals: pending_approval_keys(&before),
            ..Default::default()
        };
        let current = ThreadObservation {
            approvals: pending_approval_keys(&after),
            ..Default::default()
        };
        assert_eq!(previous.approvals.len(), current.approvals.len());
        assert_eq!(
            thread_notification(&previous, &current, None),
            Some("A Zed Agent session needs your approval.")
        );
        assert_eq!(thread_notification(&current, &current, None), None);
        assert_eq!(
            thread_notification(&ThreadObservation::default(), &current, None),
            Some("A Zed Agent session needs your approval.")
        );
    }

    #[test]
    fn chooses_failure_notification_before_generic_completion() {
        let generating = ThreadObservation {
            status: "Generating".into(),
            approvals: HashSet::new(),
            inputs: HashSet::new(),
            had_error: false,
            last_sequence: 1,
        };
        let failed = ThreadObservation {
            status: "Idle".into(),
            approvals: HashSet::new(),
            inputs: HashSet::new(),
            had_error: true,
            last_sequence: 2,
        };
        assert_eq!(
            thread_notification(&generating, &failed, Some("error")),
            Some("A Zed Agent session stopped with an error.")
        );
        assert_eq!(thread_notification(&failed, &failed, None), None);
    }

    #[test]
    fn distinguishes_native_completion_cancellation_and_unknown_stop() {
        let running = ThreadObservation {
            status: "Generating".into(),
            last_sequence: 4,
            ..Default::default()
        };
        let idle = ThreadObservation {
            status: "Idle".into(),
            last_sequence: 5,
            ..Default::default()
        };
        assert_eq!(
            thread_notification(&running, &idle, Some("completed")),
            Some("A Zed Agent session completed.")
        );
        assert_eq!(
            thread_notification(&running, &idle, Some("cancelled")),
            Some("A Zed Agent session was cancelled.")
        );
        assert_eq!(
            thread_notification(&running, &idle, Some("max_turn_requests")),
            Some("A Zed Agent session reached its turn request limit.")
        );
        assert_eq!(
            thread_notification(&running, &idle, None),
            Some("A Zed Agent session stopped. Open it to review the result.")
        );
        assert_eq!(thread_notification(&idle, &idle, None), None);
    }

    #[test]
    fn detects_new_input_without_repeating_existing_request() {
        let waiting = ThreadObservation {
            inputs: HashSet::from(["request-a".into()]),
            ..Default::default()
        };
        assert_eq!(
            thread_notification(&ThreadObservation::default(), &waiting, None),
            Some("A Zed Agent session needs your input.")
        );
        assert_eq!(thread_notification(&waiting, &waiting, None), None);
    }

    #[test]
    fn stop_reason_is_bounded_by_authoritative_snapshot_sequence() {
        let events = json!([
            {"sequence": 4, "kind": "turn.stopped", "stop_reason": "completed"},
            {"sequence": 5, "kind": "status.changed"},
            {"sequence": 6, "kind": "turn.stopped", "stop_reason": "cancelled"},
        ]);
        assert_eq!(latest_stop_reason(&events, 5), Some("completed"));
        assert_eq!(latest_stop_reason(&events, 6), Some("cancelled"));
        assert_eq!(latest_stop_reason(&events, 3), None);
    }
}
