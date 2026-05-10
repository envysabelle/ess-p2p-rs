use crate::authority::{AuthorityManager, Role};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ==========================================
// 1. HELPERS & NORMALIZERS
// ==========================================

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn short_nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:x}")
}

fn normalize_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = headers
        .into_iter()
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, v)| !k.is_empty() && !v.is_empty())
        .collect();

    out.sort_by(|a, b| {
        a.0.to_ascii_lowercase()
            .cmp(&b.0.to_ascii_lowercase())
            .then(a.1.cmp(&b.1))
    });
    out.dedup();
    out
}

fn normalize_url(url: &str) -> String { url.trim().to_string() }
fn normalize_text(s: &str) -> String { s.trim().to_string() }

fn normalize_content_type(content_type: &str) -> String {
    let ct = content_type.trim();
    if ct.is_empty() {
        "text/plain; charset=utf-8".to_string()
    } else {
        ct.to_string()
    }
}

fn normalize_namespace(namespace: &str) -> String {
    namespace.trim().trim_matches('/').to_ascii_lowercase()
}

// ==========================================
// 2. ESS URI & NAMESPACES
// ==========================================

pub const ESS_NAMESPACE_DEFAULTS: &[&str] = &[
    "wallet", "market", "dashboard", "identity", "governance", "node", "registry",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EssUri {
    pub raw: String,
    pub namespace: String,
    pub service: String,
    pub path: String,
}

pub fn parse_ess_uri(url: &str) -> Option<EssUri> {
    let raw = url.trim();
    if !raw.to_ascii_lowercase().starts_with("ess://") {
        return None;
    }

    let without_scheme = raw.get(6..).unwrap_or_default();
    let mut parts = without_scheme.split('/').filter(|s| !s.trim().is_empty());

    let namespace = normalize_namespace(parts.next().unwrap_or_default());
    if namespace.is_empty() { return None; }

    let service = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    let path = parts.collect::<Vec<_>>().join("/");

    Some(EssUri { raw: raw.to_string(), namespace, service, path })
}

pub fn is_supported_namespace(namespace: &str) -> bool {
    let ns = normalize_namespace(namespace);
    ESS_NAMESPACE_DEFAULTS.iter().any(|v| *v == ns)
}

pub fn service_key(namespace: &str, service_id: &str) -> String {
    format!("{}::{}", normalize_namespace(namespace), service_id.trim().to_ascii_lowercase())
}

fn namespace_is_core(namespace: &str) -> bool {
    matches!(normalize_namespace(namespace).as_str(), "wallet" | "market" | "governance")
}

pub fn can_publish_service(
    authority: &AuthorityManager,
    peer: &PeerId,
    namespace: &str,
) -> bool {
    match authority.role_of(peer) {
        Some(Role::Supernode) | Some(Role::Validator) => true,
        Some(Role::Gateway) | Some(Role::Standard) => !namespace_is_core(namespace),
        _ => false,
    }
}

// ==========================================
// 3. SERVICE REGISTRY
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ServiceVisibility { Private, Authority, Public }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceRecord {
    pub service_id: String,
    pub namespace: String,
    pub endpoint: String,
    pub owner_peer: String,
    pub publisher_peer: String,
    pub visibility: ServiceVisibility,
    pub description: String,
    pub tags: Vec<String>,
    pub published_at: u64,
    pub updated_at: u64,
}

impl ServiceRecord {
    pub fn new(
        namespace: impl Into<String>,
        service_id: impl Into<String>,
        endpoint: impl Into<String>,
        owner: impl Into<String>,
        publisher: impl Into<String>
    ) -> Self {
        let ts = now_secs();
        Self {
            service_id: service_id.into(),
            namespace: normalize_namespace(&namespace.into()),
            endpoint: normalize_url(&endpoint.into()),
            owner_peer: owner.into(),
            publisher_peer: publisher.into(),
            visibility: ServiceVisibility::Authority,
            description: String::new(),
            tags: Vec::new(),
            published_at: ts,
            updated_at: ts,
        }.normalized()
    }

    pub fn normalized(mut self) -> Self {
        self.service_id = self.service_id.trim().to_ascii_lowercase();
        self.namespace = normalize_namespace(&self.namespace);
        self.endpoint = normalize_url(&self.endpoint);
        self.tags = self.tags.into_iter().map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect();
        self.tags.sort();
        self.tags.dedup();
        self
    }

    pub fn key(&self) -> String { service_key(&self.namespace, &self.service_id) }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceRegistry {
    pub services: BTreeMap<String, ServiceRecord>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self { services: BTreeMap::new() }
    }

    pub fn insert_raw(&mut self, record: ServiceRecord) {
        self.services.insert(record.key(), record);
    }

    pub fn publish(
        &mut self,
        authority: &AuthorityManager,
        publisher: &PeerId,
        record: ServiceRecord
    ) -> Result<String, String> {
        let record = record.normalized();

        if record.namespace.is_empty() || record.service_id.is_empty() {
            return Err("Service namespace and service_id are required".into());
        }

        if !is_supported_namespace(&record.namespace) {
            return Err(format!("Unsupported ESS namespace: {}", record.namespace));
        }

        if !can_publish_service(authority, publisher, &record.namespace) {
            return Err(format!("Peer {} is not allowed to publish in namespace {}", publisher, record.namespace));
        }

        let key = record.key();
        self.services.insert(key.clone(), record);
        Ok(key)
    }
}

// ==========================================
// 4. WEB REQUEST & RESPONSE
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebRequest {
    pub message_id: String,
    pub from: String,
    pub to: String,
    pub kind: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub route: Vec<String>,
    pub nonce: String,
    pub ts: u64,
    pub encrypted: bool,
    pub sender_pubkey: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebResponse {
    pub message_id: String,
    pub in_reply_to: String,
    pub from: String,
    pub to: String,
    pub kind: String,
    pub ok: bool,
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub nonce: String,
    pub ts: u64,
    pub encrypted: bool,
    pub sender_pubkey: String,
    pub signature: String,
}

impl WebResponse {
    pub fn plain_ok(
        in_reply_to: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        status: u16,
        content_type: impl Into<String>,
        headers: Vec<(String, String)>,
        body: impl Into<String>
    ) -> Self {
        let ts = now_secs();
        Self {
            message_id: format!("web-resp-{ts}-{}", short_nonce()),
            in_reply_to: in_reply_to.into(),
            from: from.into(),
            to: to.into(),
            kind: "web_response".to_string(),
            ok: true,
            status,
            content_type: content_type.into(),
            headers,
            body: body.into(),
            ts,
            ..Default::default()
        }.normalized()
    }

    pub fn plain_error(
        in_reply_to: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        status: u16,
        body: impl Into<String>
    ) -> Self {
        let ts = now_secs();
        Self {
            message_id: format!("web-resp-{ts}-{}", short_nonce()),
            in_reply_to: in_reply_to.into(),
            from: from.into(),
            to: to.into(),
            kind: "web_response".to_string(),
            ok: false,
            status,
            content_type: "text/plain; charset=utf-8".to_string(),
            body: body.into(),
            ts,
            ..Default::default()
        }.normalized()
    }

    pub fn normalized(mut self) -> Self {
        self.message_id = normalize_text(&self.message_id);
        self.in_reply_to = normalize_text(&self.in_reply_to);
        self.content_type = normalize_content_type(&self.content_type);
        self.headers = normalize_headers(self.headers);
        self.signature = normalize_text(&self.signature);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ess_uri_valid() {
        let uri = parse_ess_uri("ess://wallet/transfer/some/path").unwrap();
        assert_eq!(uri.namespace, "wallet");
        assert_eq!(uri.service, "transfer");
        assert_eq!(uri.path, "some/path");
    }

    #[test]
    fn test_parse_ess_uri_invalid_scheme() {
        assert!(parse_ess_uri("http://example.com").is_none());
    }

    #[test]
    fn test_service_registry_publish_requires_auth() {
        let mut registry = ServiceRegistry::new();
        let auth = crate::authority::AuthorityManager::new(crate::authority::default_authority());
        let publisher = PeerId::random();
        let record = ServiceRecord::new("wallet", "test", "http://endpoint", "owner", publisher.to_string());
        // Karena authority tidak mengenali publisher, pasti gagal
        assert!(registry.publish(&auth, &publisher, record).is_err());
    }
}
