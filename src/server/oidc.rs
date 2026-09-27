//! Single sign-on with OpenID Connect: the dashboard's login, by the
//! authorization code flow with PKCE, and the admin API's bearer tokens.
//! Only the users and groups the server allows get in.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// where the provider sends the browser back: <public url>/oidc/callback
    pub redirect_url: String,
    pub scopes: Vec<String>,
    /// the claim that names the user; then email, then sub
    pub user_claim: String,
    pub groups_claim: String,
    pub allowed_users: HashSet<String>,
    pub allowed_groups: HashSet<String>,
    pub allow_any_user: bool,
    /// the audience the admin API's bearer tokens must have
    pub api_audience: String,
    pub ca_cert: Option<PathBuf>,
    /// what the login button calls the provider
    pub name: String,
}

/// Who a request is from, and how they proved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub via: &'static str,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    end_session_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

struct Pending {
    nonce: String,
    verifier: String,
    next: String,
    created: Instant,
}

/// Why a login did not get in.
#[derive(Debug)]
pub enum Refusal {
    /// the provider vouched for them, but the server does not allow them
    NotAllowed(String),
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for Refusal {
    fn from(e: anyhow::Error) -> Self {
        Refusal::Failed(e)
    }
}

pub struct Oidc {
    pub cfg: OidcConfig,
    http: reqwest::Client,
    meta: Discovery,
    jwks: RwLock<(JwkSet, Instant)>,
    pending: Mutex<HashMap<String, Pending>>,
}

fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A claim's strings: a string, or an array of them.
fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    }
}

impl OidcConfig {
    /// Who the claims name, and whether they may in.  Groups match with or
    /// without a leading '/', as Keycloak writes a group's full path.
    pub fn authorize(&self, claims: &Value) -> std::result::Result<Identity, Refusal> {
        let name = [self.user_claim.as_str(), "preferred_username", "email", "sub"]
            .iter()
            .find_map(|c| claims.get(*c).and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
            .ok_or_else(|| Refusal::Failed(anyhow!("the token names no user")))?
            .to_string();
        let groups = strings(claims.get(&self.groups_claim));
        let norm = |g: &str| g.trim_start_matches('/').to_string();
        let allowed_group = groups.iter().any(|g| self.allowed_groups.iter().any(|a| norm(a) == norm(g)));
        if self.allow_any_user || self.allowed_users.contains(&name) || allowed_group {
            Ok(Identity { name, via: "oidc", groups })
        } else {
            Err(Refusal::NotAllowed(name))
        }
    }
}

impl Oidc {
    /// Read the provider's configuration, and its signing keys.
    pub async fn discover(cfg: OidcConfig) -> Result<Oidc> {
        let mut b = reqwest::Client::builder().timeout(Duration::from_secs(30));
        if let Some(ca) = &cfg.ca_cert {
            let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
            b = b.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        let http = b.build()?;
        let url = format!("{}/.well-known/openid-configuration", cfg.issuer.trim_end_matches('/'));
        let meta: Discovery = http.get(&url).send().await?.error_for_status()?.json().await.with_context(|| format!("reading {url}"))?;
        if meta.issuer.trim_end_matches('/') != cfg.issuer.trim_end_matches('/') {
            bail!("{url} names the issuer {}, not {}", meta.issuer, cfg.issuer);
        }
        let jwks: JwkSet = http.get(&meta.jwks_uri).send().await?.error_for_status()?.json().await?;
        tracing::warn!("single sign-on through {} ( {} keys )", meta.issuer, jwks.keys.len());
        Ok(Oidc { cfg, http, meta, jwks: RwLock::new((jwks, Instant::now())), pending: Mutex::default() })
    }

    /// Start a login: the provider's authorization URL, and the state that
    /// ties the callback to this browser.
    pub fn begin(&self, next: &str) -> Result<(String, String)> {
        let (state, nonce, verifier) = (random_token(), random_token(), random_token());
        let url = reqwest::Url::parse_with_params(
            &self.meta.authorization_endpoint,
            &[
                ("response_type", "code"),
                ("client_id", self.cfg.client_id.as_str()),
                ("redirect_uri", self.cfg.redirect_url.as_str()),
                ("scope", self.cfg.scopes.join(" ").as_str()),
                ("state", state.as_str()),
                ("nonce", nonce.as_str()),
                ("code_challenge", pkce_challenge(&verifier).as_str()),
                ("code_challenge_method", "S256"),
            ],
        )?;
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|_, p| p.created.elapsed() < Duration::from_secs(600));
        pending.insert(state.clone(), Pending { nonce, verifier, next: next.to_string(), created: Instant::now() });
        Ok((url.to_string(), state))
    }

    /// Finish a login: exchange the code, and check the ID token.  Returns
    /// who it is, where they were going, and the ID token, for logout.
    pub async fn finish(&self, state: &str, code: &str) -> std::result::Result<(Identity, String, String), Refusal> {
        let p = self.pending.lock().unwrap().remove(state).ok_or_else(|| anyhow!("this login expired or was already used; log in again"))?;
        let mut req = self.http.post(&self.meta.token_endpoint).form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.cfg.redirect_url.as_str()),
            ("client_id", self.cfg.client_id.as_str()),
            ("code_verifier", p.verifier.as_str()),
        ]);
        if let Some(secret) = &self.cfg.client_secret {
            req = req.basic_auth(&self.cfg.client_id, Some(secret));
        }
        let resp = req.send().await.map_err(anyhow::Error::from)?;
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(Refusal::Failed(anyhow!("the provider refused the code: {status}: {}", resp.text().await.unwrap_or_default())));
        }
        let tokens: TokenResponse = resp.json().await.map_err(anyhow::Error::from)?;
        let claims = self.verify(&tokens.id_token, &self.cfg.client_id).await?;
        if claims.get("nonce").and_then(|n| n.as_str()) != Some(p.nonce.as_str()) {
            return Err(Refusal::Failed(anyhow!("the ID token's nonce is not this login's")));
        }
        let who = self.cfg.authorize(&claims)?;
        Ok((who, p.next, tokens.id_token))
    }

    /// An admin API bearer token: a JWT from the provider, for its audience.
    pub async fn verify_access_token(&self, token: &str) -> std::result::Result<Identity, Refusal> {
        let claims = self.verify(token, &self.cfg.api_audience).await?;
        self.cfg.authorize(&claims)
    }

    async fn verify(&self, token: &str, audience: &str) -> Result<Value> {
        let header = jsonwebtoken::decode_header(token).context("not a JWT")?;
        use Algorithm::*;
        if !matches!(header.alg, RS256 | RS384 | RS512 | PS256 | PS384 | PS512 | ES256 | ES384 | EdDSA) {
            bail!("tokens signed with {:?} are not accepted", header.alg);
        }
        let key = self.key(header.kid.as_deref()).await?;
        let mut v = Validation::new(header.alg);
        v.set_issuer(&[&self.meta.issuer]);
        v.set_audience(&[audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        v.leeway = 60;
        Ok(jsonwebtoken::decode::<Value>(token, &key, &v).context("the token does not verify")?.claims)
    }

    /// The signing key; the provider's keys again, at most once a minute,
    /// when it names one we do not have, as after a rotation.
    async fn key(&self, kid: Option<&str>) -> Result<DecodingKey> {
        for attempt in 0..2 {
            {
                let (set, fetched) = &*self.jwks.read().await;
                let jwk = match kid {
                    Some(k) => set.find(k),
                    None if set.keys.len() == 1 => set.keys.first(),
                    None => None,
                };
                if let Some(jwk) = jwk {
                    return Ok(DecodingKey::from_jwk(jwk)?);
                }
                if attempt == 1 || fetched.elapsed() < Duration::from_secs(60) {
                    bail!("the provider has no key {}", kid.unwrap_or("( unnamed )"));
                }
            }
            let set: JwkSet = self.http.get(&self.meta.jwks_uri).send().await?.error_for_status()?.json().await?;
            *self.jwks.write().await = (set, Instant::now());
        }
        unreachable!()
    }

    /// The provider's logout, if it has one, back to our login page.
    pub fn logout_url(&self, id_token: &str, back: &str) -> Option<String> {
        let end = self.meta.end_session_endpoint.as_deref()?;
        reqwest::Url::parse_with_params(end, &[("id_token_hint", id_token), ("post_logout_redirect_uri", back), ("client_id", &self.cfg.client_id)])
            .ok()
            .map(|u| u.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> OidcConfig {
        OidcConfig {
            issuer: "https://idp/realms/r".into(),
            client_id: "rgw-integrity".into(),
            client_secret: None,
            redirect_url: "https://rgwi/oidc/callback".into(),
            scopes: vec!["openid".into()],
            user_claim: "preferred_username".into(),
            groups_claim: "groups".into(),
            allowed_users: ["carol".to_string()].into(),
            allowed_groups: ["rgw-admins".to_string()].into(),
            allow_any_user: false,
            api_audience: "rgw-integrity".into(),
            ca_cert: None,
            name: "SSO".into(),
        }
    }

    #[test]
    fn authorization() {
        let c = cfg();
        let who = c.authorize(&json!({"sub": "1", "preferred_username": "alice", "groups": ["/rgw-admins", "/other"]})).unwrap();
        assert_eq!((who.name.as_str(), who.via), ("alice", "oidc"));
        assert!(c.authorize(&json!({"sub": "2", "preferred_username": "carol"})).is_ok(), "an allowed user");
        assert!(matches!(c.authorize(&json!({"sub": "3", "preferred_username": "bob", "groups": ["/users"]})), Err(Refusal::NotAllowed(n)) if n == "bob"));
        assert!(matches!(c.authorize(&json!({"sub": "4", "email": "dave@x", "groups": "rgw-admins"})), Ok(i) if i.name == "dave@x"));
        let any = OidcConfig { allow_any_user: true, ..cfg() };
        assert!(any.authorize(&json!({"sub": "5"})).is_ok());
    }

    #[test]
    fn pkce() {
        // RFC 7636, appendix B
        assert_eq!(pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert_ne!(random_token(), random_token());
    }
}
