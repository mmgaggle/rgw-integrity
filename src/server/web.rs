//! The dashboard, in the IBM Carbon Design System.  Server-rendered pages,
//! with Carbon's styles and the IBM Plex fonts served by the binary, so it
//! works where the cluster has no Internet access.

use std::collections::HashMap;

use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;

use super::db::{self, Filter, FindingRow, STATUSES};
use super::oidc::{Identity, Refusal};
use super::{AdminAuth, ApiError, ApiResult, SESSION_COOKIE, Shared};
use crate::finding::{Class, Confidence, Finding};
use crate::oid::iso;
use crate::proto::StartScan;
use crate::scan::{Options, now};

const CARBON_CSS: &[u8] = include_bytes!("../../assets/carbon.min.css");
const APP_CSS: &[u8] = include_bytes!("../../assets/app.css");
const APP_JS: &[u8] = include_bytes!("../../assets/app.js");
const PLEX_SANS: &[u8] = include_bytes!("../../assets/fonts/IBMPlexSans-Regular.woff2");
const PLEX_SANS_SEMIBOLD: &[u8] = include_bytes!("../../assets/fonts/IBMPlexSans-SemiBold.woff2");
const PLEX_MONO: &[u8] = include_bytes!("../../assets/fonts/IBMPlexMono-Regular.woff2");
const NOTICE: &str = concat!(
    "rgw-integrity serves these, unmodified but for the removal of @font-face rules from the styles:\n\n",
    "Carbon Design System styles, Apache-2.0:\n\n",
    include_str!("../../assets/LICENSE.carbon"),
    "\n\nIBM Plex fonts, SIL Open Font License 1.1:\n\n",
    include_str!("../../assets/fonts/LICENSE.plex")
);

const FAVICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="4" fill="#161616"/><path d="M8 17l5 5 11-12" stroke="#0f62fe" stroke-width="3.5" fill="none"/></svg>"##;

const CHEVRON: &str = r#"<svg focusable="false" class="cds--select__arrow" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" fill="currentColor"><path d="M8 11L3 6 3.7 5.3 8 9.6 12.3 5.3 13 6z"></path></svg>"#;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/static/{file}", get(asset))
        .route("/static/fonts/{file}", get(font))
        .route("/login", get(login_page).post(login))
        .route("/logout", get(logout))
        .route("/oidc/login", get(oidc_login))
        .route("/oidc/callback", get(oidc_callback))
        .route("/", get(overview))
        .route("/findings", get(findings_page))
        .route("/findings.jsonl", get(findings_export))
        .route("/findings/{id}", get(finding_page))
        .route("/findings/{id}/status", post(finding_status))
        .route("/clients", get(clients_page))
        .route("/clients/controls", post(controls))
        .route("/clients/{id}/override", post(client_override))
        .route("/clients/forget", post(forget_clients))
        .route("/scans", get(scans_page))
        .route("/scans/start", post(start_scan))
        .route("/scans/{id}", get(scan_page))
        .route("/scans/{id}/cancel", post(cancel_scan))
        .route("/settings", get(settings_page).post(save_settings))
        .route("/issues", get(issues_page))
}

/// Percent-encode a query value.
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn asset(Path(file): Path<String>) -> Response {
    let (body, kind) = match file.as_str() {
        "carbon.min.css" => (CARBON_CSS, "text/css"),
        "app.css" => (APP_CSS, "text/css"),
        "app.js" => (APP_JS, "text/javascript"),
        "NOTICE.txt" => (NOTICE.as_bytes(), "text/plain; charset=utf-8"),
        "favicon.svg" => (FAVICON.as_bytes(), "image/svg+xml"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    ([(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, "public, max-age=3600")], body).into_response()
}

async fn font(Path(file): Path<String>) -> Response {
    let body = match file.as_str() {
        "IBMPlexSans-Regular.woff2" => PLEX_SANS,
        "IBMPlexSans-SemiBold.woff2" => PLEX_SANS_SEMIBOLD,
        "IBMPlexMono-Regular.woff2" => PLEX_MONO,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    ([(header::CONTENT_TYPE, "font/woff2"), (header::CACHE_CONTROL, "public, max-age=604800")], body).into_response()
}

#[derive(Clone, Copy, PartialEq)]
enum Nav {
    Overview,
    Findings,
    Clients,
    Scans,
    Settings,
    Issues,
    None,
}

/// A message after a redirect: `?msg=...&kind=error`.
#[derive(Debug, Default, Deserialize)]
struct Flash {
    msg: Option<String>,
    kind: Option<String>,
}

fn flash(f: &Flash) -> Markup {
    match &f.msg {
        Some(msg) => notification(if f.kind.as_deref() == Some("error") { "error" } else { "success" }, msg, None),
        None => html! {},
    }
}

fn notification(kind: &str, title: &str, subtitle: Option<&str>) -> Markup {
    html! {
        div class=(format!("cds--inline-notification cds--inline-notification--{kind} cds--inline-notification--low-contrast")) role="status" {
            div class="cds--inline-notification__details" {
                div class="cds--inline-notification__text-wrapper" {
                    div class="cds--inline-notification__title" { (title) }
                    @if let Some(s) = subtitle { div class="cds--inline-notification__subtitle" { (s) } }
                }
            }
        }
    }
}

fn page(who: Option<&Identity>, title: &str, nav: Nav, refresh: Option<u32>, body: Markup) -> Markup {
    let item = |href: &str, label: &str, this: Nav| {
        html! {
            li {
                a class="cds--header__menu-item" href=(href) aria-current=[(nav == this).then_some("page")] {
                    span class="cds--text-truncate--end" { (label) }
                }
            }
        }
    };
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · rgw-integrity" }
                link rel="icon" href="/static/favicon.svg" type="image/svg+xml";
                link rel="stylesheet" href="/static/carbon.min.css";
                link rel="stylesheet" href="/static/app.css";
                script src="/static/app.js" {}
            }
            body data-refresh=[refresh] {
                header class="cds--header cds--g100" aria-label="RGW integrity" {
                    a class="cds--header__name" href="/" {
                        span class="cds--header__name--prefix" { "Ceph RGW" } (PreEscaped("&nbsp;")) "Integrity"
                    }
                    @if nav != Nav::None {
                        nav class="cds--header__nav" aria-label="RGW integrity" {
                            ul class="cds--header__menu-bar" {
                                (item("/", "Overview", Nav::Overview))
                                (item("/findings", "Findings", Nav::Findings))
                                (item("/clients", "Clients", Nav::Clients))
                                (item("/scans", "Scans", Nav::Scans))
                                (item("/settings", "Settings", Nav::Settings))
                                (item("/issues", "Known issues", Nav::Issues))
                            }
                        }
                        div class="cds--header__global" {
                            @if let Some(w) = who {
                                span class="cds--header__menu-item" title=(format!("signed in with {}", if w.via == "oidc" { "single sign-on" } else { "the admin token" })) { (w.name) }
                            }
                            a class="cds--header__menu-item" href="/logout" { "Log out" }
                        }
                    }
                }
                main class="rgwi-main" {
                    (body)
                    @if let Some(secs) = refresh {
                        label class="rgwi-refresh" {
                            input type="checkbox" id="rgwi-autorefresh";
                            "Refresh every " (secs) " s"
                        }
                    }
                    p class="rgwi-muted rgwi-mono" style="margin-top:3rem;font-size:0.75rem" {
                        "rgw-integrity " (env!("CARGO_PKG_VERSION")) " · "
                        a class="cds--link" href="/static/NOTICE.txt" { "third-party notices" }
                    }
                }
            }
        }
    }
}

fn class_color(c: Class) -> &'static str {
    match c {
        Class::DataLoss => "red",
        Class::PendingLoss => "magenta",
        Class::AtRisk => "purple",
        Class::Inconsistency => "blue",
        Class::Leak => "teal",
        Class::LatentLeak => "cyan",
    }
}

fn tag(color: &str, label: &str) -> Markup {
    html! {
        span class=(format!("cds--tag cds--tag--{color} cds--tag--sm")) { span class="cds--tag__label" { (label) } }
    }
}

fn class_tag(c: Class) -> Markup {
    tag(class_color(c), &c.as_str().replace('_', " "))
}

fn status_tag(s: &str) -> Markup {
    let color = match s {
        "open" => "red",
        "confirmed" => "magenta",
        "gone" => "green",
        _ => "gray",
    };
    tag(color, &s.replace('_', " "))
}

fn confidence_tag(c: Confidence) -> Markup {
    let color = match c {
        Confidence::High => "high-contrast",
        Confidence::Medium => "outline",
        Confidence::Low => "cool-gray",
    };
    tag(color, c.as_str())
}

fn ago(ts: i64) -> Markup {
    let d = now() - ts;
    let text = match d {
        d if d < 60 => format!("{} s ago", d.max(0)),
        d if d < 3600 => format!("{} min ago", d / 60),
        d if d < 86400 => format!("{} h ago", d / 3600),
        d => format!("{} d ago", d / 86400),
    };
    html! { span class="rgwi-nowrap" title=(iso(ts)) { (text) } }
}

fn select(name: &str, label: &str, options: &[(String, String)], current: Option<&str>) -> Markup {
    html! {
        div class="cds--form-item" {
            div class="cds--select" {
                label class="cds--label" for=(name) { (label) }
                div class="cds--select-input__wrapper" {
                    select class="cds--select-input" id=(name) name=(name) {
                        @for (value, text) in options {
                            option value=(value) selected[current == Some(value.as_str())] { (text) }
                        }
                    }
                    (PreEscaped(CHEVRON))
                }
            }
        }
    }
}

fn text_input(name: &str, label: &str, value: &str, kind: &str, placeholder: &str) -> Markup {
    html! {
        div class="cds--form-item cds--text-input-wrapper" {
            label class="cds--label" for=(name) { (label) }
            div class="cds--text-input__field-outer-wrapper" {
                div class="cds--text-input__field-wrapper" {
                    input class="cds--text-input" type=(kind) id=(name) name=(name) value=(value) placeholder=(placeholder);
                }
            }
        }
    }
}

fn checkbox(name: &str, label: &str, checked: bool) -> Markup {
    html! {
        div class="cds--form-item cds--checkbox-wrapper" {
            input class="cds--checkbox" type="checkbox" id=(name) name=(name) value="on" checked[checked];
            label class="cds--checkbox-label" for=(name) { span class="cds--checkbox-label-text" { (label) } }
        }
    }
}

fn table(title: &str, description: Option<&str>, head: &[&str], rows: Markup) -> Markup {
    html! {
        div class="cds--data-table-container" {
            @if !title.is_empty() || description.is_some() {
                div class="cds--data-table-header" {
                    @if !title.is_empty() { h4 class="cds--data-table-header__title" { (title) } }
                    @if let Some(d) = description { p class="cds--data-table-header__description" { (d) } }
                }
            }
            div class="cds--data-table-content" {
                table class="cds--data-table cds--data-table--sm" {
                    thead { tr { @for h in head { th { div class="cds--table-header-label" { (h) } } } } }
                    tbody { (rows) }
                }
            }
        }
    }
}

fn progress(done: i64, total: i64, label: &str, helper: &str) -> Markup {
    let frac = if total > 0 { done as f64 / total as f64 } else { 0.0 };
    html! {
        div class="cds--progress-bar cds--progress-bar--big" {
            div class="cds--progress-bar__label" { span class="cds--progress-bar__label-text" { (label) } }
            div class="cds--progress-bar__track" role="progressbar" aria-valuemin="0" aria-valuemax=(total) aria-valuenow=(done) {
                div class="cds--progress-bar__bar" style=(format!("transform: scaleX({frac:.4})")) {}
            }
            div class="cds--progress-bar__helper-text" { (helper) }
        }
    }
}

fn back(to: &str, msg: &str, error: bool) -> Redirect {
    let sep = if to.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{to}{sep}msg={}{}", urlencode(msg), if error { "&kind=error" } else { "" }))
}

fn human(n: i64) -> String {
    match n {
        n if n >= 1_000_000_000 => format!("{:.1} G", n as f64 / 1e9),
        n if n >= 1_000_000 => format!("{:.1} M", n as f64 / 1e6),
        n if n >= 10_000 => format!("{:.1} k", n as f64 / 1e3),
        n => n.to_string(),
    }
}

pub fn duration(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s => format!("{:.1} h", s as f64 / 3600.0),
    }
}

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
}

// ---- login

#[derive(Deserialize, Default)]
struct LoginQuery {
    next: Option<String>,
    msg: Option<String>,
}

/// Only local paths, so a login cannot send the browser elsewhere.
fn local(next: Option<String>) -> String {
    next.filter(|n| n.starts_with('/') && !n.starts_with("//")).unwrap_or_else(|| "/".into())
}

async fn login_page(State(app): State<Shared>, Query(q): Query<LoginQuery>) -> Markup {
    let next = local(q.next.clone());
    page(
        None,
        "Log in",
        Nav::None,
        None,
        html! {
            div class="rgwi-login cds--tile" {
                h1 class="rgwi-title" { "Log in" }
                @if let Some(m) = &q.msg { (notification("error", m, None)) }
                @if let Some(o) = &app.oidc {
                    div class="rgwi-actions" {
                        a class="cds--btn cds--btn--primary" href=(format!("/oidc/login?next={}", urlencode(&next))) { "Log in with " (o.cfg.name) }
                    }
                }
                @if !app.oidc_only {
                    @if app.oidc.is_some() { p class="rgwi-muted" style="margin-top:1.5rem" { "Or with the admin token:" } }
                    @else { p class="rgwi-muted" { "The admin token is in the server's admin token file, /etc/rgw-integrity/admin.token by default." } }
                    form method="post" action="/login" {
                        input type="hidden" name="next" value=(next);
                        (text_input("token", "Admin token", "", "password", ""))
                        div class="rgwi-actions" {
                            button class=(if app.oidc.is_some() { "cds--btn cds--btn--tertiary" } else { "cds--btn cds--btn--primary" }) type="submit" { "Log in" }
                        }
                    }
                }
            }
        },
    )
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
    next: Option<String>,
}

fn with_cookies(mut resp: Response, cookies: &[String]) -> Response {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

async fn login(State(app): State<Shared>, Form(f): Form<LoginForm>) -> Response {
    let next = local(f.next);
    if app.oidc_only || !app.admin_token_matches(f.token.trim()) {
        return Redirect::to(&format!("/login?next={}&msg={}", urlencode(&next), urlencode("That is not the admin token."))).into_response();
    }
    let who = Identity { name: "admin token".into(), via: "token", groups: Vec::new() };
    let id = app.new_session(who, None);
    app.event("login", "logged in with the admin token".into()).await;
    with_cookies(Redirect::to(&next).into_response(), &[app.session_cookie(&id, super::SESSION_HOURS * 3600)])
}

const OIDC_STATE_COOKIE: &str = "rgwi_oidc";

async fn oidc_login(State(app): State<Shared>, Query(q): Query<LoginQuery>) -> Response {
    let Some(o) = &app.oidc else { return StatusCode::NOT_FOUND.into_response() };
    match o.begin(&local(q.next)) {
        Ok((url, state)) => {
            let secure = if app.secure_cookies { "; Secure" } else { "" };
            // binds the provider's answer to this browser; Lax, as it comes back from the provider
            let cookie = format!("{OIDC_STATE_COOKIE}={state}; Path=/oidc; HttpOnly; SameSite=Lax; Max-Age=600{secure}");
            with_cookies(Redirect::to(&url).into_response(), &[cookie])
        }
        Err(e) => Redirect::to(&format!("/login?msg={}", urlencode(&format!("{e:#}")))).into_response(),
    }
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let all = headers.get(header::COOKIE)?.to_str().ok()?;
    all.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
}

async fn oidc_callback(State(app): State<Shared>, headers: axum::http::HeaderMap, Query(cb): Query<Callback>) -> Response {
    let Some(o) = &app.oidc else { return StatusCode::NOT_FOUND.into_response() };
    let fail = |msg: String| Redirect::to(&format!("/login?msg={}", urlencode(&msg))).into_response();
    if let Some(e) = cb.error {
        return fail(format!("The provider refused the login: {e} {}", cb.error_description.unwrap_or_default()));
    }
    let (Some(code), Some(state)) = (cb.code, cb.state) else { return fail("The provider's answer has no code.".into()) };
    if cookie(&headers, OIDC_STATE_COOKIE).as_deref() != Some(state.as_str()) {
        return fail("This login did not start in this browser; log in again.".into());
    }
    let clear = format!("{OIDC_STATE_COOKIE}=; Path=/oidc; Max-Age=0");
    match o.finish(&state, &code).await {
        Ok((who, next, id_token)) => {
            app.event("login", format!("{} logged in with single sign-on", who.name)).await;
            let id = app.new_session(who, Some(id_token));
            with_cookies(Redirect::to(&next).into_response(), &[app.session_cookie(&id, super::SESSION_HOURS * 3600), clear])
        }
        Err(Refusal::NotAllowed(name)) => {
            app.event("login", format!("{name} was refused: not an allowed user or group")).await;
            let body = page(
                None,
                "Not allowed",
                Nav::None,
                None,
                html! {
                    div class="rgwi-login cds--tile" {
                        h1 class="rgwi-title" { "Not allowed" }
                        (notification("error", &format!("{name} signed in, but is not one of the users or groups allowed here."), Some("Ask the server's administrator to allow your user or a group of yours.")))
                        a class="cds--link" href="/login" { "Log in as someone else" }
                    }
                },
            );
            with_cookies((StatusCode::FORBIDDEN, body).into_response(), &[clear])
        }
        Err(Refusal::Failed(e)) => {
            tracing::error!("single sign-on: {e:#}");
            with_cookies(fail(format!("{e:#}")), &[clear])
        }
    }
}

async fn logout(State(app): State<Shared>, headers: axum::http::HeaderMap) -> Response {
    let ended = cookie(&headers, SESSION_COOKIE).and_then(|id| app.end_session(&id));
    let clear = app.session_cookie("", 0);
    // leave the provider's session too, and come back to the login page
    if let (Some(o), Some(token), Some(public)) = (&app.oidc, ended.as_ref().and_then(|s| s.id_token.clone()), app.public_url.as_deref()) {
        if let Some(url) = o.logout_url(&token, &format!("{}/login", public.trim_end_matches('/'))) {
            return with_cookies(Redirect::to(&url).into_response(), &[clear]);
        }
    }
    with_cookies(Redirect::to("/login").into_response(), &[clear])
}

// ---- overview

async fn overview(AdminAuth(who): AdminAuth, State(app): State<Shared>, Query(fl): Query<Flash>) -> ApiResult<Markup> {
    let active = Filter { status: Some("active".into()), ..Default::default() };
    let (facets, scans, clients, events, settings) = app
        .db
        .call(move |c| Ok((db::facets(c, &active)?, db::scans(c, 1)?, db::clients(c)?, db::events(c, 12)?, db::settings(c)?)))
        .await?;
    let live = clients.iter().filter(|c| c.last_seen >= now() - 30).count();
    let running = scans.first().filter(|s| s.state == "running");
    Ok(page(
        Some(&who),
        "Overview",
        Nav::Overview,
        Some(10),
        html! {
            h1 class="rgwi-title" { "Overview" }
            (flash(&fl))
            @if settings.paused { (notification("warning", "Clients are paused.", Some("They lease no new buckets until you resume them on the Clients page."))) }
            div class="rgwi-tiles" {
                @for c in Class::ALL {
                    a class="cds--tile cds--tile--clickable" href=(format!("/findings?class={}&status=active", c.as_str())) {
                        div class="rgwi-tile-count" { (facets.tally.classes.get(c.as_str()).copied().unwrap_or(0)) }
                        div class="rgwi-tile-label" { (class_tag(c)) }
                        div class="rgwi-tile-help" { (c.describe()) }
                    }
                }
            }
            p class="rgwi-muted" style="margin-top:0.5rem" { "Open and confirmed findings." }
            div class="rgwi-cols-even" style="margin-top:1rem" {
                div {
                    h2 class="rgwi-section" { "Scan" }
                    @match running {
                        Some(s) => {
                            (progress(s.done + s.failed, s.units, &format!("Scan {} · {} of {} buckets", s.id, s.done + s.failed, s.units),
                                &format!("{} leased · {} pending · {} failed · {} RADOS objects checked · started {}", s.leased, s.pending, s.failed, human(s.rados_objects), iso(s.created))))
                        }
                        None => {
                            @match scans.first() {
                                Some(s) => p { "Last scan " a class="cds--link" href=(format!("/scans/{}", s.id)) { (s.id) } ", " (s.state) " " (ago(s.finished.unwrap_or(s.created))) ", with " (s.findings) " findings." }
                                None => p { "No scan yet." }
                            }
                            div class="rgwi-actions" { a class="cds--btn cds--btn--primary cds--btn--sm" href="/scans" { "Start a scan" } }
                        }
                    }
                    p style="margin-top:1rem" { (live) " of " (clients.len()) " clients reporting · " (settings.global_inflight) " RADOS operations in flight across them" }
                    h2 class="rgwi-section" { "Most likely causes" }
                    (table("", None, &["Cause", "Findings"], html! {
                        @for (cause, n) in &facets.tally.causes {
                            tr {
                                td { a class="cds--link" href=(format!("/findings?cause={}&status=active", urlencode(cause))) { (cause) } }
                                td { (n) }
                            }
                        }
                    }))
                }
                div {
                    h2 class="rgwi-section" { "Events" }
                    (table("", None, &["When", "Kind", "What"], html! {
                        @for e in &events {
                            tr { td { (ago(e.time)) } td class="rgwi-nowrap" { (e.kind) } td { (e.message) } }
                        }
                    }))
                }
            }
        },
    ))
}

// ---- findings

fn filter_query(f: &Filter, page: Option<usize>) -> String {
    let mut q = Vec::new();
    for (k, v) in [
        ("class", &f.class),
        ("check", &f.check),
        ("bucket", &f.bucket),
        ("cause", &f.cause),
        ("confidence", &f.confidence),
        ("key", &f.key),
    ] {
        if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
            q.push(format!("{k}={}", urlencode(v)));
        }
    }
    q.push(format!("status={}", f.status.as_deref().unwrap_or("any")));
    if let Some(a) = f.after_fix {
        q.push(format!("after_fix={a}"));
    }
    if let Some(s) = f.scan {
        q.push(format!("scan={s}"));
    }
    if let Some(p) = page {
        q.push(format!("page={p}"));
    }
    q.join("&")
}

/// The findings filter, from the page's query: empty fields mean any.
#[derive(Deserialize, Default)]
struct FindingsQuery {
    class: Option<String>,
    check: Option<String>,
    bucket: Option<String>,
    cause: Option<String>,
    status: Option<String>,
    confidence: Option<String>,
    key: Option<String>,
    after_fix: Option<String>,
    scan: Option<String>,
    page: Option<usize>,
    msg: Option<String>,
    kind: Option<String>,
}

impl FindingsQuery {
    fn filter(&self) -> Filter {
        let s = |v: &Option<String>| v.clone().filter(|v| !v.is_empty());
        Filter {
            class: s(&self.class),
            check: s(&self.check),
            bucket: s(&self.bucket),
            cause: s(&self.cause),
            status: Some(s(&self.status).unwrap_or_else(|| "active".into())).filter(|v| v != "any"),
            confidence: s(&self.confidence),
            key: s(&self.key),
            after_fix: self.after_fix.as_deref().and_then(|v| v.parse().ok()),
            scan: self.scan.as_deref().and_then(|v| v.parse().ok()),
            page: self.page,
            per_page: Some(50),
        }
    }
}

fn facet(title: &str, name: &str, values: &[(String, i64)], f: &Filter) -> Markup {
    html! {
        div class="rgwi-facet" {
            h4 { (title) }
            @for (v, n) in values {
                @let href = {
                    let mut g = f.clone();
                    match name {
                        "class" => g.class = Some(v.clone()),
                        "cause" => g.cause = Some(v.clone()),
                        "bucket" => g.bucket = Some(v.clone()),
                        "check" => g.check = Some(v.clone()),
                        _ => g.status = Some(v.clone()),
                    }
                    format!("/findings?{}", filter_query(&g, None))
                };
                a class="cds--link" href=(href) { span { (if v.is_empty() { "(none)" } else { v.as_str() }) } span class="rgwi-muted" { (n) } }
            }
        }
    }
}

fn distinct_causes(c: &rusqlite::Connection) -> anyhow::Result<Vec<String>> {
    let mut st = c.prepare("SELECT DISTINCT top_cause FROM findings WHERE top_cause IS NOT NULL ORDER BY 1")?;
    let rows = st.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

async fn findings_page(AdminAuth(who): AdminAuth, State(app): State<Shared>, Query(q): Query<FindingsQuery>) -> ApiResult<Markup> {
    let filter = q.filter();
    let f2 = filter.clone();
    let (rows, total, facets, causes) = app
        .db
        .call(move |c| {
            let (rows, total) = db::findings(c, &f2)?;
            Ok((rows, total, db::facets(c, &f2)?, distinct_causes(c)?))
        })
        .await?;
    let page_no = filter.page.unwrap_or(0);
    let pages = ((total + 49) / 50).max(1) as usize;
    let any = |mut pairs: Vec<(String, String)>| {
        pairs.insert(0, (String::new(), "Any".to_string()));
        pairs
    };
    let classes = any(Class::ALL.iter().map(|c| (c.as_str().to_string(), c.as_str().replace('_', " "))).collect());
    let mut statuses = pairs(&[("active", "open or confirmed"), ("any", "any")]);
    statuses.extend(STATUSES.iter().map(|s| (s.to_string(), s.replace('_', " "))));
    let causes = any(causes.into_iter().map(|c| (c.clone(), c)).collect());
    let confidences = any(pairs(&[("high", "high"), ("medium", "medium"), ("low", "low")]));
    let fl = Flash { msg: q.msg.clone(), kind: q.kind.clone() };
    let tally = |m: &std::collections::BTreeMap<String, u64>| m.iter().map(|(k, v)| (k.clone(), *v as i64)).collect::<Vec<_>>();
    Ok(page(
        Some(&who),
        "Findings",
        Nav::Findings,
        None,
        html! {
            h1 class="rgwi-title" { "Findings" }
            (flash(&fl))
            form method="get" action="/findings" {
                div class="rgwi-filters" {
                    (select("class", "Class", &classes, filter.class.as_deref().or(Some(""))))
                    (select("status", "Status", &statuses, Some(filter.status.as_deref().unwrap_or("any"))))
                    (select("cause", "Most likely cause", &causes, filter.cause.as_deref().or(Some(""))))
                    (select("confidence", "Confidence", &confidences, filter.confidence.as_deref().or(Some(""))))
                    (text_input("bucket", "Bucket", filter.bucket.as_deref().unwrap_or(""), "text", "exact name"))
                    (text_input("key", "Key contains", filter.key.as_deref().unwrap_or(""), "text", ""))
                    (text_input("check", "Check", filter.check.as_deref().unwrap_or(""), "text", "e.g. missing_data"))
                    div class="rgwi-actions" style="margin:0" {
                        button class="cds--btn cds--btn--primary cds--btn--sm" type="submit" { "Filter" }
                        a class="cds--btn cds--btn--ghost cds--btn--sm" href="/findings" { "Clear" }
                    }
                }
            }
            div class="rgwi-cols" {
                div {
                    (table(&format!("{total} findings"), None, &["Class", "Bucket", "Key or object", "Check", "Most likely cause", "Status", "Last seen"], html! {
                        @for r in &rows {
                            @let f = &r.finding;
                            tr {
                                td { (class_tag(f.class)) }
                                td { a class="cds--link" href=(format!("/findings?bucket={}&status=any", urlencode(&f.bucket))) { (f.bucket) } }
                                td class="rgwi-mono" { a class="cds--link" href=(format!("/findings/{}", r.id)) { (f.key.clone().unwrap_or_else(|| f.oids.first().cloned().unwrap_or_else(|| "(details)".into()))) } }
                                td { (f.check) }
                                td {
                                    @if let Some(c) = f.top_cause() { (c.cause) " " (confidence_tag(c.confidence)) } @else { span class="rgwi-muted" { "none known" } }
                                    @if f.after_fix { " " (tag("red", "after fix")) }
                                }
                                td { (status_tag(&r.status)) }
                                td { (ago(r.last_seen)) }
                            }
                        }
                    }))
                    div class="rgwi-pager" {
                        span class="rgwi-muted" { "Page " (page_no + 1) " of " (pages) }
                        div class="rgwi-actions" style="margin:0" {
                            @if page_no > 0 { a class="cds--btn cds--btn--ghost cds--btn--sm" href=(format!("/findings?{}", filter_query(&filter, Some(page_no - 1)))) { "Previous" } }
                            @if page_no + 1 < pages { a class="cds--btn cds--btn--ghost cds--btn--sm" href=(format!("/findings?{}", filter_query(&filter, Some(page_no + 1)))) { "Next" } }
                            a class="cds--btn cds--btn--tertiary cds--btn--sm" href=(format!("/findings.jsonl?{}", filter_query(&filter, None))) { "Export JSON lines" }
                        }
                    }
                }
                aside {
                    (facet("Class", "class", &tally(&facets.tally.classes), &filter))
                    (facet("Most likely cause", "cause", &tally(&facets.tally.causes), &filter))
                    (facet("Status", "status", &facets.statuses, &filter))
                    (facet("Check", "check", &facets.checks, &filter))
                    (facet("Buckets with the most", "bucket", &facets.buckets, &filter))
                }
            }
        },
    ))
}

async fn findings_export(AdminAuth(_who): AdminAuth, State(app): State<Shared>, Query(q): Query<FindingsQuery>) -> ApiResult<Response> {
    let mut filter = q.filter();
    let body = app
        .db
        .call(move |c| {
            let mut out = String::new();
            filter.per_page = Some(1000);
            for page in 0.. {
                filter.page = Some(page);
                let (rows, _) = db::findings(c, &filter)?;
                for r in &rows {
                    out.push_str(&serde_json::to_string(&r.finding)?);
                    out.push('\n');
                }
                if rows.len() < 1000 {
                    break;
                }
            }
            Ok(out)
        })
        .await?;
    Ok((
        [(header::CONTENT_TYPE, "application/x-ndjson"), (header::CONTENT_DISPOSITION, "attachment; filename=\"rgw-integrity-findings.jsonl\"")],
        body,
    )
        .into_response())
}

fn finding_detail(r: &FindingRow) -> Markup {
    let f: &Finding = &r.finding;
    html! {
        dl class="rgwi-kv" {
            dt { "Class" } dd { (class_tag(f.class)) " " span class="rgwi-muted" { (f.class.describe()) } }
            dt { "Check" } dd { (f.check) }
            dt { "Bucket" } dd { a class="cds--link" href=(format!("/findings?bucket={}&status=any", urlencode(&f.bucket))) { (f.bucket) } }
            @if let Some(k) = &f.key { dt { "Key" } dd class="rgwi-mono" { (k) } }
            @if let Some(u) = &f.upload_id { dt { "Upload" } dd class="rgwi-mono" { (u) } }
            @if let Some(t) = &f.time { dt { "Object time" } dd { (t) } }
            dt { "Status" } dd { (status_tag(&r.status)) @if !r.note.is_empty() { " " span class="rgwi-muted" { (r.note) } } }
            dt { "Seen" } dd { "first " (ago(r.first_seen)) ", last " (ago(r.last_seen))
                @if let Some(s) = r.last_scan { ", in " a class="cds--link" href=(format!("/scans/{s}")) { "scan " (s) } } }
        }
    }
}

async fn finding_page(AdminAuth(who): AdminAuth, State(app): State<Shared>, Path(id): Path<i64>, Query(fl): Query<Flash>) -> ApiResult<Markup> {
    let Some(r) = app.db.call(move |c| db::finding(c, id)).await? else {
        return Err(ApiError(StatusCode::NOT_FOUND, format!("no finding {id}")));
    };
    let f = &r.finding;
    let statuses: Vec<(String, String)> = ["open", "confirmed", "false_positive"].iter().map(|s| (s.to_string(), s.replace('_', " "))).collect();
    Ok(page(
        Some(&who),
        &format!("Finding {id}"),
        Nav::Findings,
        None,
        html! {
            nav class="cds--breadcrumb" aria-label="breadcrumb" style="margin-top:1rem" {
                ol class="cds--breadcrumb" { li class="cds--breadcrumb-item" { a class="cds--link" href="/findings" { "Findings" } } }
            }
            h1 class="rgwi-title" { (f.check.replace('_', " ")) " in " (f.bucket) }
            (flash(&fl))
            @if let Some(h) = &f.hint { (notification("info", h, None)) }
            @if f.after_fix { (notification("error", "Newer than the fixes this build carries", Some("Every known cause of this artifact is fixed in the build; escalate it."))) }
            div class="rgwi-cols" {
                div {
                    (finding_detail(&r))
                    h2 class="rgwi-section" { "Causes" }
                    (table("", Some("Ranked by the evidence; causes the cluster's release cannot have are left out."), &["Cause", "Confidence", "What", "Evidence", "Tracker", "Fix"], html! {
                        @for c in &f.causes {
                            tr {
                                td class="rgwi-nowrap" { span class="rgwi-mono" { (c.cause) } }
                                td { (confidence_tag(c.confidence)) }
                                td { (c.what) }
                                td { (c.evidence.clone().unwrap_or_default()) }
                                td class="rgwi-nowrap" { @if let Some(t) = &c.tracker { a class="cds--link" href=(t) { (t.rsplit('/').next().unwrap_or_default()) } } }
                                td class="rgwi-nowrap" { @if let Some(p) = &c.fix { a class="cds--link" href=(p) { "#" (p.rsplit('/').next().unwrap_or_default()) } @if c.fixed_here { " " (tag("green", "in this build")) } } }
                            }
                        }
                    }))
                    h2 class="rgwi-section" { "Evidence" }
                    pre class="rgwi-json" { (serde_json::to_string_pretty(&f.evidence).unwrap_or_default()) }
                    @if !f.oids.is_empty() {
                        h2 class="rgwi-section" { "RADOS objects" @if let Some(n) = f.oid_count { " (the first 100 of " (n) ")" } }
                        pre class="rgwi-json" { @for o in &f.oids { (o) "\n" } }
                    }
                }
                aside {
                    div class="cds--tile" {
                        h4 { "Triage" }
                        form method="post" action=(format!("/findings/{id}/status")) {
                            (select("status", "Status", &statuses, Some(r.status.as_str())))
                            (text_input("note", "Note", &r.note, "text", "optional"))
                            div class="rgwi-actions" { button class="cds--btn cds--btn--primary cds--btn--sm" type="submit" { "Save" } }
                        }
                    }
                }
            }
        },
    ))
}

#[derive(Deserialize)]
struct StatusForm {
    status: String,
    note: Option<String>,
}

async fn finding_status(AdminAuth(who): AdminAuth, State(app): State<Shared>, Path(id): Path<i64>, Form(f): Form<StatusForm>) -> Response {
    let msg = format!("finding {id}: {}, by {}", f.status, who.name);
    match app.db.call(move |c| db::set_status(c, id, &f.status, f.note.as_deref())).await {
        Ok(_) => {
            app.event("triage", msg).await;
            back(&format!("/findings/{id}"), "Saved.", false).into_response()
        }
        Err(e) => back(&format!("/findings/{id}"), &format!("{e:#}"), true).into_response(),
    }
}

// ---- clients

async fn clients_page(AdminAuth(who): AdminAuth, State(app): State<Shared>, Query(fl): Query<Flash>) -> ApiResult<Markup> {
    let (clients, settings) = app.db.call(|c| Ok((db::clients(c)?, db::settings(c)?))).await?;
    let live_count = clients.iter().filter(|c| c.last_seen >= now() - 30).count();
    Ok(page(
        Some(&who),
        "Clients",
        Nav::Clients,
        Some(10),
        html! {
            h1 class="rgwi-title" { "Clients" }
            (flash(&fl))
            div class="cds--tile" {
                h4 { "Concurrency" }
                p class="rgwi-muted" { "Each client gets an equal share of the RADOS operations in flight, unless it has its own limit. Changes reach the clients with their next heartbeat, within 5 seconds." }
                form method="post" action="/clients/controls" style="margin-top:1rem" {
                    div class="rgwi-form-row" {
                        (text_input("global_inflight", "RADOS operations in flight, across clients", &settings.global_inflight.to_string(), "number", ""))
                        (text_input("parallel", "Buckets each client scans at once", &settings.parallel.to_string(), "number", ""))
                        (text_input("lease_secs", "Lease, seconds", &settings.lease_secs.to_string(), "number", ""))
                        div class="rgwi-actions" style="margin:0" { button class="cds--btn cds--btn--primary cds--btn--sm" type="submit" name="action" value="save" { "Apply" } }
                    }
                    @if live_count == 0 {
                        p { "No client is reporting." }
                    } @else {
                        p { (live_count) " reporting " (if live_count == 1 { "client gets " } else { "clients get " }) (settings.global_inflight / live_count) " each." }
                    }
                }
                div class="rgwi-actions" {
                    @if settings.paused {
                        form method="post" action="/clients/controls" { button class="cds--btn cds--btn--primary" type="submit" name="action" value="resume" { "Resume clients" } }
                    } @else {
                        form method="post" action="/clients/controls" data-confirm="Pause every client? Running buckets pause too." {
                            button class="cds--btn cds--btn--secondary" type="submit" name="action" value="pause" { "Pause clients" }
                        }
                    }
                    form method="post" action="/clients/forget" { button class="cds--btn cds--btn--ghost" type="submit" { "Forget clients not seen for an hour" } }
                }
            }
            h2 class="rgwi-section" { "Status" }
            (table("", None, &["Client", "State", "Last seen", "In flight", "Scanning", "Checked", "Errors", "Own limit"], html! {
                @for c in &clients {
                    @let s = &c.status;
                    @let state = if c.last_seen < now() - 30 { ("red", "lost") } else if s.draining { ("purple", "draining") } else if settings.paused { ("gray", "paused") } else if !s.units.is_empty() { ("green", "scanning") } else { ("cool-gray", "idle") };
                    tr {
                        td { (c.host) br; span class="rgwi-muted rgwi-mono" { (c.id) " · " (c.version) } }
                        td { (tag(state.0, state.1)) }
                        td { (ago(c.last_seen)) }
                        td { (s.inflight_in_use) " / " (s.inflight_size) }
                        td { @for u in &s.units { div { (u.bucket) " " span class="rgwi-muted" { (human(u.rados_objects as i64)) " objects" } } } }
                        td { (human(s.checked as i64)) }
                        td { (s.errors) }
                        td {
                            form method="post" action=(format!("/clients/{}/override", urlencode(&c.id))) class="rgwi-form-row" style="margin:0" {
                                input class="cds--text-input" type="number" name="inflight" style="width:6rem" value=(c.inflight_override.map(|v| v.to_string()).unwrap_or_default()) placeholder="share";
                                button class="cds--btn cds--btn--ghost cds--btn--sm" type="submit" { "Set" }
                            }
                        }
                    }
                }
            }))
        },
    ))
}

async fn controls(AdminAuth(who): AdminAuth, State(app): State<Shared>, Form(f): Form<HashMap<String, String>>) -> Response {
    let result: anyhow::Result<String> = async {
        let mut s = app.settings().await?;
        let msg = match f.get("action").map(String::as_str) {
            Some("pause") => {
                s.paused = true;
                "Clients paused.".to_string()
            }
            Some("resume") => {
                s.paused = false;
                "Clients resumed.".to_string()
            }
            _ => {
                let num = |k: &str| -> anyhow::Result<Option<i64>> {
                    f.get(k)
                        .filter(|v| !v.is_empty())
                        .map(|v| v.trim().parse::<i64>().map_err(|_| anyhow::anyhow!("{k} is not a number")))
                        .transpose()
                };
                if let Some(v) = num("global_inflight")? {
                    s.global_inflight = v.max(1) as usize;
                }
                if let Some(v) = num("parallel")? {
                    s.parallel = v.max(1) as usize;
                }
                if let Some(v) = num("lease_secs")? {
                    s.lease_secs = v.max(15);
                }
                format!("{} in flight across clients, {} buckets per client, {} s leases.", s.global_inflight, s.parallel, s.lease_secs)
            }
        };
        let s2 = s.clone();
        app.db.call(move |c| db::save_settings(c, &s2)).await?;
        app.event("control", format!("{msg} ( by {} )", who.name)).await;
        Ok(msg)
    }
    .await;
    match result {
        Ok(msg) => back("/clients", &msg, false).into_response(),
        Err(e) => back("/clients", &format!("{e:#}"), true).into_response(),
    }
}

async fn client_override(AdminAuth(who): AdminAuth, State(app): State<Shared>, Path(id): Path<String>, Form(f): Form<HashMap<String, String>>) -> Response {
    let v = f.get("inflight").filter(|v| !v.trim().is_empty()).and_then(|v| v.trim().parse::<usize>().ok()).map(|v| v.max(1));
    let msg = match v {
        Some(n) => format!("{id}: its own limit of {n} in flight, by {}", who.name),
        None => format!("{id}: an equal share, by {}", who.name),
    };
    let id2 = id.clone();
    match app.db.call(move |c| db::set_override(c, &id2, v)).await {
        Ok(()) => {
            app.event("control", msg.clone()).await;
            back("/clients", &msg, false).into_response()
        }
        Err(e) => back("/clients", &format!("{e:#}"), true).into_response(),
    }
}

async fn forget_clients(AdminAuth(who): AdminAuth, State(app): State<Shared>) -> Response {
    match app.db.call(|c| db::forget_clients(c, now() - 3600)).await {
        Ok(n) => {
            app.event("control", format!("{n} clients forgotten, by {}", who.name)).await;
            back("/clients", &format!("Forgot {n} clients."), false).into_response()
        }
        Err(e) => back("/clients", &format!("{e:#}"), true).into_response(),
    }
}

// ---- scans

fn options_form(o: &Options) -> Markup {
    html! {
        div class="rgwi-form-row" {
            (text_input("grace", "Skip findings younger than, seconds", &o.grace.to_string(), "number", ""))
            (text_input("match_prefix", "Only keys starting with", o.match_prefix.as_deref().unwrap_or(""), "text", "any"))
            (text_input("threads", "Index check reads at once", &o.threads.to_string(), "number", ""))
        }
        div class="rgwi-form-row" {
            (checkbox("uploads", "Open multipart uploads", o.uploads))
            (checkbox("check_index", "Index entries against heads (one read per object)", o.check_index))
            (checkbox("refcount", "Tail references (one read per tail object)", o.refcount))
            (checkbox("orphans", "Orphans (lists the data pools; every bucket)", o.orphans))
        }
    }
}

fn options_of(f: &HashMap<String, String>) -> anyhow::Result<Options> {
    let num = |k: &str, d: i64| -> anyhow::Result<i64> {
        f.get(k).filter(|v| !v.is_empty()).map_or(Ok(d), |v| v.trim().parse().map_err(|_| anyhow::anyhow!("{k} is not a number")))
    };
    Ok(Options {
        grace: num("grace", 3600)?.max(0),
        check_index: f.contains_key("check_index"),
        refcount: f.contains_key("refcount"),
        uploads: f.contains_key("uploads"),
        match_prefix: f.get("match_prefix").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        threads: num("threads", 32)?.clamp(1, 1024) as usize,
        orphans: f.contains_key("orphans"),
    })
}

fn checks_label(o: &Options) -> String {
    let mut v = vec!["gaps"];
    if o.uploads {
        v.push("uploads");
    }
    if o.check_index {
        v.push("index");
    }
    if o.refcount {
        v.push("refcount");
    }
    if o.orphans {
        v.push("orphans");
    }
    v.join(", ")
}

fn state_color(state: &str) -> &'static str {
    match state {
        "running" | "leased" => "blue",
        "done" => "green",
        "failed" => "red",
        _ => "gray",
    }
}

async fn scans_page(AdminAuth(who): AdminAuth, State(app): State<Shared>, Query(fl): Query<Flash>) -> ApiResult<Markup> {
    let (scans, settings) = app.db.call(|c| Ok((db::scans(c, 50)?, db::settings(c)?))).await?;
    let running = scans.iter().find(|s| s.state == "running");
    Ok(page(
        Some(&who),
        "Scans",
        Nav::Scans,
        Some(10),
        html! {
            h1 class="rgwi-title" { "Scans" }
            (flash(&fl))
            @match running {
                Some(s) => {
                    div class="cds--tile" {
                        (progress(s.done + s.failed, s.units, &format!("Scan {} · {} of {} buckets", s.id, s.done + s.failed, s.units),
                            &format!("{} leased · {} pending · {} failed · {} RADOS objects checked", s.leased, s.pending, s.failed, human(s.rados_objects))))
                        div class="rgwi-actions" {
                            a class="cds--btn cds--btn--tertiary cds--btn--sm" href=(format!("/scans/{}", s.id)) { "Buckets" }
                            form method="post" action=(format!("/scans/{}/cancel", s.id)) data-confirm="Cancel this scan? Clients finish their running buckets, and lease no more." {
                                button class="cds--btn cds--btn--danger cds--btn--sm" type="submit" { "Cancel scan" }
                            }
                        }
                    }
                }
                None => {
                    div class="cds--tile" {
                        h4 { "Start a scan" }
                        p class="rgwi-muted" { "Clients lease the buckets largest first. The server takes a snapshot of the GC queue for the scan." }
                        form method="post" action="/scans/start" style="margin-top:1rem" {
                            (options_form(&settings.default_options))
                            div class="rgwi-form-row" {
                                (text_input("buckets", "Only these buckets, space separated", "", "text", "every bucket"))
                                (text_input("note", "Note", "", "text", "optional"))
                                (checkbox("gc", "Snapshot the GC queue", true))
                            }
                            div class="rgwi-actions" { button class="cds--btn cds--btn--primary" type="submit" { "Start scan" } }
                        }
                    }
                }
            }
            h2 class="rgwi-section" { "History" }
            (table("", None, &["Scan", "State", "Started", "Took", "Buckets", "RADOS objects", "Findings", "Checks", "Note"], html! {
                @for s in &scans {
                    tr {
                        td { a class="cds--link" href=(format!("/scans/{}", s.id)) { (s.id) } }
                        td { (tag(state_color(&s.state), &s.state)) }
                        td { (ago(s.created)) }
                        td { @if let Some(f) = s.finished { (duration(f - s.created)) } }
                        td { (s.done) " done" @if s.failed > 0 { ", " (s.failed) " failed" } " of " (s.units) }
                        td { (human(s.rados_objects)) }
                        td { a class="cds--link" href=(format!("/findings?scan={}&status=any", s.id)) { (s.findings) } }
                        td class="rgwi-muted" { (checks_label(&s.options)) }
                        td { (s.note) }
                    }
                }
            }))
        },
    ))
}

async fn start_scan(AdminAuth(who): AdminAuth, State(app): State<Shared>, Form(f): Form<HashMap<String, String>>) -> Response {
    let options = match options_of(&f) {
        Ok(o) => o,
        Err(e) => return back("/scans", &format!("{e:#}"), true).into_response(),
    };
    let buckets = f.get("buckets").map(|b| b.split_whitespace().map(str::to_string).collect()).unwrap_or_default();
    let req = StartScan { options, buckets, note: f.get("note").cloned().unwrap_or_default() };
    match app.start_scan(req, f.contains_key("gc")).await {
        Ok(id) => {
            app.event("scan", format!("scan {id} started by {}", who.name)).await;
            back("/scans", &format!("Scan {id} started."), false).into_response()
        }
        Err(e) => back("/scans", &format!("{e:#}"), true).into_response(),
    }
}

async fn cancel_scan(AdminAuth(who): AdminAuth, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.call(move |c| db::cancel_scan(c, id, now())).await {
        Ok(()) => {
            app.event("scan", format!("scan {id} cancelled by {}", who.name)).await;
            back("/scans", &format!("Scan {id} cancelled."), false).into_response()
        }
        Err(e) => back("/scans", &format!("{e:#}"), true).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct UnitsQuery {
    state: Option<String>,
}

async fn scan_page(AdminAuth(who): AdminAuth, State(app): State<Shared>, Path(id): Path<i64>, Query(q): Query<UnitsQuery>) -> ApiResult<Markup> {
    let state = q.state.clone().filter(|s| !s.is_empty());
    let st2 = state.clone();
    let (units, scans) = app.db.call(move |c| Ok((db::units(c, id, st2.as_deref(), 2000)?, db::scans(c, 1000)?))).await?;
    let Some(s) = scans.into_iter().find(|s| s.id == id) else { return Err(ApiError(StatusCode::NOT_FOUND, format!("no scan {id}"))) };
    let states = pairs(&[("", "Any"), ("leased", "leased"), ("pending", "pending"), ("done", "done"), ("failed", "failed"), ("cancelled", "cancelled")]);
    Ok(page(
        Some(&who),
        &format!("Scan {id}"),
        Nav::Scans,
        (s.state == "running").then_some(10),
        html! {
            nav class="cds--breadcrumb" aria-label="breadcrumb" style="margin-top:1rem" {
                ol class="cds--breadcrumb" { li class="cds--breadcrumb-item" { a class="cds--link" href="/scans" { "Scans" } } }
            }
            h1 class="rgwi-title" { "Scan " (id) }
            (progress(s.done + s.failed, s.units, &format!("{} of {} buckets · {}", s.done + s.failed, s.units, s.state),
                &format!("{} RADOS objects checked · {} findings · checks: {} · {} GC entries", human(s.rados_objects), s.findings, checks_label(&s.options), s.gc_entries)))
            form method="get" action=(format!("/scans/{id}")) class="rgwi-form-row" style="margin-top:1rem" {
                (select("state", "Buckets", &states, state.as_deref().or(Some(""))))
                button class="cds--btn cds--btn--ghost cds--btn--sm" type="submit" { "Show" }
            }
            (table("", Some("Leased and failed first, then by size; up to 2000. Orphan joins wait for every bucket and pool slice."), &["Unit", "State", "Client", "Objects", "RADOS objects", "Findings", "Took", "Attempts", "Error"], html! {
                @for u in &units {
                    tr {
                        td {
                            @if u.kind == "bucket" {
                                a class="cds--link" href=(format!("/findings?bucket={}&status=any", urlencode(&u.bucket))) { (u.bucket) }
                            } @else {
                                (tag("cool-gray", match u.kind.as_str() { "list" => "pool slice", "join" => "orphan join", _ => "orphan classification" })) " " (u.bucket)
                            }
                        }
                        td { (tag(state_color(&u.state), &u.state)) }
                        td class="rgwi-mono" { (u.client.clone().unwrap_or_default()) }
                        td { (human(u.objects)) }
                        td { (u.rados_objects.map(human).unwrap_or_default()) }
                        td { (u.findings.map(|f| f.to_string()).unwrap_or_default()) }
                        td { (u.seconds.map(|s| format!("{s:.1} s")).unwrap_or_default()) }
                        td { (u.attempts) }
                        td { (u.error.clone().unwrap_or_default()) }
                    }
                }
            }))
        },
    ))
}

// ---- settings and issues

async fn settings_page(AdminAuth(who): AdminAuth, State(app): State<Shared>, Query(fl): Query<Flash>) -> ApiResult<Markup> {
    let s = app.settings().await?;
    let releases = pairs(&[("", "from ceph versions"), ("reef", "reef (18)"), ("squid", "squid (19)"), ("tentacle", "tentacle (20)"), ("main", "main (21)")]);
    Ok(page(
        Some(&who),
        "Settings",
        Nav::Settings,
        None,
        html! {
            h1 class="rgwi-title" { "Settings" }
            (flash(&fl))
            form method="post" action="/settings" {
                div class="cds--tile" {
                    h4 { "What findings are judged against" }
                    p class="rgwi-muted" { "For scans started after the change." }
                    div class="rgwi-form-row" style="margin-top:1rem" {
                        (select("release", "Release", &releases, Some(s.release.as_deref().unwrap_or(""))))
                        (text_input("fixed", "Fixes the build carries, ceph/ceph PR numbers", &s.fixed.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", "), "text", "e.g. 72097, 72098"))
                        (text_input("fixed_since", "Deployed on", s.fixed_since.as_deref().unwrap_or(""), "date", ""))
                    }
                }
                div class="cds--tile" style="margin-top:1rem" {
                    h4 { "Scheduled scans" }
                    div class="rgwi-form-row" style="margin-top:1rem" {
                        (text_input("auto_scan_hours", "Start a scan this many hours after the last one; 0 never", &s.auto_scan_hours.to_string(), "number", ""))
                    }
                    h4 { "Their checks, and the start form's defaults" }
                    (options_form(&s.default_options))
                }
                div class="rgwi-actions" { button class="cds--btn cds--btn--primary" type="submit" { "Save" } }
            }
            p class="rgwi-muted" { "State is in " span class="rgwi-mono" { (app.db.location) } "." }
        },
    ))
}

async fn save_settings(AdminAuth(who): AdminAuth, State(app): State<Shared>, Form(f): Form<HashMap<String, String>>) -> Response {
    let result: anyhow::Result<()> = async {
        let mut s = app.settings().await?;
        s.release = f.get("release").map(|r| r.trim().to_string()).filter(|r| !r.is_empty());
        if let Some(r) = &s.release {
            crate::release_majors(r)?;
        }
        s.fixed = f
            .get("fixed")
            .map(|v| v.split(|c: char| c == ',' || c.is_whitespace()).filter(|p| !p.is_empty()).map(|p| p.trim_start_matches('#').parse()).collect())
            .transpose()
            .map_err(|_| anyhow::anyhow!("the fixes are pull request numbers"))?
            .unwrap_or_default();
        s.fixed_since = f.get("fixed_since").map(|d| d.trim().to_string()).filter(|d| !d.is_empty());
        if let Some(d) = &s.fixed_since {
            crate::oid::parse_time(&format!("{d} 00:00:00")).ok_or_else(|| anyhow::anyhow!("the date is YYYY-MM-DD"))?;
        }
        s.auto_scan_hours = f.get("auto_scan_hours").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        s.default_options = options_of(&f)?;
        let msg = format!("settings, by {}: release {:?}, fixes {:?} since {:?}, scans every {} h", who.name, s.release, s.fixed, s.fixed_since, s.auto_scan_hours);
        app.db.call(move |c| db::save_settings(c, &s)).await?;
        app.event("control", msg).await;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => back("/settings", "Saved.", false).into_response(),
        Err(e) => back("/settings", &format!("{e:#}"), true).into_response(),
    }
}

async fn issues_page(AdminAuth(who): AdminAuth, State(app): State<Shared>) -> Markup {
    let name = |m: u32| match m {
        18 => "reef",
        19 => "squid",
        20 => "tentacle",
        21 => "main",
        _ => "",
    };
    page(
        Some(&who),
        "Known issues",
        Nav::Issues,
        None,
        html! {
            h1 class="rgwi-title" { "Known issues" }
            p class="rgwi-muted" { "The causes findings can name. Extend or replace them with the server's --catalog file." }
            (table("", None, &["Cause", "What", "Releases", "Tracker", "Fix"], html! {
                @for i in &app.catalog.issues {
                    tr {
                        td class="rgwi-mono" { (i.id) }
                        td { (i.what) }
                        td { @match (i.min, i.max) {
                            (Some(lo), None) => { (name(lo)) " and later" }
                            (None, Some(hi)) => { "up to " (name(hi)) }
                            (Some(lo), Some(hi)) => { (name(lo)) " to " (name(hi)) }
                            (None, None) => { "all" }
                        } }
                        td { @if let Some(t) = i.tracker { a class="cds--link" href=(format!("https://tracker.ceph.com/issues/{t}")) { (t) } } }
                        td { @if let Some(p) = i.fix { a class="cds--link" href=(format!("https://github.com/ceph/ceph/pull/{p}")) { "#" (p) } } }
                    }
                }
            }))
        },
    )
}
