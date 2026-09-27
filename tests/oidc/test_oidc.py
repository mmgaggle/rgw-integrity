#!/usr/bin/env python3
"""
test_oidc.py: single sign-on through the Keycloak of keycloak.sh, with a
browser ( Playwright ), against a server on https://localhost:18443 started
with --oidc-issuer http://localhost:8080/realms/rgwi --oidc-client-id
rgw-integrity --oidc-allowed-groups rgw-admins --oidc-name Keycloak.

    uv run --with playwright python tests/oidc/test_oidc.py [chrome]

An allowed user gets in and lands where they were going, what they change
is recorded under their name, and logout ends both sessions; a user in no
allowed group is refused; the admin API takes an allowed user's access
token, and refuses a refused user's and a tampered one.
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import ssl

from playwright.sync_api import sync_playwright

BASE = "https://localhost:18443"
KEYCLOAK = "http://localhost:8080/realms/rgwi"
fails = 0


def check(name, ok):
    global fails
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    fails += not ok


def access_token(user, password):
    body = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "rgw-integrity", "client_secret": "rgwi-test-secret",
        "username": user, "password": password, "scope": "openid",
    }).encode()
    with urllib.request.urlopen(f"{KEYCLOAK}/protocol/openid-connect/token", body) as r:
        return json.load(r)["access_token"]


def api_status(token):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    req = urllib.request.Request(f"{BASE}/api/v1/status", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def keycloak_login(pg, user, password):
    pg.click("text=Log in with Keycloak")
    pg.wait_for_url("http://localhost:8080/**")
    pg.fill("#username", user)
    pg.fill("#password", password)
    pg.click("#kc-login")
    pg.wait_for_load_state("networkidle")


with sync_playwright() as p:
    browser = p.chromium.launch(channel=sys.argv[1] if len(sys.argv) > 1 else None)
    pg = browser.new_context(ignore_https_errors=True).new_page()
    pg.on("dialog", lambda d: d.accept())

    pg.goto(BASE + "/clients")
    check("the dashboard sends a browser to log in", "/login" in pg.url)
    keycloak_login(pg, "alice", "alice-pw")
    check("alice lands where she was going", pg.url == BASE + "/clients")
    check("the header names alice", "alice" in pg.inner_text("header"))
    pg.click("text=Pause clients")
    pg.wait_for_load_state("networkidle")
    pg.click("text=Resume clients")
    pg.wait_for_load_state("networkidle")
    pg.goto(BASE + "/")
    check("the events name alice", "( by alice )" in pg.inner_text("main"))

    pg.goto(BASE + "/logout")
    pg.wait_for_load_state("networkidle")
    check("logout comes back to the login page", pg.url.startswith(BASE + "/login"))
    pg.goto(BASE + "/clients")
    check("after logout the dashboard asks for a login again", "/login" in pg.url)

    keycloak_login(pg, "bob", "bob-pw")
    text = pg.inner_text("main")
    check("bob, in no allowed group, is refused", "Not allowed" in text and "bob" in text)
    pg.goto(BASE + "/clients")
    check("bob has no session", "/login" in pg.url)
    browser.close()

alice, bob = access_token("alice", "alice-pw"), access_token("bob", "bob-pw")
check("the admin API takes alice's access token", api_status(alice) == 200)
check("the admin API refuses bob's access token", api_status(bob) == 403)
head, claims, sig = alice.split(".")
check("the admin API refuses a tampered token", api_status(f"{head}.{claims}.{sig[:-4]}AAAA") == 401)
print(f"{fails} failed")
sys.exit(1 if fails else 0)
