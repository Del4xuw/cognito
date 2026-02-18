#!/usr/bin/env python3
"""End-to-end API testing script for the Cognito Auth System.

Usage:
    python scripts/test_api.py --api-url https://abc123.execute-api.us-east-1.amazonaws.com/dev
    python scripts/test_api.py --api-url https://abc123.execute-api.us-east-1.amazonaws.com/dev \
                               --username admin@example.com --password 'P@ssw0rd!'

The script exercises:
    1. Login flow (POST /auth/authorize)
    2. Token refresh (POST /auth/refresh)
    3. Protected endpoints (GET/POST/DELETE /events)
    4. Authorization failure scenarios
"""

import argparse
import json
import sys
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Colours for terminal output
# ---------------------------------------------------------------------------
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def _ok(msg: str) -> None:
    print(f"  {GREEN}✓ PASS{RESET}  {msg}")


def _fail(msg: str) -> None:
    print(f"  {RED}✗ FAIL{RESET}  {msg}")


def _info(msg: str) -> None:
    print(f"  {YELLOW}ℹ INFO{RESET}  {msg}")


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------
def login(api_url: str, username: str, password: str) -> dict | None:
    """Authenticate and return the token payload, or None on failure."""
    url = f"{api_url.rstrip('/')}/auth/authorize"
    print(f"\n{'='*60}")
    print(f"POST {url}")
    print(f"{'='*60}")

    resp = requests.post(url, json={"username": username, "password": password}, timeout=15)
    body = resp.json()

    if resp.status_code == 200:
        _ok(f"Login successful (HTTP {resp.status_code})")
        _info(f"AccessToken: {body['tokens']['AccessToken'][:40]}...")
        return body["tokens"]
    else:
        _fail(f"Login failed (HTTP {resp.status_code}): {body.get('message')}")
        return None


def refresh_tokens(api_url: str, refresh_token: str) -> dict | None:
    """Refresh tokens and return the new token payload."""
    url = f"{api_url.rstrip('/')}/auth/refresh"
    print(f"\n{'='*60}")
    print(f"POST {url}")
    print(f"{'='*60}")

    resp = requests.post(url, json={"refresh_token": refresh_token}, timeout=15)
    body = resp.json()

    if resp.status_code == 200:
        _ok(f"Token refresh successful (HTTP {resp.status_code})")
        return body["tokens"]
    else:
        _fail(f"Token refresh failed (HTTP {resp.status_code}): {body.get('message')}")
        return None


def test_list_events(api_url: str, access_token: str) -> None:
    """GET /events with a valid token."""
    url = f"{api_url.rstrip('/')}/events"
    print(f"\n{'='*60}")
    print(f"GET {url}")
    print(f"{'='*60}")

    resp = requests.get(url, headers=_auth_header(access_token), timeout=15)
    body = resp.json()

    if resp.status_code == 200:
        _ok(f"List events (HTTP {resp.status_code}) – {body.get('count', 0)} event(s)")
    else:
        _fail(f"List events failed (HTTP {resp.status_code}): {body}")


def test_create_event(api_url: str, access_token: str) -> str | None:
    """POST /events – create a test event; return eventId on success."""
    url = f"{api_url.rstrip('/')}/events"
    print(f"\n{'='*60}")
    print(f"POST {url}")
    print(f"{'='*60}")

    payload = {
        "title": "Test Deployment v2.1",
        "description": "Automated test event created by test_api.py",
        "visibility": "public",
    }
    resp = requests.post(url, headers=_auth_header(access_token), json=payload, timeout=15)
    body = resp.json()

    if resp.status_code == 201:
        event_id = body.get("event", {}).get("eventId", "")
        _ok(f"Event created (HTTP {resp.status_code}) – eventId={event_id}")
        return event_id
    else:
        _fail(f"Create event failed (HTTP {resp.status_code}): {body}")
        return None


def test_get_event(api_url: str, access_token: str, event_id: str) -> None:
    """GET /events/{eventId}."""
    url = f"{api_url.rstrip('/')}/events/{event_id}"
    print(f"\n{'='*60}")
    print(f"GET {url}")
    print(f"{'='*60}")

    resp = requests.get(url, headers=_auth_header(access_token), timeout=15)
    body = resp.json()

    if resp.status_code == 200:
        _ok(f"Get event (HTTP {resp.status_code}) – title={body.get('event', {}).get('title')}")
    else:
        _fail(f"Get event failed (HTTP {resp.status_code}): {body}")


def test_delete_event(api_url: str, access_token: str, event_id: str) -> None:
    """DELETE /events/{eventId}."""
    url = f"{api_url.rstrip('/')}/events/{event_id}"
    print(f"\n{'='*60}")
    print(f"DELETE {url}")
    print(f"{'='*60}")

    resp = requests.delete(url, headers=_auth_header(access_token), timeout=15)
    body = resp.json()

    if resp.status_code == 200:
        _ok(f"Event deleted (HTTP {resp.status_code})")
    elif resp.status_code == 403:
        _info(f"Delete denied (HTTP 403) – expected if user is not admin: {body.get('message')}")
    else:
        _fail(f"Delete event failed (HTTP {resp.status_code}): {body}")


def test_unauthorized_access(api_url: str) -> None:
    """Call a protected endpoint without a token – expect 401."""
    url = f"{api_url.rstrip('/')}/events"
    print(f"\n{'='*60}")
    print(f"GET {url}  (no Authorization header)")
    print(f"{'='*60}")

    resp = requests.get(url, timeout=15)

    if resp.status_code == 401:
        _ok(f"Correctly rejected (HTTP 401)")
    else:
        _fail(f"Expected 401 but got HTTP {resp.status_code}")


def test_invalid_token(api_url: str) -> None:
    """Call a protected endpoint with a garbage token – expect 401."""
    url = f"{api_url.rstrip('/')}/events"
    print(f"\n{'='*60}")
    print(f"GET {url}  (invalid token)")
    print(f"{'='*60}")

    resp = requests.get(url, headers={"Authorization": "Bearer invalid.token.here"}, timeout=15)

    if resp.status_code in (401, 403):
        _ok(f"Correctly rejected (HTTP {resp.status_code})")
    else:
        _fail(f"Expected 401/403 but got HTTP {resp.status_code}")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-end API tests")
    parser.add_argument("--api-url", required=True, help="Base API Gateway URL")
    parser.add_argument("--username", required=True, help="Cognito username")
    parser.add_argument("--password", required=True, help="Cognito password")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  Cognito Auth System – End-to-End Tests")
    print("=" * 60)

    # 1. Login
    tokens = login(args.api_url, args.username, args.password)
    if not tokens:
        print("\nAborting – login failed.")
        sys.exit(1)

    access_token: str = tokens["AccessToken"]

    # 2. Refresh
    if tokens.get("RefreshToken"):
        new_tokens = refresh_tokens(args.api_url, tokens["RefreshToken"])
        if new_tokens and new_tokens.get("AccessToken"):
            access_token = new_tokens["AccessToken"]
            _info("Using refreshed AccessToken for remaining tests")

    # 3. List events
    test_list_events(args.api_url, access_token)

    # 4. Create event
    event_id = test_create_event(args.api_url, access_token)

    # 5. Get single event
    if event_id:
        test_get_event(args.api_url, access_token, event_id)

    # 6. Delete event
    if event_id:
        test_delete_event(args.api_url, access_token, event_id)

    # 7. Unauthorized access (no token)
    test_unauthorized_access(args.api_url)

    # 8. Invalid token
    test_invalid_token(args.api_url)

    print(f"\n{'='*60}")
    print("  Tests complete")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
