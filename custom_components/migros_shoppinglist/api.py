"""Async Migros shopping-list API client.

An asyncio/aiohttp port of the login + basket parts of ``migros_list.py``
(itself a port of the migros-mcp server). It talks to:

* ``login.migros.ch`` — the credential form flow (email -> password -> TOTP),
* ``www.migros.ch`` — a silent-OAuth exchange that mints a JWT and the
  authenticated shopping-list REST API.

Cookies are tracked manually, per host (only the ``name=value`` pair), and
redirects are handled manually, mirroring the reference implementation. The
aiohttp session therefore uses a :class:`aiohttp.DummyCookieJar` so aiohttp
never stores or replays cookies of its own.

The mutable auth state (per-host cookies + cached JWT) lives in :attr:`MigrosClient.data`
so the caller can persist it (e.g. in Home Assistant's ``Store``) and restore it
across restarts to avoid logging in every time.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import random
import re
import ssl
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit

import aiohttp

LOGIN_BASE = "https://login.migros.ch"
WWW_BASE = "https://www.migros.ch"
# Per-host User-Agent. Akamai on www.migros.ch rejects Chrome but accepts this
# Firefox/Linux UA; the login origin (Cloudflare) accepts Chrome.
UA_LOGIN = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
)
UA_WWW = "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0"
REDIRECT_URI = "https://www.migros.ch/m-login-silent-login-redirect.html"

_REQUEST_TIMEOUT = 30  # seconds
_RETRYABLE_STATUSES = {502, 503, 504}
_MAX_ATTEMPTS = 3


# --- Errors ------------------------------------------------------------------


class MigrosError(RuntimeError):
    """Base error."""


class MigrosAuthError(MigrosError):
    """Login / OAuth failed (bad credentials or expired session)."""


class MigrosAPIError(MigrosError):
    """An authenticated API call returned non-2xx."""


# --- TOTP --------------------------------------------------------------------

_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def totp_code(
    secret: str, now: float | None = None, step: int = 30, digits: int = 6
) -> str:
    """RFC 6238 TOTP code from a base32-encoded shared secret."""
    if now is None:
        now = time.time()
    cleaned = "".join(secret.split()).rstrip("=").upper()
    bits = ""
    for c in cleaned:
        v = _BASE32_ALPHABET.find(c)
        if v < 0:
            raise ValueError(f"invalid base32 char in TOTP secret: {c}")
        bits += format(v, "05b")
    key_len = len(bits) // 8
    if key_len == 0:
        raise ValueError("TOTP secret too short")
    key = int(bits[: key_len * 8], 2).to_bytes(key_len, "big")
    counter = int(now) // step
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


# --- Cookies / session -------------------------------------------------------


def empty_session() -> dict[str, Any]:
    """A fresh, empty persisted-session structure."""
    return {"cookies": {}, "jwt": None, "jwtExp": 0}


def normalize_session(parsed: dict[str, Any] | None) -> dict[str, Any]:
    """Coerce a loaded session blob into the canonical shape."""
    parsed = parsed or {}
    return {
        "cookies": parsed.get("cookies") or {},
        "jwt": parsed.get("jwt"),
        "jwtExp": parsed.get("jwtExp") or 0,
    }


def ingest_set_cookie(session: dict, host: str, set_cookies) -> None:
    """Update the per-host cookie jar from Set-Cookie response headers.

    Only the ``name=value`` pair before the first semicolon is kept; attributes
    (Path, Domain, HttpOnly, ...) are intentionally discarded.
    """
    if not set_cookies:
        return
    if isinstance(set_cookies, str):
        set_cookies = [set_cookies]
    bag = session["cookies"].setdefault(host, {})
    for raw in set_cookies:
        pair = raw.split(";", 1)[0].strip()
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        name = name.strip()
        if name:
            bag[name] = value.strip()


def cookie_header(session: dict, host: str) -> str:
    """Build the Cookie: request header for a host ("" when no cookies)."""
    bag = session["cookies"].get(host)
    if not bag:
        return ""
    return "; ".join(f"{k}={v}" for k, v in bag.items())


# --- JWT helpers -------------------------------------------------------------


def strip_bearer(token: str) -> str:
    """Migros returns tokens with a literal 'Bearer ' prefix in the JSON body."""
    return re.sub(r"^bearer\s+", "", token, flags=re.IGNORECASE)


def decode_jwt_exp(jwt: str) -> int:
    """Return the ``exp`` claim (unix seconds) of a JWT without verifying it."""
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT")
    payload = json.loads(
        base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
    )
    if not isinstance(payload.get("exp"), (int, float)):
        raise ValueError("JWT has no exp claim")
    return int(payload["exp"])


# --- Login form parsing ------------------------------------------------------


class _CSRFParser(HTMLParser):
    """Captures the value of the first <input name="_csrf"> on the page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.value: str | None = None

    def handle_starttag(self, tag, attrs):
        if self.value is not None or tag != "input":
            return
        attrs_dict = dict(attrs)
        if attrs_dict.get("name") == "_csrf" and attrs_dict.get("value"):
            self.value = attrs_dict["value"]


class _FormActionParser(HTMLParser):
    """Captures the action attribute of the first <form> on the page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.action: str | None = None

    def handle_starttag(self, tag, attrs):
        if self.action is not None or tag != "form":
            return
        self.action = dict(attrs).get("action") or ""


class _ErrorParser(HTMLParser):
    """Captures the text of the first div whose class list includes
    'info-message-error' (the Migros login form's error banner)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._depth: int | None = None
        self._found = False
        self._text_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if self._depth is not None:
            if tag == "div":
                self._depth += 1
            return
        classes = (dict(attrs).get("class") or "").split()
        if not self._found and tag == "div" and "info-message-error" in classes:
            self._found = True
            self._depth = 0

    def handle_endtag(self, tag):
        if self._depth is None or tag != "div":
            return
        if self._depth == 0:
            self._depth = None
        else:
            self._depth -= 1

    def handle_data(self, data):
        if self._depth is not None:
            self._text_parts.append(data)

    @property
    def message(self) -> str | None:
        if not self._found:
            return None
        text = " ".join("".join(self._text_parts).split())
        return text or None


def find_csrf(html: str) -> str:
    parser = _CSRFParser()
    parser.feed(html)
    if not parser.value:
        raise ValueError("could not find CSRF token in form")
    return parser.value


def find_form_action(html: str, base_url: str) -> str:
    """Resolve the (possibly relative) action URL of the first <form>."""
    parser = _FormActionParser()
    parser.feed(html)
    return urljoin(base_url, parser.action) if parser.action else base_url


def find_error(html: str) -> str | None:
    """Errors render in a div with class 'info-message-error'."""
    parser = _ErrorParser()
    parser.feed(html)
    return parser.message


# --- Shopping-list item helpers ----------------------------------------------


def make_custom_item_id() -> str:
    """Client-generated id for a custom item: ``<ms timestamp>_<random>``."""
    return f"{int(time.time() * 1000)}_{random.randint(10**9, 10**10 - 1)}"


def custom_item_payload(name: str, quantity: int = 1) -> dict:
    """Payload for a custom (free-text) item.

    The app stores these as ``UNCATEGORISED_TERM`` items with a client-generated
    id. The www API clears ``name`` on write, so the text is also stored in
    ``note`` (which the app renders for titleless items).
    """
    return {
        "id": make_custom_item_id(),
        "type": "UNCATEGORISED_TERM",
        "name": name,
        "note": name,
        "quantity": quantity,
    }


def find_item(data: dict, item_id) -> dict | None:
    """Return the raw item dict for ``item_id`` in a basket response, or None."""
    for c in data.get("categories") or []:
        for i in c.get("items") or []:
            if str(i.get("id")) == str(item_id):
                return i
    return None


def iter_items(data: dict):
    """Yield (category_id, item) for every item in a basket response."""
    for c in data.get("categories") or []:
        for i in c.get("items") or []:
            yield c.get("id"), i


def item_display_name(item: dict) -> str:
    """Best human-readable label for a basket item.

    Custom items keep their text in ``note`` (``name`` comes back blank from the
    www API); products have no name on this endpoint, so fall back to the id.
    """
    return (
        (item.get("name") or "").strip()
        or (item.get("note") or "").strip()
        or f"#{item.get('id')}"
    )


# --- TLS ---------------------------------------------------------------------


def create_ssl_context() -> ssl.SSLContext:
    """TLS >= 1.3 context (matches the MCP server's minVersion: TLSv1.3).

    Blocking (loads the system trust store); create it off the event loop.
    """
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def create_session(ssl_context: ssl.SSLContext) -> aiohttp.ClientSession:
    """Build the aiohttp session used by :class:`MigrosClient`.

    Uses a DummyCookieJar (cookies are managed manually, per host) and a
    connector pinned to the TLS 1.3 context.
    """
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    return aiohttp.ClientSession(
        connector=connector,
        cookie_jar=aiohttp.DummyCookieJar(),
        timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
    )


def _ua_for(host: str) -> str:
    return UA_WWW if host == "www.migros.ch" else UA_LOGIN


class _Resp:
    """Captured response (status, headers, text) after manual cookie ingest."""

    __slots__ = ("status", "headers", "text")

    def __init__(self, status: int, headers, text: str) -> None:
        self.status = status
        self.headers = headers
        self.text = text

    def location(self, base_url: str) -> str | None:
        loc = self.headers.get("Location")
        return urljoin(base_url, loc) if loc else None

    def json(self) -> Any:
        return json.loads(self.text)


class MigrosClient:
    """Authenticated, async Migros shopping-list client."""

    def __init__(
        self,
        websession: aiohttp.ClientSession,
        *,
        session_data: dict[str, Any] | None = None,
        email: str | None = None,
        password: str | None = None,
        totp_secret: str | None = None,
    ) -> None:
        self._http = websession
        self.data = normalize_session(session_data)
        self._creds = (
            {"email": email, "password": password, "totpSecret": totp_secret}
            if email and password
            else None
        )
        self._lock = asyncio.Lock()

    # -- low-level HTTP -------------------------------------------------------

    async def _request(
        self,
        method: str,
        url: str,
        *,
        extra_headers: dict | None = None,
        form: dict | None = None,
        json_body=None,
        accept: str = "text/html",
    ) -> _Resp:
        """One request with manual redirect + per-host cookie handling."""
        host = urlsplit(url).netloc
        headers = {
            "User-Agent": _ua_for(host),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": accept,
            **(extra_headers or {}),
        }
        cookie = cookie_header(self.data, host)
        if cookie:
            headers["Cookie"] = cookie

        kwargs: dict[str, Any] = {"allow_redirects": False}
        if form is not None:
            headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"https://{host}",
                    "Referer": url,
                }
            )
            kwargs["data"] = urlencode(form)
        elif json_body is not None:
            headers["Content-Type"] = "application/json"
            kwargs["data"] = json.dumps(json_body)

        resp = await self._send(method, url, headers=headers, **kwargs)
        ingest_set_cookie(self.data, host, resp.headers.getall("Set-Cookie", []))
        text = await resp.text()
        return _Resp(resp.status, resp.headers.copy(), text)

    async def _send(self, method: str, url: str, **kwargs):
        """session.request with a short retry/backoff for transient failures."""
        last_exc: Exception | None = None
        for attempt in range(_MAX_ATTEMPTS):
            try:
                resp = await self._http.request(method, url, **kwargs)
            except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
                last_exc = e
            else:
                if resp.status not in _RETRYABLE_STATUSES:
                    return resp
                await resp.release()
                if attempt == _MAX_ATTEMPTS - 1:
                    return resp
            if attempt < _MAX_ATTEMPTS - 1:
                await asyncio.sleep(0.5 * (2**attempt))
        raise MigrosError(f"request to {url} failed: {last_exc}") from last_exc

    def _require_csrf(self, resp: _Resp, url: str) -> str:
        try:
            return find_csrf(resp.text)
        except ValueError as e:
            snippet = " ".join(resp.text[:300].split())
            raise MigrosAuthError(
                f"{e} (GET/POST {url} -> status {resp.status}; Migros may have "
                f"changed the login page markup; body starts: {snippet!r})"
            ) from e

    # -- login / oauth --------------------------------------------------------

    async def full_login(self) -> str:
        """Run the full credentialed login then mint a JWT via silent OAuth."""
        creds = self._creds
        if not creds:
            raise MigrosAuthError("no credentials configured for login")

        start = f"{LOGIN_BASE}/login"
        r = await self._request("GET", start)
        if 300 <= r.status < 400:
            nxt = r.location(start)
            if nxt:
                r = await self._request("GET", nxt)
        csrf = self._require_csrf(r, start)

        r = await self._request(
            "POST",
            f"{LOGIN_BASE}/login/email",
            form={"_csrf": csrf, "authenticationPayload": "", "email": creds["email"]},
        )
        next_url = r.location(f"{LOGIN_BASE}/login/email")
        if not next_url:
            raise MigrosAuthError(
                f"email step failed: {find_error(r.text) or f'status {r.status}'}"
            )

        if "/login/passkey" in next_url:
            next_url = f"{LOGIN_BASE}/login/password"

        r = await self._request("GET", next_url)
        csrf = self._require_csrf(r, next_url)
        password_url = find_form_action(r.text, next_url)

        r = await self._request(
            "POST",
            password_url,
            form={"_csrf": csrf, "password": creds["password"]},
        )
        next_url = r.location(password_url)
        if not next_url:
            raise MigrosAuthError(
                f"password step failed: {find_error(r.text) or f'status {r.status}'}"
            )

        if "/login/passkey" in next_url or "/login/sms" in next_url:
            next_url = f"{LOGIN_BASE}/login/authenticator"

        if re.search(r"/login/(authenticator|second|totp|otp)", next_url):
            if not creds.get("totpSecret"):
                raise MigrosAuthError(
                    "server requires 2FA but no TOTP secret was provided"
                )
            r = await self._request("GET", next_url)
            csrf = self._require_csrf(r, next_url)
            otp_url = find_form_action(r.text, next_url)
            r = await self._request(
                "POST",
                otp_url,
                form={"_csrf": csrf, "code": totp_code(creds["totpSecret"])},
            )
            next_url = r.location(otp_url)
            if not next_url:
                raise MigrosAuthError(
                    f"OTP step failed: {find_error(r.text) or f'status {r.status}'}"
                )

        hops = 0
        while next_url and hops < 10:
            r = await self._request(
                "GET", next_url, accept="text/html,application/json"
            )
            nxt = r.location(next_url)
            if not nxt:
                break
            next_url = nxt
            hops += 1

        return await self.silent_oauth()

    async def silent_oauth(self) -> str:
        """Mint a fresh JWT from current SSO cookies. Raises if they expired."""
        authorize_url = (
            f"{WWW_BASE}/authentication/public/v1/api/oauth/authorize"
            f"?redirectUri={quote(REDIRECT_URI, safe='')}"
            "&withLoginPrompt=false&claimType=LOGIN&authorizationNotRequired=true"
        )
        r = await self._request(
            "GET", authorize_url, accept="application/json, text/plain, */*"
        )
        if r.status != 200:
            raise MigrosAuthError(f"oauth/authorize -> {r.status}")
        data = r.json()
        sso_url = data.get("url") if isinstance(data, dict) else None
        if not sso_url:
            raise MigrosAuthError("oauth/authorize did not return a sso url")

        r = await self._request("GET", sso_url)
        location = r.headers.get("Location")
        if not location:
            raise MigrosAuthError(
                "silent SSO did not redirect — login.migros.ch session likely expired"
            )
        q = parse_qs(urlsplit(location).query)
        code = (q.get("code") or [None])[0]
        state = (q.get("state") or [None])[0]
        if not code or not state:
            raise MigrosAuthError("silent SSO redirected without code/state")

        success_url = (
            f"{WWW_BASE}/authentication/public/v1/api/oauth/login-success"
            f"?code={quote(code, safe='')}&state={quote(state, safe='')}"
            f"&redirectUri={quote(REDIRECT_URI, safe='')}&authorizationNotRequired=true"
        )
        r = await self._request("GET", success_url, accept="application/json")
        if r.status != 200:
            raise MigrosAuthError(f"oauth/login-success -> {r.status}")
        token_body = r.json()
        token = (
            token_body.get("accessToken")
            or token_body.get("access_token")
            or token_body.get("token")
        )
        if not token:
            raise MigrosAuthError("oauth/login-success did not return a token")
        token = strip_bearer(token)
        self.data["jwt"] = token
        self.data["jwtExp"] = decode_jwt_exp(token)
        return token

    async def _get_jwt(self, buffer_seconds: int = 60) -> str:
        """Return a usable JWT: cached -> silent OAuth -> full login."""
        now = int(time.time())
        if (
            self.data.get("jwt")
            and self.data.get("jwtExp")
            and self.data["jwtExp"] - now > buffer_seconds
        ):
            return self.data["jwt"]
        try:
            return await self.silent_oauth()
        except Exception:
            if not self._creds:
                raise MigrosAuthError(
                    "cached session expired and no credentials are configured"
                )
            return await self.full_login()

    # -- authenticated API ----------------------------------------------------

    async def _www_request(self, method: str, path: str, body, jwt: str, language: str):
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Authorization": f"Bearer {jwt}",
            "migros-language": language,
            "Accept-Language": language,
            "peer-id": "website-js-1143.0.0",
            "Origin": WWW_BASE,
            "Referer": f"{WWW_BASE}/en",
        }
        return await self._request(
            method, f"{WWW_BASE}{path}", extra_headers=headers, json_body=body
        )

    async def api(
        self, method: str, path: str, body=None, language: str = "en"
    ) -> Any:
        """Authenticated request against www.migros.ch with silent-refresh retry."""
        async with self._lock:
            jwt = await self._get_jwt()
            r = await self._www_request(method, path, body, jwt, language)

            if r.status == 401:
                try:
                    jwt = await self.silent_oauth()
                    r = await self._www_request(method, path, body, jwt, language)
                except Exception:
                    pass

        if not 200 <= r.status < 300:
            raise MigrosAPIError(f"{method} {path} -> {r.status}: {r.text[:200]}")
        return r.json()

    # -- shopping lists -------------------------------------------------------

    async def async_login(self) -> str:
        """Force a full credentialed login (used by config flow validation)."""
        async with self._lock:
            return await self.full_login()

    async def get_lists(self) -> list[dict]:
        return await self.api("GET", "/shopping-list/public/v1/lists/overview") or []

    async def get_basket(self, shopping_list_id: int) -> dict:
        return await self.api(
            "GET",
            f"/shopping-list/public/v2/list/details?shoppingListId={shopping_list_id}",
        )

    async def set_item_quantity(
        self, shopping_list_id: int, item: dict, quantity: int
    ) -> dict:
        """Upsert an item's quantity (quantity replaces, 0 removes)."""
        return await self.api(
            "PUT",
            "/shopping-list/public/v3/items",
            {
                "shoppingListId": shopping_list_id,
                "items": [{**item, "quantity": quantity}],
            },
        )

    async def add_custom_item(
        self, shopping_list_id: int, name: str, quantity: int = 1
    ) -> dict:
        return await self.set_item_quantity(
            shopping_list_id, custom_item_payload(name, quantity), quantity
        )

    async def remove_item(self, shopping_list_id: int, item_id) -> dict:
        """Remove an item by id (product or custom); resolves its type first."""
        basket = await self.get_basket(shopping_list_id)
        item = find_item(basket, item_id)
        if item is None:
            raise MigrosError(f"item {item_id!r} not found in list {shopping_list_id}")
        return await self.set_item_quantity(
            shopping_list_id, {"id": item_id, "type": item.get("type")}, 0
        )

    async def rename_item(
        self, shopping_list_id: int, item_id, name: str
    ) -> dict:
        """Rename an item, preserving its type and quantity. For custom items the
        text lives in ``note`` (which the app renders)."""
        basket = await self.get_basket(shopping_list_id)
        item = find_item(basket, item_id)
        if item is None:
            raise MigrosError(f"item {item_id!r} not found in list {shopping_list_id}")
        quantity = item.get("quantity") or 1
        payload = {
            "id": item_id,
            "type": item.get("type"),
            "name": name,
            "note": name,
        }
        return await self.set_item_quantity(shopping_list_id, payload, quantity)
