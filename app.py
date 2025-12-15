# app.py
# ------------------------------------------------------------
# NXP Parametric JSON Client (Streamlit)
# - Tries to fetch: https://www.nxp.com/webapp/parametric/json.sp?basicType=...
# - Detects CDN/WAF “Page not available” HTML (fake 404) and falls back to:
#     1) Upload JSON (recommended for Streamlit Cloud)
#     2) Run a local helper script to fetch JSON, then upload it
# - Also supports “Paste cURL” mode
#
# Requirements (requirements.txt):
#   streamlit
#   requests
#   pandas
# ------------------------------------------------------------

import json
import shlex
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import pandas as pd
import requests
import streamlit as st


BASE_URL = "https://www.nxp.com/webapp/parametric/json.sp"

BLOCK_PATTERNS = [
    "Sorry! This page is not available",
    "Contact your administrator with the error code",
    "<title>Page not available</title>",
    "cache.nxp.com/oos/logo.gif",
]


# ----------------------------
# Data structures
# ----------------------------
@dataclass
class FetchResult:
    ok: bool
    status_code: int
    url: str
    content_type: str
    headers: Dict[str, str]
    text_preview: str
    json_data: Optional[Any]
    blocked: bool
    error: Optional[str]


# ----------------------------
# Helpers
# ----------------------------
def parse_kv_lines(text: str) -> Dict[str, str]:
    """Parse key=value lines (or key: value)."""
    params: Dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
        elif ":" in line:
            k, v = line.split(":", 1)
        else:
            raise ValueError(f"Bad param line (expected key=value): {line}")
        params[k.strip()] = v.strip()
    return params


def looks_blocked(status_code: int, content_type: str, body: str) -> bool:
    if status_code in (403, 429):
        return True
    # NXP often returns a fake 404 with an HTML “Page not available” block page
    if "text/html" in (content_type or "").lower():
        snippet = (body or "")[:4000]
        for p in BLOCK_PATTERNS:
            if p.lower() in snippet.lower():
                return True
    return False


def safe_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")


def find_records(data: Any) -> list:
    """Best-effort: locate list-of-dicts inside unknown JSON shapes."""
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("records", "rows", "items", "products", "data", "result", "results"):
        v = data.get(key)
        if isinstance(v, list) and v and isinstance(v[0], dict):
            return v
    for v in data.values():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            return v
    return []


def curl_to_request(curl_cmd: str) -> Tuple[str, str, Dict[str, str], Optional[str]]:
    """
    Minimal curl(bash) -> (method, url, headers, data)
    Paste Chrome DevTools: Network -> request -> Copy -> Copy as cURL.
    """
    args = shlex.split(curl_cmd.strip())
    if not args or args[0] != "curl":
        raise ValueError("Paste a command that starts with: curl ...")

    method = "GET"
    url = None
    headers: Dict[str, str] = {}
    data = None

    i = 1
    while i < len(args):
        a = args[i]
        if a.startswith("http"):
            url = a
            i += 1
        elif a in ("-X", "--request"):
            method = args[i + 1].upper()
            i += 2
        elif a in ("-H", "--header"):
            k, v = args[i + 1].split(":", 1)
            headers[k.strip()] = v.lstrip()
            i += 2
        elif a in ("--data", "--data-raw", "--data-binary", "-d"):
            data = args[i + 1]
            if method == "GET":
                method = "POST"
            i += 2
        else:
            i += 1

    if not url:
        raise ValueError("Could not find a URL in the curl command.")
    return method, url, headers, data


def fetch_direct(
    basic_type: str,
    extra_params: Dict[str, str],
    *,
    user_agent: str,
    accept_language: str,
    cookie: str,
    proxy_url: str,
    timeout: int,
    tries: int,
    warmup: bool,
    backoff: bool,
) -> FetchResult:
    s = requests.Session()

    part_page = f"https://www.nxp.com/part/{basic_type}"
    headers = {
        "Accept": "application/json,text/plain,*/*",
        "User-Agent": user_agent or "Mozilla/5.0",
        "Accept-Language": accept_language or "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Referer": part_page,
    }
    if cookie.strip():
        headers["Cookie"] = cookie.strip()

    proxies = None
    if proxy_url.strip():
        proxies = {"http": proxy_url.strip(), "https": proxy_url.strip()}

    params = {"basicType": basic_type, **(extra_params or {})}

    # Warm-up can help when not blocked; won’t fix IP-based blocks.
    if warmup:
        try:
            s.get("https://www.nxp.com", headers=headers, timeout=timeout, proxies=proxies)
            s.get(part_page, headers=headers, timeout=timeout, proxies=proxies)
        except Exception:
            pass

    last_r: Optional[requests.Response] = None
    last_err: Optional[str] = None

    for i in range(int(tries)):
        try:
            r = s.get(
                BASE_URL,
                params=params,
                headers=headers,
                timeout=timeout,
                proxies=proxies,
            )
            last_r = r
            last_err = None
            if r.status_code == 200:
                break
        except Exception as e:
            last_err = str(e)
            last_r = None

        if backoff:
            time.sleep(1.0 + i * 1.5)

    if last_r is None:
        return FetchResult(
            ok=False,
            status_code=0,
            url=f"{BASE_URL}?{urlencode(params)}",
            content_type="",
            headers={},
            text_preview="",
            json_data=None,
            blocked=False,
            error=last_err or "Request failed",
        )

    ct = last_r.headers.get("content-type", "")
    body = last_r.text or ""
    blocked = looks_blocked(last_r.status_code, ct, body)

    # Try parse JSON
    j = None
    ok = False
    if last_r.status_code == 200 and not blocked:
        try:
            j = last_r.json()
            ok = True
        except Exception:
            ok = False

    return FetchResult(
        ok=ok,
        status_code=last_r.status_code,
        url=last_r.url,
        content_type=ct,
        headers=dict(last_r.headers),
        text_preview=body[:3000],
        json_data=j,
        blocked=blocked,
        error=None if ok else None,
    )


def fetch_from_curl(
    curl_cmd: str,
    *,
    timeout: int,
    user_agent: str,
    accept_language: str,
    cookie_override: str,
    proxy_url: str,
) -> FetchResult:
    try:
        method, url, headers, data = curl_to_request(curl_cmd)
    except Exception as e:
        return FetchResult(
            ok=False,
            status_code=0,
            url="",
            content_type="",
            headers={},
            text_preview="",
            json_data=None,
            blocked=False,
            error=str(e),
        )

    # Optional overrides from sidebar
    if user_agent.strip():
        headers["User-Agent"] = user_agent.strip()
    if accept_language.strip():
        headers["Accept-Language"] = accept_language.strip()
    if cookie_override.strip():
        headers["Cookie"] = cookie_override.strip()

    proxies = None
    if proxy_url.strip():
        proxies = {"http": proxy_url.strip(), "https": proxy_url.strip()}

    try:
        r = requests.request(method, url, headers=headers, data=data, timeout=timeout, proxies=proxies)
    except Exception as e:
        return FetchResult(
            ok=False,
            status_code=0,
            url=url,
            content_type="",
            headers={},
            text_preview="",
            json_data=None,
            blocked=False,
            error=str(e),
        )

    ct = r.headers.get("content-type", "")
    body = r.text or ""
    blocked = looks_blocked(r.status_code, ct, body)

    j = None
    ok = False
    if r.status_code == 200 and not blocked:
        try:
            j = r.json()
            ok = True
        except Exception:
            ok = False

    return FetchResult(
        ok=ok,
        status_code=r.status_code,
        url=r.url,
        content_type=ct,
        headers=dict(r.headers),
        text_preview=body[:3000],
        json_data=j,
        blocked=blocked,
        error=None if ok else None,
    )


def render_result(res: FetchResult, default_name: str = "nxp.json"):
    st.subheader("Response")
    if res.error:
        st.error(res.error)
        return

    st.write(f"**HTTP {res.status_code}** | Content-Type: `{res.content_type}`")
    st.code(res.url, language="text")

    with st.expander("Response headers"):
        # show important headers first
        important = ["content-type", "set-cookie", "server", "date", "cache-control", "pragma"]
        ordered = {}
        for k in important:
            for hk, hv in res.headers.items():
                if hk.lower() == k:
                    ordered[hk] = hv
        for hk, hv in res.headers.items():
            if hk not in ordered:
                ordered[hk] = hv
        st.json(ordered)

    if res.blocked:
        st.error(
            "Blocked by NXP security/CDN (fake 404 HTML). "
            "This is usually IP/network-based (common on Streamlit Cloud / Colab)."
        )
        st.info(
            "✅ Best fix: run this app locally OR use the Local Fetch Helper below to fetch JSON on your own machine, "
            "then upload the JSON here."
        )
        st.code(res.text_preview, language="html")
        return

    if res.json_data is None:
        st.warning("Not JSON (or JSON parse failed). Showing HTML/text preview:")
        st.code(res.text_preview, language="html")
        return

    st.success("Parsed JSON successfully.")
    if isinstance(res.json_data, dict):
        st.write("Top-level keys:", list(res.json_data.keys())[:50])

    st.json(res.json_data)

    st.download_button(
        "Download JSON",
        data=safe_json_bytes(res.json_data),
        file_name=default_name,
        mime="application/json",
    )

    # Flatten best-effort
    records = find_records(res.json_data)
    if records:
        st.markdown("### Flattened table (best-effort)")
        df = pd.json_normalize(records, sep="__")
        st.dataframe(df, use_container_width=True)

        csv_bytes = df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
        st.download_button(
            "Download CSV",
            data=csv_bytes,
            file_name=default_name.replace(".json", ".csv"),
            mime="text/csv",
        )


def local_helper_code() -> str:
    return r'''#!/usr/bin/env python3
"""
Local NXP fetch helper (run on YOUR machine/network).
It often works when Streamlit Cloud/Colab is blocked.

Usage:
  python nxp_fetch.py MRFE6VP5600H out.json
Optional:
  HTTPS_PROXY=http://user:pass@host:port python nxp_fetch.py MRFE6VP5600H out.json
"""

import json
import os
import sys
import time
import requests

BASE_URL = "https://www.nxp.com/webapp/parametric/json.sp"

BLOCK_PATTERNS = [
    "Sorry! This page is not available",
    "Contact your administrator with the error code",
    "<title>Page not available</title>",
]

def looks_blocked(status, content_type, body):
    if status in (403, 429):
        return True
    if "text/html" in (content_type or "").lower():
        snippet = (body or "")[:4000].lower()
        return any(p.lower() in snippet for p in BLOCK_PATTERNS)
    return False

def main():
    if len(sys.argv) < 3:
        print("Usage: python nxp_fetch.py <basicType> <out.json>")
        sys.exit(2)

    basic = sys.argv[1].strip()
    outp  = sys.argv[2].strip()

    s = requests.Session()
    part_page = f"https://www.nxp.com/part/{basic}"

    headers = {
        "Accept": "application/json,text/plain,*/*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": part_page,
        "Connection": "keep-alive",
    }

    proxies = None
    px = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if px:
        proxies = {"http": px, "https": px}

    # warmup
    try:
        s.get("https://www.nxp.com", headers=headers, timeout=30, proxies=proxies)
        s.get(part_page, headers=headers, timeout=30, proxies=proxies)
    except Exception:
        pass

    last = None
    for i in range(3):
        r = s.get(BASE_URL, params={"basicType": basic}, headers=headers, timeout=30, proxies=proxies)
        last = r
        if r.status_code == 200:
            break
        time.sleep(1 + i * 1.5)

    if last is None:
        print("No response.")
        sys.exit(1)

    ct = last.headers.get("content-type","")
    if looks_blocked(last.status_code, ct, last.text):
        print("BLOCKED (HTML fake-404). Try from another network or set HTTPS_PROXY.")
        print("HTTP:", last.status_code, "CT:", ct)
        print(last.text[:400])
        sys.exit(3)

    if last.status_code != 200:
        print("HTTP:", last.status_code)
        print(last.text[:400])
        sys.exit(4)

    data = last.json()
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print("Saved:", outp)

if __name__ == "__main__":
    main()
'''


# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="NXP Parametric JSON Client", layout="wide")

st.title("NXP Parametric JSON Client")
st.caption("Fetch NXP parametric JSON, detect WAF blocks, and fall back to upload workflow.")

with st.sidebar:
    mode = st.radio(
        "Mode",
        ["Direct fetch", "Paste cURL", "Upload JSON (fallback)"],
        index=0,
    )

    st.markdown("### Headers / Network")
    ua = st.text_input(
        "User-Agent",
        value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari",
    )
    accept_lang = st.text_input("Accept-Language", value="en-US,en;q=0.9")
    cookie = st.text_area("Cookie header (optional)", placeholder="Paste cookie value (no 'Cookie:' prefix)")

    proxy_url = st.text_input(
        "Proxy URL (optional)",
        placeholder="http://user:pass@host:port",
        help="If your host IP is blocked, a proxy from an allowed network can help.",
    )

    timeout = st.number_input("Timeout (sec)", min_value=5, max_value=120, value=30, step=5)
    tries = st.number_input("Retries", min_value=1, max_value=10, value=3, step=1)

    warmup = st.checkbox("Warm up (hit nxp.com + part page first)", value=True)
    backoff = st.checkbox("Retry backoff", value=True)

    st.markdown("---")
    st.markdown("### Local Fetch Helper")
    st.download_button(
        "Download nxp_fetch.py",
        data=local_helper_code().encode("utf-8"),
        file_name="nxp_fetch.py",
        mime="text/x-python",
    )
    st.caption("Run locally to generate out.json, then upload in the app.")


if mode == "Direct fetch":
    c1, c2 = st.columns([1, 1], gap="large")

    with c1:
        basic_type = st.text_input("basicType", value="MRFE6VP5600H")
        extra_params_text = st.text_area(
            "Extra query params (one per line: key=value)",
            value="",
            height=140,
            placeholder="Example:\nrows=100\nq=imx",
        )

    with c2:
        st.markdown("### Request preview")
        try:
            extra_params = parse_kv_lines(extra_params_text)
        except Exception as e:
            extra_params = None
            st.error(str(e))

        if extra_params is not None and basic_type.strip():
            full_params = {"basicType": basic_type.strip(), **extra_params}
            st.code(f"{BASE_URL}?{urlencode(full_params)}", language="text")

    fetch_btn = st.button("Fetch", type="primary", disabled=not (basic_type.strip() and extra_params is not None))

    if fetch_btn:
        with st.spinner("Requesting..."):
            res = fetch_direct(
                basic_type.strip(),
                extra_params or {},
                user_agent=ua,
                accept_language=accept_lang,
                cookie=cookie,
                proxy_url=proxy_url,
                timeout=int(timeout),
                tries=int(tries),
                warmup=warmup,
                backoff=backoff,
            )
        render_result(res, default_name=f"nxp_{basic_type.strip()}.json")

        # If blocked, show upload immediately
        if res.blocked:
            st.markdown("## Upload JSON (fallback)")
            up = st.file_uploader("Upload the JSON you fetched locally", type=["json"])
            if up:
                data = json.load(up)
                st.success("Loaded uploaded JSON")
                st.json(data)
                st.download_button(
                    "Download (re-save) JSON",
                    data=safe_json_bytes(data),
                    file_name=f"nxp_{basic_type.strip()}_uploaded.json",
                    mime="application/json",
                )


elif mode == "Paste cURL":
    st.markdown(
        """
Paste a **real** Chrome DevTools “Copy as cURL” for the `json.sp?...` request.
If your hosting IP is blocked, this may still fail unless you use a proxy from an allowed network.
"""
    )
    curl_text = st.text_area("cURL command", height=220, placeholder="curl 'https://www.nxp.com/webapp/parametric/json.sp?basicType=...' -H '...' ...")
    run_btn = st.button("Run cURL", type="primary", disabled=not curl_text.strip())

    if run_btn:
        with st.spinner("Requesting..."):
            res = fetch_from_curl(
                curl_text,
                timeout=int(timeout),
                user_agent=ua,
                accept_language=accept_lang,
                cookie_override=cookie,
                proxy_url=proxy_url,
            )
        render_result(res, default_name="nxp_from_curl.json")

        if res.blocked:
            st.markdown("## Upload JSON (fallback)")
            up = st.file_uploader("Upload the JSON you fetched locally", type=["json"])
            if up:
                data = json.load(up)
                st.success("Loaded uploaded JSON")
                st.json(data)


else:  # Upload JSON
    st.markdown("Upload a JSON file (e.g., produced by `nxp_fetch.py`) to analyze and export.")
    up = st.file_uploader("Upload JSON", type=["json"])
    if up:
        data = json.load(up)
        st.success("Loaded JSON")
        if isinstance(data, dict):
            st.write("Top-level keys:", list(data.keys())[:50])
        st.json(data)

        st.download_button(
            "Download JSON",
            data=safe_json_bytes(data),
            file_name="nxp_uploaded.json",
            mime="application/json",
        )

        records = find_records(data)
        if records:
            st.markdown("### Flattened table (best-effort)")
            df = pd.json_normalize(records, sep="__")
            st.dataframe(df, use_container_width=True)
            csv_bytes = df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
            st.download_button(
                "Download CSV",
                data=csv_bytes,
                file_name="nxp_uploaded.csv",
                mime="text/csv",
            )
