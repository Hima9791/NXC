import json
import shlex
import time
from urllib.parse import urlencode

import pandas as pd
import requests
import streamlit as st


BASE_URL = "https://www.nxp.com/webapp/parametric/json.sp"


# ----------------------------
# Helpers
# ----------------------------
def parse_kv_lines(text: str) -> dict:
    """
    Parse key=value lines (one per line).
    Ignores blanks and lines starting with '#'.
    """
    params = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            # allow "key: value" too
            if ":" in line:
                k, v = line.split(":", 1)
            else:
                raise ValueError(f"Bad param line (expected key=value): {line}")
        else:
            k, v = line.split("=", 1)
        params[k.strip()] = v.strip()
    return params


def curl_to_request(curl_cmd: str):
    """
    Minimal curl(bash) -> (method, url, headers, data)
    Paste Chrome DevTools: Network -> request -> Copy -> Copy as cURL.
    """
    args = shlex.split(curl_cmd.strip())
    if not args or args[0] != "curl":
        raise ValueError("Paste a command that starts with: curl ...")

    method = "GET"
    url = None
    headers = {}
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


def find_records(data):
    """
    Best-effort: locate list-of-dicts inside unknown JSON shapes.
    """
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


def safe_json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")


# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="NXP Parametric JSON Client", layout="wide")

st.title("NXP Parametric JSON Client")
st.caption("Calls https://www.nxp.com/webapp/parametric/json.sp?basicType=... and shows JSON/CSV outputs.")

with st.sidebar:
    mode = st.radio(
        "Mode",
        ["Direct (basicType)", "Paste cURL (recommended if blocked)"],
        index=0,
    )

    st.markdown("### Headers (optional)")
    ua = st.text_input(
        "User-Agent",
        value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari",
    )
    accept_lang = st.text_input("Accept-Language", value="en-US,en;q=0.9")
    cookie = st.text_area("Cookie header (optional)", placeholder="Paste Cookie: ... value here")

    timeout = st.number_input("Timeout (sec)", min_value=5, max_value=120, value=30, step=5)
    tries = st.number_input("Retries", min_value=1, max_value=10, value=3, step=1)

    st.markdown("---")
    warmup = st.checkbox("Warm up session by loading part page first (Direct mode)", value=True)
    backoff = st.checkbox("Retry backoff (Direct mode)", value=True)


if mode == "Direct (basicType)":
    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        basic_type = st.text_input("basicType", value="MRFE6VP5600H")
        extra_params_text = st.text_area(
            "Extra query params (one per line: key=value)",
            value="",
            height=140,
            placeholder="Example:\nrows=100\nq=imx",
        )

    with col2:
        st.markdown("### Request preview")
        try:
            extra_params = parse_kv_lines(extra_params_text)
        except Exception as e:
            extra_params = None
            st.error(str(e))

        if extra_params is not None and basic_type.strip():
            full_params = {"basicType": basic_type.strip(), **extra_params}
            st.code(f"{BASE_URL}?{urlencode(full_params)}", language="text")

    fetch = st.button("Fetch", type="primary", disabled=not (basic_type.strip() and extra_params is not None))

    if fetch:
        headers = {
            "Accept": "application/json,text/plain,*/*",
            "User-Agent": ua.strip() or "Mozilla/5.0",
            "Accept-Language": accept_lang.strip() or "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        if cookie.strip():
            headers["Cookie"] = cookie.strip()

        part_page = f"https://www.nxp.com/part/{basic_type.strip()}"
        params = {"basicType": basic_type.strip(), **(extra_params or {})}

        s = requests.Session()

        with st.spinner("Requesting..."):
            if warmup:
                try:
                    s.get(part_page, headers={**headers, "Referer": part_page}, timeout=int(timeout))
                except Exception:
                    # warmup failures shouldn't block the main request
                    pass

            last_resp = None
            for i in range(int(tries)):
                try:
                    r = s.get(
                        BASE_URL,
                        params=params,
                        headers={**headers, "Referer": part_page},
                        timeout=int(timeout),
                    )
                    last_resp = r
                    if r.status_code == 200:
                        break
                except Exception as ex:
                    last_resp = ex

                if backoff:
                    time.sleep(1.0 + i * 1.5)

        if isinstance(last_resp, Exception):
            st.error(f"Request failed: {last_resp}")
        else:
            r = last_resp
            st.subheader("Response")
            st.write(f"**HTTP {r.status_code}**  |  Content-Type: `{r.headers.get('content-type','')}`")
            st.code(r.url, language="text")

            # Show some headers
            with st.expander("Response headers"):
                show_keys = ["content-type", "cache-control", "set-cookie", "server", "date"]
                st.json({k: v for k, v in r.headers.items() if k.lower() in show_keys})

            # Try JSON
            try:
                data = r.json()
                st.success("Parsed JSON successfully.")
                st.write("Top-level keys:", list(data.keys()) if isinstance(data, dict) else f"type={type(data)}")

                st.json(data)

                st.download_button(
                    "Download JSON",
                    data=safe_json_bytes(data),
                    file_name=f"nxp_{basic_type.strip()}.json",
                    mime="application/json",
                )

                records = find_records(data)
                if records:
                    df = pd.json_normalize(records, sep="__")
                    st.markdown("### Flattened table (best-effort)")
                    st.dataframe(df, use_container_width=True)

                    csv_bytes = df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
                    st.download_button(
                        "Download CSV",
                        data=csv_bytes,
                        file_name=f"nxp_{basic_type.strip()}.csv",
                        mime="text/csv",
                    )
            except Exception:
                st.warning("Response is not JSON (or JSON parsing failed). Showing first 3000 chars:")
                st.code(r.text[:3000], language="html")


else:
    st.markdown(
        """
**Paste a Chrome DevTools “Copy as cURL” command** for the `json.sp?basicType=...` request.
This often works even when direct requests return the “Page not available” HTML.
"""
    )
    curl_text = st.text_area("cURL command", height=220, placeholder="curl 'https://www.nxp.com/webapp/parametric/json.sp?basicType=...' -H '...' ...")

    run = st.button("Run cURL request", type="primary", disabled=not curl_text.strip())

    if run:
        try:
            method, url, headers, data = curl_to_request(curl_text)
        except Exception as e:
            st.error(str(e))
        else:
            # Optionally override UA/lang/cookie from sidebar if user wants:
            if ua.strip():
                headers["User-Agent"] = ua.strip()
            if accept_lang.strip():
                headers["Accept-Language"] = accept_lang.strip()
            if cookie.strip():
                headers["Cookie"] = cookie.strip()

            with st.spinner("Requesting..."):
                r = requests.request(method, url, headers=headers, data=data, timeout=int(timeout))

            st.subheader("Response")
            st.write(f"**HTTP {r.status_code}**  |  Content-Type: `{r.headers.get('content-type','')}`")
            st.code(r.url, language="text")

            with st.expander("Response headers"):
                st.json(dict(r.headers))

            try:
                j = r.json()
                st.success("Parsed JSON successfully.")
                st.json(j)

                st.download_button(
                    "Download JSON",
                    data=safe_json_bytes(j),
                    file_name="nxp_from_curl.json",
                    mime="application/json",
                )

                records = find_records(j)
                if records:
                    df = pd.json_normalize(records, sep="__")
                    st.markdown("### Flattened table (best-effort)")
                    st.dataframe(df, use_container_width=True)

                    csv_bytes = df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
                    st.download_button(
                        "Download CSV",
                        data=csv_bytes,
                        file_name="nxp_from_curl.csv",
                        mime="text/csv",
                    )
            except Exception:
                st.warning("Not JSON (or parse failed). Showing first 3000 chars:")
                st.code(r.text[:3000], language="html")
