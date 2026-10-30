#!/usr/bin/env python3
"""Auditoria pontual: nunca registra URLs, tokens, senhas ou nomes de hosts."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from ipaddress import ip_address
import json
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPO_BASE = "https://raw.githubusercontent.com/sempaio/Iptv-Brasil-2025/master/"
SOURCES = [f"Lista BR {i:02d}.m3u8" for i in range(1, 9)]
EXTERNAL = {
    "CanaisBR04": "https://raw.githubusercontent.com/Ramys/Iptv-Brasil-2026/master/CanaisBR04.m3u8",
    "CanaisBR05": "https://raw.githubusercontent.com/Ramys/Iptv-Brasil-2026/master/CanaisBR05.m3u8",
    "Pluto_Brasil_publico": "https://panel.taila5c5c2.ts.net/iptv/pluto/plutotv_br.m3u",
}
HEADERS = {"User-Agent": "STARLINK-IPTV-source-health-audit/1.0", "Range": "bytes=0-2047"}
TIMEOUT = 9

@lru_cache(maxsize=128)
def public_host(host):
    if not host or host.lower() in {"localhost", "localhost.localdomain"}:
        return False
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        return bool(addresses) and all(ip_address(ip).is_global for ip in addresses)
    except (OSError, ValueError):
        return False

def allowed(url):
    parsed = urlsplit(url)
    return parsed.scheme in ("http", "https") and public_host(parsed.hostname or "")

class PublicRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if not allowed(newurl):
            return None
        return super().redirect_request(request, fp, code, msg, headers, newurl)

OPENER = build_opener(PublicRedirects())

def read_url(url, limit=2048, use_range=True):
    if not allowed(url):
        return "unsafe_or_dns", b"", "", ""
    try:
        with OPENER.open(Request(url, headers=HEADERS if use_range else {"User-Agent": HEADERS["User-Agent"]}), timeout=TIMEOUT) as response:
            if not allowed(response.geturl()):
                return "unsafe_redirect", b"", "", ""
            return str(response.status), response.read(limit), response.headers.get("Content-Type", "").lower(), response.geturl()
    except HTTPError as error:
        return str(error.code), b"", "", ""
    except (URLError, OSError, ValueError, TimeoutError):
        return "network_error", b"", "", ""

def parse_streams(body):
    lines = body.decode("utf-8-sig", "replace").splitlines()
    if not lines or lines[0].strip() != "#EXTM3U":
        return [], False
    out = []
    for index, line in enumerate(lines[:-1]):
        if line.startswith("#EXTINF:"):
            url = lines[index+1].strip()
            if url.startswith(("http://", "https://")):
                out.append(url)
    return out, True

def media_state(data, content_type):
    prefix = data[:32].lstrip().lower()
    if not data:
        return "empty"
    if prefix.startswith((b"<html", b"<!doctype html", b"<?xml", b'{"')):
        return "html_or_json"
    if data.startswith(b"#EXTM3U"):
        return "hls_manifest"
    if data[0] == 0x47 or b"ftyp" in data[:16] or data.startswith(b"\x1a\x45\xdf\xa3"):
        return "media_bytes"
    if content_type.startswith(("video/", "audio/")):
        return "media_bytes"
    return "unrecognized_200"

def probe(entry):
    code, data, ct, final_url = read_url(entry, limit=16384)
    if code not in ("200", "206"):
        return "HTTP_" + code
    state = media_state(data, ct)
    if state == "hls_manifest":
        # A manifestacao por si so nao comprova a entrega de segmentos.
        try:
            lines = data.decode("utf-8-sig", "replace").splitlines()
            links = [v.strip() for v in lines if v.strip() and not v.startswith("#")]
            if not links:
                return "HLS_EMPTY"
            segment_url = urljoin(final_url, links[0])
            subcode, subdata, subct, _ = read_url(segment_url, limit=2048)
            if subcode in ("200", "206"):
                substate = media_state(subdata, subct)
                return "HLS_SEGMENT_OK" if substate == "media_bytes" else "HLS_CHILD_" + substate
            return "HLS_SEGMENT_HTTP_" + subcode
        except (ValueError, UnicodeError):
            return "HLS_INVALID"
    return state.upper()

def samples(entries, n=6):
    if len(entries) <= n:
        return entries
    indexes = [(len(entries)-1)*i//(n-1) for i in range(n)]
    return [entries[i] for i in sorted(set(indexes))]

def audit():
    report = []
    for name in SOURCES:
        url = REPO_BASE + quote(name)
        code, data, _, _ = read_url(url, limit=300000, use_range=False)
        streams, syntax = parse_streams(data)
        row = {"source": name, "playlist_status": code,
               "m3u_syntax": syntax, "entries": len(streams), "unique_urls": len(set(streams)),
               "sample": samples(streams) if syntax else []}
        report.append(row)
    for name, url in EXTERNAL.items():
        code, data, _, _ = read_url(url, limit=4096)
        _, syntax = parse_streams(data)
        report.append({"source": name, "playlist_status": code,
                       "m3u_syntax": syntax, "entries": None, "unique_urls": None, "sample": []})
    tasks = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        for index, item in enumerate(report):
            for url in item.pop("sample"):
                tasks.append((index, executor.submit(probe, url)))
        counters = [Counter() for _ in report]
        for index, task in tasks:
            try:
                counters[index][task.result()] += 1
            except Exception:
                counters[index]["probe_exception"] += 1
    for index, item in enumerate(report):
        item["samples_checked"] = sum(counters[index].values())
        item["sample_results"] = dict(sorted(counters[index].items()))
        print("SOURCE_AUDIT " + json.dumps(item, ensure_ascii=False))
    print("AUDIT_SCOPE: byte-range checks only; not full stream playback or media decoding.")
    print("AUDIT_PRIVACY: never print original media URLs or credentials.")

if __name__ == "__main__":
    audit()
