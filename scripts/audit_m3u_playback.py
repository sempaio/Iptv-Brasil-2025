#!/usr/bin/env python3
"""Auditoria M3U somente-leitura: 403, HTML, HLS e segmentos reais.

Sem publicar listas, ocultar canais ou expor URLs, tokens, senhas e hosts.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
import json
import os
import re
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPO_BASE = "https://raw.githubusercontent.com/sempaio/Iptv-Brasil-2025/master/"
SOURCES = [f"Lista BR {i:02d}.m3u8" for i in range(1, 9)]
EXTERNAL = {
    "CanaisBR04_2026": "https://raw.githubusercontent.com/Ramys/Iptv-Brasil-2026/master/CanaisBR04.m3u8",
    "CanaisBR05_2026": "https://raw.githubusercontent.com/Ramys/Iptv-Brasil-2026/master/CanaisBR05.m3u8",
    "Pluto_Brasil_publico": "https://panel.taila5c5c2.ts.net/iptv/pluto/plutotv_br.m3u",
}
HEADERS = {"User-Agent": "STARLINK-IPTV-source-health-audit/2.0", "Range": "bytes=0-16383"}
TIMEOUT = 10
MAX_PLAYLIST_BYTES = 105 * 1024 * 1024
MAX_LEGACY_BYTES = 4 * 1024 * 1024
MAX_MEDIA_BYTES = 16 * 1024
MAX_HLS_DEPTH = 4
REPORT_PATH = Path("source-audit-report.json")
GROUPS = ("globo", "sportv", "telecine")
GROUP_RE = re.compile(r'group-title="([^"]*)"', re.I)


@lru_cache(maxsize=256)
def public_host(host):
    if not host or host.lower() in {"localhost", "localhost.localdomain"}:
        return False
    try:
        addresses = {x[4][0] for x in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        return bool(addresses) and all(ip_address(ip).is_global for ip in addresses)
    except (OSError, ValueError):
        return False


def allowed(url):
    try:
        parsed = urlsplit(url)
        return parsed.scheme in ("http", "https") and not parsed.username and not parsed.password and public_host(parsed.hostname or "")
    except ValueError:
        return False


class PublicRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if not allowed(newurl):
            return None
        return super().redirect_request(request, fp, code, msg, headers, newurl)


OPENER = build_opener(PublicRedirects())


def read_url(url, limit=MAX_MEDIA_BYTES, use_range=True):
    """Return status, bytes, MIME, and internal URL; never log raw URLs."""
    if not allowed(url):
        return "unsafe_or_dns", b"", "", ""
    headers = HEADERS if use_range else {"User-Agent": HEADERS["User-Agent"]}
    try:
        with OPENER.open(Request(url, headers=headers), timeout=TIMEOUT) as response:
            if not allowed(response.geturl()):
                return "unsafe_redirect", b"", "", ""
            body = response.read(limit if use_range else limit + 1)
            if not use_range and len(body) > limit:
                return "size_limit", b"", "", ""
            return str(response.status), body, response.headers.get("Content-Type", "").lower(), response.geturl()
    except HTTPError as error:
        return str(error.code), b"", "", ""
    except (URLError, OSError, ValueError, TimeoutError, OverflowError):
        return "network_error", b"", "", ""


def iter_entries(body):
    """EXTINF may be followed by EXTVLCOPT or comments before the media URL."""
    lines = body.decode("utf-8-sig", "replace").splitlines()
    if not lines or not lines[0].strip().upper().startswith("#EXTM3U"):
        return
    title = None
    category = ""
    for raw in lines[1:]:
        line = raw.strip()
        if line.upper().startswith("#EXTINF:"):
            title = line.partition(",")[2].strip()
            match = GROUP_RE.search(line)
            category = match.group(1) if match else ""
        elif title is not None and line.startswith(("https://", "http://")):
            yield title, line, category
            title = None
        elif title is not None and line and not line.startswith("#"):
            title = None


def parse_streams(body):
    if not body.lstrip(b"\xef\xbb\xbf").startswith(b"#EXTM3U"):
        return [], False
    return [url for _name, url, _group in iter_entries(body)], True


def media_state(data, content_type):
    prefix = data[:64].lstrip().lower()
    if not data:
        return "empty"
    if prefix.startswith((b"<html", b"<!doctype html", b"<?xml", b"{", b"[")) or b"<body" in data[:1024].lower():
        return "html_or_json"
    if data.lstrip().startswith(b"#EXTM3U"):
        return "hls_manifest"
    if len(data) >= 188 * 3 and any(
        data[i] == data[i + 188] == data[i + 376] == 0x47
        for i in range(min(188, len(data) - 376))
    ):
        return "media_bytes"
    if data.startswith((b"ID3", b"OggS", b"FLV", b"\x1a\x45\xdf\xa3")):
        return "media_bytes"
    if any(marker in data[:64] for marker in (b"ftyp", b"styp", b"moof")):
        return "media_bytes"
    if len(data) >= 1024 and content_type.casefold().startswith(("video/", "audio/")):
        return "media_bytes"
    return "unrecognized_200"


def probe(entry):
    """Traverse nested HLS manifests and require an actual media segment."""
    current = entry
    visited = set()
    for depth in range(MAX_HLS_DEPTH):
        if current in visited:
            return "HLS_LOOP"
        visited.add(current)
        code, data, mime, final_url = read_url(current, limit=MAX_MEDIA_BYTES)
        if code not in ("200", "206"):
            return "HTTP_" + code
        state = media_state(data, mime)
        if state == "media_bytes":
            return "HLS_SEGMENT_OK" if depth else "MEDIA_BYTES"
        if state == "html_or_json":
            return "HTML_OR_JSON"
        if state != "hls_manifest":
            return ("HLS_CHILD_" if depth else "") + state.upper()
        try:
            lines = data.decode("utf-8-sig", "replace").splitlines()
            next_urls = [v.strip() for v in lines if v.strip() and not v.lstrip().startswith("#")]
            if not next_urls:
                return "HLS_EMPTY"
            current = urljoin(final_url, next_urls[0])
        except (ValueError, UnicodeError):
            return "HLS_INVALID"
    return "HLS_TOO_DEEP"


def samples(entries, n=6):
    if len(entries) <= n:
        return entries
    indexes = [(len(entries) - 1) * i // (n - 1) for i in range(n)]
    return [entries[i] for i in sorted(set(indexes))]


def select_external_samples(entries, *, max_per_group=2, max_total=8):
    selected = []
    by_group = defaultdict(list)
    seen = set()
    for name, url in entries:
        normalized = re.sub(r"\s+", " ", name.casefold())
        label = next((group for group in GROUPS if group in normalized), "other")
        if url not in seen and len(by_group[label]) < max_total:
            by_group[label].append(url)
            seen.add(url)
    for group in GROUPS:
        selected.extend((group, url) for url in by_group[group][:max_per_group])
    if len(selected) < max_total:
        selected.extend(("other", url) for url in by_group["other"][:max_total-len(selected)])
    return selected[:max_total]


def make_public_report(source, *, playlist_status, entries, unique_urls, results):
    return {
        "source": source,
        "playlist_status": playlist_status,
        "m3u_syntax": playlist_status in ("200", "206") and entries is not None,
        "entries": entries,
        "unique_urls": unique_urls,
        "samples_checked": sum(results.values()),
        "sample_results": dict(sorted(results.items())),
    }


def _is_live(title, category):
    group = category.casefold()
    normalized = title.casefold()
    return (
        "canais" in group or "tv ao vivo" in group or "live" in group
        or any(key in normalized for key in GROUPS)
    )


def _public_summary(report):
    lines = [
        "## Auditoria M3U (somente leitura)", "",
        "Um workflow bem-sucedido NAO significa que os canais reproduzem.", "",
        "| Fonte | Arquivo | Amostras | Resultado |",
        "|---|---|---:|---|",
    ]
    for row in report["sources"]:
        states = ", ".join(f"{key}: {count}" for key, count in row["sample_results"].items()) or "nenhuma amostra"
        lines.append(f"| {row['source']} | {row['playlist_status']} | {row['samples_checked']} | {states} |")
    lines.extend(["", "Nao oculta, reativa ou publica canais; erros temporarios exigem confirmacao.", ""])
    return "\n".join(lines)


def audit():
    report = []
    work = []
    for name in SOURCES:
        code, data, _mime, _url = read_url(REPO_BASE + quote(name), limit=MAX_LEGACY_BYTES, use_range=False)
        urls, syntax = parse_streams(data)
        row = make_public_report(name, playlist_status=code,
                                 entries=len(urls) if syntax else None,
                                 unique_urls=len(set(urls)) if syntax else None, results={})
        row["m3u_syntax"] = syntax
        idx = len(report)
        report.append(row)
        if syntax:
            work.extend((idx, "other", url) for url in samples(urls, n=6))

    for name, url in EXTERNAL.items():
        limit = MAX_PLAYLIST_BYTES if name == "CanaisBR04_2026" else MAX_LEGACY_BYTES
        code, data, _mime, _last_url = read_url(url, limit=limit, use_range=False)
        syntax = data.lstrip(b"\xef\xbb\xbf").startswith(b"#EXTM3U")
        entry_count, unique_count = None, None
        stream_candidates = []
        if syntax:
            entry_count = 0
            distinct = set()
            for title, stream_url, category in iter_entries(data):
                entry_count += 1
                distinct.add(stream_url)
                if _is_live(title, category):
                    stream_candidates.append((title, stream_url))
            unique_count = len(distinct)
            del distinct
        row = make_public_report(name, playlist_status=code, entries=entry_count,
                                 unique_urls=unique_count, results={})
        row["m3u_syntax"] = syntax
        idx = len(report)
        report.append(row)
        if syntax:
            work.extend((idx, group, target) for group, target in select_external_samples(stream_candidates))

    counters = [Counter() for _ in report]
    priority = [defaultdict(Counter) for _ in report]
    with ThreadPoolExecutor(max_workers=8) as executor:
        tasks = {executor.submit(probe, url): (idx, group) for idx, group, url in work}
        for task in as_completed(tasks):
            idx, group = tasks[task]
            try:
                outcome = task.result()
            except Exception:
                outcome = "probe_exception"
            counters[idx][outcome] += 1
            if group in GROUPS:
                priority[idx][group][outcome] += 1
    for idx, row in enumerate(report):
        row["samples_checked"] = sum(counters[idx].values())
        row["sample_results"] = dict(sorted(counters[idx].items()))
        if priority[idx]:
            row["priority_results"] = {key: dict(sorted(val.items())) for key, val in sorted(priority[idx].items())}
        print("SOURCE_AUDIT " + json.dumps(row, ensure_ascii=False, sort_keys=True))

    output = {
        "schema_version": 2,
        "read_only": True,
        "notes": "Amostras HTTP/HLS, nao substituem teste de reproducao no celular.",
        "sources": report,
    }
    REPORT_PATH.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(_public_summary(output))
    print("AUDIT_SCOPE: sampling only; no publishing, hiding, recovery, or stream proxying.")
    print("AUDIT_PRIVACY: no raw URLs, hosts, credentials or tokens in reports.")
    return output


if __name__ == "__main__":
    audit()
