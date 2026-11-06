"""Regressions for safe IPTV audits. All network requests are mocked."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "audit_m3u_playback.py"
spec = importlib.util.spec_from_file_location("audit_m3u_playback", MODULE)
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


class AuditM3UTests(unittest.TestCase):
    def test_parse_extinf_allows_vlc_options_and_comments(self):
        body = (b'#EXTM3U\n#EXTINF:-1 group-title="Canais",SporTV HD\n'
                b'#EXTVLCOPT:http-user-agent=example\n'
                b'https://video.example/sport.m3u8\n'
                b'#EXTINF:-1,Telecine HD\n'
                b'# Comment\n\nhttps://video.example/telecine.m3u8\n')
        self.assertEqual(audit.parse_streams(body), (
            ["https://video.example/sport.m3u8", "https://video.example/telecine.m3u8"],
            True,
        ))

    def test_hls_master_variant_then_segment_requires_actual_media(self):
        origin = "https://video.example/live.m3u8"
        variant = "https://video.example/720p/stream.m3u8"
        segment = "https://video.example/720p/segment.ts"
        calls = []
        def fake_read(url, **kwargs):
            calls.append(url)
            if url == origin:
                return "200", b'#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1024000\n720p/stream.m3u8\n', "application/vnd.apple.mpegurl", origin
            if url == variant:
                return "200", b'#EXTM3U\n#EXTINF:4.0,\nsegment.ts\n', "application/vnd.apple.mpegurl", variant
            if url == segment:
                # Three MPEG-TS packets, with sync bytes at 188-byte intervals.
                packet = b'\x47' + b'\x00' * 187
                return "206", packet * 3, "video/mp2t", segment
            raise AssertionError("Unexpected request")
        with patch.object(audit, "read_url", side_effect=fake_read):
            self.assertEqual(audit.probe(origin), "HLS_SEGMENT_OK")
        self.assertEqual(calls, [origin, variant, segment])

    def test_hls_to_html_is_never_playable(self):
        origin = "https://video.example/live.m3u8"
        other = "https://www.google.com/"
        with patch.object(audit, "read_url", return_value=(
                "200", b'<!doctype html><html><body>Unavailable</body></html>',
                "text/html", other)):
            self.assertEqual(audit.probe(origin), "HTML_OR_JSON")

    def test_http_403_is_reported_not_bypassed(self):
        with patch.object(audit, "read_url", return_value=("403", b"", "", "")):
            self.assertEqual(audit.probe("https://video.example/stream"), "HTTP_403")

    def test_live_samples_include_globo_sportv_and_telecine_without_urls_in_report(self):
        entries = [
            ("Globo RJ HD", "https://video.example/globo"),
            ("SporTV 2 HD", "https://video.example/sportv"),
            ("Telecine Action HD", "https://video.example/telecine"),
            ("Globo RJ SD", "https://video.example/globosd"),
            ("Other live", "https://video.example/other"),
        ]
        selected = audit.select_external_samples(entries, max_per_group=2, max_total=8)
        group_names = {group for group, url in selected}
        self.assertTrue({"globo", "sportv", "telecine"} <= group_names)
        self.assertFalse(any("?" in group for group, url in selected))

    def test_report_contains_no_urls_or_credentials(self):
        report = audit.make_public_report(
            "CanaisBR04",
            playlist_status="200",
            entries=12,
            unique_urls=12,
            results={"HTTP_403": 3, "HLS_SEGMENT_OK": 2},
        )
        serialized = json.dumps(report)
        self.assertNotIn("https://", serialized)
        self.assertNotIn("password", serialized)
        self.assertNotIn("username", serialized)
        self.assertEqual(report["sample_results"]["HTTP_403"], 3)

    def test_mpeg_ts_needs_more_than_a_single_sync_byte(self):
        self.assertEqual(audit.media_state(b'\x47' + b'\x00' * 2047, "application/octet-stream"), "unrecognized_200")
        self.assertEqual(audit.media_state((b'\x47' + b'\x00' * 187) * 3, "video/mp2t"), "media_bytes")

    def test_large_media_response_is_sampled_not_rejected_for_range(self):
        class FakeResponse:
            status = 206
            headers = {"Content-Type": "video/mp2t"}
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def geturl(self):
                return "https://video.example/stream.ts"
            def read(self, count):
                return b"x" * count
        with patch.object(audit, "allowed", return_value=True):
            with patch.object(audit.OPENER, "open", return_value=FakeResponse()):
                status, data, mime, _ = audit.read_url("https://video.example/stream.ts", limit=16, use_range=True)
        self.assertEqual(status, "206")
        self.assertEqual(len(data), 16)


if __name__ == "__main__":
    unittest.main()
