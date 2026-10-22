"""Unit tests for torrelay's pure functions (no Tor or network needed)."""

import io
import unittest

from torrelay import bench
from torrelay import live
from torrelay import probes
from torrelay import profile as profile_lib
from torrelay import report
from torrelay import socks
from torrelay import target as target_lib
from torrelay import tor
from torrelay import util

FP_A = "0824D7C7FB117D5C6AC01581FD798E670C37C804"
FP_B = "A" * 40
FP_C = "C" * 40
ONION = "abc.onion"

parse_target = target_lib.parse_target


class TargetTest(unittest.TestCase):
    """URL parsing into Targets."""

    def test_schemes_and_default_ports(self):
        """Each scheme gets its default port and fields."""
        self.assertEqual(parse_target("https://example.com").port, 443)
        self.assertEqual(parse_target("http://x.onion/a?b=1").path, "/a?b=1")
        ssh = parse_target(f"ssh://luffy@{ONION}")
        self.assertEqual((ssh.user, ssh.port, ssh.is_onion),
                         ("luffy", 22, True))
        self.assertEqual(parse_target("example.com:25").scheme, "tcp")

    def test_rejects_bad_targets(self):
        """Unknown schemes, missing ports and hosts are errors."""
        for bad in ("ftp://x.com", "tcp://x.com", "https://"):
            with self.assertRaises(ValueError):
                parse_target(bad)

    def test_url_round_trip(self):
        """Canonical URLs parse back to themselves."""
        for url in ("https://example.com/f.bin", f"ssh://u@{ONION}",
                    "tcp://example.com:25", "tls://example.com:8443"):
            self.assertEqual(parse_target(url).url, url)

    def test_destination(self):
        """SSH destinations include the user only when given."""
        self.assertEqual(parse_target("ssh://u@h.com").destination, "u@h.com")
        self.assertEqual(parse_target("ssh://h.com").destination, "h.com")


class TorParsingTest(unittest.TestCase):
    """Control-port output parsing."""

    CIRCUITS = (
        "250+circuit-status=",
        f"7 BUILT ${FP_A}~g,${FP_B}~m,${FP_C}~x PURPOSE=GENERAL",
        f"123 BUILT ${FP_A}~g,${FP_B}~m,${FP_A}~r "
        "PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED",
        f"9 EXTENDED ${FP_A}~g PURPOSE=HS_CLIENT_REND",
        "250 OK",
    )

    def test_parse_hop_variants(self):
        """All three relay token spellings parse."""
        self.assertEqual(tor.parse_hop(f"${FP_A}~TheGreatKing"),
                         tor.Hop(FP_A, "TheGreatKing"))
        self.assertEqual(tor.parse_hop(f"${FP_A.lower()}=nick"),
                         tor.Hop(FP_A, "nick"))
        self.assertEqual(tor.parse_hop(f"${FP_A}"), tor.Hop(FP_A, ""))

    def test_normalize_fingerprint(self):
        """Fingerprints are canonicalised; nicknames are rejected."""
        self.assertEqual(tor.normalize_fingerprint(f"${FP_A.lower()}"), FP_A)
        with self.assertRaises(ValueError):
            tor.normalize_fingerprint("TheGreatKing")

    def test_format_path(self):
        """Paths render with arrows and fall back to fingerprints."""
        hops = (tor.Hop(FP_A, "g"), tor.Hop(FP_B))
        self.assertEqual(tor.format_path(hops), "g -> AAAAAAAA")
        self.assertEqual(tor.format_path(()), "")

    def test_parse_circuit_table(self):
        """Only BUILT circuits are indexed, with purpose and hops."""
        table = tor.parse_circuit_table(self.CIRCUITS)
        self.assertEqual(set(table), {"7", "123"})
        self.assertEqual(table["7"][0], "GENERAL")
        self.assertEqual(table["7"][1][-1].nickname, "x")

    def test_parse_circuits_filters_purpose(self):
        """Circuits are filtered by purpose."""
        circuits = tor.parse_circuits(self.CIRCUITS, "HS_CLIENT_REND")
        self.assertEqual([h.nickname for h in circuits[0]], ["g", "m", "r"])

    def test_parse_stream_circuit(self):
        """Streams match by host:port in single- and multi-line replies."""
        multi = ["250+stream-status=",
                 "4 SENTCONNECT 0 example.com:443",
                 "5 SUCCEEDED 7 Example.com:443",
                 "250 OK"]
        self.assertEqual(
            tor.parse_stream_circuit(multi, "example.com", 443), "7")
        single = ["250-stream-status=5 SUCCEEDED 123 abc.onion:22",
                  "250 OK"]
        self.assertEqual(tor.parse_stream_circuit(single, ONION, 22), "123")
        self.assertIsNone(tor.parse_stream_circuit(single, ONION, 80))

    def test_parse_stream_circuit_after_remap_to_ip(self):
        """A remapped stream is found by port only when unambiguous."""
        remapped = ["250-stream-status=5 SUCCEEDED 9 104.16.1.1:443",
                    "250 OK"]
        self.assertEqual(
            tor.parse_stream_circuit(remapped, "example.com", 443), "9")
        ambiguous = ["250+stream-status=",
                     "5 SUCCEEDED 9 104.16.1.1:443",
                     "6 SUCCEEDED 4 1.2.3.4:443", ".", "250 OK"]
        self.assertIsNone(
            tor.parse_stream_circuit(ambiguous, "example.com", 443))

    def test_read_reply_handles_data_block_with_numeric_lines(self):
        """A data line like ``123 BUILT`` must not end the reply early."""
        raw = ("250+circuit-status=\r\n123 BUILT $X PURPOSE=GENERAL\r\n"
               ".\r\n250 OK\r\n")
        lines = tor.read_reply(io.StringIO(raw, newline=""))
        self.assertEqual(lines[-1], "250 OK")
        self.assertIn("123 BUILT $X PURPOSE=GENERAL", lines)


class UtilAndSocksTest(unittest.TestCase):
    """Byte-level helpers."""

    def test_connect_request_layout(self):
        """CONNECT requests use a length-prefixed domain name."""
        request = socks.connect_request(ONION, 22)
        self.assertEqual(request[:4], b"\x05\x01\x00\x03")
        self.assertEqual(request[4], len(ONION))
        self.assertEqual(request[-2:], (22).to_bytes(2, "big"))

    def test_describe_status(self):
        """Tor's extended onion errors are named."""
        self.assertIn("descriptor not found", socks.describe_status(0xF0))
        self.assertEqual(socks.describe_status(0x99), "code 0x99")

    def test_last_line_and_speed(self):
        """Error extraction and throughput math."""
        self.assertEqual(util.last_line("a\nb\n\n", "x"), "b")
        self.assertEqual(util.last_line("", "x"), "x")
        self.assertEqual(util.kib_per_second(2048, 2.0), 1.0)


class ProbeHelpersTest(unittest.TestCase):
    """Protocol helpers that need no network."""

    def test_http_request_host_header(self):
        """Host includes the port only when it is non-default."""
        default = probes.http_request(parse_target("https://example.com/x"))
        self.assertIn(b"GET /x HTTP/1.1\r\nHost: example.com\r\n", default)
        custom = probes.http_request(parse_target("http://example.com:8080/"))
        self.assertIn(b"Host: example.com:8080\r\n", custom)

    def test_drain_respects_limit(self):
        """Draining stops at the limit or at EOF."""
        self.assertEqual(probes.drain(io.BytesIO(b"x" * 1000).read, 300), 300)
        self.assertEqual(probes.drain(io.BytesIO(b"abc").read, 300), 3)

    def test_timed_body_counts_first_byte(self):
        """The first byte is included in the count but not the timing."""
        _, total = probes.timed_body(io.BytesIO(b"x" * 10).read, 100)
        self.assertEqual(total, 10)
        self.assertEqual(probes.timed_body(io.BytesIO(b"").read, 100),
                         (0.0, 0))

    def test_ssh_cmd_precedence_and_direct(self):
        """Forced options win; direct routes disable ProxyCommand."""
        target = target_lib.Target("ssh", "x.onion", 22, user="luffy",
                                   key="/k",
                                   ssh_options=("ControlPath=/tmp/evil",))
        cmd = probes.ssh_cmd(target, 19000, "true")
        options = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-o"]
        self.assertLess(options.index("ControlPath=none"),
                        options.index("ControlPath=/tmp/evil"))
        self.assertIn("--socks 19000", options[0])
        self.assertEqual(cmd[-2:], ["luffy@x.onion", "true"])
        self.assertIn("ProxyCommand=none", probes.ssh_cmd(target, None, "x"))


class PlanTest(unittest.TestCase):
    """Which steps run for which protocol."""

    @staticmethod
    def labels(steps):
        """Returns the step labels, for readable assertions."""
        return [label for label, _ in steps]

    def test_plans_per_scheme(self):
        """SSH gets login/rtt and up/down; HTTP gets download only."""
        route, opts = probes.direct_route(), bench.BenchOptions()
        ssh = parse_target("ssh://u@h.com")
        self.assertEqual(self.labels(bench.latency_plan(ssh, opts, route)),
                         ["connect", "login", "rtt"])
        self.assertEqual(
            self.labels(bench.throughput_plan(ssh, opts, route)),
            ["download", "upload"])
        https = parse_target("https://h.com")
        self.assertEqual(
            self.labels(bench.throughput_plan(https, opts, route)),
            ["download"])
        tls = parse_target("tls://h.com")
        self.assertEqual(bench.throughput_plan(tls, opts, route), ())

    def test_connect_only(self):
        """--connect-only reduces every plan to the connect step."""
        opts = bench.BenchOptions(connect_only=True)
        ssh = parse_target("ssh://u@h.com")
        route = probes.direct_route()
        self.assertEqual(self.labels(bench.latency_plan(ssh, opts, route)),
                         ["connect"])
        self.assertEqual(bench.throughput_plan(ssh, opts, route), ())

    def test_instance_specs_pin_guards_and_exits(self):
        """One instance per pinned relay, with matching torrc lines."""
        specs = bench.instance_specs(bench.BenchOptions(
            guards=(FP_A, FP_B), exits=(FP_C,)))
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0].torrc_lines,
                         (f"EntryNodes ${FP_A}", f"ExitNodes ${FP_C}"))
        self.assertEqual(specs[1].torrc_lines, (f"EntryNodes ${FP_B}",))
        self.assertEqual(specs[0].label, "guard=0824D7C7 exit=CCCCCCCC")
        unpinned = bench.instance_specs(bench.BenchOptions(instances=3))
        self.assertEqual(len(unpinned), 3)


class ProfileTest(unittest.TestCase):
    """Profile rendering and port allocation."""

    def test_render_pinned(self):
        """Guards and exits render as torrc lines; empty is a comment."""
        self.assertEqual(profile_lib.render_pinned((FP_A, FP_B)),
                         f"EntryNodes ${FP_A},${FP_B}\n")
        self.assertEqual(profile_lib.render_pinned((), (FP_C,)),
                         f"ExitNodes ${FP_C}\n")
        self.assertTrue(profile_lib.render_pinned(()).startswith("#"))

    def test_next_ports(self):
        """Port pairs start at 9060 and skip ports in use."""
        self.assertEqual(profile_lib.next_ports([]), (9060, 9061))
        used = [profile_lib.Profile("a", "h", socks_port=9060,
                                    ctrl_port=9061)]
        self.assertEqual(profile_lib.next_ports(used), (9062, 9063))

    def test_profile_target_round_trip(self):
        """A profile reproduces the target it was created from."""
        target = parse_target("https://example.com:8443/big.bin")
        self.assertEqual(profile_lib.from_target("x", target).target, target)

    def test_socks_chain(self):
        """Failover order is the dedicated port, then fallbacks."""
        profile = profile_lib.Profile("a", "h", socks_port=9062)
        self.assertEqual(profile.socks_chain, (9062, 9050))

    def test_rejects_unsafe_names(self):
        """Names that could escape the config directory are rejected."""
        with self.assertRaises(ValueError):
            profile_lib.validate_name("../evil")


class RankingTest(unittest.TestCase):
    """Scoring, serialisation and relay selection."""

    def test_rank_and_top_relays(self):
        """Best results rank first; exits only exist for clearnet."""
        fast = bench.Result(
            "t0", connect_s=5, rtt_ms=1000, down_kib=350, up_kib=200,
            hops=(tor.Hop(FP_A, "g"), tor.Hop(FP_B, "m"),
                  tor.Hop(FP_C, "x")))
        slow = bench.Result(
            "t1", connect_s=5, rtt_ms=3000, down_kib=10, up_kib=10,
            hops=(tor.Hop(FP_B, "g2"), tor.Hop(FP_A, "m"),
                  tor.Hop(FP_A, "x2")))
        broken = bench.Result("t2", connect_s=4, error="dropped",
                              hops=(tor.Hop(FP_C, "z"),))
        ranked = bench.rank([broken, slow, fast])
        self.assertEqual([r.name for r in ranked], ["t0", "t1", "t2"])

        clearnet = parse_target("https://example.com")
        rows = [report.to_dict(r, clearnet) for r in ranked]
        self.assertEqual(report.top_relays(rows, 5), (FP_A, FP_B))
        self.assertEqual(report.top_relays(rows, 5, report.EXIT_KEY),
                         (FP_C, FP_A))

        onion = parse_target(f"ssh://{ONION}")
        onion_rows = [report.to_dict(r, onion) for r in ranked]
        self.assertEqual(report.top_relays(onion_rows, 5, report.EXIT_KEY),
                         ())

    def test_latency_fallbacks(self):
        """Latency prefers rtt, then ttfb, then setup time."""
        self.assertEqual(bench.Result("a", connect_s=1, handshake_s=0.5)
                         .latency_ms, 1500)
        self.assertEqual(bench.Result("a", connect_s=1, ttfb_ms=300)
                         .latency_ms, 300)

    def test_table_has_header_and_rows(self):
        """The table renders a header plus one row per result."""
        table = report.format_table([bench.Result("tor0", connect_s=1.0),
                                     bench.Result("tor1", error="boom")])
        lines = table.splitlines()
        self.assertTrue(lines[0].startswith("route"))
        self.assertIn("OK", lines[1])
        self.assertIn("FAIL boom", lines[2])


class LiveTest(unittest.TestCase):
    """Live view ordering and Tor bootstrap parsing."""

    def test_parse_bootstrap(self):
        """Tor's progress lines yield percent and summary; others None."""
        line = ("Oct 12 12:49:36.000 [notice] Bootstrapped 73% "
                "(loading_descriptors): Loading relay descriptors")
        self.assertEqual(tor.parse_bootstrap(line),
                         (73, "Loading relay descriptors"))
        self.assertIsNone(tor.parse_bootstrap("[notice] Opening Socks"))

    def test_ranked_orders_done_running_failed(self):
        """Done rows rank by score; running keep order; failed sink."""
        def row(stage, **fields):
            """Builds a row in ``stage`` with a result of ``fields``."""
            return live._Row(stage, result=bench.Result("x", **fields))  # pylint: disable=protected-access

        rows = [
            ("broken", row("failed", error="boom")),
            ("slow", row("done", connect_s=1, ttfb_ms=900, down_kib=50)),
            ("busy", row("download", connect_s=1)),
            ("fast", row("done", connect_s=1, ttfb_ms=300, down_kib=900)),
            ("queued", row("queued")),
        ]
        self.assertEqual([name for name, _ in live.ranked(rows)],
                         ["fast", "slow", "busy", "queued", "broken"])


if __name__ == "__main__":
    unittest.main()
