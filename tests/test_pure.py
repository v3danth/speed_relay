"""Unit tests for torrelay's pure functions (no Tor or network needed)."""

import io
import unittest

from torrelay import report
from torrelay.bench import (BenchOptions, Result, instance_specs,
                            latency_plan, rank, throughput_plan)
from torrelay.probes import direct_route, drain, http_request, ssh_cmd
from torrelay.profile import (Profile, from_target, next_ports,
                              render_pinned)
from torrelay.socks import connect_request
from torrelay.target import Target, parse_target
from torrelay.tor import (Hop, _read_reply, normalize_fingerprint,
                          parse_circuit_table, parse_circuits, parse_hop,
                          parse_stream_circuit)

FP_A = "0824D7C7FB117D5C6AC01581FD798E670C37C804"
FP_B = "A" * 40
FP_C = "C" * 40
ONION = "abc.onion"


class TargetTest(unittest.TestCase):
    def test_schemes_and_default_ports(self):
        self.assertEqual(parse_target("https://example.com").port, 443)
        self.assertEqual(parse_target("http://x.onion/a?b=1").path, "/a?b=1")
        ssh = parse_target(f"ssh://luffy@{ONION}")
        self.assertEqual((ssh.user, ssh.port, ssh.is_onion),
                         ("luffy", 22, True))
        self.assertEqual(parse_target("example.com:25").scheme, "tcp")

    def test_rejects_bad_targets(self):
        for bad in ("ftp://x.com", "tcp://x.com", "https://"):
            with self.assertRaises(ValueError):
                parse_target(bad)

    def test_url_round_trip(self):
        for url in ("https://example.com/f.bin", f"ssh://u@{ONION}",
                    "tcp://example.com:25", "tls://example.com:8443"):
            self.assertEqual(parse_target(url).url, url)


class TorParsingTest(unittest.TestCase):
    def test_parse_hop_variants(self):
        self.assertEqual(parse_hop(f"${FP_A}~TheGreatKing"),
                         Hop(FP_A, "TheGreatKing"))
        self.assertEqual(parse_hop(f"${FP_A.lower()}=nick"), Hop(FP_A, "nick"))
        self.assertEqual(parse_hop(f"${FP_A}"), Hop(FP_A, ""))

    def test_normalize_fingerprint(self):
        self.assertEqual(normalize_fingerprint(f"${FP_A.lower()}"), FP_A)
        with self.assertRaises(ValueError):
            normalize_fingerprint("TheGreatKing")

    CIRCUITS = [
        "250+circuit-status=",
        f"7 BUILT ${FP_A}~g,${FP_B}~m,${FP_C}~x PURPOSE=GENERAL",
        f"123 BUILT ${FP_A}~g,${FP_B}~m,${FP_A}~r "
        "PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED",
        f"9 EXTENDED ${FP_A}~g PURPOSE=HS_CLIENT_REND",
        "250 OK",
    ]

    def test_parse_circuit_table(self):
        table = parse_circuit_table(self.CIRCUITS)
        self.assertEqual(set(table), {"7", "123"})
        self.assertEqual(table["7"][0], "GENERAL")
        self.assertEqual(table["7"][1][-1].nickname, "x")

    def test_parse_circuits_filters_purpose(self):
        circuits = parse_circuits(self.CIRCUITS, "HS_CLIENT_REND")
        self.assertEqual([h.nickname for h in circuits[0]], ["g", "m", "r"])

    def test_parse_stream_circuit(self):
        multi = ["250+stream-status=",
                 "4 SENTCONNECT 0 example.com:443",
                 "5 SUCCEEDED 7 Example.com:443",
                 "250 OK"]
        self.assertEqual(parse_stream_circuit(multi, "example.com", 443), "7")
        single = ["250-stream-status=5 SUCCEEDED 123 abc.onion:22",
                  "250 OK"]
        self.assertEqual(parse_stream_circuit(single, ONION, 22), "123")
        self.assertIsNone(parse_stream_circuit(single, ONION, 80))

    def test_parse_stream_circuit_after_remap_to_ip(self):
        remapped = ["250-stream-status=5 SUCCEEDED 9 104.16.1.1:443",
                    "250 OK"]
        self.assertEqual(
            parse_stream_circuit(remapped, "example.com", 443), "9")
        ambiguous = ["250+stream-status=",
                     "5 SUCCEEDED 9 104.16.1.1:443",
                     "6 SUCCEEDED 4 1.2.3.4:443", ".", "250 OK"]
        self.assertIsNone(
            parse_stream_circuit(ambiguous, "example.com", 443))

    def test_read_reply_handles_data_block_with_numeric_lines(self):
        # A circuit id like "123 BUILT" must not end the reply early.
        raw = ("250+circuit-status=\r\n123 BUILT $X PURPOSE=GENERAL\r\n"
               ".\r\n250 OK\r\n")
        lines = _read_reply(io.StringIO(raw, newline=""))
        self.assertEqual(lines[-1], "250 OK")
        self.assertIn("123 BUILT $X PURPOSE=GENERAL", lines)


class SocksTest(unittest.TestCase):
    def test_connect_request_layout(self):
        req = connect_request(ONION, 22)
        self.assertEqual(req[:4], b"\x05\x01\x00\x03")
        self.assertEqual(req[4], len(ONION))
        self.assertEqual(req[-2:], (22).to_bytes(2, "big"))


class ProbeHelpersTest(unittest.TestCase):
    def test_http_request_host_header(self):
        default = http_request(parse_target("https://example.com/x"))
        self.assertIn(b"GET /x HTTP/1.1\r\nHost: example.com\r\n", default)
        custom = http_request(parse_target("http://example.com:8080/"))
        self.assertIn(b"Host: example.com:8080\r\n", custom)

    def test_drain_respects_limit(self):
        stream = io.BytesIO(b"x" * 1000)
        self.assertEqual(drain(stream.read, 300), 300)
        self.assertEqual(drain(io.BytesIO(b"abc").read, 300), 3)

    def test_ssh_cmd_precedence_and_direct(self):
        target = Target("ssh", "x.onion", 22, user="luffy", key="/k",
                        ssh_options=("ControlPath=/tmp/evil",))
        cmd = ssh_cmd(target, 19000, "true")
        opts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-o"]
        self.assertLess(opts.index("ControlPath=none"),
                        opts.index("ControlPath=/tmp/evil"))
        self.assertIn("--socks 19000", opts[0])
        self.assertEqual(cmd[-2:], ["luffy@x.onion", "true"])
        direct = ssh_cmd(target, None, "true")
        self.assertIn("ProxyCommand=none", direct)


class PlanTest(unittest.TestCase):
    def labels(self, steps):
        return [label for label, _ in steps]

    def test_plans_per_scheme(self):
        route, opts = direct_route(), BenchOptions()
        ssh = parse_target("ssh://u@h.com")
        self.assertEqual(self.labels(latency_plan(ssh, opts, route)),
                         ["connect", "login", "rtt"])
        self.assertEqual(self.labels(throughput_plan(ssh, opts, route)),
                         ["download", "upload"])
        https = parse_target("https://h.com")
        self.assertEqual(self.labels(throughput_plan(https, opts, route)),
                         ["download"])
        tls = parse_target("tls://h.com")
        self.assertEqual(throughput_plan(tls, opts, route), ())

    def test_connect_only(self):
        opts = BenchOptions(connect_only=True)
        ssh = parse_target("ssh://u@h.com")
        self.assertEqual(self.labels(latency_plan(ssh, opts,
                                                  direct_route())),
                         ["connect"])
        self.assertEqual(throughput_plan(ssh, opts, direct_route()), ())

    def test_instance_specs_pin_guards_and_exits(self):
        specs = instance_specs(BenchOptions(guards=(FP_A, FP_B),
                                            exits=(FP_C,)))
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0][1], (f"EntryNodes ${FP_A}",
                                       f"ExitNodes ${FP_C}"))
        self.assertEqual(specs[1][1], (f"EntryNodes ${FP_B}",))
        self.assertEqual(len(instance_specs(BenchOptions(instances=3))), 3)


class ProfileTest(unittest.TestCase):
    def test_render_pinned(self):
        self.assertEqual(render_pinned((FP_A, FP_B)),
                         f"EntryNodes ${FP_A},${FP_B}\n")
        self.assertEqual(render_pinned((), (FP_C,)), f"ExitNodes ${FP_C}\n")
        self.assertTrue(render_pinned(()).startswith("#"))

    def test_next_ports(self):
        self.assertEqual(next_ports([]), (9060, 9061))
        used = [Profile("a", "h", socks_port=9060, ctrl_port=9061)]
        self.assertEqual(next_ports(used), (9062, 9063))

    def test_profile_target_round_trip(self):
        target = parse_target("https://example.com:8443/big.bin")
        self.assertEqual(from_target("x", target).target, target)


class RankingTest(unittest.TestCase):
    def test_rank_and_top_relays(self):
        fast = Result("t0", connect_s=5, rtt_ms=1000, down_kib=350,
                      up_kib=200, hops=(Hop(FP_A, "g"), Hop(FP_B, "m"),
                                        Hop(FP_C, "x")))
        slow = Result("t1", connect_s=5, rtt_ms=3000, down_kib=10,
                      up_kib=10, hops=(Hop(FP_B, "g2"), Hop(FP_A, "m"),
                                       Hop(FP_A, "x2")))
        broken = Result("t2", connect_s=4, error="dropped",
                        hops=(Hop(FP_C, "z"),))
        ranked = rank([broken, slow, fast])
        self.assertEqual([r.name for r in ranked], ["t0", "t1", "t2"])
        clearnet = parse_target("https://example.com")
        rows = [report.to_dict(r, clearnet) for r in ranked]
        self.assertEqual(report.top_relays(rows, 5), (FP_A, FP_B))
        self.assertEqual(report.top_relays(rows, 5, "exit_fingerprint"),
                         (FP_C, FP_A))
        onion_rows = [report.to_dict(r, parse_target(f"ssh://{ONION}"))
                      for r in ranked]
        self.assertEqual(report.top_relays(onion_rows, 5,
                                           "exit_fingerprint"), ())

    def test_latency_fallbacks(self):
        self.assertEqual(Result("a", connect_s=1, handshake_s=0.5)
                         .latency_ms, 1500)
        self.assertEqual(Result("a", connect_s=1, ttfb_ms=300).latency_ms,
                         300)


if __name__ == "__main__":
    unittest.main()
