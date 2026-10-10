# torrelay

Test whether you can reach a server over Tor, race several Tor circuits to
it at the same time, rank them, and pin the fastest relays into a dedicated
Tor instance (falling back to your system Tor automatically).

Works for `.onion` and clearnet hosts, over TCP, TLS, SSH, HTTP and HTTPS.
Stdlib-only Python 3.9+. Needs `tor` (`brew install tor`).

## Run without installing

```bash
./bin/torrelay --help
```

(Optional, later: `pip install -e .` puts `torrelay` on your PATH.)

## Targets

| URL | measures |
|---|---|
| `tcp://host:port` (or `host:port`) | connect time |
| `tls://host[:443]` | + TLS handshake, version, cipher |
| `ssh://[user@]host[:22]` | + SSH banner; with credentials: login, RTT, down/up throughput |
| `http(s)://host[:port]/path` | + TTFB, status; download speed of `path` (use a big file) |

Add `--insecure` to skip TLS verification, `--key`/`--user`/`-o` for SSH.

## Quick connectivity check (uses the Tor you already run)

```bash
./bin/torrelay check https://example.com --direct     # Tor :9050 vs no Tor
./bin/torrelay check ssh://XXXX.onion                 # banner only
./bin/torrelay check ssh://luffy@XXXX.onion --key ~/.ssh/id_ed25519 --full
./bin/torrelay check tcp://XXXX.onion:80 --socks 9050 --socks 9150
```

## Race fresh circuits

```bash
./bin/torrelay bench https://speed.cloudflare.com/__down?bytes=8388608 -n 6 --direct
./bin/torrelay bench ssh://luffy@XXXX.onion --key ~/.ssh/id_ed25519 -n 6
./bin/torrelay bench https://example.com --guard FP1 --guard FP2   # specific relays
./bin/torrelay bench https://example.com --exit FP --connect-only
```

Latency runs on all circuits at once; throughput runs one circuit at a time
(`--parallel-throughput` to overlap). `--json` for machine output.

## Keep the fastest path (profiles)

```bash
./bin/torrelay init pi ssh://luffy@XXXX.onion --key ~/.ssh/id_ed25519 -o Ciphers=aes128-ctr
./bin/torrelay bench pi -n 6 --apply 2          # pin top 2 guards
./bin/torrelay up pi                            # dedicated Tor on :9060
./bin/torrelay ssh-config pi --alias pi-fast    # review, then add to ~/.ssh/config

./bin/torrelay init web https://example.com/big.bin
./bin/torrelay bench web --apply 2 --exits      # clearnet: pin guards + exits
./bin/torrelay up web && eval "$(./bin/torrelay env web)"   # ALL_PROXY for curl etc.
```

| command | purpose |
|---|---|
| `check TARGET` | test via running SOCKS port(s); `--full` for throughput |
| `bench TARGET` | race N fresh circuits; `--apply N [--exits]` to pin |
| `init NAME URL` / `list` | save / list profiles |
| `apply NAME --top N [--exits]` | pin from the last saved bench |
| `pin NAME FP... [--exit FP]` / `--clear` | pin specific relays |
| `up` / `down` / `status NAME` | dedicated Tor lifecycle and live state |
| `service install/uninstall NAME` | run it as a launchd agent |
| `ssh-config NAME` / `env NAME` | wire up ssh / any SOCKS-aware tool |
| `proxy HOST PORT --profile NAME` | ProxyCommand: pinned Tor first, then fallbacks |

`TARGET` is a URL or a profile name.

## Design

```
 routes (strategy):  fresh Tor instance | existing SOCKS port | direct
 probes (per scheme): tcp | tls | ssh | http(s)  -> dict of measurements
 phases:  latency (all routes in parallel) -> throughput (sequential)
          each a fold of named steps over an immutable Result

 control plane:  bench -> results.json -> pin -> pinned.conf -> SIGHUP
 data plane:     client -> torrelay proxy -> :9060 pinned tor
                                         \-> :9050 system tor (fallback)
```

- **Real circuits:** the path shown is the circuit that carried *your*
  stream (guard -> middle -> exit for clearnet; the client half of the
  rendezvous circuit for onions).
- **Isolation:** each profile has its own Tor, so pins never affect other
  Tor traffic. Benchmark instances use auto-assigned ports.
- **Hot reload:** pins live in an `%include`d file; changing them sends
  SIGHUP instead of restarting Tor.
- **Failover:** the proxy tries SOCKS ports in order.

Caveats: an onion service picks its own three hops, so only your half is
pinnable (guards; onions have no exit). Tor performance drifts, so a
single run is a snapshot, and you should re-bench when things feel slow.
Pinning relays reduces anonymity, so keep a profile's Tor for its target.

## Development

The code follows the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
and PEP 8:

- imports name modules only (`from torrelay import tor`, then `tor.Hop`),
  with an exception for `typing`;
- every function and class, including private and nested ones, has a
  Google-style docstring saying why it exists;
- functions do one thing; shared logic lives in one place (`util`,
  `probes.open_stream`, `profile.Profile.socks_chain`, ...).

```bash
pip install -e '.[dev]'                       # pylint + ruff
python3 -m unittest discover -s tests -t .    # unit + style tests
ruff check . bin/torrelay                     # PEP 8, Google docstrings/imports
pylint torrelay tests bin/torrelay            # Google's pylintrc (.pylintrc)
```

`tests/test_style.py` enforces the docstring and import rules, which
linters do not fully cover.
