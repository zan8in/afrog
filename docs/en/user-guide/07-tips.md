<!--
title: Practical Tips
slug: /docs/user-guide/tips
lang: en
summary: High-frequency afrog recipes: target input, asset discovery, performance and stability, OOB, output, and resume.
status: published
source: new
last_reviewed: 2026-09-23
-->

This page is not a parameter dictionary. It combines frequently used flags into recipes you can copy directly. For the full parameter reference, see [CLI Options](./04-cli-options.md).

## Focus on high-severity findings only

```bash
afrog -T targets.txt -S high,critical
```

Pair it with `-sort severity` to order results by risk, which helps when you only want the highlights first.

## Pull assets from cyberspace mapping

```bash
afrog -cs zoomeye -q "app:'tomcat'" -qc 1000
```

`-cs` selects the mapping platform, `-q` passes the query, and `-qc` caps the number of results (default 100). Configure credentials in the `cyberspace` section of your [configuration](./05-configuration.md) first.

## Probe before scanning on network ranges

```bash
afrog -t 192.168.1.0/24 -ps
```

- `-ps`: enable port pre-scanning, suited to IPs, ranges and CIDRs
- `-w`: web asset info collection (URL / status / title / Server / tech-stack fingerprint), **enabled by default**; turn it off with `-w=false`
- `-p`: control the port range with `top`, `full`, `80,443,8080`, or `1-65535`
  - `top` covers about 640 common ports and returns in seconds; `full` / `all` scans all 65535 ports, so use it deliberately
  - Full-port runtime depends on how the target responds: a host that answers with `RST` finishes fast, while a host dropping most probes is bound by `per-port timeout × 65535 ÷ per-host concurrency`
- `-Pn`: skip host discovery and go straight to port scanning

## Run only the PoCs you care about

```bash
afrog -t https://example.com -s spring,weblogic   # keyword filter (id / name / tags)
afrog -t https://example.com -P ./my-pocs/        # specific PoC file or directory
afrog -t https://example.com -ap ./extra-pocs/    # append beyond built-in PoCs
afrog -t https://example.com -ep log4j            # exclude a category
```

Before writing or importing PoCs, validate and confirm:

```bash
afrog -validate ./pocs/        # validate PoC syntax
afrog -pl -s weaver,ecology    # list matched PoCs
afrog -pd ssh-weak-login       # inspect a single PoC
```

## Protect targets during bulk scans

```bash
afrog -T targets.txt -c 50            # per-target adaptive limiting is on by default
afrog -T targets.txt -rl 80 -rlt 5    # or pin a fixed per-target rate instead
afrog -T targets.txt -mt -balanced
```

- `-c` concurrency, `-rl` global requests per second (default 150), `-rlt` requests per second per target
- Per-target limiting is adaptive by default via `-auto-req-limit`; `-rlt` pins a fixed rate, `-polite` / `-balanced` / `-aggressive` pick a preset, and these are mutually exclusive
- `-mt` monitors target liveness, useful on the public internet or unstable networks

In practice, do not speed things up by only raising `-c`; tune concurrency and rate limits together.

## Concurrency limits on low-end machines and servers

Port pre-scan concurrency is also bounded by the number of open file descriptors (fds) available to the process. The default `-prate 500` pool is fine on a well-provisioned workstation, but a Linux server commonly runs with systemd's default `ulimit -n 1024`, and a container may allow only `256`. Once fds run out, connections outside the scan — reports, logs, the web listener — start failing too.

afrog falls back in three steps:

1. On startup it raises the soft limit toward the hard limit (the same trick nmap uses), and silently skips if it cannot.
2. It narrows the global pool to `min(-prate, budget)`, printing a line when it does:

```
[WRN] port-scan fd-limit probes=128 concurrency=500->128 lowered to fit open-file limit
```

3. If the process still runs out mid-scan (Windows offers no readable handle limit, so only a runtime signal is available), those failures are counted separately from target-side signals, warned about exactly once, and the in-flight concurrency is halved temporarily:

```
[WRN] port-scan fd-exhausted failed=3 raise ulimit -n or lower -prate
```

To tune it yourself:

```bash
ulimit -n 65535                    # raise the fd limit for this shell
afrog -t 10.0.0.1 -ps -prate 200   # lower concurrency explicitly
```

In containers, pass `--ulimit nofile=65535:65535`. Windows has no fd limit to set — just lower `-prate` if you see the warning above.

## Do not take your own network down

The previous section is about local resources; this one is about the network afrog runs on. The real risk of port scanning is not bandwidth (one TCP probe round trip is under 200 bytes, so 1000/s is 1–2 Mbps), it is the NAT/conntrack session table of the exit device: closed ports answer with RST immediately and their entries are released quickly, while **filtered ports never reply, so their entries linger for the 30–120s timeout**. Once that table fills up, every new connection from anyone on the same network fails.

The crux is that **concurrency does not bound the rate**. `-prate 500` against the internet (a few hundred ms RTT) works out to roughly 1000 connections per second, but against a LAN (1 ms RTT) the theoretical ceiling is 500,000 per second — two orders of magnitude apart. So afrog caps the connection rate of the port pre-scan by default:

```bash
afrog -t 10.0.0.0/24 -ps              # default: 1000/s global, 100/s per host
afrog -t 10.0.0.0/24 -ps -polite      # more conservative: 200/s global, 20/s per host
afrog -t 10.0.0.0/24 -ps -pcps 200    # tune the global rate only
afrog -t 10.0.0.0/24 -ps -aggressive  # no cap (same as -pcps 0)
```

At the default rate, a full 65535-port scan of one host finishes in about 65 seconds, which is plenty for everyday use; lift the cap explicitly only when you really need to saturate.

During the scan afrog also measures the RTT to the default gateway (`-ps-link-probe`, on by default). The gateway is one hop away, so its RTT can only rise because the local uplink or the gateway itself is saturated — a clean local signal. When it climbs well above the idle baseline taken before the scan, or when more than half of the probes get no reply, afrog eases the rate off multiplicatively and warns; it ramps back up once the link recovers.

```
[WRN] port-scan throttled rate=1000->700 no-reply=100% gw-rtt=42ms baseline=3ms probes unanswered, easing off to protect the local network -pcps 0 disables
```

Seeing that line means the scan already converged on its own — no action needed. If you are confident the link is robust enough, you can turn the protection off with `-pcps 0`.

## Use OOB for blind vulnerabilities

```bash
afrog -t https://example.com -oob ceyeio
```

Available adapters include `ceyeio`, `dnslogcn`, and `alphalog`. Fill in the matching platform credentials in the `reverse` section of your [configuration](./05-configuration.md) first. Use `-orl` and `-oc` to control OOB rate and concurrency.

## Output and automation

```bash
afrog -T targets.txt -o report.html        # HTML report
afrog -T targets.txt -j result.json        # compact JSON
afrog -T targets.txt -ja result_full.json  # full JSON with requests and responses
```

Output controls worth knowing:

- `-silent`: output results only
- `-live-stats`: render live statistics on a single line
- `-nc`: disable ANSI colors
- `-doh`: disable automatic HTML report generation

## Resume long-running scans

```bash
afrog -T big-targets.txt -resume resume.afg
```

After an interruption, pass the same `-resume` file to continue. Best suited to long scans over large target sets.

## Troubleshooting

```bash
afrog -t https://example.com -debug   # more debug output
afrog -t https://example.com -nf      # skip fingerprinting for a quick check
afrog -t https://example.com -test    # test mode, disables requires gating
```

Both `-nf` and `-test` affect `requires`-based gating, so avoid using them as regular scan modes.

### Open ports differ between runs

Scanning the same target twice and getting a different port list is usually the **target rate-limiting or blocking you**, not the scanner dropping results:

- A closed port answers with `RST`; a dropped probe answers with nothing. Under load the target (or the device in front of it) discards some `SYN`s, so a few ports go missing each time.
- It gets worse with concurrency: per-host concurrency defaults to 100; pushing it into the hundreds easily trips the target's connection limit, and more ports go missing rather than fewer.
- If a host drops nearly every probe, `-debug` prints a `[WRN] port-scan filtered host=… drop-rate=… probes=… results may be incomplete` warning that the result set may be incomplete. It is hidden by default so it never cuts into the progress bar.

```bash
afrog -t 192.0.2.10 -ps -p full -ps-host-concurrency 20   # lower per-host concurrency further (default 100)
afrog -t 192.0.2.10 -ps -ptries 2                          # add retries when the target drops probes (default 0, no retry)
afrog -t 192.0.2.10 -ps -ptimeout 2000                     # a longer connect timeout
```

`-ptries` defaults to 0: every extra retry costs a full timeout plus backoff on a dropping port, so a full-port scan slows down in multiples. Only enable it once you have confirmed target-side throttling.

To confirm: scan from a machine on a different network, or at a different time. If the results become consistent, the throttling is on the target side.

## Notifications and web services

```bash
afrog -web         # start the web service
afrog -dingtalk    # start the DingTalk webhook service
afrog -wecom       # start the WeCom webhook service
```

Notification thresholds and tokens are configured in the `webhook` section of your [configuration](./05-configuration.md).

> **← Previous:** [Output and Reports](./06-output-and-report.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Next →:** [Web Scan Workspace](./08-web-console.md)
