# Threat Intelligence: A Guided Walkthrough

Same format as the previous three phases: the *why* first, then the file
that implements it. This phase is different in flavor from the others —
instead of protecting the application, it's about *watching* for people
trying to attack it, and building a small forensics toolkit for
investigating what happened afterward.

## Table of contents

1. [The honeypot: why a decoy, and why it's isolated](#1-the-honeypot-why-a-decoy-and-why-its-isolated)
2. [Classifying attacks: transparent patterns over a black-box model](#2-classifying-attacks-transparent-patterns-over-a-black-box-model)
3. [The log analyzer: four patterns, four different signals](#3-the-log-analyzer-four-patterns-four-different-signals)
4. [Packet analysis without needing root](#4-packet-analysis-without-needing-root)
5. [Forensic string extraction: the oldest trick that still works](#5-forensic-string-extraction-the-oldest-trick-that-still-works)
6. [Three real bugs this phase found — through actually running the code](#6-three-real-bugs-this-phase-found--through-actually-running-the-code)
7. [Design decisions worth defending in an interview](#7-design-decisions-worth-defending-in-an-interview)
8. [Known simplifications in this phase](#8-known-simplifications-in-this-phase)

---

## 1. The honeypot: why a decoy, and why it's isolated

A honeypot is a fake target, deliberately made to look worth attacking,
whose entire purpose is to be probed, poked, and attacked — every
interaction with it is, by definition, suspicious, because nothing
legitimate has any reason to talk to it. That's what makes a honeypot
valuable: unlike monitoring real production traffic (where you have to
separate normal use from abuse), *everything* a honeypot sees is signal.

`app/honeypot/server.py` is a small, separate Flask application — not a
route bolted onto the main FastAPI app — for three deliberate reasons,
explained in the file's own docstring: it runs on its own port (so it can
be exposed independently), writes to its own tables (`honeypot_logs` /
`threat_intel`, kept separate from `audit_logs`, which is about *your*
real users), and runs on a different framework entirely (so a
framework-specific bug in one never automatically compromises the other).

The route itself is a catch-all: `@app.route("/<path:path>", ...)` means
there is no "correct" URL to find — every path, every method, lands in the
same handler and gets logged and classified.

## 2. Classifying attacks: transparent patterns over a black-box model

`app/honeypot/classifier.py` uses regular expressions grouped by attack
category (XSS, LFI, RCE, SQLi), not a trained ML classifier. That's a
deliberate choice, not a shortcut: the well-known attack signatures below
catch the overwhelming majority of real-world automated scanning traffic,
which tends to reuse the same handful of well-known payloads across the
entire internet (`' OR '1'='1`, `../../../etc/passwd`, `<script>alert(1)</script>`
show up constantly in real logs). Pattern matching is also fully
explainable — you can always point at the exact regex that fired — which
matters for a security tool: "why was this flagged?" needs a real answer,
not "the model said so."

Confidence scales with how many *distinct* patterns matched:

```python
confidence = min(1.0, 0.5 + 0.25 * len(matched))
```

One matched pattern gives 75% confidence; two or more caps at 100%. This
means a request matching multiple SQLi signatures (a quote, an `OR`
condition, *and* a comment marker) is scored more confidently than one
matching a single, more ambiguous pattern — without needing a full
statistical model to express that intuition.

## 3. The log analyzer: four patterns, four different signals

`app/analysis/log_analyzer.py` reads the main application's own request
log (written by `app/middleware/access_log.py`, one JSON line per
request) and looks for four specific patterns — each chosen because it's
detectable from request *metadata* alone, without needing to inspect
payloads the way the honeypot classifier does:

| Pattern | Signal | Severity |
|---------|--------|----------|
| Brute force | 5+ `401` responses from one IP within 60s | HIGH |
| Suspicious user agent | Known scanner tool name, or missing entirely | MEDIUM |
| Directory traversal | `../` or `/etc/passwd` in the path — against the **real app**, not a decoy | CRITICAL |
| Traffic spike | 50+ requests from one IP within 60s | LOW |

The severities aren't arbitrary. Directory traversal is CRITICAL because
it's happening against real application resources — the honeypot version
of the same signature (section 1) is just data collection, but this one
means someone found a real endpoint and is actively probing it. Traffic
spikes are LOW because this pattern has the most legitimate explanations
(an aggressive but harmless scraper, a burst of real user activity) —
worth surfacing, not worth an urgent page.

**The sliding-window detection logic is worth understanding, not just
trusting:**
```python
for i in range(len(timestamps) - BRUTE_FORCE_THRESHOLD + 1):
    window_start = timestamps[i]
    window_end = timestamps[i + BRUTE_FORCE_THRESHOLD - 1]
    if (window_end - window_start) <= timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS):
        ...
```
This checks every possible 5-attempt window in a sorted timestamp list,
not just fixed, non-overlapping 60-second buckets — the same precision
argument made for the sliding-window rate limiter back in Week 5-6 (see
`docs/week-05-06-api-security.md`): a naive fixed-bucket approach could
miss 5 attempts that straddle a bucket boundary (3 at the end of one
minute, 2 at the start of the next) even though they happened within 4
real seconds of each other.

## 4. Packet analysis without needing root

`app/forensics/packet_sniffer.py` analyzes `.pcap` files rather than
sniffing live traffic. This isn't a reduced version of the exercise — the
blueprint explicitly allows for it ("scapy (or pcap file parser)") — it's
the more broadly usable choice: live sniffing needs a raw socket, which
needs root/administrator privileges on every OS, which is a real barrier
for anyone who just wants to clone this repo and run the tests. Analyzing
a capture someone hands you is also, realistically, the more common
forensics scenario — incident responders are usually handed a `.pcap`
from a compromised host, not sniffing live at the moment of compromise.

**Port scan detection** uses a well-established, simple heuristic:

```python
if tcp_layer.flags & 0x02 and not (tcp_layer.flags & 0x10):
    ports_by_source[packet[IP].src].add(tcp_layer.dport)
```

`0x02` is the SYN flag (a new connection attempt), `0x10` is ACK. A packet
with SYN set and ACK *not* set is a fresh connection attempt, not a
response to one — which is exactly what distinguishes "someone probing
many ports" from "a server replying to many different clients." This is
proven directly with a dedicated test
(`test_syn_ack_responses_are_not_counted_as_scan_attempts`) that feeds in
only SYN-ACK responses and confirms they're correctly ignored.

**TLS SNI extraction** deserves a specific callout: SNI (Server Name
Indication) is the hostname a client sends *in the clear*, before
encryption starts, during the TLS handshake — so even fully-encrypted
HTTPS traffic reveals which hostname a client was connecting to. This is
genuinely useful forensic signal (e.g. "this host reached out to
`known-c2-domain.example` over HTTPS") that survives encryption, which is
worth understanding as a concept independent of this specific
implementation.

## 5. Forensic string extraction: the oldest trick that still works

`app/forensics/string_extractor.py` reimplements the core idea behind the
decades-old Unix `strings` command: scan raw bytes for runs of printable
ASCII at least N characters long. It works on *any* binary — an
executable, a memory dump, a core file — without understanding that
file's format at all, because it never tries to parse structure, only to
find embedded plaintext:

```python
for byte in data:
    if byte in _PRINTABLE_BYTE_RANGE:
        current_run.append(byte)
    else:
        if len(current_run) >= min_length:
            strings_found.append(current_run.decode("ascii"))
        current_run = bytearray()
```

This is a real, standard first step in malware triage — before any deep
reverse engineering, an analyst runs `strings` on an unknown binary
looking for hardcoded URLs, error messages, or (embarrassingly often for
attackers) leftover credentials or API keys. `filter_iocs()` runs three
regexes over the extracted strings for exactly those categories, and
`cross_reference_iocs()` checks matches against a known-bad set — a real,
if simplified, version of matching extracted indicators against a threat
intelligence feed.

## 6. Three real bugs this phase found — through actually running the code

Worth being completely direct about all three, because "how do you find
bugs like this" is a genuinely strong interview answer when the honest
answer is "by actually running the thing, not just trusting the test
suite."

**Bug 1 — the honeypot never created its own database tables when run
standalone.** The main FastAPI app's `main.py` creates every table at
import time (`Base.metadata.create_all(...)`), and the original test
suite always imported `app.main` first (via `conftest.py`), so tables
always existed by the time honeypot tests ran. The moment the honeypot
was started as its *own* process — the way the module docstring says it's
actually meant to be deployed — every single request 500'd trying to
`INSERT` into a table that didn't exist. Fixed by adding the same
`Base.metadata.create_all(...)` call directly to `app/honeypot/server.py`.
The regression test for this
(`test_honeypot_creates_its_own_tables_when_run_standalone`) genuinely
has to spawn a real subprocess — importing the module fresh within the
same pytest process wouldn't reproduce the bug, since Python's module
cache (and the fact that `app.main` had already run elsewhere in the test
session) would silently hide the exact failure mode a real standalone
deployment hits.

**Bug 2 — LFI attacks delivered via the query string were completely
invisible to the classifier.** The classic LFI payload
(`?file=../../../../etc/passwd`) lives in the URL's query string, not the
path — but Flask's routed `path` parameter and `request.path` never
include it. The honeypot was passing only the bare path to the classifier,
so an attack sent exactly the way real attackers actually send it went
completely unclassified and unflagged. Found by manually running the
honeypot as a real server and attacking it with `curl` — the original
automated test suite happened not to include a query-string attack case,
so it passed cleanly while missing this entirely. Fixed by folding
`request.query_string` into the path used for both classification and
logging.

**Bug 3 — the access log middleware wrote to a fixed, real path on
disk, with no way to isolate it in tests.** Every test run using the main
app (auth tests, vault tests, RBAC tests — nearly the whole suite)
silently appended entries to the real `logs/access.log` on disk, forever
accumulating test noise in a file that isn't meant to hold it. Fixed by
making the path configurable via `ACCESS_LOG_PATH`, with
`tests/conftest.py` now pointing it at a fresh temp directory for the
whole test session.

Each of these is a good, honest answer to "walk me through a bug you
found and how" — and notably, none of them were caught by unit tests in
isolation; all three only surfaced by actually running the real
deployment path (a standalone process, a live curl attack, a full test
suite run against real disk paths) rather than trusting that passing
tests meant the system worked end to end.

## 7. Design decisions worth defending in an interview

- **The honeypot's response is deliberately boring.** It returns a
  plausible `401 Unauthorized` with a generic message — never an error
  page, a stack trace, or anything that might tip off an attacker that
  their request was logged and classified in detail.
- **`threat_intel` only gets a row for classified attacks; `honeypot_logs`
  gets one for every single request, unconditionally.** This keeps
  `threat_intel` a genuinely curated feed (what a SOC analyst would want
  to triage) separate from the complete raw record (what a forensics
  investigation would want later).
- **Webhook alert failures are deliberately swallowed, not raised** — the
  one explicit exception to this project's general "never hide errors"
  philosophy, because a broken notification pipeline degrading visibility
  is a much smaller problem than it taking down the honeypot's ability to
  keep logging.
- **JSON-lines for the access log, not a traditional web-server log
  format.** Since this project's own analyzer is the only consumer, there
  was no interoperability reason to use a text format that needs regex to
  parse correctly (and can be mis-split by a stray space or quote in a
  field) — one JSON object per line trivially avoids that whole class of
  parsing bug.

## 8. Known simplifications in this phase

- **The log analyzer runs on demand, not as a scheduled background task.**
  The blueprint describes it running "every 5 minutes" — this phase
  implements the `analyze()` function itself and proves it works
  correctly; wiring it to a scheduler (APScheduler, a cron job, a
  background thread) is a small, separate addition, not a gap in the
  detection logic.
- **The attack classifier is pattern-based, not ML-based.** As discussed
  in section 2, this is a deliberate choice for transparency and
  zero-training-data requirements, not an unfinished shortcut — but it's
  worth naming directly that a determined attacker who knows the patterns
  could craft payloads designed to evade them, the same limitation every
  signature-based detection system has.
- **Port scan detection uses a single, simple heuristic** (distinct SYN
  destination ports from one source) — real network intrusion detection
  systems combine several signals (timing, packet size patterns, protocol
  anomalies) for higher-confidence detection with fewer false positives.
- **The YARA rule generator produces a simplified, illustrative rule**,
  not a fully spec-compliant one — real YARA supports hex patterns,
  regex conditions, and boolean logic well beyond "matches any of these
  strings."
