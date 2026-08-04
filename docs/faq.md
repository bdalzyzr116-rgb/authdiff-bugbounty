# FAQ

**How is 0% false positives possible?**
Findings marked *proven* require a canary whose HMAC binds it to a specific
owner. If identity B's response contains identity A's canary, the app leaked
A's data — there is no room for a guess. Softer signals (e.g. BFLA's unexpected
2xx) are labelled *heuristic* so you can tell them apart.

**Does it work on production?**
Yes, safely: it is non-destructive by default (no writes without `--allow-writes`),
rate-limited, and scope-gated. Seeding canaries requires writes and is opt-in.

**Why do I need two identities?**
The test is differential — it compares what one identity can reach against what
another owns. One identity cannot express a cross-identity invariant.

**Does the single-packet racer work over HTTP/1.1?**
The coalesced single-packet attack requires HTTP/2 over TLS. HTTP/1.1 last-byte
sync is on the roadmap.

**Where are HTTP/3 / the web dashboard / distributed mode?**
Shipped as clearly marked roadmap stubs so the core stays lean and fully tested.
