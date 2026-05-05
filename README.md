# BrokenBlade

**[zeroxjf.github.io/BrokenBlade](https://zeroxjf.github.io/BrokenBlade/)**

iPhone · iOS 18.0–18.3

---

## BETA — USE AT YOUR OWN RISK

This is an active beta of an experimental userland exploit chain. **Not for daily drivers.** Expect: page freezes, Safari crashes, repeated retries, SpringBoard crashes, and kernel panics. Back up before testing. Author is not liable for any damage or data loss.

---

## HOW TESTING WORKS

**The chain will fail for most runs right now.** I am iteratively improving it — every run uploads a log automatically (see Privacy below) and even failed runs help me move the chain forward. **Please run the chain a few times in a row.**

- Each tap of **Run** is one attempt. The chain is non-deterministic; sometimes a retry progresses further than the previous attempt.
- If the page barely freezes (under ~10 s) or the WebContent log stops well before *Starting check_attempt*, the chain didn’t make it past Safari’s setup. **Clear Safari cache** (Settings → Apps → Safari → Clear History and Website Data) and try again.
- If many tries in a row stall in the same place, **reboot the device** for a fresh kernel and Safari state, then try once more.

---

## PRIVACY — AUTO-UPLOAD

When you run the chain, your WebContent log auto-uploads to a private Cloudflare R2 bucket I control so I can debug failures. Stored fields: **build, iOS, user-agent, country, chain trace**. **No IP addresses or personal identifiers are kept.** Logs auto-delete after 30 days. [See exact sample](docs/sample-weblog.txt) · [Worker source](log-worker/worker.js).
