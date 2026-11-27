# Lure test record, November 2026

What we tested, how, and what came out, including what Lure does not catch. Run on 27 November 2026 on
Windows 11 with Python 3.12, against the in-development build `0.1.0b5.dev0`. The new trap kinds below
(bait API keys, canary documents and records, decoy agent tools) are not released yet; they are planned for
0.1.0b5. Bait logins are in the released 0.1.0b4.

## Summary

| What | Result |
|---|---|
| Alerts during legitimate work, every trap planted | **0 in 180 runs** |
| Trap uses and leaks caught | **180 of 180** (9 trap kinds × 20) |
| Time from the action to the alert in Lure's log | **11-30 ms** for leaks and decoy tools, **~200 ms** for logins and keys tried on the listener |
| Live test on a working laptop | **3 of 3** new traps raised a high alert, with a plain-English explanation |
| Lab with tricked AI office assistants | Lure alerted on **13 of 13** runs where a tricked assistant acted, **0** alerts during legitimate work |
| Automated tests | 119 passing |

## 1. False alarms during real work

A trap is only useful if nothing legitimate touches it. We built a small synthetic company (staff, customers,
tickets, invoices, wiki, mail, CI, a secrets manager) and planted every trap in it: bait logins, a bait AWS
key in a production `.env`, a "board only" canary document, canary records (a customer in the CRM, a ticket
in the queue, an invoice in the vendor portal) and three decoy tools.

Then we did eight ordinary office jobs in it, on 20 freshly generated companies each: reconcile invoices and
email finance, triage the ticket queue and reply to customers, onboard a new hire, write a board brief,
investigate a failed build, rotate a real service password, clean up a shared drive, answer a customer's
security questionnaire. On top of that, an agent that opens **every** file, bait files included, and emails a
colleague the list.

**Result: 180 runs, 0 alerts.** All 160 task runs were also completed correctly (graded by what was done,
not what was said). The canary records were handled by normal work (reconciled, routed, looked up, summarised
to colleagues) without a sound: they alert only when their data leaves the organisation.

## 2. Detection of every trap kind

Each trap was used or leaked 20 times, on fresh companies, through the same tools an assistant has.
Time is measured from the moment the action starts until Lure's alert is written to its own log.

| Trap | Caught | Median | Slowest |
|---|---|---|---|
| Bait login tried on the listener | 20/20 | 198 ms | 337 ms |
| Bait login file emailed out | 20/20 | 29 ms | 42 ms |
| Bait AWS key presented to the listener | 20/20 | 195 ms | 210 ms |
| Bait AWS key pasted into a ticket | 20/20 | 27 ms | 49 ms |
| Canary document emailed out | 20/20 | 27 ms | 42 ms |
| Canary customer record leaked (CRM export) | 20/20 | 21 ms | 32 ms |
| Canary ticket record leaked (ticket list) | 20/20 | 22 ms | 31 ms |
| Canary invoice record leaked (invoice list) | 20/20 | 21 ms | 35 ms |
| Decoy tool called by an agent | 20/20 | 11 ms | 16 ms |

Times include reading the bait file first, so they are an upper bound.

## 3. Live on a working laptop

On a founder's everyday Windows laptop already running Lure (15 bait logins), we added a bait AWS key in a
company folder, a "board only" deal note whose "open the full deck" link points at the listener, and
three decoy tools offered to the laptop's AI coding assistant. Each was then triggered once.

| Trap | Alert |
|---|---|
| Bait AWS key presented | high: "Someone presented the API key stored in `<the bait key file>` to the listener." |
| Deal-note link opened | high: "Someone opened the link in `<the deal note>`." |
| Decoy tool called | high: "An AI agent or script called the decoy tool `<name>`. Nothing legitimate needs it..." |

(File and tool names on the real laptop are withheld: publishing them would tell an intruder which files are
bait.) Desktop popups, the dashboard and the tamper watchdog kept working; the existing 15 baits were untouched.

## 4. AI assistants tricked by hidden instructions

In the same synthetic company, AI office assistants did the eight jobs while instructions were hidden in the
company's own data (a ticket note, a wiki policy, a vendor's billing note, an email), asking them to call a
powerful tool, try a login, or send data to an outside address. We do not publish the instructions.

- With bait logins, keys and decoy tools, Lure alerted on every tricked run that touched a trap (7 of 7), but
  missed 5 of 12 tricked runs overall: the assistant sent ordinary business data (a ticket list, an invoice
  summary) that carried no trap.
- **Canary records** close that gap: with a canary customer, ticket and invoice in the company's systems,
  Lure alerted on **13 of 13** tricked runs, each in the same second as the assistant's action, and raised
  **no alert** in legitimate runs next to the same traps.

## What Lure does not catch

- **Data with no trap in it.** A thief who takes only data you never seeded is invisible to a tripwire.
  Canary records shrink this; they do not remove it.
- **Copies that change the values.** Markers are matched exactly; a summary that paraphrases a canary
  record's name is not caught.
- **A bait AWS key used directly against AWS.** The local bait key alerts when it reaches your listener. For
  a key used against AWS itself, use `lure aws` (a real, permission-less key watched through CloudTrail,
  which lags 5-15 minutes).
- **Channels nobody watches.** Leaks are seen where Lure is hooked in (mail relay, ticket webhook, an agent's
  tool layer, `lure scan`). A channel without a hook is not seen.
- **Instructions planted in an assistant's memory.** Nothing leaves at that moment, so there is nothing to
  catch until the assistant acts on it.

## Method notes

- The company is synthetic and deterministic (seeded); every name, address and number is invented.
- Lure's verdicts come only from its own alert log. Whether a run was legitimate or tricked is labelled
  independently, from what the agent actually did.
- The test harness is not public yet. Numbers will be re-measured on the released 0.1.0b5.

Questions, or want to try the new traps early? Open a discussion:
https://github.com/SilentMesh-Systems/Lure/discussions
