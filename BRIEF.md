# Research Project: Replace Tizen with Android on a Samsung Smart TV

Owner: liewjiajun · Started 2026-10-19
Goal: determine whether, and how, a Samsung Tizen smart TV can be made to run Android.

Hardware: on the same LAN as the test host. Model number UNKNOWN as of start.
Not yet reachable on LAN (full sweep found no Samsung responders — TV likely off or on another VLAN).

Established prior research (2026-10-19, see ~/clawd/memory/2026-10-19.md):
- tv-vibehack (Android debloat tool) does NOT apply: Tizen has no ADB, no pm/launcher intents.
- Root on Tizen IS now achievable (public chain as of Aug 2026):
  chris-ritsen/samsung-tv-root (archive-root, QN90B/QN90F) and
  DemonKingSwarn/samsung-tv-tizen-root (reproduction on QA55QEF1AULXL, Tizen 9.0.0, platform "rosel").
- Root alone does not give Android. This project asks the harder question.

Research lanes:
  01 hardware + boot chain      → research/01-hardware-bootchain.md
  02 prior art (anyone done it?) → research/02-prior-art.md
  03 Android userspace on rooted Tizen kernel → research/03-userspace-on-rooted-kernel.md

Method note: web_search provider was returning HTTP 402 this session; lanes use web_fetch +
DuckDuckGo HTML endpoints + GitHub API via curl.
