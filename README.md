<!-- banner --><a href="https://github.com/kenmwara"><img src="https://raw.githubusercontent.com/kenmwara/kenmwara/main/assets/brand/card-tor.png?v=bee27ad413" width="100%" alt="Unauthorized Tor: A portable Tor Browser on a lab endpoint, hunted back out of Defender telemetry and an investigation package. 3 Tor relays traced on 443."></a>

# Unauthorized Tor: hidden browsing on a test computer

**A Cyber Range exercise: the Tor Browser, which hides where its user goes online, was run on a dedicated test computer, then traced back out of Microsoft Defender's security logs as if on a real company laptop. The logs showed the download, the install, and the three-relay hidden connection over a normal web port. What they could not show, by design, is which sites were visited.**

**Analyst:** Ken Kariuki · **Date:** 26 September 2026 · **Tools:** Microsoft Defender for Endpoint, KQL (Microsoft's log search language)

## Key takeaways

<img src="images/scorecard.png" width="100%" alt="Key takeaways. Hidden web browsing on a test computer, traced from security logs. 3: Hops to hide the traffic. The Tor browser sent the traffic through three relays, over a normal web port. ≈1 h 40 m: How long it ran. From about 05:41 to 07:21 UTC. 0: Websites that can be named. Tor hides which sites were visited, and the computer kept no trace of them. 3: Kinds of evidence combined. File, program and network records, plus a full evidence package from the computer.">

## How the attack unfolded

<img src="images/story.png" width="100%" alt="Unauthorized Tor: how the attack unfolded. 26 September 2026, times in UTC. One test computer, one user account. 05:40 – 05:41, The download: 05:40 · The user downloads the portable Tor Browser; 05:41 · Runs the installer; the files land on the Desktop. 05:41, Hidden browsing starts: 05:41 · The browser starts; 05:41 · Tor connects through three relays, over the normal web port (443). 05:45 – 07:21, Evidence kept: 05:45 · The analyst collects an evidence package from Defender; 07:21 · The browser is closed.">

## What went wrong, and the fix

<img src="images/gaps.png" width="100%" alt="What went wrong, and how to fix it. What went wrong: Rules that watch for Tor's usual ports. Why it mattered: All the traffic used the normal web port, so they missed it. The fix: Watch for the Tor program itself, how it was started, and known relay addresses. What went wrong: The installed-software list missed it. Why it mattered: The portable version installs nothing Windows tracks. The fix: Use program-run records, which caught it. What went wrong: Web-lookup (DNS) logs were blind. Why it mattered: Tor does its own lookups inside the encrypted link. The fix: Don't rely on DNS logs to spot Tor.">

## What to do now

1. Tor use confirmed on the test computer; management would get this report.
2. Evidence kept: a Defender investigation package collected at 05:45.
3. In a real company: isolate the computer while the user is interviewed, remove the Tor Browser folder, and block unsigned programs from running out of user folders (WDAC or AppLocker).

## The full report

This page is the short version. The full incident report covers the hunt's method, every finding with its evidence,
the attacker techniques seen (MITRE ATT&CK), the new alert rules and how they were tested, and the indicators.

- **[The full report (REPORT.md)](REPORT.md)**, readable on GitHub.

---

*More hunts: [kenmwara/threat-hunts](https://github.com/kenmwara/threat-hunts).*
