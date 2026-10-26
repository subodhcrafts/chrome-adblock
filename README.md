# Simple AdBlock

A lightweight Manifest V3 ad, pop-up and scam blocker for Chrome.

## Features

- **Ad & tracker blocking** with `declarativeNetRequest` rules (`rules/ads.json`) plus cosmetic hiding of common ad containers.
- **Pop-up / popunder blocking**: stops scripts opening cross-site tabs (including via fresh iframes and fake link clicks) and closes tabs that land on known pop-up ad networks.
- **Scam overlay removal**: removes floating "Install Ad Blocker Pro", fake virus and "click Allow" overlays, including ones built inside `srcdoc` iframes and shadow DOM.
- **Scam protection**
  - Downloads public threat lists every 12 hours (HaGeZi Pop-Up Ads & Fake, uBlock Origin Badware, Phishing Filter, URLhaus Malware Filter; optional HaGeZi Threat Intelligence) and redirects listed sites to a warning page.
  - Scores unknown pages for scam signals (scam wording, opened as a pop-up, instant notification prompts, suspicious TLDs/bait words, ad-network tracking URLs) and offers to block the site.
  - Your own block and trust lists, managed from the popup and the settings page.
- Per-site allowlist and global on/off toggle.

## Install

1. Open `chrome://extensions` and enable **Developer mode**.
2. Click **Load unpacked** and pick this folder.
3. Optional: under the extension's **Details**, enable **Allow in Incognito**.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | Extension manifest |
| `background.js` | Ad allowlist rules, pop-up tab closing |
| `scam.js` | Threat-list download, scam block/trust rules, messaging |
| `rules/ads.json` | Static ad/tracker/pop-up network rules |
| `content.js` | Cosmetic filtering and scam overlay removal |
| `popup-guard.js` | Main-world pop-up blocker and scam signals |
| `scam-detect.js` | Per-page scam scoring and the block prompt |
| `blocked.html/js` | Warning page for blocked sites |
| `popup.html/js` | Toolbar popup |
| `options.html/js` | Settings: lists, blocked and trusted sites |
