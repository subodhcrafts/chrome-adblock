// Cosmetic filtering: hide common ad containers that slip past network blocking.
const SELECTORS = [
  "ins.adsbygoogle", "[id^='google_ads_']", "[id^='div-gpt-ad']", "[data-ad-slot]",
  "[data-google-query-id]", "iframe[src*='doubleclick.net']", "iframe[id^='google_ads_iframe']",
  ".adsbox", ".ad-banner", ".ad-container", ".ad-slot", ".ad-wrapper", ".advert",
  ".advertisement", ".sponsored-content", ".taboola", "[id^='taboola-']",
  ".OUTBRAIN", "[data-widget-id^='outbrain']", "#carbonads", ".trc_rbox_container",
  "[aria-label='Advertisement']", "[class*='AdSlot']"
];

(async () => {
  const { enabled = true, allowlist = [] } = await chrome.storage.local.get(["enabled", "allowlist"]);
  let host;
  try { host = window.top.location.hostname; } catch { host = location.hostname; }
  if (!enabled || allowlist.some(d => host === d || host.endsWith("." + d))) return;

  const style = document.createElement("style");
  style.id = "simple-adblock-css";
  style.textContent = `${SELECTORS.join(",\n")} { display: none !important; }`;
  (document.head || document.documentElement).appendChild(style);

  startOverlayKiller();
})();

// Scam overlays ("Install Ad Blocker Pro", fake virus alerts, notification bait)
// use random class names, so match them by text and by being a floating layer.
const SCAM_TEXT = [
  /install\s+["“]?.{0,40}["”]?\s*(browser\s+)?extension/i,
  /\badd\s+extension\b/i,
  /available\s+in\s+the\s*chrome\s+web\s+store/i,
  /your\s+(computer|device|phone)\s+(is|may be)\s+infected/i,
  /click\s+["“]?allow["”]?\s+to\s+(continue|confirm|watch)/i,
  /\bvirus(es)?\s+(detected|found)\b/i
];

// Walk up to the outermost fixed/sticky ancestor, crossing shadow-root boundaries.
function isFloating(el) {
  let found = null;
  for (let n = el; n && n !== document.body && n !== document.documentElement;
       n = n.parentElement || (n.getRootNode() instanceof ShadowRoot ? n.getRootNode().host : null)) {
    const pos = getComputedStyle(n).position;
    if (pos === "fixed" || pos === "sticky") found = n;
  }
  return found;
}

// All elements matching a selector, including inside (open) shadow roots.
function deepQuery(root, selector, out = []) {
  out.push(...root.querySelectorAll(selector));
  for (const el of root.querySelectorAll("*")) if (el.shadowRoot) deepQuery(el.shadowRoot, selector, out);
  return out;
}

// Ad frames that carry their whole page in srcdoc (e.g. the "Ad Blocker Pro" box) are readable from here.
function scanSrcdocFrames() {
  for (const frame of deepQuery(document, "iframe[srcdoc]")) {
    const text = frame.srcdoc.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ");
    if (!SCAM_TEXT.some(re => re.test(text))) continue;
    const layer = isFloating(frame) || frame;
    console.debug("[Simple AdBlock] removed scam srcdoc frame:", layer);
    layer.remove();
    unlockScroll();
  }
}

// Text of an element including anything inside (open) shadow roots.
function textOf(el) {
  let text = el.textContent || "";
  const walk = (node) => {
    for (const child of node.querySelectorAll("*")) {
      if (child.shadowRoot) { text += " " + child.shadowRoot.textContent; walk(child.shadowRoot); }
    }
  };
  if (el.shadowRoot) { text += " " + el.shadowRoot.textContent; walk(el.shadowRoot); }
  walk(el);
  return text;
}

const isScam = (text) => text.length < 5000 && SCAM_TEXT.some(re => re.test(text));

function unlockScroll() {
  document.documentElement.style.removeProperty("overflow");
  document.body && document.body.style.removeProperty("overflow");
}

function scan(root) {
  if (!(root instanceof HTMLElement) || root.id === "simple-adblock-css") return;
  if (!isScam(textOf(root))) return;
  // Only remove floating layers, so normal page text that mentions extensions is never touched.
  const layer = isFloating(root) || (getComputedStyle(root).position === "absolute" && root);
  if (!layer) return;
  console.debug("[Simple AdBlock] removed scam overlay:", layer);
  layer.remove();
  unlockScroll();
}

function scanFloatingLayers() {
  scanSrcdocFrames();
  if (!document.body) return;
  for (const el of deepQuery(document.body, "*")) {
    const pos = getComputedStyle(el).position;
    if (pos === "fixed" || (pos === "absolute" && +getComputedStyle(el).zIndex > 10)) scan(el);
  }
}

function startOverlayKiller() {
  // Inside an ad iframe: if it's a scam, ask the parent page to remove this frame.
  if (window !== window.top) {
    const check = () => {
      if (document.body && isScam(textOf(document.body))) {
        document.body.replaceChildren();
        parent.postMessage({ simpleAdblockRemoveFrame: true }, "*");
      }
    };
    new MutationObserver(check).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
    return;
  }

  window.addEventListener("message", (e) => {
    if (!e.data || !e.data.simpleAdblockRemoveFrame) return;
    for (const frame of document.querySelectorAll("iframe, frame")) {
      if (frame.contentWindow === e.source) {
        console.debug("[Simple AdBlock] removed scam frame:", frame);
        (isFloating(frame) || frame).remove();
        unlockScroll();
      }
    }
  });

  // Rescan on any DOM, style or class change (overlays are often added hidden and shown later).
  let pending = false;
  new MutationObserver((mutations) => {
    for (const m of mutations) for (const n of m.addedNodes) scan(n);
    if (!pending) {
      pending = true;
      setTimeout(() => { pending = false; scanFloatingLayers(); }, 300);
    }
  }).observe(document.documentElement, {
    childList: true, subtree: true, attributes: true, attributeFilter: ["style", "class", "hidden"]
  });
}
