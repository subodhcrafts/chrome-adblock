importScripts("scam.js");

// Allowlisted sites get a high-priority allowAllRequests dynamic rule (IDs 10000-19999).
const ALLOW_RULE_BASE = 10000;

chrome.runtime.onInstalled.addListener(async () => {
  const { enabled } = await chrome.storage.local.get("enabled");
  if (enabled === undefined) await chrome.storage.local.set({ enabled: true, allowlist: [] });
  await chrome.declarativeNetRequest.setExtensionActionOptions({ displayActionCountAsBadgeText: true });
  await syncRules();
});

chrome.runtime.onStartup.addListener(syncRules);

async function syncRules() {
  const { enabled = true, allowlist = [] } = await chrome.storage.local.get(["enabled", "allowlist"]);

  await chrome.declarativeNetRequest.updateEnabledRulesets(
    enabled ? { enableRulesetIds: ["ads"] } : { disableRulesetIds: ["ads"] }
  );

  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.filter(r => r.id >= ALLOW_RULE_BASE && r.id < ALLOW_RULE_BASE + 10000).map(r => r.id),
    addRules: allowlist.map((domain, i) => ({
      id: ALLOW_RULE_BASE + i,
      priority: 100,
      action: { type: "allowAllRequests" },
      condition: { requestDomains: [domain], resourceTypes: ["main_frame", "sub_frame"] }
    }))
  });

  // Popup guard runs everywhere except allowlisted sites.
  await chrome.scripting.unregisterContentScripts({ ids: ["popup-guard"] }).catch(() => {});
  if (enabled) {
    await chrome.scripting.registerContentScripts([{
      id: "popup-guard",
      js: ["popup-guard.js"],
      matches: ["<all_urls>"],
      excludeMatches: allowlist.flatMap(d => [`*://${d}/*`, `*://*.${d}/*`]),
      runAt: "document_start",
      allFrames: true,
      matchOriginAsFallback: true,
      world: "MAIN"
    }]);
  }

  await chrome.action.setBadgeBackgroundColor({ color: enabled ? "#d32f2f" : "#888" });
}

// Backstop: close any new tab a page opens onto a known popunder network.
let popupDomains;
async function getPopupDomains() {
  if (!popupDomains) {
    const rules = await (await fetch(chrome.runtime.getURL("rules/ads.json"))).json();
    popupDomains = rules.find(r => r.id === 3).condition.requestDomains;
  }
  return popupDomains;
}

// Popunders often open about:blank first and redirect a moment later, so watch new tabs briefly.
const freshPopups = new Set();

async function closeIfPopupAd(tabId, url) {
  const { enabled = true } = await chrome.storage.local.get("enabled");
  if (!enabled) return;
  let host;
  try { host = new URL(url).hostname; } catch { return; }
  const domains = await getPopupDomains();
  if (domains.some(d => host === d || host.endsWith("." + d))) {
    freshPopups.delete(tabId);
    chrome.tabs.remove(tabId).catch(() => {});
  }
}

chrome.webNavigation.onCreatedNavigationTarget.addListener(({ tabId, url }) => {
  freshPopups.add(tabId);
  setTimeout(() => freshPopups.delete(tabId), 10000);
  closeIfPopupAd(tabId, url);
});

chrome.webNavigation.onBeforeNavigate.addListener(({ tabId, frameId, url }) => {
  if (frameId === 0 && freshPopups.has(tabId)) closeIfPopupAd(tabId, url);
});
