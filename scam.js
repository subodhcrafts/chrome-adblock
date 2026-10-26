// Scam protection: public threat lists + your own block/trust lists, enforced as dynamic DNR rules.
// Dynamic rule IDs: 10000-19999 belong to the ad allowlist (background.js), 20000+ to this file.

const SCAM_LISTS = {
  popupads: {
    name: "HaGeZi Pop-Up Ads",
    about: "Pop-up / redirect ad networks and their landing pages",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
    format: "domains", enabled: true
  },
  fake: {
    name: "HaGeZi Fake",
    about: "Fake shops, fake support, scam and fraud sites",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
    format: "domains", enabled: true
  },
  badware: {
    name: "uBlock Origin Badware",
    about: "Fake ad blockers, adware installers and other badware",
    url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    format: "adblock", enabled: true
  },
  phishing: {
    name: "Phishing Filter",
    about: "Phishing sites (OpenPhish, PhishTank, PhishStats)",
    url: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
    format: "domains", enabled: true
  },
  urlhaus: {
    name: "URLhaus Malware Filter",
    about: "Sites distributing malware (abuse.ch URLhaus)",
    url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
    format: "domains", enabled: true
  },
  tif: {
    name: "HaGeZi Threat Intelligence (mini)",
    about: "Large combined threat feed, ~210k domains",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
    format: "domains", enabled: false
  }
};

const TRUST_RULE_ID = 20000;
const LIST_RULE_BASE = 100000;
const CHUNK = 5000;
const UPDATE_EVERY_MIN = 12 * 60;
const ALL_TYPES = ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object",
  "xmlhttprequest", "ping", "media", "websocket", "webtransport", "webbundle", "other"];
const ADBLOCK_OPTS = new Set(["", "doc", "document", "all", "popup", "important", "third-party", "3p", "1p", "first-party"]);

// "fd01ce9a02.0012e30263.com" -> "0012e30263.com", "a.b.co.uk" -> "b.co.uk"
function baseDomain(host) {
  const parts = host.replace(/^www\./, "").split(".");
  const n = parts.length >= 3 && parts.at(-1).length === 2 && parts.at(-2).length <= 3 ? 3 : 2;
  return parts.slice(-n).join(".");
}

function parseList(text, format) {
  const out = new Set();
  for (let line of text.split("\n")) {
    line = line.trim().toLowerCase();
    if (!line || line[0] === "#" || line[0] === "!") continue;
    if (format === "adblock") {
      const m = line.match(/^\|\|([a-z0-9.-]+\.[a-z0-9-]{2,})\^(?:\$(.*))?$/);
      if (m && (m[2] || "").split(",").every(o => ADBLOCK_OPTS.has(o.replace(/^~/, "")))) out.add(m[1]);
    } else if (/^[a-z0-9_.-]+\.[a-z0-9-]{2,}$/.test(line)) {
      out.add(line);
    }
  }
  return [...out];
}

async function getScamSettings() {
  const s = await chrome.storage.local.get(["scamProtection", "scamLists", "userBlocked", "trusted", "scamMeta"]);
  const lists = {};
  for (const [id, l] of Object.entries(SCAM_LISTS)) lists[id] = s.scamLists?.[id] ?? l.enabled;
  return {
    scamProtection: s.scamProtection !== false,
    scamLists: lists,
    userBlocked: s.userBlocked || [],
    trusted: s.trusted || [],
    scamMeta: s.scamMeta || {}
  };
}

async function updateScamLists(force = false) {
  const { scamLists, scamMeta } = await getScamSettings();
  for (const [id, list] of Object.entries(SCAM_LISTS)) {
    if (!scamLists[id]) continue;
    const meta = scamMeta[id] || {};
    if (!force && meta.updated && Date.now() - meta.updated < UPDATE_EVERY_MIN * 60000) continue;
    try {
      const res = await fetch(list.url, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const domains = parseList(await res.text(), list.format);
      if (!domains.length) throw new Error("list was empty");
      await chrome.storage.local.set({ [`list:${id}`]: domains });
      scamMeta[id] = { count: domains.length, updated: Date.now() };
    } catch (e) {
      scamMeta[id] = { ...meta, error: `${e.message} (${new Date().toLocaleString()})` };
    }
  }
  await chrome.storage.local.set({ scamMeta });
  return rebuildScamRules();
}

async function rebuildScamRules() {
  const s = await getScamSettings();
  const rules = [];

  if (s.scamProtection) {
    if (s.trusted.length) {
      rules.push({
        id: TRUST_RULE_ID, priority: 300, action: { type: "allow" },
        condition: { requestDomains: s.trusted, resourceTypes: ALL_TYPES }
      });
    }

    const warnPage = chrome.runtime.getURL("blocked.html");
    let id = LIST_RULE_BASE;
    const seen = new Set();
    const addSource = (domains, source) => {
      const fresh = domains.filter(d => !seen.has(d) && seen.add(d));
      for (let i = 0; i < fresh.length; i += CHUNK) {
        const chunk = fresh.slice(i, i + CHUNK);
        // Pages: send to our warning page (original URL kept in the hash). Everything else: block.
        rules.push({
          id: id++, priority: 200,
          action: { type: "redirect", redirect: { regexSubstitution: `${warnPage}?src=${source}#\\0` } },
          condition: { regexFilter: "^.+$", requestDomains: chunk, resourceTypes: ["main_frame"] }
        }, {
          id: id++, priority: 200, action: { type: "block" },
          condition: { requestDomains: chunk, resourceTypes: ALL_TYPES.filter(t => t !== "main_frame") }
        });
      }
    };

    addSource(s.userBlocked, "you");
    for (const [listId, on] of Object.entries(s.scamLists)) {
      if (!on) continue;
      const stored = await chrome.storage.local.get(`list:${listId}`);
      addSource(stored[`list:${listId}`] || [], listId);
    }
  }

  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.filter(r => r.id >= TRUST_RULE_ID).map(r => r.id),
      addRules: rules
    });
    await chrome.storage.local.set({ scamRuleError: null });
  } catch (e) {
    console.error("[Simple AdBlock] could not apply scam rules:", e);
    await chrome.storage.local.set({ scamRuleError: e.message });
  }
}

async function addToList(key, domain) {
  const cur = (await chrome.storage.local.get(key))[key] || [];
  if (!cur.includes(domain)) await chrome.storage.local.set({ [key]: [...cur, domain] });
}

async function removeFromList(key, domain) {
  const cur = (await chrome.storage.local.get(key))[key] || [];
  await chrome.storage.local.set({ [key]: cur.filter(d => d !== domain) });
}

// Remember tabs that another site opened, so the page can count "opened as a pop-up" as a scam signal.
chrome.webNavigation.onCreatedNavigationTarget.addListener(async ({ tabId, sourceTabId }) => {
  let sourceHost = "";
  try { sourceHost = new URL((await chrome.tabs.get(sourceTabId)).url).hostname; } catch {}
  chrome.storage.session.set({ [`popup:${tabId}`]: { at: Date.now(), sourceHost } });
});

chrome.tabs.onRemoved.addListener(tabId => chrome.storage.session.remove(`popup:${tabId}`));

const scamHandlers = {
  async pageContext(msg, sender) {
    const s = await getScamSettings();
    const host = new URL(sender.tab.url).hostname;
    const domain = baseDomain(host);
    const popup = (await chrome.storage.session.get(`popup:${sender.tab.id}`))[`popup:${sender.tab.id}`];
    return {
      scamProtection: s.scamProtection,
      trusted: s.trusted.some(d => host === d || host.endsWith("." + d)),
      openedAsPopup: !!popup && Date.now() - popup.at < 60000 &&
        (!popup.sourceHost || baseDomain(popup.sourceHost) !== domain)
    };
  },
  // tabId (from the popup) or redirect:true (from the page itself) sends that tab to the warning page.
  async blockSite({ domain, tabId, redirect }, sender) {
    await removeFromList("trusted", domain);
    await addToList("userBlocked", domain);
    await rebuildScamRules();
    const tab = tabId ? await chrome.tabs.get(tabId) : redirect && sender.tab;
    if (tab) {
      const url = `${chrome.runtime.getURL("blocked.html")}?src=you#${tab.url}`;
      chrome.tabs.update(tab.id, { url });
    }
    return true;
  },
  async trustSite({ domain }) {
    await removeFromList("userBlocked", domain);
    await addToList("trusted", domain);
    await rebuildScamRules();
    return true;
  },
  async unblockSite({ domain }) { await removeFromList("userBlocked", domain); await rebuildScamRules(); return true; },
  async untrustSite({ domain }) { await removeFromList("trusted", domain); await rebuildScamRules(); return true; },
  async scamStatus() {
    const s = await getScamSettings();
    const { scamRuleError } = await chrome.storage.local.get("scamRuleError");
    const lists = Object.entries(SCAM_LISTS).map(([id, l]) => ({ id, ...l, enabled: s.scamLists[id], meta: s.scamMeta[id] || {} }));
    return { ...s, lists, ruleError: scamRuleError };
  },
  async setScamSettings({ scamProtection, scamLists }) {
    const patch = {};
    if (scamProtection !== undefined) patch.scamProtection = scamProtection;
    if (scamLists) patch.scamLists = scamLists;
    await chrome.storage.local.set(patch);
    return updateScamLists(false); // fetches any newly enabled list, then rebuilds
  },
  updateScamLists: () => updateScamLists(true)
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = msg && scamHandlers[msg.type];
  if (!handler) return;
  handler(msg, sender).then(sendResponse, e => sendResponse({ error: e.message }));
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("scam-update", { periodInMinutes: UPDATE_EVERY_MIN });
  updateScamLists(false);
});

chrome.runtime.onStartup.addListener(() => updateScamLists(false));

chrome.alarms.onAlarm.addListener(a => { if (a.name === "scam-update") updateScamLists(false); });
