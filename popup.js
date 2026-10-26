const enabledEl = document.getElementById("enabled");
const hostEl = document.getElementById("host");
const siteBtn = document.getElementById("siteBtn");

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let host = "";
  try { host = new URL(tab.url).hostname.replace(/^www\./, ""); } catch {}

  const { enabled = true, allowlist = [] } = await chrome.storage.local.get(["enabled", "allowlist"]);
  enabledEl.checked = enabled;

  const render = (list) => {
    const allowed = list.includes(host);
    hostEl.textContent = host || "(no site)";
    siteBtn.textContent = allowed ? "Block ads on this site" : "Allow ads on this site";
    siteBtn.disabled = !host;
  };
  render(allowlist);

  enabledEl.addEventListener("change", async () => {
    await chrome.storage.local.set({ enabled: enabledEl.checked });
    await chrome.runtime.sendMessage("sync");
    chrome.tabs.reload(tab.id);
  });

  siteBtn.addEventListener("click", async () => {
    const { allowlist = [] } = await chrome.storage.local.get("allowlist");
    const next = allowlist.includes(host) ? allowlist.filter(d => d !== host) : [...allowlist, host];
    await chrome.storage.local.set({ allowlist: next });
    await chrome.runtime.sendMessage("sync");
    render(next);
    chrome.tabs.reload(tab.id);
  });

  // Scam protection
  const scamBtn = document.getElementById("scamBtn");
  const s = await chrome.runtime.sendMessage({ type: "scamStatus" });
  const total = s.lists.filter(l => l.enabled).reduce((n, l) => n + (l.meta.count || 0), 0);
  document.getElementById("scamState").textContent = s.scamProtection ? "On" : "Off";
  document.getElementById("scamInfo").textContent = s.scamProtection
    ? `${total.toLocaleString()} known scam domains + ${s.userBlocked.length} you blocked` : "";
  scamBtn.disabled = !host || !/^https?:/.test(tab.url);
  scamBtn.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "blockSite", domain: host, tabId: tab.id });
    window.close();
  });
  document.getElementById("settings").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
})();
