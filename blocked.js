const target = location.hash.slice(1);
const src = new URLSearchParams(location.search).get("src");
let host = "";
try { host = new URL(target).hostname; } catch {}

// Trust only the exact host that was blocked, not its whole parent domain.
const domain = host.replace(/^www\./, "");
document.getElementById("host").textContent = host || "(unknown)";

(async () => {
  const status = await chrome.runtime.sendMessage({ type: "scamStatus" });
  const list = status.lists.find(l => l.id === src);
  document.getElementById("why").textContent = src === "you"
    ? "You added this site to your block list."
    : `It is listed in "${list ? list.name : src}" — ${list ? list.about.toLowerCase() : "a public threat list"}.`;
})();

document.getElementById("back").onclick = async () => {
  if (history.length > 1) return history.back();
  const tab = await chrome.tabs.getCurrent();
  chrome.tabs.remove(tab.id);
};

document.getElementById("proceed").onclick = async () => {
  if (!host) return;
  await chrome.runtime.sendMessage({ type: "trustSite", domain });
  location.replace(target);
};
