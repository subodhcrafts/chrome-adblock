const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

function ago(ts) {
  if (!ts) return "never";
  const m = Math.round((Date.now() - ts) / 60000);
  return m < 1 ? "just now" : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`;
}

function siteList(el, domains, buttonLabel, type) {
  el.replaceChildren();
  if (!domains.length) {
    el.innerHTML = '<div class="empty">None yet.</div>';
    return;
  }
  for (const d of domains) {
    const row = document.createElement("div");
    row.className = "site";
    const name = document.createElement("span");
    name.textContent = d;
    const btn = document.createElement("button");
    btn.textContent = buttonLabel;
    btn.onclick = async () => { await send({ type, domain: d }); render(); };
    row.append(name, btn);
    el.appendChild(row);
  }
}

async function render() {
  const s = await send({ type: "scamStatus" });
  $("scamProtection").checked = s.scamProtection;
  $("ruleError").textContent = s.ruleError ? `Chrome rejected the block rules: ${s.ruleError}` : "";

  const lists = $("lists");
  lists.replaceChildren();
  for (const l of s.lists) {
    const row = document.createElement("label");
    row.className = "list";
    row.innerHTML = `<input type="checkbox"><div><b></b><div class="meta"></div><div class="meta stats"></div><div class="err"></div></div>`;
    const box = row.querySelector("input");
    box.checked = l.enabled;
    box.onchange = async () => {
      $("status").textContent = "Applying…";
      await send({ type: "setScamSettings", scamLists: { ...s.scamLists, [l.id]: box.checked } });
      $("status").textContent = "";
      render();
    };
    row.querySelector("b").textContent = l.name;
    row.querySelector(".meta").textContent = l.about;
    row.querySelector(".stats").textContent = l.meta.count
      ? `${l.meta.count.toLocaleString()} domains · updated ${ago(l.meta.updated)}` : "not downloaded yet";
    row.querySelector(".err").textContent = l.meta.error ? `Last update failed: ${l.meta.error}` : "";
    lists.appendChild(row);
  }

  siteList($("userBlocked"), s.userBlocked, "Unblock", "unblockSite");
  siteList($("trusted"), s.trusted, "Remove", "untrustSite");
}

$("scamProtection").onchange = async (e) => {
  await send({ type: "setScamSettings", scamProtection: e.target.checked });
  render();
};

$("updateNow").onclick = async () => {
  $("updateNow").disabled = true;
  $("status").textContent = "Downloading lists…";
  await send({ type: "updateScamLists" });
  $("status").textContent = "Done.";
  $("updateNow").disabled = false;
  render();
};

$("addBtn").onclick = async () => {
  let d = $("addDomain").value.trim().toLowerCase();
  try { if (d.includes("/")) d = new URL(d.includes("://") ? d : `https://${d}`).hostname; } catch {}
  d = d.replace(/^www\./, "");
  if (!/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(d)) return alert("Enter a domain like example.com");
  await send({ type: "blockSite", domain: d });
  $("addDomain").value = "";
  render();
};

render();
