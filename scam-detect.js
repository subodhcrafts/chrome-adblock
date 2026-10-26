// Scores the current page for scam signals and, past a threshold, offers to block the site.
(() => {
  const THRESHOLD = 4;

  const TEXT_SIGNALS = [
    [/install\s+["“]?[^"”\n]{0,40}["”]?\s*(browser\s+)?extension/i, 3, "Pushes you to install a browser extension"],
    [/(computer|device|phone|pc|mac|iphone|android)\s+(is|may be|has been)\s+(infected|hacked|compromised|damaged)/i, 3, "Fake virus / infection warning"],
    [/\b\d+\s+(viruses|threats|trojans)\s+(were\s+)?(found|detected)/i, 3, "Fake virus / infection warning"],
    [/(press|click|tap)\s+["“]?allow["”]?\s+(to|if)\s+/i, 3, "Tricks you into allowing notifications"],
    [/(windows\s*(key)?\s*\+\s*r|win\s*\+\s*r)\b[\s\S]{0,200}(ctrl\s*\+\s*v|paste)/i, 4, "Fake CAPTCHA asking you to run a command"],
    [/(call|contact)\s+(microsoft|apple|windows|amazon)\s+(support|technician|helpline)/i, 3, "Fake tech-support number"],
    [/congratulations[\s\S]{0,80}you('ve|\s+have)\s+(won|been selected)|lucky\s+(winner|visitor)/i, 3, "Fake prize / giveaway"],
    [/(send|deposit)\s[\s\S]{0,40}(btc|eth|usdt|bitcoin)[\s\S]{0,80}(double|x2|receive\s+back)/i, 4, "Crypto doubling scam"],
    [/your\s+(subscription|license|antivirus|mcafee|norton)[\s\S]{0,30}(has\s+)?expired/i, 3, "Fake expired-antivirus warning"]
  ];
  const BAD_TLDS = /\.(cyou|xyz|top|click|buzz|icu|sbs|cfd|rest|monster|quest|autos|lol|bond|mom|info|online|site|live|shop|pro|space|website|fun)$/;
  const BAIT_WORDS = /(ad-?block|antivirus|security|update|captcha|verify|prize|winner|reward|giveaway|cleaner|booster|driver|flash-?player|support)/;
  const TRACKING_PARAMS = /^(clickid|click_id|subid|sub_id|zoneid|zone_id|lp|campaign_?id|bannerid|var|source|fr|fu|fy|ft|fx)$/i;

  const host = location.hostname.replace(/^www\./, "");

  function pageText() {
    let text = (document.body?.innerText || "").slice(0, 20000);
    for (const f of document.querySelectorAll("iframe[srcdoc]")) {
      text += " " + f.srcdoc.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ");
    }
    return text;
  }

  function score(ctx) {
    const reasons = [];
    let total = 0;
    const add = (w, why) => { if (!reasons.includes(why)) { total += w; reasons.push(why); } };

    const text = pageText();
    for (const [re, w, why] of TEXT_SIGNALS) if (re.test(text)) add(w, why);
    if (ctx.openedAsPopup) add(2, "Opened by another site as a pop-up");
    const signals = document.documentElement.dataset.sabSignals || "";
    if (signals.includes("notification")) add(2, "Asked for notification permission as soon as it loaded");
    if (BAD_TLDS.test(host)) add(1, `Uses a domain ending (.${host.split(".").pop()}) common in scams`);
    if (BAIT_WORDS.test(host)) add(1, "Domain name uses bait words (e.g. adblock, security, update)");
    const params = [...new URLSearchParams(location.search).keys()];
    if (params.length >= 4 && params.filter(p => TRACKING_PARAMS.test(p)).length >= 2) add(1, "URL carries ad-network tracking parameters");

    return { total, reasons };
  }

  function showPrompt(domain, reasons) {
    if (document.getElementById("simple-adblock-scam-prompt")) return;
    const host = document.createElement("div");
    host.id = "simple-adblock-scam-prompt";
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `
      <style>
        .box { position: fixed; top: 16px; right: 16px; z-index: 2147483647; width: min(360px, calc(100vw - 32px));
               background: #fff; color: #222; border-left: 5px solid #d32f2f; border-radius: 8px;
               box-shadow: 0 6px 24px rgba(0,0,0,.35); font: 13px/1.45 system-ui, sans-serif; padding: 14px 16px; }
        h2 { margin: 0 0 6px; font-size: 15px; color: #b71c1c; }
        ul { margin: 6px 0 12px; padding-left: 18px; }
        .row { display: flex; gap: 8px; }
        button { flex: 1; padding: 8px; border: 0; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 13px; }
        .block { background: #d32f2f; color: #fff; }
        .safe { background: #eee; color: #333; }
        .x { position: absolute; top: 6px; right: 8px; flex: none; background: none; font-size: 18px; color: #888; padding: 2px 6px; }
      </style>
      <div class="box" role="alertdialog" aria-label="Possible scam site">
        <button class="x" title="Dismiss">×</button>
        <h2>⚠ This looks like a scam site</h2>
        <div><b></b> shows these warning signs:</div>
        <ul></ul>
        <div class="row">
          <button class="block">Block this site</button>
          <button class="safe">It's safe</button>
        </div>
      </div>`;
    root.querySelector("b").textContent = domain;
    const ul = root.querySelector("ul");
    for (const r of reasons) { const li = document.createElement("li"); li.textContent = r; ul.appendChild(li); }

    root.querySelector(".block").onclick = () => chrome.runtime.sendMessage({ type: "blockSite", domain, redirect: true });
    root.querySelector(".safe").onclick = () => { chrome.runtime.sendMessage({ type: "trustSite", domain }); host.remove(); };
    root.querySelector(".x").onclick = () => {
      try { sessionStorage.setItem("sab-dismissed", "1"); } catch {}
      host.remove();
    };
    document.documentElement.appendChild(host);
  }

  function baseDomain(h) {
    const parts = h.split(".");
    const n = parts.length >= 3 && parts.at(-1).length === 2 && parts.at(-2).length <= 3 ? 3 : 2;
    return parts.slice(-n).join(".");
  }

  async function run() {
    try { if (sessionStorage.getItem("sab-dismissed")) return; } catch {}
    const ctx = await chrome.runtime.sendMessage({ type: "pageContext" });
    if (!ctx || ctx.error || !ctx.scamProtection || ctx.trusted) return;

    // Scam pages often build themselves after load, so check a few times.
    for (const delay of [0, 2000, 5000]) {
      await new Promise(r => setTimeout(r, delay));
      const { total, reasons } = score(ctx);
      if (total >= THRESHOLD) return showPrompt(baseDomain(host), reasons);
    }
  }

  if (/^https?:$/.test(location.protocol)) run();
})();
