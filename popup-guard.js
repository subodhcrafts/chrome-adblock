// Runs in the page's MAIN world. Blocks script-opened cross-site windows/tabs
// (popups/popunders) while leaving normal link clicks and sign-in popups alone.
(() => {
  const AUTH_HOSTS = [
    "accounts.google.com", "appleid.apple.com", "login.microsoftonline.com",
    "login.live.com", "github.com", "facebook.com", "www.facebook.com",
    "api.twitter.com", "x.com", "paypal.com", "www.paypal.com", "checkout.stripe.com"
  ];

  const baseDomain = (host) => host.split(".").slice(-2).join(".");
  const here = baseDomain(location.hostname);

  function shouldBlock(rawUrl) {
    if (!rawUrl) return false;
    let url;
    try { url = new URL(rawUrl, location.href); } catch { return false; }
    if (!/^https?:$/.test(url.protocol)) return false;
    if (AUTH_HOSTS.includes(url.hostname)) return false;
    return baseDomain(url.hostname) !== here;
  }

  // Leave scam signals for the (isolated-world) scam detector to read.
  const signal = (name) => {
    const el = document.documentElement;
    if (el && !(el.dataset.sabSignals || "").includes(name)) el.dataset.sabSignals = `${el.dataset.sabSignals || ""} ${name}`.trim();
  };
  if (window === window.top && window.Notification) {
    const origRequest = Notification.requestPermission;
    Notification.requestPermission = function (...args) {
      if (performance.now() < 15000) signal("notification");
      return origRequest.apply(this, args);
    };
  }

  // Ad widgets hide inside closed shadow roots so blockers can't read them; force them open.
  const origAttach = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (init) {
    return origAttach.call(this, { ...init, mode: "open" });
  };

  function guardOpen(win) {
    try {
      if (!win || win.open.__guarded) return;
      const origOpen = win.open;
      const guarded = function (url, ...rest) {
        if (shouldBlock(url)) {
          console.debug("[Simple AdBlock] blocked popup:", url);
          return null;
        }
        return origOpen.call(this, url, ...rest);
      };
      guarded.__guarded = true;
      win.open = guarded;
    } catch {} // cross-origin frame: its own copy of this script guards it
  }
  guardOpen(window);

  // Popunder scripts grab a clean window.open from a fresh blank iframe; guard those too.
  for (const proto of [HTMLIFrameElement.prototype, HTMLFrameElement.prototype, HTMLObjectElement.prototype]) {
    const desc = Object.getOwnPropertyDescriptor(proto, "contentWindow");
    Object.defineProperty(proto, "contentWindow", {
      ...desc,
      get() { const w = desc.get.call(this); guardOpen(w); return w; }
    });
  }
  const docDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, "contentDocument");
  Object.defineProperty(HTMLIFrameElement.prototype, "contentDocument", {
    ...docDesc,
    get() { const d = docDesc.get.call(this); if (d) guardOpen(d.defaultView); return d; }
  });
  const framesDesc = Object.getOwnPropertyDescriptor(window, "frames");
  // window[0], window.frames[i] also expose child windows.
  if (framesDesc && framesDesc.get) {
    Object.defineProperty(window, "frames", {
      ...framesDesc,
      get() { const f = framesDesc.get.call(this); for (let i = 0; i < f.length; i++) guardOpen(f[i]); return f; }
    });
  }

  // Popunders often fake a click on a hidden target=_blank link.
  const opensNewTab = (a) => a && a.target && a.target !== "_self" && shouldBlock(a.href);

  const origClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function () {
    if (opensNewTab(this)) return console.debug("[Simple AdBlock] blocked popup:", this.href);
    return origClick.call(this);
  };

  window.addEventListener("click", (e) => {
    if (e.isTrusted) return;
    const a = e.target.closest && e.target.closest("a");
    if (opensNewTab(a)) { e.preventDefault(); e.stopImmediatePropagation(); }
  }, true);
})();
