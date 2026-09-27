// the theme follows the system's; pages with data-refresh reload while idle
(function () {
  var root = document.documentElement;
  var dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");
  function theme() {
    root.classList.toggle("cds--g100", !!(dark && dark.matches));
    root.classList.toggle("cds--g10", !(dark && dark.matches));
  }
  theme();
  if (dark && dark.addEventListener) dark.addEventListener("change", theme);

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("form[data-confirm]").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        if (!window.confirm(f.getAttribute("data-confirm"))) e.preventDefault();
      });
    });
    var secs = parseInt(document.body.getAttribute("data-refresh") || "0", 10);
    var box = document.getElementById("rgwi-autorefresh");
    if (!secs || !box) return;
    var key = "rgwi-autorefresh";
    try { box.checked = window.localStorage.getItem(key) !== "off"; } catch (e) { box.checked = true; }
    box.addEventListener("change", function () {
      try { window.localStorage.setItem(key, box.checked ? "on" : "off"); } catch (e) {}
    });
    setInterval(function () {
      var busy = document.activeElement && /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName);
      if (box.checked && !busy && !document.hidden) window.location.reload();
    }, secs * 1000);
  });
})();
