// Tabs and copy buttons. The page works without this file: every panel is
// shown and the code can be selected by hand.
(function () {
  "use strict";

  // Tabs: a [data-tabs] element holds a [role=tablist] (hidden until this
  // runs) and one [role=tabpanel] per tab, in the same order.
  document.querySelectorAll("[data-tabs]").forEach(function (group) {
    var list = group.querySelector("[role=tablist]");
    var tabs = Array.prototype.slice.call(list.querySelectorAll("[role=tab]"));
    var panels = Array.prototype.slice.call(group.querySelectorAll("[role=tabpanel]"));

    function select(index, focus) {
      tabs.forEach(function (tab, i) {
        var on = i === index;
        tab.setAttribute("aria-selected", on ? "true" : "false");
        tab.tabIndex = on ? 0 : -1;
        panels[i].hidden = !on;
      });
      if (focus) tabs[index].focus();
    }

    tabs.forEach(function (tab, i) {
      tab.addEventListener("click", function () { select(i, false); });
      tab.addEventListener("keydown", function (event) {
        var next = null;
        if (event.key === "ArrowRight") next = (i + 1) % tabs.length;
        if (event.key === "ArrowLeft") next = (i - 1 + tabs.length) % tabs.length;
        if (event.key === "Home") next = 0;
        if (event.key === "End") next = tabs.length - 1;
        if (next !== null) {
          event.preventDefault();
          select(next, true);
        }
      });
    });

    list.hidden = false;
    group.classList.add("tabs-on");
    select(0, false);
  });

  // Copy buttons: a [data-copy] button copies the text of the <code> in the
  // same .code block.
  document.querySelectorAll("[data-copy]").forEach(function (button) {
    var block = button.closest(".code");
    var code = block && block.querySelector("code");
    if (!code || !navigator.clipboard) return;
    button.hidden = false;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(code.textContent.trim()).then(function () {
        button.textContent = "Copied";
        setTimeout(function () { button.textContent = "Copy"; }, 1600);
      }, function () {
        button.textContent = "Select it";
      });
    });
  });
})();
