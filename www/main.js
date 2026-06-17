/* ============================================================================
   LEGIS — landing-page interactions (progressive enhancement)
   The page is content-complete without JS: all four 2×2 cells render statically
   in a real grid, every cell description is present, and every link works with
   JS disabled. This script only layers in *additive emphasis* faithful to the
   weft-hub UI kit:
     · the cell filter (All four / Chill / Coached / Structured / Protected)
       dims the non-matching cells; "All four" is the default and clears it.
   The filter is a toolbar of toggle buttons (aria-pressed) — there are no
   panels to switch, so it is not a tablist — with arrow-key roving focus. It
   adds no content: with JS off, all four cells are simply always shown.
   ============================================================================ */
(function () {
  "use strict";

  var btns = Array.prototype.slice.call(document.querySelectorAll(".cell-btn"));
  var grid = document.querySelector(".cell-grid");
  if (!btns.length || !grid) return;

  var cards = Array.prototype.slice.call(grid.querySelectorAll(".cell-card"));

  function selectCell(cell, focus) {
    btns.forEach(function (b) {
      var active = b.getAttribute("data-cell") === cell;
      b.classList.toggle("is-active", active);
      b.setAttribute("aria-pressed", String(active));
      if (active && focus) b.focus();
    });

    if (cell === "all") {
      grid.classList.remove("is-filtered");
      cards.forEach(function (c) { c.classList.remove("is-match"); });
    } else {
      grid.classList.add("is-filtered");
      cards.forEach(function (c) {
        c.classList.toggle("is-match", c.getAttribute("data-cell") === cell);
      });
    }
  }

  btns.forEach(function (btn, i) {
    btn.addEventListener("click", function () {
      selectCell(btn.getAttribute("data-cell"));
    });
    // Roving-tabindex keyboard model expected of an ARIA tablist.
    btn.addEventListener("keydown", function (e) {
      var next = null;
      if (e.key === "ArrowRight" || e.key === "ArrowDown") next = (i + 1) % btns.length;
      else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = (i - 1 + btns.length) % btns.length;
      else if (e.key === "Home") next = 0;
      else if (e.key === "End") next = btns.length - 1;
      if (next === null) return;
      e.preventDefault();
      selectCell(btns[next].getAttribute("data-cell"), true);
    });
  });
})();
