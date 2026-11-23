/* Filtros en vivo y paginación local para la Consola DTI (CSP script-src 'self'). */
(function () {
  "use strict";

  function norm(s) {
    return (s || "")
      .toString()
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "");
  }

  function bindTableFilter(config) {
    var table = document.getElementById(config.tableId);
    if (!table || !table.tBodies.length) return;
    var rows = Array.prototype.slice.call(table.tBodies[0].querySelectorAll("tr[data-row='1']"));
    var search = config.searchId ? document.getElementById(config.searchId) : null;
    var selects = (config.selects || [])
      .map(function (s) {
        return { el: document.getElementById(s.id), attr: s.attr };
      })
      .filter(function (s) {
        return Boolean(s.el);
      });
    var counter = config.countId ? document.getElementById(config.countId) : null;

    var pageSize = config.pageSize || 8;
    var currentPage = 1;
    var matchedRows = rows.slice();

    // Crear barra de paginación debajo del contenedor .scroll de la tabla
    var scrollWrap = table.parentElement;
    var pager = document.createElement("div");
    pager.className = "pager";

    var info = document.createElement("span");
    info.className = "pager-info";

    var controls = document.createElement("div");
    controls.className = "pager-controls";

    var sizeSel = document.createElement("select");
    sizeSel.setAttribute("aria-label", "Filas por página");
    [8, 15, 25, 50].forEach(function (n) {
      var opt = document.createElement("option");
      opt.value = String(n);
      opt.textContent = n + " por pág.";
      if (n === pageSize) opt.selected = true;
      sizeSel.appendChild(opt);
    });

    var prevBtn = document.createElement("button");
    prevBtn.type = "button";
    prevBtn.className = "secondary";
    prevBtn.textContent = "« Anterior";

    var nextBtn = document.createElement("button");
    nextBtn.type = "button";
    nextBtn.className = "secondary";
    nextBtn.textContent = "Siguiente »";

    controls.appendChild(sizeSel);
    controls.appendChild(prevBtn);
    controls.appendChild(nextBtn);
    pager.appendChild(info);
    pager.appendChild(controls);
    if (scrollWrap && scrollWrap.parentNode) {
      scrollWrap.parentNode.insertBefore(pager, scrollWrap.nextSibling);
    }

    function renderPage() {
      var total = matchedRows.length;
      var totalPages = Math.max(1, Math.ceil(total / pageSize));
      if (currentPage > totalPages) currentPage = totalPages;
      if (currentPage < 1) currentPage = 1;

      var start = (currentPage - 1) * pageSize;
      var end = start + pageSize;

      rows.forEach(function (tr) {
        tr.classList.add("is-hidden");
      });
      matchedRows.slice(start, end).forEach(function (tr) {
        tr.classList.remove("is-hidden");
      });

      if (counter) {
        counter.textContent = total + " coincidencia" + (total === 1 ? "" : "s") + " (de " + rows.length + ")";
      }
      if (total === 0) {
        info.textContent = "Sin resultados para el filtro actual";
      } else {
        info.textContent =
          "Página " + currentPage + " de " + totalPages +
          " · Mostrando " + (start + 1) + "–" + Math.min(end, total) + " de " + total;
      }
      prevBtn.disabled = currentPage <= 1;
      nextBtn.disabled = currentPage >= totalPages;
      pager.classList.toggle("is-hidden", rows.length === 0);
    }

    function applyFilter() {
      var q = search ? norm(search.value.trim()) : "";
      matchedRows = rows.filter(function (tr) {
        var textMatch = !q || norm(tr.getAttribute("data-search") || tr.textContent).indexOf(q) !== -1;
        var selMatch = selects.every(function (s) {
          var want = norm(s.el.value);
          if (!want || want === "all") return true;
          var got = norm(tr.getAttribute(s.attr));
          return got === want || got.indexOf(want) !== -1;
        });
        return textMatch && selMatch;
      });
      currentPage = 1;
      renderPage();
    }

    prevBtn.addEventListener("click", function () {
      if (currentPage > 1) {
        currentPage -= 1;
        renderPage();
      }
    });
    nextBtn.addEventListener("click", function () {
      var totalPages = Math.max(1, Math.ceil(matchedRows.length / pageSize));
      if (currentPage < totalPages) {
        currentPage += 1;
        renderPage();
      }
    });
    sizeSel.addEventListener("change", function () {
      pageSize = parseInt(sizeSel.value, 10) || 8;
      currentPage = 1;
      renderPage();
    });

    if (search) search.addEventListener("input", applyFilter);
    selects.forEach(function (s) {
      s.el.addEventListener("change", applyFilter);
    });
    var clearBtn = config.clearId ? document.getElementById(config.clearId) : null;
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        if (search) search.value = "";
        selects.forEach(function (s) {
          s.el.value = "all";
        });
        applyFilter();
      });
    }
    applyFilter();
  }

  document.addEventListener("DOMContentLoaded", function () {
    bindTableFilter({
      tableId: "tbl-sessions",
      searchId: "f-sessions-q",
      clearId: "f-sessions-clear",
      countId: "f-sessions-count",
      pageSize: 8,
    });
    bindTableFilter({
      tableId: "tbl-policies",
      searchId: "f-policies-q",
      selects: [
        { id: "f-policies-role", attr: "data-role" },
        { id: "f-policies-state", attr: "data-state" },
      ],
      clearId: "f-policies-clear",
      countId: "f-policies-count",
      pageSize: 8,
    });
    bindTableFilter({
      tableId: "tbl-users",
      searchId: "f-users-q",
      selects: [
        { id: "f-users-role", attr: "data-role" },
        { id: "f-users-active", attr: "data-active" },
      ],
      clearId: "f-users-clear",
      countId: "f-users-count",
      pageSize: 8,
    });
    bindTableFilter({
      tableId: "tbl-events",
      searchId: "f-events-q",
      selects: [{ id: "f-events-action", attr: "data-action" }],
      clearId: "f-events-clear",
      countId: "f-events-count",
      pageSize: 8,
    });
    bindTableFilter({
      tableId: "tbl-auth",
      searchId: "f-auth-q",
      selects: [{ id: "f-auth-outcome", attr: "data-outcome" }],
      clearId: "f-auth-clear",
      countId: "f-auth-count",
      pageSize: 8,
    });
  });
})();
