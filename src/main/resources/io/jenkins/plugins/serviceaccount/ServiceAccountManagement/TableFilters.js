document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("table[data-filterable]").forEach(function (table) {
    var body = table.tBodies[0];
    if (!body) {
      return;
    }

    var controls = Array.from(table.querySelectorAll("[data-filter-column]"));
    var rows = Array.from(body.rows).filter(function (row) {
      return !row.hasAttribute("data-filter-empty");
    });
    var emptyRow = body.querySelector("[data-filter-empty]");

    function updateRows() {
      rows.forEach(function (row) {
        var matches = controls.every(function (control) {
          var filter = control.value.trim().toLowerCase();
          if (!filter) {
            return true;
          }

          var cell = row.cells[Number(control.dataset.filterColumn)];
          if (!cell) {
            return false;
          }

          var value = cell.textContent.trim().toLowerCase();
          return control.tagName === "SELECT" ? value === filter : value.includes(filter);
        });
        row.hidden = !matches;
      });

      if (emptyRow) {
        emptyRow.hidden = rows.some(function (row) {
          return !row.hidden;
        });
      }
    }

    controls.forEach(function (control) {
      control.addEventListener("input", updateRows);
      control.addEventListener("change", updateRows);
    });
  });
});
