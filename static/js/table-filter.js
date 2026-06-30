/* LazyOwnBT — filtro de tabla en cliente (vanilla JS).
   Reemplaza a DataTables para evitar CDN (CSP estricta).
   Uso: <script>tableFilter('alertsTable', 'filter');</script>
*/

function tableFilter(tableId, inputId) {
  const table = document.getElementById(tableId);
  const input = document.getElementById(inputId);
  if (!table || !input) return;
  const tbody = table.tBodies[0];
  if (!tbody) return;

  const rows = Array.from(tbody.rows);

  function apply() {
    const q = input.value.trim().toLowerCase();
    for (const row of rows) {
      if (!q) { row.style.display = ""; continue; }
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(q) ? "" : "none";
    }
  }

  input.addEventListener("input", apply);
  apply();
}

if (typeof window !== "undefined") { window.tableFilter = tableFilter; }
