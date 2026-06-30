/* LazyOwnBT — formulario de comandos.
   El backend (lazyownbt.web._handle_command) valida cada acción contra
   el ActionRegistry; este JS solo garantiza que el payload se ajuste al
   esquema declarado (params como dict, no string).
*/

const ACTION_SCHEMAS = {
  do_resp_block_ip: {
    fields: [
      { name: "ip_address", label: "IP a bloquear", type: "text", required: true, placeholder: "203.0.113.42" },
      { name: "interface",  label: "Cadena iptables", type: "text", required: false, placeholder: "INPUT", value: "INPUT" },
    ],
  },
  do_resp_kill_proc: {
    fields: [
      { name: "pid",    label: "PID",   type: "number", required: true,  min: 1 },
      { name: "signal", label: "Señal (9, 15, 19, 23)", type: "number", required: false, value: 15 },
    ],
  },
  do_net_scan:  { fields: [] },
  do_fim_scan:  { fields: [] },
  lazynmap: {
    fields: [
      { name: "target", label: "Objetivo (host o CIDR)", type: "text", required: true, placeholder: "scanme.nmap.org" },
    ],
  },
  ai_playbook: {
    fields: [
      { name: "scenario", label: "Escenario", type: "text", required: true, placeholder: "phishing_campaign" },
    ],
  },
};

function renderParams(action, host) {
  host.innerHTML = "";
  const schema = ACTION_SCHEMAS[action] || { fields: [] };
  if (!schema.fields.length) {
    const hint = document.createElement("p");
    hint.className = "error-msg";
    hint.textContent = "Esta acción no requiere parámetros.";
    host.appendChild(hint);
    return;
  }
  for (const field of schema.fields) {
    const row = document.createElement("div");
    row.className = "row";

    const lbl = document.createElement("label");
    lbl.htmlFor = `param-${field.name}`;
    lbl.textContent = field.label + (field.required ? " *" : "");
    row.appendChild(lbl);

    const input = document.createElement("input");
    input.id = `param-${field.name}`;
    input.name = field.name;
    input.type = field.type || "text";
    if (field.placeholder) input.placeholder = field.placeholder;
    if (field.required) input.required = true;
    if (field.value !== undefined) input.value = field.value;
    if (field.type === "number" && field.min !== undefined) input.min = field.min;
    row.appendChild(input);

    host.appendChild(row);
  }
}

function collectParams(action) {
  const schema = ACTION_SCHEMAS[action] || { fields: [] };
  const params = {};
  for (const field of schema.fields) {
    const el = document.getElementById(`param-${field.name}`);
    if (!el) continue;
    const v = el.value.trim();
    if (v === "" && !field.required) continue;
    params[field.name] = field.type === "number" ? Number(v) : v;
  }
  return params;
}

async function submitCommand(e) {
  e.preventDefault();
  const out = document.getElementById("output");
  const err = document.getElementById("error");
  const btn = e.target.querySelector("button[type=submit]");
  out.textContent = "";
  err.textContent = "";
  btn.disabled = true;

  const action = document.getElementById("command").value;
  const params = collectParams(action);

  try {
    const res = await AUTH.fetch("/commands", {
      method: "POST",
      body: JSON.stringify({ command: action, params }),
    });
    const data = await res.json();
    if (!res.ok) {
      err.textContent = data.error || `HTTP ${res.status}`;
      return;
    }
    out.textContent = data.output || "(sin salida)";
  } catch (e2) {
    err.textContent = e2.message || String(e2);
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (!AUTH.requireOrRedirect()) return;
  const sel = document.getElementById("command");
  const host = document.getElementById("params-host");
  const form = document.getElementById("commandForm");
  if (!sel || !host || !form) return;

  renderParams(sel.value, host);
  sel.addEventListener("change", () => renderParams(sel.value, host));
  form.addEventListener("submit", submitCommand);
});
