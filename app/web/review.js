"use strict";

// Trace content (intents, model output, observations) is untrusted: it is only
// ever inserted with textContent, never as HTML.

const KEY_STORAGE = "cybercore-review-key";
const VERDICT_LABEL = { approved: "Aprobada", rejected: "Rechazada", pending: "Pendiente" };

const state = { key: null, traces: [], filter: "pending", selected: null };

const $ = (id) => document.getElementById(id);

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (name === "text") node.textContent = value;
    else if (name === "className") node.className = value;
    else node.setAttribute(name, value);
  }
  for (const child of children) node.append(child);
  return node;
}

function readKey() {
  try { return sessionStorage.getItem(KEY_STORAGE); } catch { return null; }
}

function storeKey(value) {
  try {
    if (value) sessionStorage.setItem(KEY_STORAGE, value);
    else sessionStorage.removeItem(KEY_STORAGE);
  } catch { /* storage unavailable: the key lives only in memory */ }
}

class ApiError extends Error {
  constructor(status, detail) {
    super(detail);
    this.status = status;
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${state.key}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
  });
  if (!response.ok) {
    let detail = `Error ${response.status}`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d) => d.msg).join("; ");
    } catch { /* keep the generic message */ }
    throw new ApiError(response.status, detail);
  }
  return response.status === 204 ? null : response.json();
}

function verdictOf(trace) {
  return trace.latest_verdict || "pending";
}

function formatDate(value) {
  return new Date(value).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" });
}

// --- session ---------------------------------------------------------------

async function login(key) {
  state.key = key;
  try {
    await loadTraces();
  } catch (error) {
    state.key = null;
    storeKey(null);
    const message = error.status === 401 ? "Clave no válida."
      : error.status === 403 ? "Esa clave no tiene el rol de revisor (approver)."
      : error.status === 503 ? "CyberCore no tiene configurada la autenticación o la base de datos."
      : `No se pudo conectar: ${error.message}`;
    $("login-error").textContent = message;
    return;
  }
  storeKey(key);
  $("login").hidden = true;
  $("workspace").hidden = false;
  $("session").hidden = false;
  $("who").textContent = "Sesión de revisor activa";
}

function logout() {
  storeKey(null);
  state.key = null;
  state.traces = [];
  state.selected = null;
  $("workspace").hidden = true;
  $("session").hidden = true;
  $("login").hidden = false;
  $("api-key").value = "";
  $("login-error").textContent = "";
}

// --- list ------------------------------------------------------------------

async function loadTraces() {
  state.traces = await api("/v1/traces?limit=500");
  renderList();
}

function renderList() {
  const list = $("trace-list");
  list.replaceChildren();
  const visible = state.traces.filter(
    (trace) => state.filter === "all" || verdictOf(trace) === state.filter,
  );
  const pending = state.traces.filter((trace) => verdictOf(trace) === "pending").length;
  const approved = state.traces.filter((trace) => verdictOf(trace) === "approved").length;
  $("counts").textContent =
    `${state.traces.length} ejecuciones · ${pending} pendientes · ${approved} aprobadas`;

  if (!visible.length) {
    list.append(el("li", { className: "empty", text: "No hay ejecuciones en este filtro." }));
    return;
  }
  for (const trace of visible) {
    const verdict = verdictOf(trace);
    const button = el("button", { type: "button" }, [
      el("span", { className: "intent", text: trace.operator_intent }),
      el("span", {
        className: "meta",
        text: `${formatDate(trace.started_at)} · ${trace.step_count} pasos · ${trace.requested_by}`,
      }),
      el("span", { className: `badge ${verdict}`, text: VERDICT_LABEL[verdict] }),
    ]);
    if (trace.run_id === state.selected) button.classList.add("selected");
    button.addEventListener("click", () => openTrace(trace.run_id));
    list.append(el("li", {}, [button]));
  }
}

// --- detail ----------------------------------------------------------------

function parseOutput(raw) {
  if (raw == null) return { ok: false, text: "(sin salida)" };
  try {
    return { ok: true, value: JSON.parse(raw), text: JSON.stringify(JSON.parse(raw), null, 2) };
  } catch {
    return { ok: false, text: raw };
  }
}

async function openTrace(runId) {
  state.selected = runId;
  renderList();
  const detail = $("detail");
  detail.replaceChildren(el("p", { className: "empty", text: "Cargando…" }));
  let trace;
  let previous;
  try {
    [trace, previous] = await Promise.all([
      api(`/v1/traces/${runId}`),
      api(`/v1/traces/${runId}/reviews/latest`),
    ]);
  } catch (error) {
    detail.replaceChildren(el("p", { className: "error", text: error.message }));
    return;
  }
  renderTrace(trace, previous);
}

function renderTrace(trace, previous) {
  const detail = $("detail");
  const head = el("section", { className: "card run-head" }, [
    el("h2", { text: trace.operator_intent }),
    el("div", { className: "run-meta" }, [
      el("span", { text: `Lanzada por ${trace.requested_by}` }),
      el("span", { text: formatDate(trace.started_at) }),
      el("span", { text: `Modelo ${trace.model}` }),
      el("span", { text: `Estado ${trace.status}` }),
    ]),
    el("h4", { text: "Informe final" }),
    el("p", { className: "report", text: trace.final_report }),
  ]);

  const steps = trace.steps.map((step) => renderStep(step));

  const notes = el("textarea", { rows: "2", placeholder: "Notas para el equipo (opcional)" });
  const status = el("span", { className: "status", role: "status" });
  const approve = el("button", { type: "button", className: "approve", text: "Aprobar" });
  const reject = el("button", { type: "button", className: "reject", text: "Rechazar" });
  const bar = el("section", { className: "card review-bar" }, [
    previous
      ? el("p", {
          className: "previous",
          text: `Última revisión: ${VERDICT_LABEL[previous.verdict]} por ${previous.reviewer}, ${formatDate(previous.reviewed_at)}${previous.notes ? ` — «${previous.notes}»` : ""}`,
        })
      : el("p", { className: "previous", text: "Sin revisar todavía." }),
    el("label", { text: "Notas" }, [notes]),
    el("div", { className: "review-actions" }, [approve, reject, status]),
  ]);

  const submit = async (verdict) => {
    status.className = "status";
    let corrections = {};
    if (verdict === "approved") {
      try {
        corrections = collectCorrections(steps);
      } catch (error) {
        status.className = "status error";
        status.textContent = error.message;
        return;
      }
    } else if (steps.some((s) => !s.correctionPanel.hidden)) {
      status.className = "status error";
      status.textContent = "Cierra las correcciones abiertas antes de rechazar.";
      return;
    }
    approve.disabled = reject.disabled = true;
    try {
      await api(`/v1/traces/${trace.run_id}/reviews`, {
        method: "POST",
        body: JSON.stringify({ verdict, notes: notes.value.trim(), corrections }),
      });
    } catch (error) {
      status.className = "status error";
      status.textContent = error.message;
      approve.disabled = reject.disabled = false;
      return;
    }
    const corrected = Object.keys(corrections).length;
    status.className = "status ok-msg";
    status.textContent = verdict === "approved"
      ? `Aprobada${corrected ? ` con ${corrected} corrección(es)` : ""}.`
      : "Rechazada.";
    await loadTraces();
    const next = state.traces.find((t) => verdictOf(t) === "pending" && t.run_id !== trace.run_id);
    if (next && state.filter === "pending") setTimeout(() => openTrace(next.run_id), 700);
  };
  approve.addEventListener("click", () => submit("approved"));
  reject.addEventListener("click", () => submit("rejected"));

  detail.replaceChildren(head, ...steps.map((s) => s.node), bar);
}

function renderStep(step) {
  const node = $("step-template").content.firstElementChild.cloneNode(true);
  const output = parseOutput(step.raw_output);
  node.querySelector("h3").textContent = `Paso ${step.step_number}`;
  const badge = node.querySelector(".badge");
  badge.textContent = output.ok ? "JSON válido" : "Salida inválida";
  badge.classList.add(output.ok ? "valid" : "invalid");
  node.querySelector(".output").textContent = output.text;
  node.querySelector(".step-error").textContent = step.error ? `Error: ${step.error}` : "";
  node.querySelector(".observation").textContent = step.observation || "(sin resultado)";

  const messages = node.querySelector(".message-list");
  for (const message of step.messages) {
    messages.append(el("div", {}, [
      el("span", { className: "role", text: message.role }),
      el("pre", { text: message.content }),
    ]));
  }

  const panel = node.querySelector(".correction");
  const form = {
    thought: panel.querySelector('[name="thought"]'),
    action_type: panel.querySelector('[name="action_type"]'),
    tool: panel.querySelector('[name="tool"]'),
    arguments: panel.querySelector('[name="arguments"]'),
    final_summary: panel.querySelector('[name="final_summary"]'),
  };
  const prefill = output.ok ? output.value : {};
  form.thought.value = prefill.thought || "";
  form.action_type.value = prefill.action_type === "call_tool" ? "call_tool" : "final_answer";
  if (prefill.tool) form.tool.value = prefill.tool;
  form.arguments.value = prefill.arguments ? JSON.stringify(prefill.arguments) : "{}";
  form.final_summary.value = prefill.final_summary || "";

  const syncFields = () => {
    const isTool = form.action_type.value === "call_tool";
    panel.querySelectorAll(".tool-field").forEach((f) => { f.hidden = !isTool; });
    panel.querySelectorAll(".final-field").forEach((f) => { f.hidden = isTool; });
  };
  form.action_type.addEventListener("change", syncFields);
  syncFields();

  const toggle = node.querySelector(".toggle-correction");
  toggle.addEventListener("click", () => {
    panel.hidden = !panel.hidden;
    toggle.textContent = panel.hidden ? "Corregir este paso" : "Descartar corrección";
    badge.textContent = panel.hidden ? (output.ok ? "JSON válido" : "Salida inválida") : "Corregido";
    badge.className = `badge ${panel.hidden ? (output.ok ? "valid" : "invalid") : "corrected"}`;
  });

  return { node, step, form, correctionPanel: panel, errorNode: panel.querySelector(".correction-error") };
}

function collectCorrections(steps) {
  const corrections = {};
  for (const { step, form, correctionPanel, errorNode } of steps) {
    errorNode.textContent = "";
    if (correctionPanel.hidden) continue;
    const thought = form.thought.value.trim();
    const actionType = form.action_type.value;
    const fail = (message) => {
      errorNode.textContent = message;
      throw new Error(`Paso ${step.step_number}: ${message}`);
    };
    if (!thought) fail("El razonamiento no puede estar vacío.");
    const action = { thought, action_type: actionType, tool: null, arguments: null, final_summary: null };
    if (actionType === "call_tool") {
      let args;
      try { args = JSON.parse(form.arguments.value || "{}"); } catch { fail("Los argumentos no son JSON válido."); }
      if (!args || typeof args !== "object" || Array.isArray(args)) fail("Los argumentos deben ser un objeto JSON.");
      if (!args.target) fail("Los argumentos necesitan un \"target\".");
      action.tool = form.tool.value;
      action.arguments = args;
    } else {
      const summary = form.final_summary.value.trim();
      if (!summary) fail("La respuesta final necesita un resumen.");
      action.final_summary = summary;
    }
    corrections[step.step_number] = action;
  }
  return corrections;
}

// --- wiring ----------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", (event) => {
    event.preventDefault();
    $("login-error").textContent = "";
    login($("api-key").value.trim());
  });
  $("logout").addEventListener("click", logout);
  $("refresh").addEventListener("click", () => loadTraces().catch((e) => {
    $("counts").textContent = e.message;
  }));
  document.querySelectorAll(".filters button").forEach((button) => {
    button.addEventListener("click", () => {
      state.filter = button.dataset.filter;
      document.querySelectorAll(".filters button").forEach((b) => b.classList.toggle("active", b === button));
      renderList();
    });
  });
  const saved = readKey();
  if (saved) login(saved);
});
