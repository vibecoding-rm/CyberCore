"use strict";

// Case content and model answers are untrusted: they are only ever inserted
// with textContent, never as HTML. The page never learns which system wrote
// an answer; the server only sends opaque answer ids.

const KEY_STORAGE = "cybercore-review-key";
const CRITERIA = [
  ["fidelity", "Fidelidad", "0: alguna afirmación no está respaldada · 2: todo se rastrea hasta una evidencia"],
  ["completeness", "Completitud", "0: omite un hueco o contradicción del motor · 2: explica cada uno y por qué importa"],
  ["actionability", "Accionabilidad", "0: vaga o sin pasos · 2: pasos concretos, defensivos y reversibles, en orden"],
  ["calibration", "Calibración", "0: la confianza no corresponde al estado · 2: la justifica con la evidencia"],
  ["clarity", "Claridad", "0: confusa o no está en español · 2: clara para quien no conoce el caso"],
];
const SECTIONS = [
  ["contradictions", "Contradicciones"],
  ["missing_evidence", "Evidencia que falta"],
  ["recommended_actions", "Acciones recomendadas"],
];

const state = { key: null, run: null };
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

// --- session ---------------------------------------------------------------

async function login(key) {
  state.key = key;
  let runs;
  try {
    runs = await api("/v1/analyst-bench/runs");
  } catch (error) {
    state.key = null;
    storeKey(null);
    $("login-error").textContent = error.status === 401 ? "Clave no válida."
      : error.status === 403 ? "Esa clave no tiene el rol de revisor (approver)."
      : error.status === 503 ? "CyberCore no tiene configurada la autenticación o la base de datos."
      : `No se pudo conectar: ${error.message}`;
    return;
  }
  storeKey(key);
  $("login").hidden = true;
  $("session").hidden = false;
  renderRuns(runs);
}

function logout() {
  storeKey(null);
  Object.assign(state, { key: null, run: null });
  $("runs").hidden = true;
  $("case").hidden = true;
  $("session").hidden = true;
  $("login").hidden = false;
  $("api-key").value = "";
  $("progress").textContent = "";
}

// --- runs ------------------------------------------------------------------

function renderRuns(runs) {
  const list = $("run-list");
  list.replaceChildren();
  $("runs").hidden = false;
  $("case").hidden = true;
  if (!runs.length) {
    list.append(el("li", { className: "empty", text: "No hay ejecuciones publicadas." }));
    return;
  }
  for (const run of runs) {
    const button = el("button", { type: "button" }, [
      el("span", { className: "intent", text: run.run_id }),
      el("span", { className: "meta", text: `${run.split} · ${run.cases} casos · ${run.systems.length} respuestas por caso` }),
    ]);
    button.addEventListener("click", () => openRun(run.run_id));
    list.append(el("li", {}, [button]));
  }
}

async function openRun(runId) {
  state.run = runId;
  $("runs").hidden = true;
  await loadNext();
}

// --- case ------------------------------------------------------------------

async function loadNext() {
  const panel = $("case");
  panel.hidden = false;
  panel.replaceChildren(el("p", { className: "empty", text: "Cargando…" }));
  let blind;
  try {
    blind = await api(`/v1/analyst-bench/runs/${encodeURIComponent(state.run)}/next`);
  } catch (error) {
    panel.replaceChildren(el("p", { className: "error", text: error.message }));
    return;
  }
  if (!blind) {
    $("progress").textContent = "";
    const back = el("button", { type: "button", className: "ghost", text: "Volver a las ejecuciones" });
    back.addEventListener("click", () => login(state.key));
    panel.replaceChildren(el("section", { className: "card" }, [
      el("h2", { text: "Has puntuado todas las respuestas de esta ejecución." }),
      el("p", { text: "Gracias. El informe comparativo se genera con scripts/analyst_bench_report." }),
      back,
    ]));
    return;
  }
  $("progress").textContent = `Caso ${blind.reviewed_cases + 1} de ${blind.total_cases}`;
  renderCase(blind);
}

function list(items) {
  return el("ul", {}, items.map((item) => el("li", { text: String(item) })));
}

function renderView(view) {
  const engine = view.evaluacion_del_motor;
  const vuln = view.vulnerabilidad || {};
  const evidence = view.evidencias.map((item) => el("details", { className: "messages" }, [
    el("summary", { text: `${item.evidence_id} · ${item.fuente} · ${item.objetivo}` }),
    el("pre", { text: JSON.stringify(item.datos, null, 2) }),
  ]));
  return el("section", { className: "card run-head" }, [
    el("h2", { text: `${vuln.vulnerability_id || ""} en ${view.objetivo}` }),
    el("div", { className: "run-meta" }, [
      el("span", { className: "badge pending", text: `Estado del motor: ${engine.estado}` }),
      el("span", { text: vuln.title || "" }),
    ]),
    el("h4", { text: "Conclusión del motor" }),
    el("p", { className: "report", text: engine.conclusion }),
    el("h4", { text: "Observaciones" }),
    list(engine.observaciones),
    el("h4", { text: "Huecos de evidencia detectados por el motor" }),
    engine.evidencia_que_falta.length
      ? list(engine.evidencia_que_falta.map((gap) => gap.descripcion))
      : el("p", { className: "empty", text: "Ninguno." }),
    el("h4", { text: "Evidencias selladas" }),
    ...evidence,
  ]);
}

function renderAnswer(answer, index, blind) {
  const out = answer.output;
  const body = [
    el("h4", { text: "Resumen" }),
    el("p", { text: out.summary }),
    el("h4", { text: "Interpretación de la evidencia" }),
    list(out.evidence_interpretation.map((i) => `${i.evidence_id}: ${i.statement}`)),
  ];
  for (const [field, title] of SECTIONS) {
    body.push(el("h4", { text: title }));
    body.push(out[field].length ? list(out[field]) : el("p", { className: "empty", text: "(vacío)" }));
  }
  body.push(el("h4", { text: "Confianza" }), el("p", { text: out.confidence_explanation }));

  const form = el("form", { className: "rubric-form" });
  for (const [name, label, hint] of CRITERIA) {
    const group = $("rubric-template").content.firstElementChild.cloneNode(true);
    group.querySelector("legend").textContent = label;
    group.querySelector(".hint").textContent = hint;
    group.querySelectorAll("input").forEach((input) => { input.name = name; });
    form.append(group);
  }
  const comment = el("textarea", { rows: "2", name: "comment", placeholder: "Comentario (opcional): qué sobra, qué falta o qué es incorrecto" });
  const status = el("span", { className: "status", role: "status" });
  const submit = el("button", { type: "submit", text: "Guardar puntuación" });
  form.append(el("label", { text: "Comentario" }, [comment]), el("div", { className: "review-actions" }, [submit, status]));

  const card = el("article", { className: "card step" }, [
    el("header", { className: "step-head" }, [el("h3", { text: `Respuesta ${String.fromCharCode(65 + index)}` })]),
    ...body,
    form,
  ]);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const scores = Object.fromEntries(CRITERIA.map(([name]) => [name, Number(data.get(name))]));
    submit.disabled = true;
    status.className = "status";
    try {
      await api(`/v1/analyst-bench/runs/${encodeURIComponent(state.run)}/scores`, {
        method: "POST",
        body: JSON.stringify({
          case_id: blind.case_id, answer_id: answer.answer_id, scores,
          comment: String(data.get("comment") || "").trim(),
        }),
      });
    } catch (error) {
      status.className = "status error";
      status.textContent = error.message;
      submit.disabled = false;
      return;
    }
    status.className = "status ok-msg";
    status.textContent = "Guardada.";
    form.querySelectorAll("input, textarea").forEach((input) => { input.disabled = true; });
    card.classList.add("done");
    if (!document.querySelector(".bench .step:not(.done)")) setTimeout(loadNext, 600);
  });
  return card;
}

function renderCase(blind) {
  $("case").replaceChildren(
    renderView(blind.view),
    el("div", { className: "answers" }, blind.answers.map((a, i) => renderAnswer(a, i, blind))),
  );
  window.scrollTo(0, 0);
}

// --- wiring ----------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", (event) => {
    event.preventDefault();
    $("login-error").textContent = "";
    login($("api-key").value.trim());
  });
  $("logout").addEventListener("click", logout);
  const saved = readKey();
  if (saved) login(saved);
});
