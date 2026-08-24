"use strict";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const desktopSessionToken = document.querySelector('meta[name="aegis-session-token"]')?.content || "";
document.documentElement.dataset.aegisDesktop = desktopSessionToken ? "true" : "false";

const state = {
  overview: null,
  cases: [],
  activeCase: null,
  topology: null,
  campaigns: null,
  indicators: null,
  assets: null,
  research: null,
  experiment: null,
  learning: null,
  agents: null,
  telemetryStatus: null,
  telemetryEvents: null,
  hardware: null,
  trace: null,
  traceExperiment: null,
  traceGraph: null,
  steering: null,
  governance: null,
  access: null,
  audit: null,
  gateway: null,
  gatewayPendingRecords: null,
  gatewayPreview: null,
  evidenceVerification: null,
};

const api = async (path, options = {}) => {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (desktopSessionToken) headers["X-AEGIS-Desktop-Token"] = desktopSessionToken;
  const response = await fetch(path, {
    ...options,
    headers,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(error.detail || error.error || `Request failed: ${response.status}`);
  }
  return response.json();
};

const percent = (value) => Math.round(Number(value || 0) * 100);
const titleCase = (value) => String(value || "")
  .replace(/_/g, " ")
  .replace(/\b\w/g, (letter) => letter.toUpperCase());
const escapeHtml = (value) => String(value ?? "")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#039;");
const shortTime = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
};
const shortHash = (value, size = 15) => value ? `${String(value).slice(0, size)}…` : "—";
const slug = (value) => String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
const duration = (seconds) => {
  const total = Math.max(0, Number(seconds || 0));
  if (total < 60) return `${Math.floor(total)} sec`;
  if (total < 3600) return `${Math.floor(total / 60)} min`;
  if (total < 86400) return `${Math.floor(total / 3600)} hr ${Math.floor(total % 3600 / 60)} min`;
  return `${Math.floor(total / 86400)} d ${Math.floor(total % 86400 / 3600)} hr`;
};
const telemetryDetail = (event) => {
  const payload = event?.payload || {};
  const details = [];
  if (payload.windows_event_id) details.push(`Event ${payload.windows_event_id}`);
  if (payload.ProcessName) details.push(payload.ProcessName);
  if (payload.NewProcessName) details.push(payload.NewProcessName);
  if (payload.files_measured != null) details.push(`${payload.files_measured} files measured`);
  if (payload.manifest_sha256) details.push(`manifest ${shortHash(payload.manifest_sha256, 12)}`);
  if (payload.memory_available_gib != null) details.push(`${payload.memory_available_gib} GiB free`);
  Object.entries(payload)
    .filter(([key]) => key.endsWith("_ref"))
    .slice(0, 2)
    .forEach(([key, value]) => details.push(`${titleCase(key.replace(/_ref$/, ""))} ${value}`));
  return details.join(" · ") || payload.privacy || "Contract-valid local observation";
};

function toast(message, error = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("error", error);
  node.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("show"), 2800);
}

function setLoading(button, loading) {
  if (!button) return;
  button.classList.toggle("loading", loading);
  button.disabled = loading;
  button.setAttribute("aria-busy", String(loading));
}

function renderOverview(overview) {
  state.overview = overview;
  $("#activeCases").textContent = overview.active_cases;
  $("#decoyAssets").textContent = overview.decoy_assets;
  $("#campaignLinks").textContent = overview.campaign_links;
  $("#modelConfidence").textContent = percent(overview.mean_model_confidence);
  $("#sideNodeState").textContent = overview.node_state === "ONLINE" ? "NODE ONLINE" : titleCase(overview.node_state);
  $("#sideNodeDetail").textContent = `${overview.active_collectors} ACTIVE COLLECTORS`;
  $("#missionNodeState").textContent = overview.node_state === "ONLINE" ? "LOCAL NODE ONLINE" : "LOCAL NODE DEGRADED";
  $("#systemState").textContent = overview.system_state === "CONTAINED"
    ? "Contained intelligence loop"
    : titleCase(overview.system_state);
}

function renderBeliefBars(container, distribution = []) {
  container.replaceChildren(...distribution.map((item, index) => {
    const row = document.createElement("div");
    row.className = `belief-row${index === 0 ? " leading" : ""}`;
    row.innerHTML = `
      <span>${escapeHtml(item.name)}</span>
      <div class="belief-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent(item.probability)}">
        <div class="belief-fill" style="width:${percent(item.probability)}%"></div>
      </div>
      <span class="belief-value">${percent(item.probability)}%</span>`;
    return row;
  }));
}

function renderTimeline(container, events = [], limit = 12) {
  if (!events.length) {
    const empty = document.createElement("div");
    empty.className = "timeline-item";
    empty.innerHTML = "<p>No observations recorded.</p>";
    container.replaceChildren(empty);
    return;
  }
  container.replaceChildren(...events.slice(0, limit).map((event) => {
    const node = document.createElement("div");
    node.className = "timeline-item";
    node.innerHTML = `
      <div><strong>${escapeHtml(titleCase(event.event_type))}</strong><time>${escapeHtml(shortTime(event.timestamp))}</time></div>
      <p>${escapeHtml(event.actor)} → ${escapeHtml(event.target)}</p>`;
    return node;
  }));
}

function renderEvidenceRows(events = []) {
  const rows = events.map((event) => {
    const row = document.createElement("div");
    row.className = "data-row";
    row.innerHTML = `
      <span>${escapeHtml(event.sequence)}</span>
      <span>${escapeHtml(shortTime(event.timestamp))}</span>
      <span title="${escapeHtml(titleCase(event.event_type))}">${escapeHtml(titleCase(event.event_type))}</span>
      <span title="${escapeHtml(event.target)}">${escapeHtml(event.target)}</span>
      <span><code title="${escapeHtml(event.event_hash)}">${escapeHtml(shortHash(event.event_hash, 18))}</code></span>`;
    return row;
  });
  $("#evidenceRows").replaceChildren(...rows);
  $("#ledgerEventCount").textContent = `${events.length} EVENTS`;
}

function renderCase(caseData) {
  state.activeCase = caseData;
  const belief = caseData.belief_summary;

  $("#caseId").textContent = `Case ${caseData.id}`;
  $("#riskBadge").textContent = `RISK ${caseData.risk_score}`;
  $("#caseSource").textContent = caseData.source;
  $("#caseStage").textContent = `Stage · ${caseData.stage}`;
  $("#caseConfidence").textContent = `${percent(belief.confidence)}% confidence`;
  $("#topHypothesis").textContent = belief.top_hypothesis;
  $("#caseSummary").textContent = caseData.summary;
  renderBeliefBars($("#beliefBars"), belief.distribution);
  renderTimeline($("#timeline"), caseData.events, 8);

  $("#detailCaseId").textContent = caseData.id;
  $("#detailRisk").textContent = `RISK ${caseData.risk_score}`;
  $("#detailHypothesis").textContent = belief.top_hypothesis;
  $("#detailConfidence").textContent = `${percent(belief.confidence)}%`;
  $("#detailEvidence").textContent = `${caseData.evidence_count} events`;
  $("#detailSummary").textContent = caseData.summary;
  renderBeliefBars($("#detailBeliefBars"), belief.distribution);
  renderTimeline($("#detailTimeline"), caseData.events, 30);

  $("#vaultCaseId").textContent = caseData.id;
  renderEvidenceRows(caseData.events);
  renderCaseList(state.cases);
  if (state.evidenceVerification) renderEvidence(state.evidenceVerification);
}

function renderCaseList(cases = []) {
  $("#caseCount").textContent = `${cases.length} ACTIVE`;
  const nodes = cases.map((caseItem) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `case-list-item${state.activeCase?.id === caseItem.id ? " active" : ""}`;
    button.dataset.caseId = caseItem.id;
    button.setAttribute("aria-pressed", String(state.activeCase?.id === caseItem.id));
    button.innerHTML = `
      <span class="case-row"><strong>${escapeHtml(caseItem.id)}</strong><em>RISK ${escapeHtml(caseItem.risk_score)}</em></span>
      <p>${escapeHtml(caseItem.summary)}</p>
      <small>${escapeHtml(caseItem.stage)} · ${escapeHtml(caseItem.evidence_count)} evidence events</small>`;
    button.addEventListener("click", () => selectCase(caseItem.id));
    return button;
  });
  $("#caseList").replaceChildren(...nodes);
}

async function selectCase(caseId) {
  try {
    const caseData = await api(`/api/cases/${encodeURIComponent(caseId)}`);
    renderCase(caseData);
  } catch (error) {
    toast(`Could not load case: ${error.message}`, true);
  }
}

function renderTopology(topology) {
  state.topology = topology;
  const nodesById = Object.fromEntries(topology.nodes.map((node) => [node.id, node]));
  const edgeNodes = topology.edges.map((edge) => {
    const from = nodesById[edge.from];
    const to = nodesById[edge.to];
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", from.x);
    line.setAttribute("y1", from.y);
    line.setAttribute("x2", to.x);
    line.setAttribute("y2", to.y);
    line.setAttribute("class", edge.state);
    return line;
  });
  $("#topologyEdges").replaceChildren(...edgeNodes);

  const nodeElements = topology.nodes.map((item) => {
    const node = document.createElement("div");
    node.className = `topology-node ${item.kind}`;
    node.style.left = `${item.x}%`;
    node.style.top = `${item.y}%`;
    node.textContent = item.label;
    node.title = `${item.label}: ${item.state}`;
    return node;
  });
  $("#topologyNodes").replaceChildren(...nodeElements);
}

function certificateMarkup(certificate) {
  const permitted = certificate.decision === "PERMIT";
  const checks = certificate.checks.map((check) => `
    <span class="check-item ${check.passed ? "" : "failed"}" title="Observed: ${escapeHtml(check.observed)} · Required: ${escapeHtml(check.required)}">
      <i></i>${escapeHtml(titleCase(check.rule))}
    </span>`).join("");
  return `
    <div class="cert-result">
      <div><span class="cert-decision ${permitted ? "" : "deny"}">${escapeHtml(certificate.decision)}</span><small>${escapeHtml(certificate.action.action_id)}</small></div>
      <small>${escapeHtml(certificate.action.action_type)} → ${escapeHtml(certificate.action.target)}</small>
      <div class="check-list">${checks}</div>
      <code title="${escapeHtml(certificate.digest)}">${escapeHtml(certificate.digest)}</code>
    </div>`;
}

function renderCertificate(certificate) {
  if (!certificate?.decision) return;
  const permitted = certificate.decision === "PERMIT";
  [["#gateState", "#certificate"], ["#policyGateState", "#policyCertificate"]].forEach(([gateSelector, certificateSelector]) => {
    const gate = $(gateSelector);
    gate.classList.toggle("denied", !permitted);
    gate.innerHTML = `<i></i> ${escapeHtml(certificate.decision)}`;
    $(certificateSelector).innerHTML = certificateMarkup(certificate);
  });
}

function clearCertificates() {
  [["#gateState", "#certificate"], ["#policyGateState", "#policyCertificate"]].forEach(([gateSelector, certificateSelector], index) => {
    const gate = $(gateSelector);
    gate.className = "gate-state";
    gate.innerHTML = "<i></i> READY";
    $(certificateSelector).innerHTML = `<div class="cert-empty"><span class="cert-icon">◇</span><strong>No ${index ? "proposal evaluated" : "action pending"}</strong><small>${index ? "Run either test to inspect the complete rule result." : "Evaluate the diagnostic probe to issue a certificate."}</small></div>`;
  });
}

function renderEvidence(result) {
  state.evidenceVerification = result;
  const current = result.cases.find((item) => item.case_id === state.activeCase?.id) || result.cases.at(-1);
  const head = current?.head_hash || "No evidence events";
  [["#ledgerState", "#chainHead"], ["#vaultLedgerState", "#vaultChainHead"]].forEach(([stateSelector, headSelector]) => {
    const stateNode = $(stateSelector);
    stateNode.textContent = result.valid ? "VERIFIED" : "INTEGRITY FAILURE";
    stateNode.classList.toggle("valid", result.valid);
    stateNode.classList.toggle("invalid", !result.valid);
    const headNode = $(headSelector);
    headNode.textContent = head;
    headNode.title = head;
  });
  $("#verifiedCases").textContent = result.verified_cases;
  $("#verifiedEvents").textContent = result.verified_events;
}

function clearEvidence() {
  state.evidenceVerification = null;
  [["#ledgerState", "#chainHead"], ["#vaultLedgerState", "#vaultChainHead"]].forEach(([stateSelector, headSelector], index) => {
    const stateNode = $(stateSelector);
    stateNode.textContent = "NOT CHECKED";
    stateNode.className = "ledger-state";
    $(headSelector).textContent = index ? "Awaiting verification" : "Run verification to calculate";
  });
  $("#verifiedCases").textContent = "—";
  $("#verifiedEvents").textContent = "—";
}

function renderCampaigns(result) {
  state.campaigns = result;
  const campaign = result.campaigns[0];
  const link = result.links[0];
  if (!campaign || !link) {
    $("#campaignName").textContent = "No campaign cluster";
    $("#campaignStrength").textContent = "NO LINK";
    $("#campaignScore").textContent = "0%";
    $("#campaignNarrative").textContent = result.boundary;
    $("#campaignNodes").replaceChildren();
    $("#campaignEdges").replaceChildren();
    return;
  }

  $("#campaignName").textContent = campaign.label;
  $("#campaignStrength").textContent = `${campaign.strength.toUpperCase()} LINK`;
  $("#campaignScore").textContent = `${percent(campaign.confidence)}%`;
  $("#campaignNarrative").textContent = campaign.narrative;
  $("#attributionStatus").textContent = campaign.attribution_status;
  $("#campaignSupport").replaceChildren(...campaign.supporting_evidence.map((evidence) => {
    const node = document.createElement("div");
    node.className = "support-item";
    node.textContent = evidence;
    return node;
  }));

  const casePositions = [[24, 33], [77, 68], [22, 76], [78, 25]];
  const coordinates = { campaign: [50, 50] };
  campaign.linked_cases.forEach((caseId, index) => { coordinates[caseId] = casePositions[index] || [20 + index * 15, 80]; });
  const edges = campaign.linked_cases.map((caseId) => {
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", coordinates.campaign[0]);
    line.setAttribute("y1", coordinates.campaign[1]);
    line.setAttribute("x2", coordinates[caseId][0]);
    line.setAttribute("y2", coordinates[caseId][1]);
    return line;
  });
  $("#campaignEdges").replaceChildren(...edges);

  const nodeSpecs = [
    { id: "campaign", label: campaign.id, sublabel: "BEHAVIOUR CLUSTER", kind: "campaign" },
    ...campaign.linked_cases.map((caseId) => ({ id: caseId, label: caseId.replace("AEGIS-26-", "CASE "), sublabel: "AUTHORIZED SESSION", kind: "case" })),
  ];
  const nodes = nodeSpecs.map((spec) => {
    const node = document.createElement("div");
    node.className = `campaign-node ${spec.kind}`;
    node.style.left = `${coordinates[spec.id][0]}%`;
    node.style.top = `${coordinates[spec.id][1]}%`;
    node.innerHTML = `<div class="node-core">${escapeHtml(spec.label)}</div><small>${escapeHtml(spec.sublabel)}</small>`;
    return node;
  });
  $("#campaignNodes").replaceChildren(...nodes);
}

function renderIndicators(result) {
  state.indicators = result;
  const techniqueRows = result.techniques.map((technique) => {
    const row = document.createElement("div");
    row.className = "data-row";
    row.innerHTML = `
      <span title="${escapeHtml(technique.name)}">${escapeHtml(technique.id)} · ${escapeHtml(technique.name)}</span>
      <span>${escapeHtml(technique.tactic)}</span>
      <span title="${escapeHtml(technique.case_ids.join(", "))}">${escapeHtml(technique.case_ids.length)}</span>
      <span>${escapeHtml(technique.observations)}</span>`;
    return row;
  });
  $("#techniqueRows").replaceChildren(...techniqueRows);

  const indicators = result.behavioural_indicators.map((indicator) => {
    const node = document.createElement("div");
    node.className = "indicator-item";
    node.innerHTML = `
      <div><strong>${escapeHtml(titleCase(indicator.type))}</strong><em>${percent(indicator.confidence)}%</em></div>
      <code>${escapeHtml(indicator.value)}</code>`;
    node.title = indicator.scope;
    return node;
  });
  $("#behavioralIndicators").replaceChildren(...indicators);
}

function renderAssets(result) {
  state.assets = result;
  $("#worldVersion").textContent = result.world_version.toUpperCase();
  $("#fabricAssetCount").textContent = result.assets.length;
  $("#engagedAssetCount").textContent = result.assets.filter((asset) => ["ENGAGED", "TRIGGERED"].includes(asset.state)).length;
  const rows = result.assets.map((asset) => {
    const row = document.createElement("div");
    row.className = "data-row";
    row.innerHTML = `
      <span title="${escapeHtml(asset.id)}">${escapeHtml(asset.id)}</span>
      <span>${escapeHtml(asset.type)}</span>
      <span>${escapeHtml(asset.surface)}</span>
      <span class="asset-state ${escapeHtml(asset.state.toLowerCase())}">${escapeHtml(asset.state)}</span>
      <span>${escapeHtml(asset.sessions)}</span>
      <span>${escapeHtml(asset.isolation)}</span>`;
    return row;
  });
  $("#assetRows").replaceChildren(...rows);
}

function renderResearch(result) {
  state.research = result;
  const reproducibility = result.reproducibility;
  $("#researchRelease").textContent = `RELEASE ${result.release}`;
  $("#scenarioCount").textContent = reproducibility.seeded_scenarios;
  $("#automatedTests").textContent = reproducibility.automated_tests;
  $("#externalTargets").textContent = reproducibility.external_targets;
  const rows = result.experiments.map((experiment) => {
    const node = document.createElement("div");
    node.className = "experiment-card";
    node.innerHTML = `
      <small>${escapeHtml(experiment.id)}</small>
      <strong>${escapeHtml(experiment.name)}</strong>
      <p>${escapeHtml(experiment.metric)}</p>
      <em class="${escapeHtml(experiment.status.toLowerCase())}">${escapeHtml(experiment.status)}</em>`;
    return node;
  });
  $("#experimentRows").replaceChildren(...rows);
}

function renderExperiment(result) {
  state.experiment = result;
  const metrics = result.metrics;
  $("#modelAccuracy").textContent = percent(metrics.accuracy);
  $("#modelMacroF1").textContent = percent(metrics.macro_f1);
  $("#modelBrier").textContent = Number(metrics.multiclass_brier).toFixed(3);
  $("#modelECE").textContent = Number(metrics.expected_calibration_error).toFixed(3);
  $("#datasetSummary").textContent = `${result.dataset.samples} SEQUENCES · ${result.model.vocabulary_size} FEATURES`;

  const matrix = metrics.confusion_matrix;
  const matrixNodes = [];
  const corner = document.createElement("div");
  corner.className = "matrix-corner";
  corner.textContent = "TRUE ↓ · PRED →";
  matrixNodes.push(corner);
  matrix.labels.forEach((label) => {
    const header = document.createElement("div");
    header.className = "matrix-label column";
    header.textContent = label;
    header.title = label;
    matrixNodes.push(header);
  });
  matrix.rows.forEach((row, rowIndex) => {
    const label = document.createElement("div");
    label.className = "matrix-label row";
    label.textContent = matrix.labels[rowIndex];
    matrixNodes.push(label);
    const maximum = Math.max(...row, 1);
    row.forEach((value, columnIndex) => {
      const cell = document.createElement("div");
      cell.className = `matrix-cell${rowIndex === columnIndex ? " diagonal" : ""}`;
      cell.style.setProperty("--heat", String(value / maximum));
      cell.textContent = value;
      cell.title = `${matrix.labels[rowIndex]} predicted as ${matrix.labels[columnIndex]}: ${value}`;
      matrixNodes.push(cell);
    });
  });
  $("#confusionMatrix").style.gridTemplateColumns = `minmax(118px, 1.3fr) repeat(${matrix.labels.length}, minmax(62px, 1fr))`;
  $("#confusionMatrix").replaceChildren(...matrixNodes);

  const populatedBins = metrics.reliability.filter((bin) => bin.count > 0);
  $("#reliabilityBars").replaceChildren(...populatedBins.map((bin) => {
    const node = document.createElement("div");
    node.className = "reliability-bin";
    node.innerHTML = `
      <div class="reliability-track" title="${escapeHtml(bin.count)} samples · confidence ${percent(bin.mean_confidence)}% · accuracy ${percent(bin.empirical_accuracy)}%">
        <span style="height:${percent(bin.empirical_accuracy)}%"></span>
        <i style="bottom:${percent(bin.mean_confidence)}%"></i>
      </div>
      <small>${Math.round(bin.lower * 10) / 10}–${Math.round(bin.upper * 10) / 10}</small>
      <em>n=${escapeHtml(bin.count)}</em>`;
    return node;
  }));

  const provenance = [
    ["RUN", result.run_id],
    ["MODEL", result.model.family],
    ["CALIBRATION", `T=${result.model.temperature} · held-out family`],
  ].map(([label, value]) => {
    const node = document.createElement("div");
    node.innerHTML = `<small>${escapeHtml(label)}</small><strong title="${escapeHtml(value)}">${escapeHtml(value)}</strong>`;
    return node;
  });
  $("#modelProvenance").replaceChildren(...provenance);

  $("#classMetrics").replaceChildren(...metrics.per_class.map((item) => {
    const node = document.createElement("div");
    node.className = "class-metric-card";
    node.innerHTML = `
      <div><strong>${escapeHtml(item.label)}</strong><span>${escapeHtml(item.support)} TEST</span></div>
      <p>${percent(item.f1)}<em>% F1</em></p>
      <small>Precision ${percent(item.precision)}% · Recall ${percent(item.recall)}%</small>`;
    return node;
  }));
  $("#modelLimitations").replaceChildren(...result.limitations.slice(0, 3).map((limitation) => {
    const node = document.createElement("span");
    node.textContent = limitation;
    return node;
  }));
}

function renderLearningFabric(result) {
  state.learning = result;
  $("#fabricModelCount").textContent = `${result.models.length} MEASURED`;
  $("#modelFabric").replaceChildren(...result.models.map((model, index) => {
    const node = document.createElement("article");
    node.className = `fabric-model ${slug(model.status)}`;
    const weights = model.weights
      ? Object.entries(model.weights).filter(([, weight]) => weight > 0).map(([id, weight]) => `${id.replace("INTENT-", "").replace("-V1", "")} ${percent(weight)}%`).join(" · ")
      : `${model.feature_count} learned features`;
    node.innerHTML = `
      <div><span>${String(index + 1).padStart(2, "0")}</span><em>${escapeHtml(model.status)}</em></div>
      <strong>${escapeHtml(model.name)}</strong>
      <p>${escapeHtml(model.role)}</p>
      <div class="fabric-score"><b>${percent(model.test.macro_f1)}<small>% F1</small></b><span>Brier ${Number(model.test.multiclass_brier).toFixed(3)}</span></div>
      <code title="${escapeHtml(weights)}">${escapeHtml(weights)}</code>`;
    return node;
  }));

  const promotion = result.promotion;
  const promotionState = $("#promotionState");
  promotionState.textContent = promotion.decision.replace(/_/g, " ");
  promotionState.className = `promotion-state ${slug(promotion.decision)}`;
  $("#promotionRoute").replaceChildren(...result.learning_cycle.map((stage, index) => {
    const node = document.createElement("div");
    node.className = `promotion-step ${slug(stage.state)}`;
    node.innerHTML = `<span>${String(index + 1).padStart(2, "0")}</span><div><strong>${escapeHtml(stage.stage)}</strong><small>${escapeHtml(stage.detail)}</small></div><em>${escapeHtml(stage.state)}</em>`;
    return node;
  }));
  $("#promotionChecks").replaceChildren(...promotion.checks.map((check) => {
    const node = document.createElement("div");
    node.className = `promotion-check ${check.passed ? "passed" : "held"}`;
    node.title = `Observed: ${check.observed} · Required: ${check.required}`;
    node.innerHTML = `<i></i><span>${escapeHtml(titleCase(check.rule))}</span><em>${check.passed ? "PASS" : "HOLD"}</em>`;
    return node;
  }));
  $("#learningBoundary").textContent = result.boundary;

  $("#futureModels").replaceChildren(...result.planned_models.map((model) => {
    const node = document.createElement("article");
    node.className = "future-model";
    node.innerHTML = `<small>${escapeHtml(model.id)}</small><strong>${escapeHtml(model.role)}</strong><em>${escapeHtml(model.status)}</em>`;
    return node;
  }));
}

function renderAgents(result) {
  state.agents = result;
  const agent = result.agents[0];
  if (!agent) return;
  $("#nodeOnlineBadge").innerHTML = `<i></i> ${escapeHtml(agent.state)}`;
  $("#nodeOnlineBadge").className = `node-online ${slug(agent.state)}`;
  const edition = agent.launch_mode === "windows-service"
    ? "Resident Service"
    : agent.launch_mode === "desktop-executable"
      ? "Desktop Edition"
      : "Research Runtime";
  $("#environmentChipText").textContent = `${agent.state === "ONLINE" ? "Local node online" : "Local node degraded"} · ${edition}`;
  $("#nodeId").textContent = agent.node_id;
  $("#nodeUptime").textContent = duration(agent.uptime_seconds);
  $("#nodeMemory").textContent = agent.host.memory_available_gib ?? "N/A";
  $("#activeCollectors").textContent = agent.active_collectors;
  $("#nodePlatform").textContent = `${agent.host.platform} · ${agent.host.architecture}`;
  $("#collectorList").replaceChildren(...agent.collectors.map((collector) => {
    const node = document.createElement("article");
    node.className = `collector-card ${slug(collector.state)}`;
    node.innerHTML = `
      <div class="collector-icon"><i></i></div>
      <div><small>${escapeHtml(collector.id)} · ${escapeHtml(collector.source)}</small><strong>${escapeHtml(collector.name)}</strong><p>${escapeHtml(collector.detail)}</p></div>
      <div class="collector-meta"><em>${escapeHtml(collector.state)}</em><span>${escapeHtml(collector.mode)}</span><span>${escapeHtml(collector.privilege)}</span></div>`;
    return node;
  }));
  const hostRows = [
    ["Operating system", `${agent.host.platform} ${agent.host.release}`],
    ["Architecture", agent.host.architecture],
    ["Logical CPU", agent.host.cpu_logical ?? "Unavailable"],
    ["Memory", agent.host.memory_total_gib == null ? "Unavailable" : `${agent.host.memory_total_gib} GiB total`],
    ["Storage", agent.host.storage_free_gib == null ? "Unavailable" : `${agent.host.storage_free_gib} GiB free`],
    ["Python runtime", agent.host.python],
    ["Launch mode", titleCase(agent.launch_mode)],
    ["Service installed", agent.service_installed ? "Yes · always-on" : "No · window-owned runtime"],
  ];
  $("#nodeProfile").replaceChildren(...hostRows.map(([label, value]) => {
    const node = document.createElement("div");
    node.innerHTML = `<span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong>`;
    return node;
  }));
  $("#agentBoundary").textContent = agent.boundary;
  $("#deploymentPaths").replaceChildren(...agent.deployment_profiles.map((profile, index) => {
    const node = document.createElement("article");
    node.className = `deployment-path ${slug(profile.state)}`;
    node.innerHTML = `<span>${String(index + 1).padStart(2, "0")}</span><strong>${escapeHtml(profile.name)}</strong><p>${escapeHtml(profile.shape)}</p><em>${escapeHtml(profile.state)}</em>`;
    return node;
  }));
}

function renderTelemetryStatus(result) {
  state.telemetryStatus = result;
  const summary = result.summary || {};
  const latest = result.latest_run;
  const runtimeBadge = $("#telemetryRuntimeBadge");
  runtimeBadge.innerHTML = `<i></i> ${escapeHtml(result.runtime_state)}`;
  runtimeBadge.className = `telemetry-runtime-badge ${slug(result.runtime_state)}`;
  $("#telemetryCount").textContent = summary.total_observations ?? 0;
  $("#telemetryLastSeen").textContent = shortTime(summary.latest_observed_at);
  $("#telemetryInterval").textContent = result.interval_seconds;
  $("#telemetryEgress").textContent = result.privacy?.outbound_transmission ? "ENABLED" : "NONE";
  $("#telemetryStorage").textContent = result.privacy?.storage || "Local store";
  $("#telemetryRunId").textContent = latest?.run_id ? shortHash(latest.run_id, 17) : "AWAITING FIRST CYCLE";

  const collectors = latest?.collectors || [];
  if (!collectors.length) {
    const node = document.createElement("div");
    node.className = "telemetry-empty";
    node.innerHTML = "<strong>No collection cycle recorded</strong><p>Run an on-demand cycle or start the resident host.</p>";
    $("#telemetryCollectorRuns").replaceChildren(node);
  } else {
    $("#telemetryCollectorRuns").replaceChildren(...collectors.map((collector, index) => {
      const node = document.createElement("article");
      node.className = `telemetry-collector ${slug(collector.state)}`;
      node.innerHTML = `
        <span>${String(index + 1).padStart(2, "0")}</span>
        <div><small>${escapeHtml(collector.id)}</small><strong>${escapeHtml(collector.name)}</strong><p>${escapeHtml(collector.detail)}</p></div>
        <div><em>${escapeHtml(collector.state)}</em><b>${escapeHtml(collector.observed)} observed</b><small>${escapeHtml(collector.duration_ms)} ms</small></div>`;
      return node;
    }));
  }

  const privacy = result.privacy || {};
  const privacyRows = [
    ["Outbound transmission", privacy.outbound_transmission ? "ENABLED" : "NONE"],
    ["Raw command lines", privacy.raw_command_lines ? "STORED" : "DISCARDED"],
    ["Raw usernames", privacy.raw_usernames ? "STORED" : "PSEUDONYMIZED"],
    ["Raw IP addresses", privacy.raw_ip_addresses ? "STORED" : "PSEUDONYMIZED"],
  ];
  $("#telemetryPrivacy").replaceChildren(...privacyRows.map(([label, value]) => {
    const node = document.createElement("div");
    node.innerHTML = `<span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong>`;
    return node;
  }));
}

function renderTelemetryEvents(result) {
  state.telemetryEvents = result;
  const events = result.events || [];
  $("#telemetryEventCount").textContent = result.summary?.total_observations ?? events.length;
  $("#telemetryRows").replaceChildren(...events.map((event) => {
    const row = document.createElement("div");
    row.className = "data-row";
    const detail = telemetryDetail(event);
    row.innerHTML = `
      <span>${escapeHtml(shortTime(event.timestamp))}</span>
      <span title="${escapeHtml(event.source)}">${escapeHtml(titleCase(event.source))}</span>
      <span title="${escapeHtml(event.event_type)}">${escapeHtml(titleCase(event.event_type))}</span>
      <span><em class="telemetry-severity ${escapeHtml(slug(event.severity))}">${escapeHtml(event.severity.toUpperCase())}</em></span>
      <span title="${escapeHtml(detail)}">${escapeHtml(detail)}</span>`;
    return row;
  }));
}

function renderHardware(profile) {
  state.hardware = profile;
  $("#hardwareState").textContent = profile.status;
  $("#hardwareProfile").textContent = profile.purpose;
  $("#hardwareInvariants").replaceChildren(...profile.invariants.map((invariant, index) => {
    const node = document.createElement("div");
    node.innerHTML = `<span>${String(index + 1).padStart(2, "0")}</span><p>${escapeHtml(invariant)}</p>`;
    return node;
  }));
}

function renderHardwareReceipt(result) {
  const receipt = result.receipt;
  const accepted = receipt.decision === "ACCEPTED_DRY_RUN";
  $("#hardwareState").textContent = accepted ? receipt.final_state.replace(/_/g, " ") : "REFUSED";
  $("#hardwareState").classList.toggle("verified", accepted);
  $("#hardwareState").classList.toggle("refused", !accepted);
  $("#hardwareReceipt").textContent = receipt.simulated_receipt_sha256;
  $("#hardwareReceipt").title = receipt.simulated_receipt_sha256;
}

function renderThreatTrace(report) {
  state.trace = report;
  const assessment = report.leading_assessment || {};
  const leading = report.links?.[0] || { matched_families: [], family_results: [], alternative_explanations: [] };
  const confidence = percent(assessment.confidence);
  const sources = [...new Set((report.profiles || []).flatMap((profile) => profile.signals?.source || []))];

  $("#traceConfidence").textContent = confidence;
  $("#traceStrength").textContent = `${assessment.strength || "LOW"} · calibrated activity relationship`;
  $("#traceDiversity").textContent = leading.matched_families?.length || 0;
  $("#traceSourceState").textContent = sources.length > 1 ? `ROTATED · ${sources.length} REFS` : `${sources.length} OPAQUE REF`;
  $("#traceIdentity").textContent = assessment.human_identity || "NOT INFERRED";
  $("#traceAssessment").textContent = titleCase(assessment.status || "insufficient_evidence");
  $("#traceAssessmentStrength").textContent = assessment.strength || "LOW";
  $("#traceScore").textContent = confidence;
  $("#traceId").textContent = report.trace_id || "—";
  $("#traceBoundary").textContent = report.identity_boundary || "AEGIS links observations, not people.";

  const alternatives = (leading.alternative_explanations || []).map((alternative) => {
    const node = document.createElement("div");
    node.className = "trace-alternative";
    node.innerHTML = `<strong>${escapeHtml(alternative.explanation)}</strong><p>${escapeHtml(alternative.why_plausible)}</p>`;
    return node;
  });
  $("#traceAlternatives").replaceChildren(...alternatives);

  const familyRows = (leading.family_results || report.signal_catalog || []).map((family) => {
    const similarity = Number(family.similarity || 0);
    const node = document.createElement("div");
    node.className = `trace-signal-row${family.divergent ? " divergent" : ""}${family.available === false ? " unavailable" : ""}`;
    const stateLabel = family.matched ? "MATCHED" : family.divergent ? "DIVERGENT" : family.available === false ? "UNAVAILABLE" : "WEAK";
    node.innerHTML = `
      <div class="trace-signal-label"><strong>${escapeHtml(family.label)}</strong><small>${escapeHtml(stateLabel)} · REL ${Math.round(Number(family.reliability || 0) * 100)} · SPOOF ${Math.round(Number(family.spoofability || 0) * 100)}</small></div>
      <div class="trace-signal-track"><span style="width:${Math.round(similarity * 100)}%"></span></div>
      <div class="trace-signal-score">${Math.round(similarity * 100)}%</div>`;
    return node;
  });
  $("#traceSignalRows").replaceChildren(...familyRows);

  const timeline = (report.timeline || []).slice(0, 10).map((event) => {
    const node = document.createElement("div");
    node.className = "trace-timeline-item";
    node.innerHTML = `<div><strong>${escapeHtml(titleCase(event.event_type))}</strong><time>${escapeHtml(shortTime(event.timestamp))}</time></div><p><em>${escapeHtml(event.session_id)}</em> · ${escapeHtml(event.target)} · ${escapeHtml(event.technique?.id || "UNMAPPED")}</p>`;
    return node;
  });
  $("#traceTimelineRows").replaceChildren(...timeline);
  $("#traceTimelineCount").textContent = `${report.timeline?.length || 0} EVENTS`;

  const sourceCards = (report.profiles || []).map((profile) => {
    const node = document.createElement("div");
    node.className = "trace-source-card";
    const source = profile.signals?.source?.[0]?.replace(/^source_ref:/, "") || "not retained";
    node.innerHTML = `<small>${escapeHtml(profile.session_id)} · PSEUDONYMOUS SOURCE CONTEXT</small><code title="${escapeHtml(source)}">${escapeHtml(source)}</code>`;
    return node;
  });
  $("#traceSourceRoute").replaceChildren(...sourceCards);
  renderTraceGraph(report.graph || { nodes: [], edges: [] });
}

function renderTraceGraph(graph) {
  const nodes = graph.nodes || [];
  const sessions = nodes.filter((node) => node.kind === "session");
  const signals = nodes.filter((node) => node.kind === "signal");
  const positions = {};
  nodes.filter((node) => node.kind === "cluster").forEach((node) => { positions[node.id] = { x: 50, y: 50 }; });
  sessions.forEach((node, index) => { positions[node.id] = { x: 17, y: 32 + index * 36 }; });
  signals.forEach((node, index) => { positions[node.id] = { x: 83, y: 16 + index * (68 / Math.max(1, signals.length - 1)) }; });

  const svg = $("#traceEdges");
  svg.replaceChildren(...(graph.edges || []).map((edge) => {
    const from = positions[edge.from];
    const to = positions[edge.to];
    if (!from || !to) return document.createComment("missing trace position");
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", from.x);
    line.setAttribute("y1", from.y);
    line.setAttribute("x2", to.x);
    line.setAttribute("y2", to.y);
    line.setAttribute("class", edge.kind || "supports");
    return line;
  }));
  $("#traceNodes").replaceChildren(...nodes.map((item) => {
    const node = document.createElement("div");
    const position = positions[item.id] || { x: 50, y: 50 };
    node.className = `trace-node ${slug(item.kind)}`;
    node.style.left = `${position.x}%`;
    node.style.top = `${position.y}%`;
    node.textContent = item.label;
    node.title = item.id;
    return node;
  }));
}

function renderTraceExperiment(experiment) {
  state.traceExperiment = experiment;
  const dataset = experiment.dataset || {};
  const winnerId = experiment.winner?.id;
  $("#traceRunId").textContent = experiment.run_id || "RUN —";
  $("#traceDatasetSummary").textContent = `${dataset.sessions || 0} sessions · ${dataset.pairs || 0} balanced pairs · grouped ${Object.values(dataset.splits || {}).join(" / ")}`;
  $("#traceExperimentStatus").textContent = `${experiment.status || "UNKNOWN"} · ${experiment.winner?.promotion || "RESEARCH ONLY"}`;

  const rows = (experiment.models || []).map((model) => {
    const metrics = model.test || {};
    const row = document.createElement("div");
    row.className = `trace-model-row${model.id === winnerId ? " winner" : ""}${model.id === "TRACE-IP-ONLY" ? " baseline-source" : ""}`;
    row.innerHTML = `
      <div class="trace-model-name"><strong>${escapeHtml(model.name)}</strong><small>${escapeHtml(model.status)}${model.id === winnerId ? " · BEST HELD-OUT RESULT" : ""}</small></div>
      <div class="trace-model-bar" title="F1 ${escapeHtml(metrics.f1)}"><span style="width:${percent(metrics.f1)}%"></span></div>
      <div class="trace-model-stat"><small>F1</small><strong>${percent(metrics.f1)}%</strong></div>
      <div class="trace-model-stat"><small>FALSE LINK</small><strong>${percent(metrics.false_link_rate)}%</strong></div>
      <div class="trace-model-stat"><small>BRIER</small><strong>${Number(metrics.brier || 0).toFixed(3)}</strong></div>`;
    return row;
  });
  $("#traceModelComparison").replaceChildren(...rows);
}

function renderTraceGraphExperiment(experiment) {
  state.traceGraph = experiment;
  const winner = experiment.winner || {};
  const metrics = winner.stress || {};
  const protocol = experiment.protocol || {};
  const audit = experiment.bridge_audit || {};
  $("#graphBCubed").textContent = percent(metrics.b_cubed_f1);
  $("#graphFalseMerge").textContent = percent(metrics.false_merge_rate);
  $("#graphRejected").textContent = `${audit.rejected || 0} / ${audit.injected || 0}`;
  $("#graphTestNodes").textContent = experiment.dataset?.graph_test_nodes || 0;
  $("#graphStatus").textContent = experiment.status || "UNKNOWN";
  $("#graphAssociationThreshold").textContent = Number(protocol.association_threshold || 0).toFixed(2);
  $("#graphSeedThreshold").textContent = Number(protocol.seed_threshold || 0).toFixed(2);
  $("#graphCrossSupport").textContent = `${percent(protocol.minimum_cross_support)}%`;
  $("#graphSizeCap").textContent = `${protocol.max_cluster_size || "—"} NODES`;
  $("#graphRunId").textContent = experiment.run_id || "—";
  $("#graphDatasetDigest").textContent = `DATASET ${shortHash(experiment.dataset?.dataset_sha256, 18)}`;

  $("#graphBridgeDecisions").replaceChildren(...(audit.decisions || []).map((decision, index) => {
    const node = document.createElement("div");
    node.className = `graph-audit-row ${slug(decision.decision)}`;
    node.innerHTML = `<span>${String(index + 1).padStart(2, "0")}</span><div><strong>${escapeHtml(decision.left.replace("SYN-F4-", ""))} ↛ ${escapeHtml(decision.right.replace("SYN-F4-", ""))}</strong><small>${escapeHtml(titleCase(decision.reason))} · support ${percent(decision.cross_support)}%</small></div><em>${escapeHtml(decision.decision)}</em>`;
    return node;
  }));

  $("#graphMethodRows").replaceChildren(...(experiment.methods || []).map((method) => {
    const stress = method.stress || {};
    const node = document.createElement("div");
    node.className = `graph-method-row${method.id === winner.id ? " winner" : ""}${method.status === "BASELINE" ? " baseline" : ""}`;
    node.innerHTML = `<span><strong>${escapeHtml(method.name)}</strong><small>${escapeHtml(method.status)}${method.id === winner.id ? " · SELECTED" : ""}</small></span><span>${percent(stress.b_cubed_f1)}%</span><span>${percent(stress.false_merge_rate)}%</span><span>${percent(stress.split_campaign_rate)}%</span><span>${escapeHtml(stress.largest_cluster)}</span>`;
    node.title = method.role;
    return node;
  }));

  const clusters = experiment.cluster_preview || [];
  $("#graphClusterCount").textContent = `${clusters.length} CLUSTERS`;
  $("#graphClusterCards").replaceChildren(...clusters.map((cluster) => {
    const composition = Object.entries(cluster.campaign_composition || {})
      .map(([campaign, count]) => `${campaign.replace("CMP-", "C")} × ${count}`)
      .join(" · ");
    const node = document.createElement("article");
    node.className = `graph-cluster-card${cluster.size === 1 ? " abstained" : ""}`;
    node.innerHTML = `<header><strong>${escapeHtml(cluster.id)}</strong><span>${escapeHtml(cluster.size)} NODE${cluster.size === 1 ? "" : "S"}</span></header><div>${Array.from({ length: Math.min(cluster.size, 8) }, (_, index) => `<i style="--node:${index}"></i>`).join("")}</div><p>${escapeHtml(composition)}</p><small>${cluster.size === 1 ? "ABSTAINED / UNRESOLVED" : "COHORT-SUPPORTED"}</small>`;
    node.title = (cluster.members || []).join(" · ");
    return node;
  }));
}

function renderSteeringExperiment(experiment) {
  state.steering = experiment;
  const winner = experiment.winner || {};
  const heldOut = winner.held_out_family || {};
  const gain = winner.gain_over_static || {};
  const checks = experiment.validity_checks || {};
  const dataset = experiment.dataset || {};
  const demo = experiment.demonstration_episode || {};

  $("#steeringSuccess").textContent = percent(heldOut.correct_confidence_rate);
  $("#steeringSaved").textContent = Number(gain.mean_interactions || 0).toFixed(2);
  $("#steeringEntropy").textContent = Number(gain.final_entropy_bits || 0).toFixed(3);
  $("#steeringUnsafe").textContent = checks.unsafe_acceptances ?? 0;
  $("#steeringStatus").textContent = experiment.status || "UNKNOWN";
  $("#steeringThreshold").textContent = `≥ ${Number(dataset.confidence_threshold || 0).toFixed(2)}`;
  $("#steeringFamily").textContent = `F${checks.held_out_family ?? "—"}`;
  $("#steeringSafetyPermits").textContent = heldOut.safety_permits ?? 0;
  $("#steeringRunId").textContent = experiment.run_id || "—";
  $("#steeringDatasetDigest").textContent = `DATASET ${shortHash(dataset.dataset_sha256, 18)}`;

  $("#steeringPolicyRows").replaceChildren(...(experiment.policies || []).map((policy) => {
    const metrics = policy.held_out_family || {};
    const node = document.createElement("div");
    node.className = `steering-policy-row${policy.id === winner.id ? " winner" : ""}`;
    node.innerHTML = `<span><strong>${escapeHtml(policy.name)}</strong><small>${escapeHtml(policy.status)}${policy.id === winner.id ? " · SELECTED" : ""}</small></span><span>${percent(metrics.correct_confidence_rate)}%</span><span>${percent(metrics.wrong_confidence_rate)}%</span><span>${Number(metrics.mean_interactions_to_correct_confidence || 0).toFixed(2)}</span><span>${Number(metrics.mean_final_entropy_bits || 0).toFixed(3)}</span><span>${Number(metrics.multiclass_brier || 0).toFixed(3)}</span>`;
    node.title = policy.role;
    return node;
  }));

  $("#steeringEpisodeIntent").textContent = demo.hidden_intent || "—";
  $("#steeringEpisodeResult").textContent = `${demo.success ? "CORRECT HIGH CONFIDENCE" : demo.wrong_confidence ? "WRONG CONFIDENCE" : "ABSTAINED"} · ${demo.executed_interactions || 0} STEPS`;
  $("#steeringEpisodeResult").classList.toggle("refused", Boolean(demo.wrong_confidence));
  $("#steeringEpisodeSteps").replaceChildren(...(demo.trace || []).map((step) => {
    const reduction = Number(step.prior_entropy_bits || 0) - Number(step.posterior_entropy_bits || 0);
    const node = document.createElement("article");
    node.className = `steering-step${reduction < 0 ? " entropy-rise" : ""}`;
    node.innerHTML = `<header><span>${String(step.step).padStart(2, "0")}</span><em>${escapeHtml(step.safety_decision)}</em></header><strong>${escapeHtml(step.probe)}</strong><p>${escapeHtml(step.outcome).toUpperCase()} → ${escapeHtml(step.leading_hypothesis)}</p><div><span>POSTERIOR <b>${percent(step.top_probability)}%</b></span><span>ΔH <b>${reduction >= 0 ? "+" : ""}${reduction.toFixed(3)}</b></span></div>`;
    node.title = `${step.probe_id} · expected information gain ${step.expected_information_gain_bits} bits`;
    return node;
  }));

  $("#steeringProbeCards").replaceChildren(...(experiment.probes || []).map((probe, index) => {
    const node = document.createElement("article");
    node.className = "steering-probe";
    node.innerHTML = `<header><span>${String(index + 1).padStart(2, "0")}</span><em>COST ${Number(probe.cost || 0).toFixed(2)}</em></header><strong>${escapeHtml(probe.label)}</strong><code>${escapeHtml(probe.target)}</code><div><span>DECOY ONLY</span><span>NO EGRESS</span><span>SYNTHETIC</span></div>`;
    return node;
  }));
}

function renderGovernance(result) {
  state.governance = result;
  const artifacts = result.artifacts || [];
  const registryVerification = result.registry_verification || {};
  const ledgerVerification = result.ledger_verification || {};
  const decisions = result.decisions || [];
  $("#governanceArtifactCount").textContent = artifacts.length;
  $("#governanceVerifiedCount").textContent = registryVerification.verified || 0;
  $("#governanceDecisionCount").textContent = decisions.length;
  $("#governanceChainState").textContent = ledgerVerification.valid ? "VERIFIED" : "INVALID";
  $("#governanceChainState").classList.toggle("refused", !ledgerVerification.valid);
  $("#governanceRegistryState").textContent = registryVerification.valid ? "ALL VERIFIED" : "VERIFY FAILED";
  $("#governanceKeyId").textContent = result.key_id || "LOCAL KEY —";
  $("#governanceChainHead").textContent = `CHAIN ${shortHash(ledgerVerification.chain_head, 16)}`;

  const candidates = artifacts.filter((artifact) => artifact.artifact_type === "model" && artifact.status === "SHADOW");
  const candidateSelect = $("#governanceCandidate");
  const selected = candidateSelect.value || result.default_candidate;
  candidateSelect.replaceChildren(...candidates.map((artifact) => {
    const option = document.createElement("option");
    option.value = artifact.artifact_id;
    option.textContent = `${artifact.name} · ${artifact.artifact_id}`;
    option.selected = artifact.artifact_id === selected;
    return option;
  }));

  $("#governanceArtifactCards").replaceChildren(...artifacts.map((artifact) => {
    const verification = (registryVerification.results || []).find((item) => item.artifact_id === artifact.artifact_id);
    const node = document.createElement("article");
    node.className = `governance-artifact ${slug(artifact.artifact_type)} ${verification?.valid ? "verified" : "invalid"}`;
    node.innerHTML = `<header><span>${escapeHtml(artifact.artifact_type.toUpperCase())}</span><em>${verification?.valid ? "VERIFIED" : "INVALID"}</em></header><strong>${escapeHtml(artifact.name)}</strong><code>${escapeHtml(artifact.artifact_id)}</code><div><small>${escapeHtml(artifact.status)}</small><small>${artifact.lineage?.length || 0} PARENT${artifact.lineage?.length === 1 ? "" : "S"}</small></div><p title="${escapeHtml(artifact.descriptor_sha256)}">SHA ${escapeHtml(shortHash(artifact.descriptor_sha256, 14))}</p>`;
    return node;
  }));

  const attestationRows = [
    ["LOCAL INTEGRITY", result.attestation?.method || "—"],
    ["EXTERNAL SIGNATURE", result.attestation?.external_digital_signature ? "PRESENT" : "NOT PRESENT"],
    ["NON-REPUDIATION", result.attestation?.non_repudiation ? "CLAIMED" : "NOT CLAIMED"],
    ["AUTO WEIGHT UPDATE", result.promotion_policy?.automatic_weight_updates ? "ENABLED" : "DISABLED"],
    ["API HUMAN SIGN-OFF", result.promotion_policy?.api_can_create_human_signoff ? "ALLOWED" : "IMPOSSIBLE"],
  ];
  $("#governanceAttestation").replaceChildren(...attestationRows.map(([label, value]) => {
    const node = document.createElement("div");
    node.innerHTML = `<span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong>`;
    return node;
  }));

  const latest = decisions[0];
  if (latest) {
    $("#governanceDecision").textContent = latest.decision.replace(/_/g, " ");
    $("#governanceDecision").className = `promotion-state ${slug(latest.decision)}`;
    $("#governanceCandidateId").textContent = latest.candidate_artifact_id;
    $("#governanceDecisionId").textContent = latest.decision_id;
    $("#governanceRecordHash").textContent = latest.record_hash;
    $("#governancePromotionChecks").replaceChildren(...(latest.record?.checks || []).map((check) => {
      const node = document.createElement("div");
      node.className = `governance-check ${check.passed ? "passed" : "held"}`;
      node.title = `Observed: ${JSON.stringify(check.observed)} · Required: ${check.required}`;
      node.innerHTML = `<i></i><span>${escapeHtml(titleCase(check.rule))}</span><em>${check.passed ? "PASS" : "HOLD"}</em>`;
      return node;
    }));
  }

  $("#promotionLedgerRows").replaceChildren(...decisions.map((decision) => {
    const row = document.createElement("div");
    row.className = "data-row";
    row.innerHTML = `<span>${escapeHtml(decision.sequence)}</span><span>${escapeHtml(shortTime(decision.created_at))}</span><span title="${escapeHtml(decision.candidate_artifact_id)}">${escapeHtml(shortHash(decision.candidate_artifact_id, 16))}</span><span><em class="governance-decision ${escapeHtml(slug(decision.decision))}">${escapeHtml(decision.decision)}</em></span><span><code title="${escapeHtml(decision.previous_hash)}">${escapeHtml(shortHash(decision.previous_hash, 14))}</code></span><span><code title="${escapeHtml(decision.record_hash)}">${escapeHtml(shortHash(decision.record_hash, 14))}</code></span>`;
    return row;
  }));
}

function renderAccess(result) {
  state.access = result;
  const license = result.license || {};
  const operator = result.operator || {};
  const audit = result.audit || {};
  const licenseValid = Boolean(license.valid);
  const auditValid = Boolean(audit.valid);

  $("#accessLicenseState").textContent = license.state || "UNKNOWN";
  $("#accessLicenseState").classList.toggle("refused", !licenseValid);
  $("#accessLicenseEdition").textContent = `${license.edition || "LOCKED"} · ${license.signature_verified ? "SIGNED" : "LOCAL RESEARCH"}`;
  $("#accessRole").textContent = operator.role || "—";
  $("#auditCommandCount").textContent = audit.commands ?? 0;
  $("#auditChainState").textContent = auditValid ? "VERIFIED" : "INVALID";
  $("#auditChainState").classList.toggle("refused", !auditValid);

  $("#licenseBadge").textContent = license.state || "UNKNOWN";
  $("#licenseBadge").className = `license-badge ${slug(license.state)}`;
  $("#licenseEdition").textContent = license.edition || "LOCKED";
  $("#licenseCustomer").textContent = license.customer || "No verified customer claim";
  const contractRows = [
    ["SIGNATURE", license.signature_verified ? "ED25519 VERIFIED" : "NOT INSTALLED"],
    ["LICENSE ID", license.license_id || "RESEARCH FALLBACK"],
    ["KEY ID", license.key_id || "NO PUBLIC KEY"],
    ["VALID UNTIL", license.expires_at ? new Date(license.expires_at).toLocaleString() : "NO EXPIRY / RESEARCH"],
    ["NODE LIMIT", license.max_nodes ?? 0],
    ["COMMERCIAL USE", license.commercial_use ? "LICENSED" : "NOT GRANTED"],
  ];
  $("#licenseContract").replaceChildren(...contractRows.map(([label, value]) => {
    const node = document.createElement("div");
    node.innerHTML = `<span>${escapeHtml(label)}</span><strong title="${escapeHtml(value)}">${escapeHtml(value)}</strong>`;
    return node;
  }));
  $("#licenseEntitlements").replaceChildren(...(license.entitlements || []).map((entitlement) => {
    const chip = document.createElement("span");
    chip.textContent = titleCase(entitlement);
    return chip;
  }));
  $("#licenseReason").textContent = license.reason || "No license decision available.";

  const scopes = operator.scopes || [];
  $("#operatorCoreRole").textContent = operator.role || "—";
  $("#operatorScopeCount").textContent = `${scopes.length} SCOPE${scopes.length === 1 ? "" : "S"}`;
  $("#operatorSessionRef").textContent = operator.session_ref || "—";
  $("#operatorAuthentication").textContent = titleCase(operator.authentication || "unknown");
  $("#operatorScopes").replaceChildren(...["read", "operate", "administer"].map((scope, index) => {
    const active = scopes.includes(scope);
    const node = document.createElement("div");
    node.className = `scope-step ${active ? "active" : "locked"}`;
    node.innerHTML = `<span>${String(index + 1).padStart(2, "0")}</span><strong>${escapeHtml(scope.toUpperCase())}</strong><em>${active ? "GRANTED" : "LOCKED"}</em>`;
    return node;
  }));
}

function renderAudit(result) {
  state.audit = result;
  const summary = result.summary || result;
  const events = result.events || [];
  const valid = Boolean(summary.valid);
  $("#auditCommandCount").textContent = summary.commands ?? 0;
  $("#auditChainState").textContent = valid ? "VERIFIED" : "INVALID";
  $("#auditChainState").classList.toggle("refused", !valid);
  $("#auditChainHead").textContent = `CHAIN ${shortHash(summary.chain_head, 17)}`;
  $("#auditChainHead").title = summary.chain_head || "";

  if (!events.length) {
    const empty = document.createElement("div");
    empty.className = "audit-empty";
    empty.textContent = "No operator commands have been issued in this installation.";
    $("#auditRows").replaceChildren(empty);
    return;
  }
  $("#auditRows").replaceChildren(...events.map((event) => {
    const row = document.createElement("div");
    row.className = "data-row";
    row.innerHTML = `
      <span>${escapeHtml(event.sequence)}</span>
      <span>${escapeHtml(shortTime(event.created_at))}</span>
      <span><code title="${escapeHtml(event.command_id)}">${escapeHtml(shortHash(event.command_id, 15))}</code></span>
      <span>${escapeHtml(event.operator_role)}</span>
      <span title="${escapeHtml(event.path)}">${escapeHtml(event.path.replace(/^\/api\//, ""))}</span>
      <span><em class="audit-decision ${escapeHtml(slug(event.decision))}">${escapeHtml(event.decision)}</em></span>
      <span><code title="${escapeHtml(event.record_hash)}">${escapeHtml(shortHash(event.record_hash, 15))}</code></span>`;
    return row;
  }));
}

function renderGatewayStatus(result) {
  state.gateway = result;
  const connectors = result.connectors || [];
  const summaryRows = Object.values(result.summary?.connectors || {});
  const inserted = summaryRows.reduce((total, item) => total + Number(item.inserted || 0), 0);
  $("#gatewayConnectorCount").textContent = connectors.length;
  $("#gatewayImportCount").textContent = result.summary?.total_imports || 0;
  $("#gatewayInsertedCount").textContent = inserted;
  $("#gatewayRawIp").textContent = result.privacy?.raw_ip_persisted ? "VIOLATION" : "ZERO";
  $("#gatewayMode").textContent = result.mode || "OFFLINE ONLY";

  $("#gatewayConnectorCards").replaceChildren(...connectors.map((connector) => {
    const card = document.createElement("article");
    card.className = "gateway-connector-card";
    card.innerHTML = `
      <header><strong>${escapeHtml(connector.name)}</strong><span>${escapeHtml(connector.status)}</span></header>
      <p>${escapeHtml(connector.role)}</p>
      <div class="gateway-contract-columns"><div><small>RETAINED</small><span>${escapeHtml(connector.retained.join(" · "))}</span></div><div><small>DISCARDED</small><span>${escapeHtml(connector.discarded.join(" · "))}</span></div></div>
      <a href="${escapeHtml(connector.official_reference)}" target="_blank" rel="noopener">Official format reference ↗</a>`;
    return card;
  }));

  const privacyEntries = [
    ["RAW ENDPOINTS", result.privacy?.raw_ip_persisted ? "VIOLATION" : "DISCARDED"],
    ["PACKET CONTENT", result.privacy?.packet_content_persisted ? "VIOLATION" : "DISCARDED"],
    ["SENSITIVE REFERENCES", result.privacy?.pseudonymization || "LOCAL HMAC"],
    ["OUTBOUND CONNECTION", result.privacy?.outbound_connection ? "ENABLED" : "ABSENT"],
    ["CASE PROMOTION", result.privacy?.automatic_case_promotion ? "AUTOMATIC" : "MANUAL / SEPARATE"],
  ];
  $("#gatewayPrivacy").replaceChildren(...privacyEntries.map(([label, value]) => {
    const node = document.createElement("div");
    node.innerHTML = `<span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong>`;
    return node;
  }));
  if (result.last_import && !state.gatewayPreview) renderGatewayReport(result.last_import, true);
}

function renderGatewayReport(report, committed = false) {
  state.gatewayPreview = report;
  $("#gatewayAcceptedCount").textContent = report.counts?.accepted || 0;
  $("#gatewayManifest").textContent = report.manifest_sha256 || "No manifest";
  $("#gatewayManifest").title = report.manifest_sha256 || "";
  $("#gatewayMode").textContent = `${report.mode} · ${report.counts?.accepted || 0}/${report.counts?.received || 0} ACCEPTED`;
  const rows = (report.outcomes || []).map((outcome) => {
    const row = document.createElement("div");
    row.className = "data-row";
    const payload = outcome.safe_payload || {};
    const references = Object.entries(payload)
      .filter(([key]) => key.endsWith("_ref") || key.includes("fingerprint"))
      .slice(0, 4)
      .map(([key, value]) => `${key.replace(/_/g, " ")}: ${value}`)
      .join(" · ");
    row.innerHTML = `
      <span>${escapeHtml(Number(outcome.index) + 1)}</span>
      <span class="gateway-row-status ${outcome.status === "REJECTED" ? "rejected" : ""}">${escapeHtml(outcome.status)}</span>
      <span>${escapeHtml(titleCase(outcome.event_type || outcome.reason || "rejected record"))}</span>
      <span>${escapeHtml((outcome.severity || "—").toUpperCase())}</span>
      <span class="gateway-reference-line" title="${escapeHtml(references || outcome.reason || "No sensitive value retained")}">${escapeHtml(references || outcome.reason || "No sensitive value retained")}</span>`;
    return row;
  });
  $("#gatewayRows").replaceChildren(...rows);
  const canCommit = !committed && report.mode === "PREVIEW" && Number(report.counts?.accepted || 0) > 0;
  $("#gatewayCommitButton").disabled = !canCommit;
}

function setGatewayRecords(records, label) {
  state.gatewayPendingRecords = records;
  state.gatewayPreview = null;
  $("#gatewayFileName").textContent = `${label} · ${records.length} record${records.length === 1 ? "" : "s"}`;
  $(".gateway-dropzone").classList.add("loaded");
  $("#gatewayPreviewButton").disabled = !records.length;
  $("#gatewayCommitButton").disabled = true;
  $("#gatewayManifest").textContent = "Awaiting privacy preview";
}

function parseGatewayFile(text) {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("The selected file is empty");
  if (trimmed.startsWith("[")) {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) throw new Error("JSON root must be an array");
    return parsed;
  }
  return trimmed.split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => JSON.parse(line));
}

async function loadGatewaySample(button) {
  setLoading(button, true);
  try {
    const connector = $("#gatewayConnector").value;
    const sample = await api(`/api/gateway/sample?connector=${encodeURIComponent(connector)}`);
    setGatewayRecords(sample.records, `${sample.connector.name} safe sample`);
    toast(`Loaded ${sample.records.length} synthetic documentation-range records`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function processGatewayRecords(button, commit = false) {
  if (!state.gatewayPendingRecords) return toast("Load a sample or local file first", true);
  setLoading(button, true);
  try {
    const connector = $("#gatewayConnector").value;
    const report = await api(commit ? "/api/gateway/import" : "/api/gateway/preview", {
      method: "POST",
      body: JSON.stringify({ connector, records: state.gatewayPendingRecords }),
    });
    renderGatewayReport(report, commit);
    if (commit) {
      const [gateway, telemetryStatus, telemetryEvents, overview] = await Promise.all([
        api("/api/gateway/status"),
        api("/api/telemetry/status"),
        api("/api/telemetry/events?limit=80"),
        api("/api/overview"),
      ]);
      renderGatewayStatus(gateway);
      renderTelemetryStatus(telemetryStatus);
      renderTelemetryEvents(telemetryEvents);
      renderOverview(overview);
      toast(`Committed ${report.counts.inserted} privacy-bounded observations · ${report.counts.deduplicated} deduplicated`);
    } else {
      toast(`Privacy preview complete · ${report.counts.accepted} accepted · ${report.counts.rejected} rejected`);
    }
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function loadDashboard(preferredCaseId = state.activeCase?.id) {
  const [overview, casesResult, topology, latestCertificate, campaigns, indicators, assets, research, experiment, learning, agents, telemetryStatus, telemetryEvents, hardware, trace, traceExperiment, traceGraph, steering, gateway, governance, access, audit] = await Promise.all([
    api("/api/overview"),
    api("/api/cases"),
    api("/api/topology"),
    api("/api/certificates/latest"),
    api("/api/investigation/campaigns"),
    api("/api/investigation/indicators"),
    api("/api/deception/assets"),
    api("/api/research/status"),
    api("/api/research/experiment"),
    api("/api/models/fabric"),
    api("/api/system/agents"),
    api("/api/telemetry/status"),
    api("/api/telemetry/events?limit=80"),
    api("/api/hardware/profile"),
    api("/api/trace/report"),
    api("/api/trace/experiment"),
    api("/api/trace/graph-experiment"),
    api("/api/steering/experiment"),
    api("/api/gateway/status"),
    api("/api/governance/status"),
    api("/api/access/status"),
    api("/api/audit/events?limit=80"),
  ]);

  state.cases = casesResult.cases;
  renderOverview(overview);
  renderCaseList(state.cases);
  renderTopology(topology);
  renderCampaigns(campaigns);
  renderIndicators(indicators);
  renderAssets(assets);
  renderResearch(research);
  renderExperiment(experiment);
  renderLearningFabric(learning);
  renderAgents(agents);
  renderTelemetryStatus(telemetryStatus);
  renderTelemetryEvents(telemetryEvents);
  renderHardware(hardware);
  renderThreatTrace(trace);
  renderTraceExperiment(traceExperiment);
  renderTraceGraphExperiment(traceGraph);
  renderSteeringExperiment(steering);
  renderGatewayStatus(gateway);
  renderGovernance(governance);
  renderAccess(access);
  renderAudit(audit);
  if (latestCertificate?.decision) renderCertificate(latestCertificate);

  const selected = state.cases.find((caseItem) => caseItem.id === preferredCaseId) || state.cases[0];
  if (selected) await selectCase(selected.id);
}

async function performSimulation(button) {
  setLoading(button, true);
  const caseId = state.activeCase?.id;
  try {
    const result = await api("/api/simulate", {
      method: "POST",
      body: JSON.stringify({ case_id: caseId }),
    });
    await loadDashboard(result.case.id);
    toast(`Contained observation: ${titleCase(result.event.event_type)}`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function evaluateProposal(button, blockedDemo = false) {
  setLoading(button, true);
  const payload = blockedDemo ? {
    action_type: "deploy_external_interceptor",
    target: "production-payments-api",
    namespace: "production",
    decoy_only: false,
    network_egress: true,
    synthetic_data_only: false,
    reversible: false,
    memory_mb: 4096,
    cpu_cores: 8,
    ttl_seconds: 7200,
    rationale: "Deliberately invalid proposal used only to verify that the Safety Gate denies it",
  } : {};
  try {
    const certificate = await api("/api/actions/evaluate", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderCertificate(certificate);
    renderOverview(await api("/api/overview"));
    toast(blockedDemo
      ? `Unsafe proposal ${certificate.decision === "DENY" ? "correctly blocked" : "was not blocked"}`
      : `Safety certificate issued: ${certificate.decision}`,
    blockedDemo && certificate.decision !== "DENY");
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function verifyAll(button) {
  setLoading(button, true);
  try {
    const result = await api("/api/evidence/verify");
    renderEvidence(result);
    toast(result.valid ? `Verified ${result.verified_events} evidence events` : "Evidence integrity failure", !result.valid);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function exportSelectedCase(button) {
  if (!state.activeCase) return toast("Select a case before exporting", true);
  setLoading(button, true);
  try {
    const bundle = await api(`/api/cases/${encodeURIComponent(state.activeCase.id)}/bundle`);
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = `${state.activeCase.id}-AEGIS-evidence-bundle.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(href);
    toast(`Manifested case bundle exported · ${shortHash(bundle.manifest_sha256, 12)}`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function rerunExperiment(button) {
  setLoading(button, true);
  try {
    const experiment = await api("/api/research/experiment/run", { method: "POST", body: "{}" });
    renderExperiment(experiment);
    toast(`Experiment reproduced · macro-F1 ${percent(experiment.metrics.macro_f1)}%`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function rerunTraceExperiment(button) {
  setLoading(button, true);
  try {
    const result = await api("/api/trace/experiment/run", { method: "POST", body: "{}" });
    renderTraceExperiment(result);
    toast(`Threat trace reproduced · held-out F1 ${percent(result.winner.test.f1)}% · candidate stays in shadow`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function rerunTraceGraphExperiment(button) {
  setLoading(button, true);
  try {
    const result = await api("/api/trace/graph-experiment/run", { method: "POST", body: "{}" });
    renderTraceGraphExperiment(result);
    toast(`Graph stress reproduced · ${result.bridge_audit.rejected}/${result.bridge_audit.injected} bridges rejected · candidate stays in shadow`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function rerunSteeringExperiment(button) {
  setLoading(button, true);
  try {
    const result = await api("/api/steering/experiment/run", { method: "POST", body: "{}" });
    renderSteeringExperiment(result);
    toast(`Steering protocol reproduced · ${percent(result.winner.held_out_family.correct_confidence_rate)}% correct high confidence · zero unsafe acceptances`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function evaluateGovernanceCandidate(button) {
  setLoading(button, true);
  try {
    const result = await api("/api/governance/evaluate", {
      method: "POST",
      body: JSON.stringify({ candidate_artifact_id: $("#governanceCandidate").value }),
    });
    renderGovernance(result.governance);
    toast(`${result.decision_record.decision.replace(/_/g, " ")} · immutable decision ${shortHash(result.decision_record.decision_id, 15)}`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function verifyGovernance(button) {
  setLoading(button, true);
  try {
    const result = await api("/api/governance/verify");
    const valid = result.registry.valid && result.ledger.valid;
    toast(valid ? `Registry + ledger verified · ${result.registry.verified} artifacts · ${result.ledger.records} decisions` : "Governance verification failed", !valid);
    const status = await api("/api/governance/status");
    renderGovernance(status);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function refreshAccessAudit() {
  const [access, audit] = await Promise.all([
    api("/api/access/status"),
    api("/api/audit/events?limit=80"),
  ]);
  renderAccess(access);
  renderAudit(audit);
}

async function verifyAuditChain(button) {
  setLoading(button, true);
  try {
    const verification = await api("/api/audit/verify");
    await refreshAccessAudit();
    toast(
      verification.valid
        ? `Verified ${verification.records} receipts across ${verification.commands} commands`
        : `Audit integrity failed at sequence ${verification.failure_sequence || "unknown"}`,
      !verification.valid,
    );
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function reloadOfflineLicense(button) {
  setLoading(button, true);
  try {
    const result = await api("/api/license/reload", { method: "POST", body: "{}" });
    renderAccess(result.access);
    await refreshAccessAudit();
    const license = state.access.license;
    toast(`${license.edition} license state · ${license.state}`, !license.valid);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

function exportThreatTrace(button) {
  if (!state.trace) return toast("Threat trace is not loaded", true);
  setLoading(button, true);
  try {
    const blob = new Blob([JSON.stringify(state.trace, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = `${state.trace.trace_id || "AEGIS-TRACE"}-manifest.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(href);
    toast(`Manifested activity trace exported · ${shortHash(state.trace.manifest_sha256, 12)}`);
  } finally {
    setLoading(button, false);
  }
}

async function evaluateLearningFabric(button) {
  setLoading(button, true);
  try {
    const result = await api("/api/models/fabric/evaluate", { method: "POST", body: "{}" });
    renderLearningFabric(result);
    const held = result.promotion.decision === "HOLD_SHADOW";
    toast(held
      ? "Candidate retained in shadow · automatic promotion remains locked"
      : `Promotion gate: ${result.promotion.decision.replace(/_/g, " ")}`,
    !held && result.promotion.decision !== "PROMOTE");
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function refreshAgentHeartbeat() {
  try {
    const [agents, telemetryStatus, telemetryEvents] = await Promise.all([
      api("/api/system/agents"),
      api("/api/telemetry/status"),
      api("/api/telemetry/events?limit=80"),
    ]);
    renderAgents(agents);
    renderTelemetryStatus(telemetryStatus);
    renderTelemetryEvents(telemetryEvents);
  } catch (error) {
    $("#nodeOnlineBadge").textContent = "NODE UNREACHABLE";
    $("#nodeOnlineBadge").className = "node-online unreachable";
  }
}

async function collectTelemetry(button) {
  setLoading(button, true);
  try {
    const run = await api("/api/telemetry/collect", { method: "POST", body: "{}" });
    const [status, events, overview] = await Promise.all([
      api("/api/telemetry/status"),
      api("/api/telemetry/events?limit=80"),
      api("/api/overview"),
    ]);
    renderTelemetryStatus(status);
    renderTelemetryEvents(events);
    renderOverview(overview);
    toast(run.status === "ALREADY_RUNNING"
      ? "A resident telemetry cycle is already in progress"
      : `Telemetry cycle ${run.status.toLowerCase()} · ${run.inserted_count ?? 0} new observations`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function runHardwareDryRun(button) {
  setLoading(button, true);
  try {
    const result = await api("/api/hardware/dry-run", { method: "POST", body: "{}" });
    renderHardwareReceipt(result);
    const receipt = result.receipt;
    toast(receipt.decision === "ACCEPTED_DRY_RUN"
      ? "Attested rule commit and rollback reproduced with zero packet effects"
      : "Hardware profile correctly refused the certificate",
    receipt.decision !== "ACCEPTED_DRY_RUN");
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

function activateWorkspace(name, updateHash = true) {
  if (name === "policy") name = "trust";
  const workspace = $(`#workspace-${name}`) || $("#workspace-mission");
  const selectedName = workspace.id.replace("workspace-", "");
  $$(".workspace").forEach((item) => item.classList.toggle("active", item === workspace));
  $$(".nav-item").forEach((item) => {
    const active = item.dataset.workspace === selectedName;
    item.classList.toggle("active", active);
    item.setAttribute("aria-current", active ? "page" : "false");
  });
  $("#workspaceTitle").textContent = workspace.dataset.title;
  $("#workspaceEyebrow").textContent = workspace.dataset.eyebrow;
  document.title = `AEGIS — ${workspace.dataset.title}`;
  if (updateHash && location.hash !== `#${selectedName}`) history.replaceState(null, "", `#${selectedName}`);
  if (selectedName === "access" && state.access) {
    refreshAccessAudit().catch((error) => toast(`Could not refresh access evidence: ${error.message}`, true));
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}

$("#simulateButton").addEventListener("click", (event) => performSimulation(event.currentTarget));
$("#caseSimulateButton").addEventListener("click", (event) => performSimulation(event.currentTarget));
$("#evaluateButton").addEventListener("click", (event) => evaluateProposal(event.currentTarget));
$("#safeEvaluateButton").addEventListener("click", (event) => evaluateProposal(event.currentTarget));
$("#unsafeEvaluateButton").addEventListener("click", (event) => evaluateProposal(event.currentTarget, true));
$("#verifyButton").addEventListener("click", (event) => verifyAll(event.currentTarget));
$("#vaultVerifyButton").addEventListener("click", (event) => verifyAll(event.currentTarget));
$("#exportCaseButton").addEventListener("click", (event) => exportSelectedCase(event.currentTarget));
$("#runExperimentButton").addEventListener("click", (event) => rerunExperiment(event.currentTarget));
$("#evaluateLearningButton").addEventListener("click", (event) => evaluateLearningFabric(event.currentTarget));
$("#hardwareDryRunButton").addEventListener("click", (event) => runHardwareDryRun(event.currentTarget));
$("#collectTelemetryButton").addEventListener("click", (event) => collectTelemetry(event.currentTarget));
$("#traceExperimentButton").addEventListener("click", (event) => rerunTraceExperiment(event.currentTarget));
$("#traceExportButton").addEventListener("click", (event) => exportThreatTrace(event.currentTarget));
$("#graphExperimentButton").addEventListener("click", (event) => rerunTraceGraphExperiment(event.currentTarget));
$("#steeringExperimentButton").addEventListener("click", (event) => rerunSteeringExperiment(event.currentTarget));
$("#governanceEvaluateButton").addEventListener("click", (event) => evaluateGovernanceCandidate(event.currentTarget));
$("#governanceVerifyButton").addEventListener("click", (event) => verifyGovernance(event.currentTarget));
$("#auditVerifyButton").addEventListener("click", (event) => verifyAuditChain(event.currentTarget));
$("#licenseReloadButton").addEventListener("click", (event) => reloadOfflineLicense(event.currentTarget));
$("#gatewaySampleButton").addEventListener("click", (event) => loadGatewaySample(event.currentTarget));
$("#gatewayPreviewButton").addEventListener("click", (event) => processGatewayRecords(event.currentTarget, false));
$("#gatewayCommitButton").addEventListener("click", (event) => processGatewayRecords(event.currentTarget, true));
$("#gatewayConnector").addEventListener("change", () => {
  state.gatewayPendingRecords = null;
  state.gatewayPreview = null;
  $("#gatewayFileName").textContent = "Choose a JSON/JSONL evidence file";
  $("#gatewayPreviewButton").disabled = true;
  $("#gatewayCommitButton").disabled = true;
  $(".gateway-dropzone").classList.remove("loaded");
});
$("#gatewayFileInput").addEventListener("change", async (event) => {
  const file = event.currentTarget.files?.[0];
  if (!file) return;
  try {
    if (file.size > 1_000_000) throw new Error("File exceeds the 1 MiB loopback request boundary");
    const records = parseGatewayFile(await file.text());
    setGatewayRecords(records, file.name);
  } catch (error) {
    toast(`Could not parse evidence file: ${error.message}`, true);
    event.currentTarget.value = "";
  }
});

$("#resetButton").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  setLoading(button, true);
  try {
    await api("/api/demo/reset", { method: "POST", body: "{}" });
    clearEvidence();
    clearCertificates();
    await loadDashboard();
    toast("Synthetic investigation reset");
  } catch (error) {
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
});

$$(".nav-item").forEach((button) => {
  button.addEventListener("click", () => activateWorkspace(button.dataset.workspace));
});
$$('[data-workspace-link]').forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    activateWorkspace(link.dataset.workspaceLink);
  });
});
window.addEventListener("hashchange", () => activateWorkspace(location.hash.slice(1) || "mission", false));

window.addEventListener("load", async () => {
  activateWorkspace(location.hash.slice(1) || "mission", false);
  try {
    await loadDashboard();
    setInterval(refreshAgentHeartbeat, 15_000);
  } catch (error) {
    toast(`AEGIS initialization failed: ${error.message}`, true);
  } finally {
    setTimeout(() => $("#splash").classList.add("hidden"), 1050);
  }
});
