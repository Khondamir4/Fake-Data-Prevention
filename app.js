const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  authorityKeys: null,
  producerKeys: null,
  producerCertificate: null,
  signedToken: "",
  seenMessageIds: new Set(),
  auditEvents: [],
};

const els = {
  issueKeysBtn: document.querySelector("#issueKeysBtn"),
  signDataBtn: document.querySelector("#signDataBtn"),
  verifyBtn: document.querySelector("#verifyBtn"),
  tamperBtn: document.querySelector("#tamperBtn"),
  untrustedBtn: document.querySelector("#untrustedBtn"),
  expiredBtn: document.querySelector("#expiredBtn"),
  resetBtn: document.querySelector("#resetBtn"),
  deviceId: document.querySelector("#deviceId"),
  location: document.querySelector("#location"),
  reading: document.querySelector("#reading"),
  timestamp: document.querySelector("#timestamp"),
  statusText: document.querySelector("#statusText"),
  dataBadge: document.querySelector("#dataBadge"),
  trustBadge: document.querySelector("#trustBadge"),
  resultList: document.querySelector("#resultList"),
  certificateOutput: document.querySelector("#certificateOutput"),
  tokenOutput: document.querySelector("#tokenOutput"),
  auditLog: document.querySelector("#auditLog"),
};

const signingAlgorithm = {
  name: "ECDSA",
  namedCurve: "P-256",
};

const verifyAlgorithm = {
  name: "ECDSA",
  hash: "SHA-256",
};

function toBase64Url(bytes) {
  const binary = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64Url(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function encodeJson(value) {
  return toBase64Url(encoder.encode(JSON.stringify(value)));
}

function decodeJson(value) {
  return JSON.parse(decoder.decode(fromBase64Url(value)));
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = canonicalize(value[key]);
      return result;
    }, {});
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

async function generateKeyPair() {
  return crypto.subtle.generateKey(signingAlgorithm, true, ["sign", "verify"]);
}

async function signText(privateKey, text) {
  const signature = await crypto.subtle.sign(verifyAlgorithm, privateKey, encoder.encode(text));
  return toBase64Url(signature);
}

async function verifyText(publicKey, text, signature) {
  return crypto.subtle.verify(verifyAlgorithm, publicKey, fromBase64Url(signature), encoder.encode(text));
}

async function exportPublicJwk(publicKey) {
  return crypto.subtle.exportKey("jwk", publicKey);
}

async function importPublicJwk(jwk) {
  return crypto.subtle.importKey("jwk", jwk, signingAlgorithm, true, ["verify"]);
}

function setBadge(element, text, kind) {
  element.textContent = text;
  element.className = `badge ${kind}`;
}

function setStatus(text) {
  els.statusText.textContent = text;
}

function updateTimestamp() {
  els.timestamp.value = new Date().toISOString();
}

function currentPayload() {
  return {
    messageId: crypto.randomUUID(),
    deviceId: els.deviceId.value.trim(),
    location: els.location.value.trim(),
    reading: Number(els.reading.value),
    unit: "kWh",
    timestamp: els.timestamp.value,
  };
}

function addAuditEvent(action, result) {
  state.auditEvents.unshift({
    action,
    result,
    time: new Date().toLocaleTimeString(),
  });
  state.auditEvents = state.auditEvents.slice(0, 8);
  renderAuditLog();
}

function renderAuditLog() {
  els.auditLog.innerHTML = "";
  if (!state.auditEvents.length) {
    const empty = document.createElement("li");
    empty.textContent = "No security events yet.";
    els.auditLog.append(empty);
    return;
  }
  for (const event of state.auditEvents) {
    const item = document.createElement("li");
    const action = document.createElement("strong");
    const result = document.createElement("span");
    action.textContent = event.action;
    result.textContent = `${event.result} at ${event.time}`;
    item.append(action, result);
    els.auditLog.append(item);
  }
}

function renderChecks(checks) {
  els.resultList.innerHTML = "";
  for (const check of checks) {
    const row = document.createElement("div");
    row.className = `check ${check.kind}`;
    const icon = document.createElement("span");
    const content = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");

    icon.className = "check-icon";
    icon.textContent = check.kind === "good" ? "OK" : "!";
    title.textContent = check.title;
    detail.textContent = check.detail;
    content.append(title, detail);
    row.append(icon, content);
    els.resultList.append(row);
  }
}

function renderCertificate() {
  els.certificateOutput.textContent = state.producerCertificate
    ? JSON.stringify(state.producerCertificate, null, 2)
    : "No certificate issued.";
}

function renderToken() {
  els.tokenOutput.textContent = state.signedToken || "No token signed.";
}

function enableWorkflow(hasKeys) {
  els.signDataBtn.disabled = !hasKeys;
  els.verifyBtn.disabled = !state.signedToken;
  els.tamperBtn.disabled = !state.signedToken;
  els.untrustedBtn.disabled = !state.signedToken;
  els.expiredBtn.disabled = !hasKeys;
}

async function issueKeys() {
  updateTimestamp();
  state.authorityKeys = await generateKeyPair();
  state.producerKeys = await generateKeyPair();

  const producerPublicJwk = await exportPublicJwk(state.producerKeys.publicKey);
  const certificateBody = {
    issuer: "System Security Root Authority",
    subject: "Certified Energy Meter Producer",
    publicKey: producerPublicJwk,
    validFrom: new Date().toISOString(),
    validTo: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
  };

  state.producerCertificate = {
    body: certificateBody,
    signature: await signText(state.authorityKeys.privateKey, canonicalJson(certificateBody)),
  };

  state.signedToken = "";
  state.seenMessageIds.clear();
  setStatus("Keys issued");
  setBadge(els.dataBadge, "unsigned", "muted");
  setBadge(els.trustBadge, "not checked", "muted");
  renderChecks([{ kind: "good", title: "Trust anchor created", detail: "The authority can now certify producer keys." }]);
  addAuditEvent("Key issuing", "Authority and producer keys created");
  renderCertificate();
  renderToken();
  enableWorkflow(true);
}

async function signData() {
  updateTimestamp();
  const header = {
    alg: "ES256",
    typ: "JWT",
    kid: "producer-edge-meter",
  };
  const payload = currentPayload();
  const signingInput = `${encodeJson(header)}.${encodeJson(payload)}`;
  const signature = await signText(state.producerKeys.privateKey, signingInput);

  state.signedToken = `${signingInput}.${signature}`;
  setStatus("Data signed");
  setBadge(els.dataBadge, "signed", "good");
  setBadge(els.trustBadge, "not checked", "muted");
  renderChecks([{ kind: "good", title: "JWT signed", detail: "The payload is bound to the producer private key." }]);
  addAuditEvent("Data signing", `Message ${payload.messageId} signed`);
  renderToken();
  enableWorkflow(true);
}

function tamperPayload() {
  const parts = state.signedToken.split(".");
  const payload = decodeJson(parts[1]);
  payload.reading = Number((payload.reading + 18.5).toFixed(1));
  payload.location = "Modified Location";
  parts[1] = encodeJson(payload);
  state.signedToken = parts.join(".");
  setStatus("Payload modified");
  setBadge(els.dataBadge, "tampered", "bad");
  setBadge(els.trustBadge, "not checked", "muted");
  renderChecks([{ kind: "warn", title: "Payload changed", detail: "The signature was intentionally left unchanged." }]);
  addAuditEvent("Tampering", "Payload changed after signing");
  renderToken();
}

async function useUntrustedProducer() {
  const attackerKeys = await generateKeyPair();
  const parts = state.signedToken.split(".");
  const signature = await signText(attackerKeys.privateKey, `${parts[0]}.${parts[1]}`);
  state.signedToken = `${parts[0]}.${parts[1]}.${signature}`;
  setStatus("Untrusted signature");
  setBadge(els.dataBadge, "signed by attacker", "warn");
  setBadge(els.trustBadge, "not checked", "muted");
  renderChecks([{ kind: "warn", title: "Attacker token created", detail: "The token was signed with a key that is not in the certificate." }]);
  addAuditEvent("Untrusted producer", "Token signed by a non-certified key");
  renderToken();
}

async function expireCertificate() {
  const expiredBody = {
    ...state.producerCertificate.body,
    validFrom: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
    validTo: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
  };
  state.producerCertificate = {
    body: expiredBody,
    signature: await signText(state.authorityKeys.privateKey, canonicalJson(expiredBody)),
  };
  setStatus("Certificate expired");
  setBadge(els.trustBadge, "not checked", "muted");
  renderChecks([{ kind: "warn", title: "Certificate expired", detail: "The authority signature is still valid, but the validity period is over." }]);
  addAuditEvent("Certificate expiration", "Producer certificate validity changed");
  renderCertificate();
}

async function verifyToken() {
  const checks = [];
  const now = new Date();
  const certificate = state.producerCertificate;
  if (!certificate || !state.signedToken) {
    setStatus("Nothing to verify");
    renderChecks([{ kind: "bad", title: "Missing input", detail: "Issue keys and sign data before verifying." }]);
    return;
  }

  const certificateBody = certificate.body;
  const authorityPublicKey = state.authorityKeys.publicKey;
  const producerPublicKey = await importPublicJwk(certificateBody.publicKey);
  const certificateValid = await verifyText(authorityPublicKey, canonicalJson(certificateBody), certificate.signature);
  const dateValid = new Date(certificateBody.validFrom) <= now && now <= new Date(certificateBody.validTo);

  checks.push({
    kind: certificateValid ? "good" : "bad",
    title: "Certificate signature",
    detail: certificateValid ? "The producer certificate was signed by the trusted authority." : "The producer certificate is not trusted.",
  });

  checks.push({
    kind: dateValid ? "good" : "bad",
    title: "Certificate validity",
    detail: dateValid ? "The certificate is currently inside its validity period." : "The certificate is expired or not yet valid.",
  });

  const parts = state.signedToken.split(".");
  let tokenValid = false;
  let payload;
  let replayDetected = false;
  try {
    payload = decodeJson(parts[1]);
    tokenValid = await verifyText(producerPublicKey, `${parts[0]}.${parts[1]}`, parts[2]);
    replayDetected = Boolean(payload?.messageId && state.seenMessageIds.has(payload.messageId));
  } catch (error) {
    tokenValid = false;
  }

  checks.push({
    kind: tokenValid ? "good" : "bad",
    title: "Payload signature",
    detail: tokenValid ? "The token was signed by the certified producer key." : "The token was modified or signed by a key that is not certified.",
  });

  checks.push({
    kind: payload?.deviceId ? "good" : "bad",
    title: "Payload structure",
    detail: payload?.deviceId ? `Message ${payload.messageId} from ${payload.deviceId} at ${payload.timestamp}.` : "The payload could not be decoded as expected.",
  });

  checks.push({
    kind: replayDetected ? "bad" : "good",
    title: "Replay protection",
    detail: replayDetected ? "This message ID was already accepted before." : "This message ID has not been accepted before.",
  });

  const accepted = certificateValid && dateValid && tokenValid && !replayDetected;
  if (accepted && payload?.messageId) {
    state.seenMessageIds.add(payload.messageId);
  }
  setStatus(accepted ? "Accepted as authentic" : "Rejected as fake");
  setBadge(els.trustBadge, accepted ? "trusted" : "rejected", accepted ? "good" : "bad");
  setBadge(els.dataBadge, accepted ? "verified" : "failed", accepted ? "good" : "bad");
  renderChecks(checks);
  addAuditEvent("Verification", accepted ? "Accepted authentic data" : "Rejected suspicious data");
}

function resetDemo() {
  state.authorityKeys = null;
  state.producerKeys = null;
  state.producerCertificate = null;
  state.signedToken = "";
  state.seenMessageIds = new Set();
  state.auditEvents = [];
  updateTimestamp();
  setStatus("Waiting for keys");
  setBadge(els.dataBadge, "unsigned", "muted");
  setBadge(els.trustBadge, "not checked", "muted");
  els.resultList.innerHTML = '<p class="empty">Create keys and sign data to begin.</p>';
  renderCertificate();
  renderToken();
  renderAuditLog();
  enableWorkflow(false);
}

els.issueKeysBtn.addEventListener("click", issueKeys);
els.signDataBtn.addEventListener("click", signData);
els.verifyBtn.addEventListener("click", verifyToken);
els.tamperBtn.addEventListener("click", tamperPayload);
els.untrustedBtn.addEventListener("click", useUntrustedProducer);
els.expiredBtn.addEventListener("click", expireCertificate);
els.resetBtn.addEventListener("click", resetDemo);

resetDemo();
