const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  authorityKeys: null,
  producerKeys: null,
  producerCertificate: null,
  signedToken: "",
  tampered: false,
  untrustedMode: false,
};

const els = {
  issueKeysBtn: document.querySelector("#issueKeysBtn"),
  signDataBtn: document.querySelector("#signDataBtn"),
  verifyBtn: document.querySelector("#verifyBtn"),
  tamperBtn: document.querySelector("#tamperBtn"),
  untrustedBtn: document.querySelector("#untrustedBtn"),
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
    deviceId: els.deviceId.value.trim(),
    location: els.location.value.trim(),
    reading: Number(els.reading.value),
    unit: "kWh",
    timestamp: els.timestamp.value,
  };
}

function renderChecks(checks) {
  els.resultList.innerHTML = "";
  for (const check of checks) {
    const row = document.createElement("div");
    row.className = `check ${check.kind}`;
    row.innerHTML = `
      <span class="check-icon">${check.kind === "good" ? "OK" : "!"}</span>
      <div>
        <strong>${check.title}</strong>
        <span>${check.detail}</span>
      </div>
    `;
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
  state.tampered = false;
  state.untrustedMode = false;
  setStatus("Keys issued");
  setBadge(els.dataBadge, "unsigned", "muted");
  setBadge(els.trustBadge, "not checked", "muted");
  renderChecks([{ kind: "good", title: "Trust anchor created", detail: "The authority can now certify producer keys." }]);
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
  state.tampered = false;
  state.untrustedMode = false;
  setStatus("Data signed");
  setBadge(els.dataBadge, "signed", "good");
  setBadge(els.trustBadge, "not checked", "muted");
  renderChecks([{ kind: "good", title: "JWT signed", detail: "The payload is bound to the producer private key." }]);
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
  state.tampered = true;
  setStatus("Payload modified");
  setBadge(els.dataBadge, "tampered", "bad");
  setBadge(els.trustBadge, "not checked", "muted");
  renderChecks([{ kind: "warn", title: "Payload changed", detail: "The signature was intentionally left unchanged." }]);
  renderToken();
}

async function useUntrustedProducer() {
  const attackerKeys = await generateKeyPair();
  const parts = state.signedToken.split(".");
  const signature = await signText(attackerKeys.privateKey, `${parts[0]}.${parts[1]}`);
  state.signedToken = `${parts[0]}.${parts[1]}.${signature}`;
  state.untrustedMode = true;
  state.tampered = false;
  setStatus("Untrusted signature");
  setBadge(els.dataBadge, "signed by attacker", "warn");
  setBadge(els.trustBadge, "not checked", "muted");
  renderChecks([{ kind: "warn", title: "Attacker token created", detail: "The token was signed with a key that is not in the certificate." }]);
  renderToken();
}

async function verifyToken() {
  const checks = [];
  const now = new Date();
  const certificate = state.producerCertificate;
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
  try {
    payload = decodeJson(parts[1]);
    tokenValid = await verifyText(producerPublicKey, `${parts[0]}.${parts[1]}`, parts[2]);
  } catch (error) {
    tokenValid = false;
  }

  checks.push({
    kind: tokenValid ? "good" : "bad",
    title: "Payload signature",
    detail: tokenValid ? "The data matches the certified producer public key." : "The data was modified or signed by an uncertified key.",
  });

  checks.push({
    kind: payload?.deviceId ? "good" : "bad",
    title: "Payload structure",
    detail: payload?.deviceId ? `Verified payload from ${payload.deviceId} at ${payload.timestamp}.` : "The payload could not be decoded as expected.",
  });

  const accepted = certificateValid && dateValid && tokenValid;
  setStatus(accepted ? "Accepted as authentic" : "Rejected as fake");
  setBadge(els.trustBadge, accepted ? "trusted" : "rejected", accepted ? "good" : "bad");
  setBadge(els.dataBadge, accepted ? "verified" : "failed", accepted ? "good" : "bad");
  renderChecks(checks);
}

function resetDemo() {
  state.authorityKeys = null;
  state.producerKeys = null;
  state.producerCertificate = null;
  state.signedToken = "";
  state.tampered = false;
  state.untrustedMode = false;
  updateTimestamp();
  setStatus("Waiting for keys");
  setBadge(els.dataBadge, "unsigned", "muted");
  setBadge(els.trustBadge, "not checked", "muted");
  els.resultList.innerHTML = '<p class="empty">Create keys and sign data to begin.</p>';
  renderCertificate();
  renderToken();
  enableWorkflow(false);
}

els.issueKeysBtn.addEventListener("click", issueKeys);
els.signDataBtn.addEventListener("click", signData);
els.verifyBtn.addEventListener("click", verifyToken);
els.tamperBtn.addEventListener("click", tamperPayload);
els.untrustedBtn.addEventListener("click", useUntrustedProducer);
els.resetBtn.addEventListener("click", resetDemo);

resetDemo();
