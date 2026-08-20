const API_BASE = "http://127.0.0.1:8000";

async function request(endpoint, options = {}) {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(
      `API ${response.status}: ${text || response.statusText}`
    );
  }

  return response.json();
}


// ================================
// Health
// ================================

export async function getHealth() {
  return request("/");
}

export async function getAIHealth() {
  return request("/ai/health");
}


// ================================
// Incidents
// ================================

export async function getIncidents() {
  return request("/incidents");
}

export async function getIncident(id) {
  return request(`/incidents/${id}`);
}


// ================================
// Honeypot
// ================================

export async function getHoneypotEvents() {
  return request("/honeypot/events");
}


// ================================
// Machine Learning
// ================================

export async function predictThreat(features) {
  return request("/ml/predict", {
    method: "POST",
    body: JSON.stringify(features),
  });
}


// ================================
// Threat Intelligence
// ================================

export async function checkIOC(ioc) {
  return request(
    `/api/threat-intelligence/check/${encodeURIComponent(ioc)}`
  );
}

export async function analyzeIOC(ioc) {
  return request(
    `/api/threat-intelligence/analyze/${encodeURIComponent(ioc)}`
  );
}


// ================================
// Threat Hunting
// ================================

export async function getAllHuntingEvents() {
  return request("/hunting/all");
}

export async function huntIOC(ioc) {
  return request(
    `/hunting/ioc/${encodeURIComponent(ioc)}`
  );
}

export async function huntProcess(processName) {
  return request(
    `/hunting/process/${encodeURIComponent(processName)}`
  );
}

export async function huntIP(ip) {
  return request(
    `/hunting/ip/${encodeURIComponent(ip)}`
  );
}
