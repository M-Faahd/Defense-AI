export const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

async function request(path, options) {
  const response = await fetch(API + path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Request failed (${response.status})`);
  }
  return data;
}

const post = { method: "POST" };

export const api = {
  stats: () => request("/api/stats"),
  events: () => request("/api/events?limit=200"),
  sessions: () => request("/api/sessions"),
  session: (id) => request(`/api/sessions/${encodeURIComponent(id)}`),
  analyze: (id, refresh = false) =>
    request(`/api/analyze/${encodeURIComponent(id)}${refresh ? "?refresh=true" : ""}`, post),
  adaptations: () => request("/api/adaptations?limit=100"),
  decoys: () => request("/api/decoys"),
  simulate: () => request("/api/simulate", post),
  reset: () => request("/api/reset", post),
};
