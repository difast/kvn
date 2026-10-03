// Thin API client. The backend is a plain JSON/Bearer API, so mobile/desktop apps can reuse it as is.
const BASE = window.KVN_API_BASE || '/api';
const store = {
  get: () => { try { return JSON.parse(localStorage.getItem('kvn_tokens') || 'null'); } catch { return null; } },
  set: (t) => localStorage.setItem('kvn_tokens', JSON.stringify(t)),
  clear: () => localStorage.removeItem('kvn_tokens'),
};

export class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

async function raw(path, { method = 'GET', body, auth = true } = {}) {
  const t = store.get();
  const res = await fetch(BASE + path, {
    method,
    headers: { ...(body && { 'Content-Type': 'application/json' }), ...(auth && t && { Authorization: `Bearer ${t.accessToken}` }) },
    body: body && JSON.stringify(body),
  });
  return res;
}

let refreshing;
async function refresh() {
  const t = store.get();
  if (!t?.refreshToken) return false;
  refreshing ||= raw('/auth/refresh', { method: 'POST', body: { refreshToken: t.refreshToken }, auth: false })
    .then(async (r) => { if (!r.ok) return false; store.set(await r.json()); return true; })
    .finally(() => { refreshing = null; });
  return refreshing;
}

async function request(path, opts = {}, asText = false) {
  let res = await raw(path, opts);
  if (res.status === 401 && opts.auth !== false && (await refresh())) res = await raw(path, opts);
  if (!res.ok) {
    let e = {};
    try { e = (await res.json()).error || {}; } catch { /* non-json */ }
    if (res.status === 401 && opts.auth !== false) { store.clear(); }
    throw new ApiError(res.status, e.code || 'error', e.message || 'Ошибка запроса');
  }
  if (res.status === 204) return null;
  return asText ? res.text() : res.json();
}

export const api = {
  isLoggedIn: () => !!store.get(),
  async register(email, password) { store.set(await request('/auth/register', { method: 'POST', body: { email, password }, auth: false })); },
  async login(email, password) { store.set(await request('/auth/login', { method: 'POST', body: { email, password }, auth: false })); },
  async logout() {
    const t = store.get();
    store.clear();
    if (t) await request('/auth/logout', { method: 'POST', body: { refreshToken: t.refreshToken }, auth: false }).catch(() => {});
  },
  forgot: (email) => request('/auth/password/forgot', { method: 'POST', body: { email }, auth: false }),
  reset: (token, password) => request('/auth/password/reset', { method: 'POST', body: { token, password }, auth: false }),
  plans: () => request('/plans', { auth: false }),
  me: () => request('/me'),
  pay: (planId = 'monthly') => request('/payments', { method: 'POST', body: { planId } }),
  profiles: () => request('/vpn/profiles'),
  createProfile: (name) => request('/vpn/profiles', { method: 'POST', body: { name } }),
  revokeProfile: (id) => request(`/vpn/profiles/${id}/revoke`, { method: 'POST' }),
  config: (id) => request(`/vpn/profiles/${id}/config`, {}, true),
};

export const $ = (s) => document.querySelector(s);
export function flash(el, text, kind = 'err') {
  el.textContent = text; // textContent: never inject server text as HTML
  el.className = `msg show ${kind}`;
}
export const fmtDate = (iso) => new Date(iso).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' });
