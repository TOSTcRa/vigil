const API_BASE = '/api';

function getToken(): string | null {
  return localStorage.getItem('vigil_token');
}

function getAdminKey(): string | null {
  return localStorage.getItem('vigil_admin_key');
}

export function setToken(token: string) {
  localStorage.setItem('vigil_token', token);
}

export function setAdminKey(key: string) {
  localStorage.setItem('vigil_admin_key', key);
}

export function clearAuth() {
  localStorage.removeItem('vigil_token');
  localStorage.removeItem('vigil_admin_key');
  localStorage.removeItem('vigil_player');
}

export function isLoggedIn(): boolean {
  return getToken() !== null;
}

export function getStoredPlayer(): { id: string; name: string } | null {
  const raw = localStorage.getItem('vigil_player');
  return raw ? JSON.parse(raw) : null;
}

export function storePlayer(player: { id: string; name: string }) {
  localStorage.setItem('vigil_player', JSON.stringify(player));
}

async function request<T>(
  path: string,
  opts: RequestInit = {},
  useAdmin = false,
): Promise<{ success: boolean; data: T | null; error: string | null }> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(opts.headers as Record<string, string> || {}),
  };

  const token = getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (useAdmin) {
    const key = getAdminKey();
    if (key) {
      headers['X-Admin-Key'] = key;
    }
  }

  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers });

  if (res.status === 401) {
    clearAuth();
    window.location.hash = '#/login';
    return { success: false, data: null, error: 'unauthorized' };
  }

  if (res.status === 403) {
    return { success: false, data: null, error: 'forbidden' };
  }

  return res.json();
}

export async function register(name: string, password: string) {
  return request<{ player: { id: string; name: string }; token: string }>(
    '/player/register',
    { method: 'POST', body: JSON.stringify({ name, password }) },
  );
}

export async function login(name: string, password: string) {
  return request<{ player: { id: string; name: string }; token: string }>(
    '/player/login',
    { method: 'POST', body: JSON.stringify({ name, password }) },
  );
}

export async function getPlayer(id: string) {
  return request<{
    id: string;
    name: string;
    registered_at: string;
    last_report: string | null;
    is_clean: boolean;
    config_hash: string | null;
  }>(`/player/${id}`);
}

export async function getPlayerStatus(id: string) {
  return request<{
    player_id: string;
    player_name: string;
    verified: boolean;
    is_clean: boolean;
    last_report: string | null;
    config_hash_match: boolean;
  }>(`/player/${id}/status`);
}

export async function listPlayers() {
  return request<Array<{
    id: string;
    name: string;
    registered_at: string;
    last_report: string | null;
    is_clean: boolean;
    config_hash: string | null;
  }>>('/players', {}, true);
}

export async function listMatches() {
  return request<Array<{
    id: string;
    created_at: string;
    ended_at: string | null;
    player_ids: string[];
  }>>('/matches', {}, true);
}

export async function getMatchIntegrity(id: string) {
  return request<{
    match_id: string;
    players: Array<{
      player_id: string;
      player_name: string;
      reports_during_match: number;
      is_clean: boolean;
      violations: string[];
    }>;
    all_clean: boolean;
  }>(`/match/${id}/integrity`);
}

export async function setExpectedConfig(content: string) {
  return request<{ config_hash: string }>(
    '/admin/config',
    { method: 'POST', body: content },
    true,
  );
}

export async function health() {
  return request<{ status: string; service: string }>('/health');
}
