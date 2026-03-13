import * as api from '../api.js';
import { renderSidebar, initSidebar } from '../components/sidebar.js';

function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = Math.max(0, now - then);
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function truncate(str: string, len: number): string {
  return str.length > len ? str.slice(0, len) + '...' : str;
}

interface Player {
  id: string;
  name: string;
  registered_at: string;
  last_report: string | null;
  is_clean: boolean;
  config_hash: string | null;
}

let allPlayers: Player[] = [];

function renderTable(players: Player[]): string {
  if (players.length === 0) {
    return '<tr><td colspan="5">No players found.</td></tr>';
  }

  return players.map(p => `
    <tr>
      <td>
        <div>${escapeHtml(p.name)}</div>
        <div class="mono" style="font-size: 0.75rem; color: var(--text-muted);">${p.id}</div>
      </td>
      <td><span class="badge ${p.is_clean ? 'badge-green' : 'badge-red'}">${p.is_clean ? 'CLEAN' : 'FLAGGED'}</span></td>
      <td><span class="mono">${p.config_hash ? truncate(p.config_hash, 16) : '--'}</span></td>
      <td>${p.last_report ? timeAgo(p.last_report) : 'Never'}</td>
      <td><a href="#/player/${p.id}">View</a></td>
    </tr>`).join('');
}

export async function renderPlayers() {
  const app = document.getElementById('app')!;

  app.innerHTML = `
<div class="layout">
  ${renderSidebar()}
  <div class="main">
    <div class="page-header">
      <h1>Players List</h1>
      <div class="search-bar">
        <input type="text" class="search-input" id="player-search" placeholder="Search players..." />
      </div>
    </div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Player Name</th>
            <th>Status</th>
            <th>Config Hash</th>
            <th>Last Report</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="players-body">
          <tr><td colspan="5">Loading...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>`;

  initSidebar();

  const res = await api.listPlayers();
  if (!res.success || !res.data) {
    document.getElementById('players-body')!.innerHTML =
      '<tr><td colspan="5">Failed to load players.</td></tr>';
    return;
  }

  allPlayers = res.data;
  const tbody = document.getElementById('players-body')!;
  tbody.innerHTML = renderTable(allPlayers);

  const searchInput = document.getElementById('player-search') as HTMLInputElement;
  searchInput.addEventListener('input', () => {
    const query = searchInput.value.toLowerCase().trim();
    const filtered = query
      ? allPlayers.filter(p => p.name.toLowerCase().includes(query))
      : allPlayers;
    tbody.innerHTML = renderTable(filtered);
  });
}
