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

function truncate(str: string, len: number): string {
  return str.length > len ? str.slice(0, len) + '...' : str;
}

export async function renderMatches() {
  const app = document.getElementById('app')!;

  app.innerHTML = `
<div class="layout">
  ${renderSidebar()}
  <div class="main">
    <div class="page-header">
      <h1>Matches</h1>
    </div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Match ID</th>
            <th>Created</th>
            <th>Ended</th>
            <th>Players</th>
          </tr>
        </thead>
        <tbody id="matches-body">
          <tr><td colspan="4">Loading...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>`;

  initSidebar();

  const res = await api.listMatches();
  if (!res.success || !res.data) {
    document.getElementById('matches-body')!.innerHTML =
      '<tr><td colspan="4">Failed to load matches.</td></tr>';
    return;
  }

  const matches = res.data;
  const tbody = document.getElementById('matches-body')!;

  if (matches.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4">No matches found.</td></tr>';
    return;
  }

  const sorted = [...matches].sort((a, b) =>
    new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );

  tbody.innerHTML = sorted.map(m => `
    <tr class="clickable" data-match-id="${m.id}">
      <td><span class="mono">${truncate(m.id, 16)}</span></td>
      <td>${timeAgo(m.created_at)}</td>
      <td>${m.ended_at ? timeAgo(m.ended_at) : '<span class="badge badge-green">LIVE</span>'}</td>
      <td>${m.player_ids.length}</td>
    </tr>`).join('');

  tbody.querySelectorAll<HTMLTableRowElement>('tr.clickable').forEach(row => {
    row.addEventListener('click', () => {
      const matchId = row.dataset.matchId;
      if (matchId) {
        window.location.hash = `#/match/${matchId}`;
      }
    });
  });
}
