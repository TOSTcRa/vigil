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

export async function renderDashboard() {
  const app = document.getElementById('app')!;

  app.innerHTML = `
<div class="layout">
  ${renderSidebar()}
  <div class="main">
    <div class="page-header">
      <h1>GLOBAL OVERVIEW</h1>
      <div class="status-indicator">
        <span class="status-dot"></span>
        <span>System Online</span>
      </div>
    </div>
    <div class="stats-grid" id="stats-grid">
      <div class="stat-card"><div class="stat-label">Total Players</div><div class="stat-value">--</div><div class="stat-sub">loading...</div></div>
      <div class="stat-card"><div class="stat-label">Active Now</div><div class="stat-value">--</div><div class="stat-sub">last 30s</div></div>
      <div class="stat-card"><div class="stat-label">Clean %</div><div class="stat-value">--</div><div class="stat-sub">integrity rate</div></div>
      <div class="stat-card"><div class="stat-label">Flagged</div><div class="stat-value">--</div><div class="stat-sub">players</div></div>
    </div>
    <div class="section">
      <h2>Recent Activity</h2>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Player</th>
              <th>Status</th>
              <th>Last Report</th>
            </tr>
          </thead>
          <tbody id="activity-body">
            <tr><td colspan="3">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>`;

  initSidebar();

  const res = await api.listPlayers();
  if (!res.success || !res.data) return;

  const players = res.data;
  const total = players.length;
  const now = Date.now();
  const activeNow = players.filter(p => p.last_report && (now - new Date(p.last_report).getTime()) < 30_000).length;
  const clean = players.filter(p => p.is_clean).length;
  const flagged = total - clean;
  const cleanPct = total > 0 ? Math.round((clean / total) * 100) : 0;

  const statsGrid = document.getElementById('stats-grid')!;
  statsGrid.innerHTML = `
    <div class="stat-card"><div class="stat-label">Total Players</div><div class="stat-value">${total}</div><div class="stat-sub">registered</div></div>
    <div class="stat-card"><div class="stat-label">Active Now</div><div class="stat-value">${activeNow}</div><div class="stat-sub">last 30s</div></div>
    <div class="stat-card"><div class="stat-label">Clean %</div><div class="stat-value">${cleanPct}%</div><div class="stat-sub">integrity rate</div></div>
    <div class="stat-card"><div class="stat-label">Flagged</div><div class="stat-value">${flagged}</div><div class="stat-sub">players</div></div>`;

  const activityBody = document.getElementById('activity-body')!;
  if (players.length === 0) {
    activityBody.innerHTML = '<tr><td colspan="3">No players registered yet.</td></tr>';
    return;
  }

  const sorted = [...players].sort((a, b) => {
    const aTime = a.last_report ? new Date(a.last_report).getTime() : 0;
    const bTime = b.last_report ? new Date(b.last_report).getTime() : 0;
    return bTime - aTime;
  });

  activityBody.innerHTML = sorted.slice(0, 20).map(p => `
    <tr>
      <td><a href="#/player/${p.id}">${escapeHtml(p.name)}</a></td>
      <td><span class="badge ${p.is_clean ? 'badge-green' : 'badge-red'}">${p.is_clean ? 'CLEAN' : 'FLAGGED'}</span></td>
      <td>${p.last_report ? timeAgo(p.last_report) : 'Never'}</td>
    </tr>`).join('');
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
