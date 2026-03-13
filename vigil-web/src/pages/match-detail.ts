import * as api from '../api.js';
import { renderSidebar, initSidebar } from '../components/sidebar.js';

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

export async function renderMatchDetail(params: Record<string, string>) {
  const app = document.getElementById('app')!;

  app.innerHTML = `
<div class="layout">
  ${renderSidebar()}
  <div class="main">
    <div class="page-header">
      <h1>Match Details</h1>
      <a href="#/matches" class="btn">Back to Matches</a>
    </div>
    <p>Loading integrity data...</p>
  </div>
</div>`;

  initSidebar();

  const res = await api.getMatchIntegrity(params.id);
  if (!res.success || !res.data) {
    document.querySelector('.main')!.innerHTML = `
      <div class="page-header">
        <h1>Match Not Found</h1>
        <a href="#/matches" class="btn">Back to Matches</a>
      </div>
      <p>Could not load integrity data for match: ${escapeHtml(params.id)}</p>`;
    return;
  }

  const data = res.data;
  const totalReports = data.players.reduce((sum, p) => sum + p.reports_during_match, 0);
  const detections = data.players.filter(p => !p.is_clean).length;

  const mainEl = document.querySelector('.main')!;
  mainEl.innerHTML = `
    <div class="page-header">
      <h1>Match Details</h1>
      <a href="#/matches" class="btn">Back to Matches</a>
    </div>

    <div class="verdict ${data.all_clean ? 'verdict-clean' : 'verdict-compromised'}">
      ${data.all_clean ? 'CLEAN MATCH' : 'INTEGRITY COMPROMISED'}
    </div>

    <div class="info-grid">
      <div class="info-item">
        <div class="info-label">Total Reports</div>
        <div class="info-value">${totalReports}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Detections</div>
        <div class="info-value">${detections}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Match ID</div>
        <div class="info-value mono" style="font-size: 0.85rem; word-break: break-all;">${data.match_id}</div>
      </div>
    </div>

    <div class="section">
      <h2>Player Breakdown</h2>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Player</th>
              <th>Reports</th>
              <th>Status</th>
              <th>Violations</th>
            </tr>
          </thead>
          <tbody>
            ${data.players.map(p => `
              <tr>
                <td><a href="#/player/${p.player_id}">${escapeHtml(p.player_name)}</a></td>
                <td>${p.reports_during_match}</td>
                <td><span class="badge ${p.is_clean ? 'badge-green' : 'badge-red'}">${p.is_clean ? 'CLEAN' : 'FLAGGED'}</span></td>
                <td>${p.violations.length > 0
                  ? p.violations.map(v => `<span class="tag">${escapeHtml(v)}</span>`).join(' ')
                  : '<span style="color: var(--text-muted);">None</span>'}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>`;
}
