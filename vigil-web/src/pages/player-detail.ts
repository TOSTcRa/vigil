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

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export async function renderPlayerDetail(params: Record<string, string>) {
  const app = document.getElementById('app')!;

  app.innerHTML = `
<div class="layout">
  ${renderSidebar()}
  <div class="main">
    <div class="page-header">
      <h1>Loading player...</h1>
    </div>
  </div>
</div>`;

  initSidebar();

  const [playerRes, statusRes] = await Promise.all([
    api.getPlayer(params.id),
    api.getPlayerStatus(params.id),
  ]);

  if (!playerRes.success || !playerRes.data) {
    document.querySelector('.main')!.innerHTML = `
      <div class="page-header"><h1>Player Not Found</h1></div>
      <p>Could not load player with ID: ${escapeHtml(params.id)}</p>`;
    return;
  }

  const player = playerRes.data;
  const status = statusRes.data;
  const isClean = status ? status.is_clean : player.is_clean;
  const verified = status ? status.verified : false;

  const mainEl = document.querySelector('.main')!;
  mainEl.innerHTML = `
    <div class="page-header">
      <h1>
        ${escapeHtml(player.name)}
        <span class="badge ${isClean ? 'badge-green' : 'badge-red'}">${isClean ? (verified ? 'VERIFIED' : 'CLEAN') : 'FLAGGED'}</span>
      </h1>
      <a href="#/players" class="btn">Back to Players</a>
    </div>

    <div class="info-grid">
      <div class="info-item">
        <div class="info-label">Player ID</div>
        <div class="info-value mono">${player.id}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Join Date</div>
        <div class="info-value">${formatDate(player.registered_at)}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Status</div>
        <div class="info-value">
          <span class="badge ${isClean ? 'badge-green' : 'badge-red'}">${isClean ? 'CLEAN' : 'FLAGGED'}</span>
          ${status && !status.config_hash_match ? '<span class="badge badge-red" style="margin-left:0.5rem;">CONFIG MISMATCH</span>' : ''}
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Report History Timeline</h2>
      <div class="timeline" id="timeline">
        ${player.last_report
          ? `<div class="timeline-item">
               <div class="timeline-dot"></div>
               <div class="timeline-time">${timeAgo(player.last_report)}</div>
               <div class="timeline-text">Integrity report received</div>
             </div>`
          : '<p style="color: var(--text-muted);">No reports received yet.</p>'}
      </div>
    </div>

    ${!isClean ? `
    <div class="section">
      <h2>Violations</h2>
      <p>This player has been flagged for integrity violations. Check match integrity reports for details.</p>
    </div>` : ''}`;
}
