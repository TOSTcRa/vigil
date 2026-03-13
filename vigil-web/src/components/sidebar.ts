import { clearAuth, getStoredPlayer } from '../api';
import { navigate } from '../router';

const EYE_SVG = `<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/>
  <circle cx="12" cy="12" r="3"/>
</svg>`;

interface NavItem {
  label: string;
  hash: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', hash: '#/dashboard' },
  { label: 'Players', hash: '#/players' },
  { label: 'Matches', hash: '#/matches' },
  { label: 'Settings', hash: '#/settings' },
];

function getActiveHash(): string {
  return window.location.hash || '#/dashboard';
}

function getPlayerName(): string {
  const player = getStoredPlayer();
  return player ? player.name : 'Unknown';
}

export function renderSidebar(): string {
  const activeHash = getActiveHash();
  const playerName = getPlayerName();

  const navLinks = NAV_ITEMS.map(item => {
    const activeClass = activeHash === item.hash ? ' active' : '';
    return `<a class="sidebar-link${activeClass}" href="${item.hash}" data-nav="${item.hash}">${item.label}</a>`;
  }).join('');

  return `
<aside class="sidebar">
  <div class="sidebar-logo">
    ${EYE_SVG}
    <span>VIGIL</span>
  </div>
  <nav class="sidebar-nav">
    ${navLinks}
  </nav>
  <div class="sidebar-user">
    <div class="sidebar-user-avatar">${playerName.charAt(0).toUpperCase()}</div>
    <div>
      <div class="sidebar-user-name">${playerName}</div>
      <div class="sidebar-user-role">Player</div>
    </div>
  </div>
  <a class="sidebar-link" href="#/login" data-logout>Logout</a>
</aside>`;
}

export function initSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;

  // Handle nav link clicks — update active state
  sidebar.querySelectorAll<HTMLAnchorElement>('.sidebar-link[data-nav]').forEach(link => {
    link.addEventListener('click', () => {
      sidebar.querySelectorAll('.sidebar-link[data-nav]').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
    });
  });

  // Handle logout
  const logoutLink = sidebar.querySelector<HTMLAnchorElement>('[data-logout]');
  if (logoutLink) {
    logoutLink.addEventListener('click', (e) => {
      e.preventDefault();
      clearAuth();
      navigate('/login');
    });
  }

  // Keep active state in sync when hash changes externally
  window.addEventListener('hashchange', () => {
    const activeHash = getActiveHash();
    sidebar.querySelectorAll<HTMLAnchorElement>('.sidebar-link[data-nav]').forEach(link => {
      if (link.dataset.nav === activeHash) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });
  });
}
