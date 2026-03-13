import { route, start } from './router.js';
import { isLoggedIn } from './api.js';
import { renderLogin } from './pages/login.js';
import { renderDashboard } from './pages/dashboard.js';
import { renderPlayers } from './pages/players.js';
import { renderPlayerDetail } from './pages/player-detail.js';
import { renderMatches } from './pages/matches.js';
import { renderMatchDetail } from './pages/match-detail.js';
import { renderSettings } from './pages/settings.js';

// redirect to login if not authenticated
function guard(fn: (params: Record<string, string>) => Promise<void>) {
  return async (params: Record<string, string>) => {
    if (!isLoggedIn()) {
      window.location.hash = '#/login';
      return;
    }
    await fn(params);
  };
}

route('/login', renderLogin);
route('/dashboard', guard(renderDashboard));
route('/players', guard(renderPlayers));
route('/player/:id', guard(renderPlayerDetail));
route('/matches', guard(renderMatches));
route('/match/:id', guard(renderMatchDetail));
route('/settings', guard(renderSettings));

// default redirect
route('/', async () => {
  window.location.hash = isLoggedIn() ? '#/dashboard' : '#/login';
});

start();
