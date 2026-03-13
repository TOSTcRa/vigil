import * as api from '../api.js';

const EYE_SVG = `<svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="var(--green)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/>
  <circle cx="12" cy="12" r="3"/>
</svg>`;

export async function renderLogin() {
  const app = document.getElementById('app')!;

  app.innerHTML = `
<div class="login-page">
  <div class="login-card">
    <div class="login-logo">${EYE_SVG}</div>
    <h1>Vigil</h1>
    <p class="login-tagline">VIGIL WATCHES. CHEATERS LOSE.</p>
    <form id="login-form">
      <div class="form-group">
        <label for="login-name">Name</label>
        <input type="text" id="login-name" autocomplete="username" required />
      </div>
      <div class="form-group">
        <label for="login-password">Password</label>
        <input type="password" id="login-password" autocomplete="current-password" required />
      </div>
      <div class="login-error" id="login-error"></div>
      <button type="submit" class="btn btn-primary" id="login-btn">Access Dashboard</button>
    </form>
    <p class="login-register">
      No account? <a href="#" id="register-link">Register</a>
    </p>
  </div>
</div>`;

  const form = document.getElementById('login-form') as HTMLFormElement;
  const errorEl = document.getElementById('login-error')!;
  const nameInput = document.getElementById('login-name') as HTMLInputElement;
  const passwordInput = document.getElementById('login-password') as HTMLInputElement;
  const registerLink = document.getElementById('register-link')!;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorEl.textContent = '';
    const name = nameInput.value.trim();
    const password = passwordInput.value;

    if (!name || !password) {
      errorEl.textContent = 'Name and password are required.';
      return;
    }

    const res = await api.login(name, password);
    if (res.success && res.data) {
      api.setToken(res.data.token);
      api.storePlayer(res.data.player);
      window.location.hash = '#/dashboard';
    } else {
      errorEl.textContent = res.error || 'Login failed.';
    }
  });

  registerLink.addEventListener('click', async (e) => {
    e.preventDefault();
    errorEl.textContent = '';
    const name = nameInput.value.trim();
    const password = passwordInput.value;

    if (!name || !password) {
      errorEl.textContent = 'Name and password are required.';
      return;
    }

    const res = await api.register(name, password);
    if (res.success && res.data) {
      api.setToken(res.data.token);
      api.storePlayer(res.data.player);
      window.location.hash = '#/dashboard';
    } else {
      errorEl.textContent = res.error || 'Registration failed.';
    }
  });
}
