import * as api from '../api.js';
import { renderSidebar, initSidebar } from '../components/sidebar.js';

export async function renderSettings() {
  const app = document.getElementById('app')!;

  const currentAdminKey = localStorage.getItem('vigil_admin_key');

  app.innerHTML = `
<div class="layout">
  ${renderSidebar()}
  <div class="main">
    <div class="page-header">
      <h1>Admin Settings</h1>
    </div>

    <div class="settings-section">
      <h2>Global Security Config</h2>
      <div class="card">
        <p>Current expected config hash:</p>
        <div class="config-hash-display" id="config-hash-display">Loading...</div>
        <div class="form-group" style="margin-top: 1rem;">
          <label for="config-content">Paste new config content</label>
          <textarea id="config-content" rows="6" placeholder="Paste your security config content here..."></textarea>
        </div>
        <button class="btn btn-primary" id="update-config-btn">Update Security Config</button>
        <div id="config-status" style="margin-top: 0.75rem;"></div>
      </div>
    </div>

    <div class="settings-section">
      <h2>API Access</h2>
      <div class="card">
        <div class="form-group">
          <label for="admin-key-input">Admin Key</label>
          <input type="password" id="admin-key-input" placeholder="Enter admin key..." value="${currentAdminKey ? '********' : ''}" />
        </div>
        <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1rem;">
          Status: ${currentAdminKey ? '<span style="color: var(--green);">Key configured</span>' : '<span style="color: var(--yellow);">No key set</span>'}
        </p>
        <button class="btn btn-primary" id="save-key-btn">Save Admin Key</button>
        <div id="key-status" style="margin-top: 0.75rem;"></div>
      </div>
    </div>
  </div>
</div>`;

  initSidebar();

  // Try to load current config hash by fetching player list (which exercises admin auth)
  const hashDisplay = document.getElementById('config-hash-display')!;
  hashDisplay.textContent = 'Submit a config to see its hash.';

  // Update config handler
  const updateBtn = document.getElementById('update-config-btn')!;
  const configTextarea = document.getElementById('config-content') as HTMLTextAreaElement;
  const configStatus = document.getElementById('config-status')!;

  updateBtn.addEventListener('click', async () => {
    configStatus.textContent = '';
    const content = configTextarea.value.trim();
    if (!content) {
      configStatus.innerHTML = '<span style="color: var(--red);">Config content cannot be empty.</span>';
      return;
    }

    updateBtn.setAttribute('disabled', 'true');
    updateBtn.textContent = 'Updating...';

    const res = await api.setExpectedConfig(content);

    updateBtn.removeAttribute('disabled');
    updateBtn.textContent = 'Update Security Config';

    if (res.success && res.data) {
      hashDisplay.textContent = res.data.config_hash;
      configStatus.innerHTML = '<span style="color: var(--green);">Config updated successfully.</span>';
      configTextarea.value = '';
    } else {
      configStatus.innerHTML = `<span style="color: var(--red);">${res.error || 'Failed to update config.'}</span>`;
    }
  });

  // Save admin key handler
  const saveKeyBtn = document.getElementById('save-key-btn')!;
  const adminKeyInput = document.getElementById('admin-key-input') as HTMLInputElement;
  const keyStatus = document.getElementById('key-status')!;

  adminKeyInput.addEventListener('focus', () => {
    if (adminKeyInput.value === '********') {
      adminKeyInput.value = '';
    }
  });

  saveKeyBtn.addEventListener('click', () => {
    const key = adminKeyInput.value.trim();
    if (!key || key === '********') {
      keyStatus.innerHTML = '<span style="color: var(--yellow);">Enter a new key to save.</span>';
      return;
    }

    api.setAdminKey(key);
    adminKeyInput.value = '********';
    keyStatus.innerHTML = '<span style="color: var(--green);">Admin key saved.</span>';
  });
}
