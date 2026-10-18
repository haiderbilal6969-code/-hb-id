(() => {
  'use strict';
  document.getElementById('year').textContent = String(new Date().getFullYear());
  const issuerInput = String(window.HB_ID_PUBLIC_CONFIG?.issuer || '').trim().replace(/\/$/, '');
  let issuer = null;
  try {
    const parsed = new URL(issuerInput);
    if (parsed.protocol === 'https:' && parsed.pathname === '/' && !parsed.search && !parsed.hash && !parsed.username && !parsed.password) issuer = parsed.origin;
  } catch (_e) {}
  if (!issuer) return;
  for (const id of ['main-portal', 'nav-portal']) {
    const link = document.getElementById(id);
    link.href = `${issuer}/portal/login`;
  }
  const discover = document.getElementById('discover-link');
  discover.hidden = false;
  discover.href = `${issuer}/.well-known/openid-configuration`;
  document.getElementById('status-icon').textContent = '🔗';
  document.getElementById('status-heading').textContent = 'Identity server URL configured';
  document.getElementById('status-body').textContent = `HB ID portal: ${issuer}. Open the portal to check whether the server is currently available.`;
})();