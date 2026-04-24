/* ============================================================
   VM Portal – Application Router & Utilities
   ============================================================ */

const PAGES = {
  dashboard:       { module: DashboardPage,          label: 'Dashboard' },
  vulnerabilities: { module: VulnsPage,              label: 'Findings · Vulnerabilities' },
  recommendations: { module: RecommendationsPage,    label: 'Findings · Recommendations' },
  prioritization:  { module: PrioritizationPage,     label: 'Prioritization' },
  assets:          { module: AssetsPage,             label: 'Inventory' },
  webdomains:      { module: WebDomainsPage,         label: 'Web & Domains' },
  cve:             { module: CVEPage,                label: 'CVE Database' },
  reports:         { module: null,                   label: 'Reports' },
  settings:        { module: SettingsPage,           label: 'Settings' },
};

let currentPage = 'dashboard';

const ASSET_SUB_LABELS = { hosts: 'Hosts', cloud: 'Cloud', apps: 'Applications / Systems' };

function navigateVulns(tab) {
  tab = tab || 'list';
  document.querySelectorAll('.nav-sub-item[data-vtab]').forEach(el => {
    el.classList.toggle('active', el.dataset.vtab === tab);
  });
  document.getElementById('nav-vulns-sub')?.classList.add('visible');
  if (tab === 'recommendations') navigate('recommendations');
  else navigate('vulnerabilities');
}

function navigatePrioritization(tab) {
  tab = tab || 'dashboard';
  PrioritizationPage._tab = tab;
  document.querySelectorAll('.nav-sub-item[data-ptab]').forEach(el => {
    el.classList.toggle('active', el.dataset.ptab === tab);
  });
  document.getElementById('nav-prio-sub')?.classList.add('visible');
  navigate('prioritization');
}

function navigateAssets(tab, platform) {
  tab = tab || AssetsPage.state.tab || 'hosts';
  AssetsPage.state.tab = tab;

  // If a cloud platform is specified, pre-set it before render
  if (tab === 'cloud' && platform !== undefined) {
    AssetsPage._cloudState.platform = platform;
  }

  // Update sidebar sub-nav active state
  document.querySelectorAll('.nav-sub-item[data-tab]').forEach(el => {
    el.classList.toggle('active', el.dataset.tab === tab);
  });

  // Show/hide cloud sub-nav and set active platform item
  const cloudSub = document.getElementById('nav-cloud-sub');
  if (cloudSub) {
    cloudSub.classList.toggle('visible', tab === 'cloud');
    cloudSub.querySelectorAll('.nav-sub-sub-item').forEach(el => {
      el.classList.toggle('active', platform !== undefined && el.dataset.cloudplatform === platform);
    });
  }

  if (currentPage === 'assets') {
    const label = document.getElementById('topbar-page-name');
    if (label) label.textContent = `Inventory · ${ASSET_SUB_LABELS[tab] || tab}`;
    AssetsPage.switchTab(tab);
  } else {
    navigate('assets');
  }
}

function navigateSettings(tab) {
  tab = tab || 'general';
  SettingsPage._tab = tab;
  document.querySelectorAll('.nav-sub-item[data-stab]').forEach(el => {
    el.classList.toggle('active', el.dataset.stab === tab);
  });
  document.getElementById('nav-settings-sub')?.classList.add('visible');
  navigate('settings');
}

function navigate(page) {
  if (!PAGES[page]) return;

  // Update nav items
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });

  // Show/hide sub-navs
  document.getElementById('nav-assets-sub')?.classList.toggle('visible', page === 'assets');
  const vulnsSubPages = ['vulnerabilities', 'recommendations'];
  document.getElementById('nav-vulns-sub')?.classList.toggle('visible', vulnsSubPages.includes(page));
  document.getElementById('nav-prio-sub')?.classList.toggle('visible', page === 'prioritization');
  document.getElementById('nav-settings-sub')?.classList.toggle('visible', page === 'settings');

  // Show cloud sub-nav when on cloud tab
  if (page === 'assets') {
    const tab = AssetsPage.state.tab || 'hosts';
    document.getElementById('nav-cloud-sub')?.classList.toggle('visible', tab === 'cloud');
  } else {
    document.getElementById('nav-cloud-sub')?.classList.remove('visible');
  }

  // Sync vulns sub-nav active state
  document.querySelectorAll('.nav-sub-item[data-vtab]').forEach(el => {
    el.classList.toggle('active',
      (page === 'vulnerabilities'  && el.dataset.vtab === 'list') ||
      (page === 'recommendations'  && el.dataset.vtab === 'recommendations')
    );
  });

  // Keep Findings nav-item highlighted for its sub-pages
  if (page === 'recommendations') {
    document.querySelector('.nav-item[data-page="vulnerabilities"]')?.classList.add('active');
  }

  // Prioritization nav-item highlighted when on prioritization
  if (page === 'prioritization') {
    document.querySelector('.nav-item[data-page="prioritization"]')?.classList.add('active');
  }

  // Update topbar
  const label = document.getElementById('topbar-page-name');
  if (page === 'assets') {
    const tab = AssetsPage.state.tab || 'list';
    if (label) label.textContent = `Inventory · ${ASSET_SUB_LABELS[tab] || tab}`;
    // Sync sub-nav active state
    document.querySelectorAll('.nav-sub-item[data-tab]').forEach(el => {
      el.classList.toggle('active', el.dataset.tab === tab);
    });
  } else {
    if (label) label.textContent = PAGES[page].label;
  }

  currentPage = page;
  const content = document.getElementById('page-content');

  const mod = PAGES[page].module;
  if (!mod) {
    content.innerHTML = renderPlaceholderPage(page);
    return;
  }

  content.innerHTML = `<div class="loader"><div class="spinner"></div> Loading…</div>`;
  mod.render(content).catch(err => {
    content.innerHTML = `<div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <h3>Failed to load page</h3>
      <p>${esc(err.message)}</p>
    </div>`;
    console.error(err);
  });

  // Update timestamp
  const ts = document.getElementById('last-updated');
  if (ts) ts.textContent = new Date().toLocaleTimeString();
}

function refreshCurrentPage() {
  navigate(currentPage);
}

function renderPlaceholderPage(page) {
  const configs = {
    reports: {
      icon: `<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>`,
      title: 'Reports',
      desc: 'Generate executive summaries, compliance reports, and detailed vulnerability exports.',
      items: ['Executive Summary (PDF)', 'Vulnerability Detail Report', 'Asset Risk Report', 'Compliance Overview', 'Trend Analysis Report'],
    },
    settings: {
      icon: `<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>`,
      title: 'Settings',
      desc: 'Manage scanner credentials, notification settings, and user preferences.',
      items: ['Scanner credential management', 'Alert thresholds & notifications', 'User access control', 'Audit log', 'Data retention policies'],
    },
  };

  const c = configs[page] || { title: page, desc: 'Coming soon.', items: [] };
  return `
    <div class="card" style="max-width:600px;margin:0 auto">
      <div style="display:flex;flex-direction:column;align-items:center;text-align:center;padding:32px 0 24px">
        <div style="width:56px;height:56px;border-radius:12px;background:var(--accent-glow);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;margin-bottom:16px">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5">${c.icon}</svg>
        </div>
        <h2 style="font-size:18px;font-weight:600;color:var(--text-primary);margin-bottom:8px">${c.title}</h2>
        <p style="font-size:13px;color:var(--text-muted);max-width:360px">${c.desc}</p>
      </div>
      <div style="border-top:1px solid var(--border);padding-top:20px">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px">Planned Features</div>
        ${c.items.map(item => `
          <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:13px;color:var(--text-secondary)">
            <span style="color:var(--accent)">→</span> ${item}
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

/* ── Detail Panel ──────────────────────────────────────────── */

function openDetail(title, metaHtml, bodyHtml, actionsHtml) {
  document.getElementById('detail-title').textContent   = title;
  document.getElementById('detail-meta').innerHTML      = metaHtml;
  document.getElementById('detail-body').innerHTML      = bodyHtml;
  document.getElementById('detail-actions').innerHTML   = actionsHtml;
  document.getElementById('detail-overlay').classList.add('open');
  document.getElementById('detail-panel').classList.add('open');
}

function closeDetail() {
  document.getElementById('detail-overlay').classList.remove('open');
  document.getElementById('detail-panel').classList.remove('open');
}

/* ── Scan Modal ────────────────────────────────────────────── */

async function showScanModal() {
  const scanners = await API.get('/scanners/');
  const configured = scanners.filter(s => s.configured);

  if (!configured.length) {
    toast('No scanners configured. Add one in Settings → Integrations.', 'error');
    navigateSettings('integrations');
    return;
  }

  openDetail(
    'Run Scan',
    '',
    `<div style="padding:8px 0">
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Select a scanner to run:</div>
      ${configured.map(s => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:13px;color:var(--text-primary)">${s.name}</span>
          <button class="btn btn-primary btn-sm" onclick="ScannersPage.runScan(${s.id},'${s.name}');closeDetail()">Start</button>
        </div>
      `).join('')}
    </div>`,
    `<button class="btn btn-secondary btn-sm" onclick="closeDetail()">Cancel</button>`
  );
}

/* ── Toast ─────────────────────────────────────────────────── */

function toast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      ${type === 'success' ? '<polyline points="20 6 9 17 4 12"/>'
        : type === 'error' ? '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'
        : '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'}
    </svg>
    <span>${esc(message)}</span>
  `;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

/* ── Pagination ────────────────────────────────────────────── */

const _pageCallbacks = {};

function renderPagination(containerId, page, perPage, total, onPage) {
  _pageCallbacks[containerId] = onPage;
  const totalPages = Math.ceil(total / perPage);
  const el = document.getElementById(containerId);
  if (!el || totalPages <= 1) { if (el) el.innerHTML = ''; return; }

  const start = (page - 1) * perPage + 1;
  const end   = Math.min(page * perPage, total);

  const pages = [];
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) pages.push(i);
  } else {
    pages.push(1);
    if (page > 3) pages.push('…');
    for (let i = Math.max(2, page-1); i <= Math.min(totalPages-1, page+1); i++) pages.push(i);
    if (page < totalPages - 2) pages.push('…');
    pages.push(totalPages);
  }

  el.innerHTML = `
    <div class="pagination">
      <span>Showing ${start}–${end} of ${total.toLocaleString()}</span>
      <div class="pagination-btns">
        <button class="page-btn" ${page === 1 ? 'disabled' : ''} onclick="_pageCallbacks['${containerId}'](${page-1})">‹</button>
        ${pages.map(p => p === '…'
          ? `<span class="page-btn" style="cursor:default">…</span>`
          : `<button class="page-btn ${p === page ? 'active' : ''}" onclick="_pageCallbacks['${containerId}'](${p})">${p}</button>`
        ).join('')}
        <button class="page-btn" ${page === totalPages ? 'disabled' : ''} onclick="_pageCallbacks['${containerId}'](${page+1})">›</button>
      </div>
    </div>`;
}

/* ── Helpers ───────────────────────────────────────────────── */

function esc(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

const SOURCE_COLORS = {
  nessus:  { bg: '#1d4ed820', border: '#1d4ed840', text: '#60a5fa' },
  aws:     { bg: '#ea580c20', border: '#ea580c40', text: '#fb923c' },
  nuclei:  { bg: '#16a34a20', border: '#16a34a40', text: '#4ade80' },
  mde:     { bg: '#7c3aed20', border: '#7c3aed40', text: '#a78bfa' },
  openvas: { bg: '#15803d20', border: '#15803d40', text: '#86efac' },
  nmap:    { bg: '#ca8a0420', border: '#ca8a0440', text: '#fbbf24' },
  manual:  { bg: '#37415120', border: '#37415140', text: '#9ca3af' },
};

function sourceBadge(src) {
  const c = SOURCE_COLORS[src] || { bg: '#37415120', border: '#37415140', text: '#9ca3af' };
  const label = src === 'mde' ? 'Defender' : src === 'openvas' ? 'OpenVAS' : (src || 'unknown');
  return `<span style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.3px;
    background:${c.bg};border:1px solid ${c.border};color:${c.text};
    border-radius:3px;padding:1px 5px">${esc(label)}</span>`;
}

function sevBadge(sev) {
  return `<span class="sev-badge sev-${sev}">${sev}</span>`;
}

function critBadge(crit) {
  const map = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' };
  return `<span class="sev-badge ${map[crit] || 'sev-info'}">${crit}</span>`;
}

function fmtDate(iso) {
  if (!iso) return '–';
  return new Date(iso).toLocaleString('en-GB', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' });
}

function fmtDateShort(iso) {
  if (!iso) return '–';
  return new Date(iso).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' });
}

function emptyState(msg) {
  return `<div class="empty-state">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
    <p>${msg}</p>
  </div>`;
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

/* ── Badge helpers for decision buckets ────────────────────── */

const BUCKET_COLORS = {
  P0: { bg: '#ef444420', border: '#ef444460', text: '#ef4444' },
  P1: { bg: '#f9731620', border: '#f9731660', text: '#f97316' },
  P2: { bg: '#eab30820', border: '#eab30860', text: '#eab308' },
  P3: { bg: '#3b82f620', border: '#3b82f660', text: '#3b82f6' },
  P4: { bg: '#37415120', border: '#37415160', text: '#9ca3af' },
};

function bucketBadge(bucket) {
  if (!bucket) return '';
  const c = BUCKET_COLORS[bucket] || BUCKET_COLORS.P4;
  return `<span style="font-size:11px;font-weight:700;letter-spacing:0.5px;
    background:${c.bg};border:1px solid ${c.border};color:${c.text};
    border-radius:4px;padding:2px 7px">${esc(bucket)}</span>`;
}

function slaCountdown(deadline) {
  if (!deadline) return '–';
  const now = Date.now();
  const end = new Date(deadline).getTime();
  const diff = end - now;
  if (diff < 0) {
    const days = Math.floor(Math.abs(diff) / 86400000);
    return `<span style="color:#ef4444;font-weight:600">Overdue ${days}d</span>`;
  }
  const hours = Math.floor(diff / 3600000);
  const days  = Math.floor(diff / 86400000);
  if (hours < 24) return `<span style="color:#f97316;font-weight:600">${hours}h</span>`;
  if (days < 7)   return `<span style="color:#eab308;font-weight:600">${days}d</span>`;
  return `<span style="color:var(--text-muted)">${days}d</span>`;
}

function slaStatusBadge(status) {
  if (!status) return '–';
  const colors = {
    'On Track': { bg: '#22c55e20', border: '#22c55e40', text: '#22c55e' },
    'At Risk':  { bg: '#eab30820', border: '#eab30840', text: '#eab308' },
    'Breached': { bg: '#ef444420', border: '#ef444440', text: '#ef4444' },
  };
  const c = colors[status] || { bg: '#37415120', border: '#37415140', text: '#9ca3af' };
  return `<span style="font-size:10px;font-weight:600;background:${c.bg};border:1px solid ${c.border};
    color:${c.text};border-radius:3px;padding:1px 5px">${esc(status)}</span>`;
}

/* ── Init ──────────────────────────────────────────────────── */

document.querySelectorAll('.nav-item[data-page]').forEach(el => {
  el.addEventListener('click', () => {
    if (el.dataset.page === 'assets') navigateAssets(AssetsPage.state.tab || 'hosts');
    else if (el.dataset.page === 'vulnerabilities') navigateVulns('list');
    else if (el.dataset.page === 'settings') navigateSettings('general');
    else if (el.dataset.page === 'prioritization') navigatePrioritization('dashboard');
    else navigate(el.dataset.page);
  });
});

async function _updateP0Badge() {
  try {
    const data = await API.get('/scoring/priority-dashboard');
    const critical = data.kpis?.critical_open || 0;
    const badge = document.getElementById('nav-badge-p0');
    if (badge) {
      badge.textContent = critical;
      badge.style.display = critical > 0 ? 'inline' : 'none';
    }
    const vulnBadge = document.getElementById('nav-badge-vulns');
    if (vulnBadge) {
      vulnBadge.textContent = data.kpis?.total_open || '–';
    }
  } catch (e) {
    // silently fail badge update
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const orgName = localStorage.getItem('org_name');
  if (orgName) {
    const logoText = document.querySelector('.logo-text');
    if (logoText) logoText.textContent = orgName;
  }
  navigate('dashboard');
  // Update P0 badge after short delay to allow page to load
  setTimeout(_updateP0Badge, 1500);
});
