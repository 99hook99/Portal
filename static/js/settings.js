/* Settings page */

const SettingsPage = {
  _tab: 'general',
  _cfg: null,

  async render(el) {
    el.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;
    try { this._cfg = await API.get('/scoring/config'); } catch(e) { this._cfg = {}; }
    el.innerHTML = this._renderPage();
    this._attachListeners();
    this._postRender();
  },

  _tabs: [
    { id: 'general',       label: 'General' },
    { id: 'integrations',  label: 'Integrations' },
    { id: 'notifications', label: 'Notifications' },
    { id: 'sla',           label: 'SLA Policies' },
    { id: 'schedules',     label: 'Scan Schedules' },
    { id: 'access',        label: 'Access & Roles' },
    { id: 'apikeys',       label: 'API Keys' },
    { id: 'audit',         label: 'Audit Log' },
    { id: 'scoring',       label: 'Risk Scoring Model' },
  ],

  _renderPage() {
    return `
      <div style="border-bottom:1px solid var(--border);margin-bottom:24px;overflow-x:auto;display:flex">
        ${this._tabs.map(t => `
          <button onclick="SettingsPage.switchTab('${t.id}')"
            style="flex-shrink:0;padding:9px 16px;font-size:12px;
                   font-weight:${this._tab === t.id ? '600' : '500'};
                   color:${this._tab === t.id ? 'var(--text-primary)' : 'var(--text-muted)'};
                   background:none;border:none;
                   border-bottom:2px solid ${this._tab === t.id ? 'var(--accent)' : 'transparent'};
                   cursor:pointer;white-space:nowrap;margin-bottom:-1px;transition:color 0.15s">
            ${t.label}
          </button>
        `).join('')}
      </div>
      <div id="settings-tab-content">${this._renderTabContent()}</div>
    `;
  },

  switchTab(tab) {
    this._tab = tab;
    const el = document.getElementById('page-content');
    if (el) this.render(el);
    document.querySelectorAll('.nav-sub-item[data-stab]').forEach(item => {
      item.classList.toggle('active', item.dataset.stab === tab);
    });
  },

  _renderTabContent() {
    switch (this._tab) {
      case 'general':       return this._renderGeneral();
      case 'integrations':  return `<div id="settings-integrations-mount"><div class="loader"><div class="spinner"></div></div></div>`;
      case 'notifications': return this._renderPlaceholder('Notifications', 'Configure email, Slack, and webhook alerts for vulnerability events.', ['Email notifications', 'Slack integration', 'Webhook endpoints', 'Alert thresholds', 'Digest schedules']);
      case 'sla':           return this._renderSLA();
      case 'schedules':     return this._renderSchedules();
      case 'access':        return this._renderPlaceholder('Access & Roles', 'Manage user accounts, roles, and permissions.', ['User management', 'Role-based access control', 'SSO / SAML integration', 'Session management', 'IP allowlist']);
      case 'apikeys':       return this._renderPlaceholder('API Keys', 'Generate and manage API keys for programmatic access.', ['Create API keys', 'Key permissions scope', 'Usage analytics', 'Key rotation', 'Expiry management']);
      case 'audit':         return this._renderPlaceholder('Audit Log', 'Track all user actions and system events.', ['User login/logout events', 'Configuration changes', 'Scan triggers', 'Finding status changes', 'Export audit data']);
      case 'scoring':       return this._renderScoring();
      default:              return this._renderGeneral();
    }
  },

  _postRender() {
    if (this._tab === 'integrations') {
      const el = document.getElementById('settings-integrations-mount');
      if (el) ScannersPage.render(el);
    } else if (this._tab === 'schedules') {
      this._loadSchedules();
    }
  },

  // ── General ───────────────────────────────────────────────────────────────

  _renderGeneral() {
    const orgName = localStorage.getItem('org_name') || 'VM Portal';
    const defSched = localStorage.getItem('default_schedule') || '24h';
    return `
      <div style="max-width:620px;display:flex;flex-direction:column;gap:20px">
        <div class="card">
          <div class="settings-section-title">Organization</div>
          <p class="settings-desc">Displayed in the portal header and reports.</p>
          <div class="settings-field-row" style="margin-top:10px">
            <div class="settings-field-label">Organization Name</div>
            <div style="flex:1;max-width:300px">
              <input type="text" id="gen-org-name"
                value="${this._esc(orgName)}"
                placeholder="e.g. Acme Security Team"
                style="width:100%;box-sizing:border-box;background:var(--bg-secondary);
                       border:1px solid var(--border);border-radius:6px;
                       padding:7px 10px;color:var(--text-primary);font-size:13px;outline:none"
                onfocus="this.style.borderColor='var(--accent)'"
                onblur="this.style.borderColor='var(--border)'">
            </div>
          </div>
        </div>

        <div class="card">
          <div class="settings-section-title">Default Scan Schedule</div>
          <p class="settings-desc">Default interval applied to new scanner integrations. Individual scanners can override this in
            <a href="#" onclick="SettingsPage.switchTab('schedules');return false" style="color:var(--accent)">Scan Schedules</a>.
          </p>
          <div class="settings-field-row" style="margin-top:10px">
            <div class="settings-field-label">Scan Frequency</div>
            <div style="flex:1;max-width:240px">
              <select id="gen-default-schedule"
                style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);
                       border-radius:6px;padding:7px 10px;color:var(--text-primary);font-size:13px;
                       outline:none;cursor:pointer"
                onfocus="this.style.borderColor='var(--accent)'"
                onblur="this.style.borderColor='var(--border)'">
                <option value="manual" ${defSched==='manual'?'selected':''}>Manual only</option>
                <option value="6h"     ${defSched==='6h'    ?'selected':''}>Every 6 hours</option>
                <option value="12h"    ${defSched==='12h'   ?'selected':''}>Every 12 hours</option>
                <option value="24h"    ${defSched==='24h'   ?'selected':''}>Every 24 hours</option>
                <option value="48h"    ${defSched==='48h'   ?'selected':''}>Every 48 hours</option>
                <option value="weekly" ${defSched==='weekly'?'selected':''}>Weekly</option>
              </select>
            </div>
          </div>
        </div>

        <div style="display:flex;justify-content:flex-end">
          <button class="btn btn-primary" onclick="SettingsPage._saveGeneral()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
              <polyline points="17 21 17 13 7 13 7 21"/>
              <polyline points="7 3 7 8 15 8"/>
            </svg>
            Save Settings
          </button>
        </div>
      </div>
    `;
  },

  _saveGeneral() {
    const name = document.getElementById('gen-org-name')?.value?.trim() || 'VM Portal';
    const schedule = document.getElementById('gen-default-schedule')?.value || '24h';
    localStorage.setItem('org_name', name);
    localStorage.setItem('default_schedule', schedule);
    const logoText = document.querySelector('.logo-text');
    if (logoText) logoText.textContent = name;
    toast('General settings saved', 'success');
  },

  _esc(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  },

  // ── SLA Policies ──────────────────────────────────────────────────────────

  _renderSLA() {
    const c = this._cfg;
    if (!c || !Object.keys(c).length) return `<div class="empty-state"><p>Failed to load configuration.</p></div>`;
    return `
      <div style="max-width:800px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
          <p style="font-size:12px;color:var(--text-muted)">
            Score thresholds that determine vulnerability classification and remediation deadlines.
          </p>
          <button class="btn btn-primary" onclick="SettingsPage._saveSLA()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
              <polyline points="17 21 17 13 7 13 7 21"/>
              <polyline points="7 3 7 8 15 8"/>
            </svg>
            Save &amp; Recalculate
          </button>
        </div>
        <div class="card">
          <div class="sla-table-wrap">
            <table class="sla-table">
              <thead>
                <tr>
                  <th>Classification</th>
                  <th>Score Range</th>
                  <th>Current SLA</th>
                  <th>Threshold (lower bound)</th>
                  <th>SLA Value</th>
                </tr>
              </thead>
              <tbody>
                <tr class="sla-row-critical">
                  <td><span class="sev-badge sev-critical">Critical</span></td>
                  <td>${this._cfgVal('threshold_critical')}–10.0</td>
                  <td><strong>${c.sla_critical_hours}h</strong></td>
                  <td>${this._fieldInline('threshold_critical', c.threshold_critical, 0, 10, 0.5)}</td>
                  <td>${this._fieldInline('sla_critical_hours', c.sla_critical_hours, 1, 168, 1, 'hours')}</td>
                </tr>
                <tr class="sla-row-high">
                  <td><span class="sev-badge sev-high">High</span></td>
                  <td>${this._cfgVal('threshold_high')}–${this._cfgVal('threshold_critical')}</td>
                  <td><strong>${c.sla_high_days} days</strong></td>
                  <td>${this._fieldInline('threshold_high', c.threshold_high, 0, 10, 0.5)}</td>
                  <td>${this._fieldInline('sla_high_days', c.sla_high_days, 1, 365, 1, 'days')}</td>
                </tr>
                <tr class="sla-row-medium">
                  <td><span class="sev-badge sev-medium">Medium</span></td>
                  <td>${this._cfgVal('threshold_medium')}–${this._cfgVal('threshold_high')}</td>
                  <td><strong>${c.sla_medium_days} days</strong></td>
                  <td>${this._fieldInline('threshold_medium', c.threshold_medium, 0, 10, 0.5)}</td>
                  <td>${this._fieldInline('sla_medium_days', c.sla_medium_days, 1, 365, 1, 'days')}</td>
                </tr>
                <tr class="sla-row-low">
                  <td><span class="sev-badge sev-low">Low</span></td>
                  <td>0.0–${this._cfgVal('threshold_medium')}</td>
                  <td><strong>${c.sla_low_days} days</strong></td>
                  <td><span style="font-size:11px;color:var(--text-muted)">–</span></td>
                  <td>${this._fieldInline('sla_low_days', c.sla_low_days, 1, 365, 1, 'days')}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  },

  async _saveSLA() {
    const payload = {};
    document.querySelectorAll('.settings-input[data-key]').forEach(el => {
      const val = parseFloat(el.value);
      if (!isNaN(val)) payload[el.dataset.key] = val;
    });
    try {
      this._cfg = await API.patch('/scoring/config', payload);
      toast('SLA policies saved. Recalculation running in background.', 'success');
      const el = document.getElementById('page-content');
      if (el) this.render(el);
    } catch(e) { toast(e.message, 'error'); }
  },

  // ── Scan Schedules ────────────────────────────────────────────────────────

  _renderSchedules() {
    const defSched = localStorage.getItem('default_schedule') || '24h';
    const schedLabels = { manual:'Manual only', '6h':'Every 6 hours', '12h':'Every 12 hours', '24h':'Every 24 hours', '48h':'Every 48 hours', weekly:'Weekly' };
    return `
      <div style="max-width:640px;display:flex;flex-direction:column;gap:16px">
        <div class="card">
          <div class="settings-section-title">Default Schedule</div>
          <p class="settings-desc">
            Global default: <strong style="color:var(--text-primary)">${schedLabels[defSched] || defSched}</strong>.
            Change it in <a href="#" onclick="SettingsPage.switchTab('general');return false" style="color:var(--accent)">General</a>.
          </p>
        </div>
        <div class="card">
          <div class="settings-section-title">Per-Integration Schedule</div>
          <p class="settings-desc">Override the default schedule per integration. Manage integrations in
            <a href="#" onclick="SettingsPage.switchTab('integrations');return false" style="color:var(--accent)">Integrations</a>.
          </p>
          <div id="schedules-scanners-list" style="margin-top:14px">
            <div class="loader"><div class="spinner"></div></div>
          </div>
        </div>
      </div>
    `;
  },

  async _loadSchedules() {
    const el = document.getElementById('schedules-scanners-list');
    if (!el) return;
    const defSched = localStorage.getItem('default_schedule') || '24h';
    const opts = [
      { val:'manual', label:'Manual only' }, { val:'6h', label:'Every 6 hours' },
      { val:'12h', label:'Every 12 hours' }, { val:'24h', label:'Every 24 hours' },
      { val:'48h', label:'Every 48 hours' }, { val:'weekly', label:'Weekly' },
    ];
    try {
      const scanners = await API.get('/scanners/');
      if (!scanners.length) {
        el.innerHTML = `<div style="font-size:12px;color:var(--text-muted);padding:8px 0">No integrations connected. Add one in <a href="#" onclick="SettingsPage.switchTab('integrations');return false" style="color:var(--accent)">Integrations</a>.</div>`;
        return;
      }
      el.innerHTML = scanners.map(s => {
        const saved = localStorage.getItem(`sched_${s.id}`) || 'default';
        return `
          <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)">
            <div>
              <div style="font-size:13px;font-weight:500;color:var(--text-primary)">${this._esc(s.name)}</div>
              <div style="font-size:11px;color:var(--text-muted)">${s.scanner_type}</div>
            </div>
            <select data-scanner-sched="${s.id}"
              style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                     padding:5px 8px;color:var(--text-primary);font-size:12px;outline:none;cursor:pointer"
              onchange="SettingsPage._saveSchedule(${s.id}, this.value)">
              <option value="default" ${saved==='default'?'selected':''}>Use default (${defSched})</option>
              ${opts.map(o => `<option value="${o.val}" ${saved===o.val?'selected':''}>${o.label}</option>`).join('')}
            </select>
          </div>
        `;
      }).join('');
    } catch(e) {
      el.innerHTML = `<div style="font-size:12px;color:var(--text-muted)">Failed to load integrations.</div>`;
    }
  },

  _saveSchedule(scannerId, value) {
    localStorage.setItem(`sched_${scannerId}`, value);
    toast('Schedule saved', 'success');
  },

  // ── Risk Scoring Model ────────────────────────────────────────────────────

  _scoringSubtab: 'operational',

  _renderScoring() {
    const c = this._cfg;
    if (!c || !Object.keys(c).length) return `<div class="empty-state"><p>Failed to load scoring config.</p></div>`;
    const sub = this._scoringSubtab || 'operational';

    const subtabs = [
      { id: 'operational', label: 'Operational Scoring' },
      { id: 'campaigns',  label: 'Campaign Prioritization' },
      { id: 'help',       label: 'Methodology & Help' },
    ];

    return `
      <div style="border-bottom:1px solid var(--border);margin-bottom:20px;display:flex;gap:0">
        ${subtabs.map(t => `
          <button onclick="SettingsPage._switchScoringTab('${t.id}')"
            style="padding:7px 14px;font-size:11px;font-weight:${sub===t.id?'600':'500'};
                   color:${sub===t.id?'var(--text-primary)':'var(--text-muted)'};
                   background:none;border:none;
                   border-bottom:2px solid ${sub===t.id?'var(--accent)':'transparent'};
                   cursor:pointer;white-space:nowrap;margin-bottom:-1px;transition:color 0.15s">
            ${t.label}
          </button>
        `).join('')}
        <div style="margin-left:auto;padding:4px 0;display:flex;gap:8px">
          <button class="btn btn-secondary btn-sm" id="settings-restore-btn" onclick="SettingsPage._restoreDefaults()" title="Reset all weights to defaults">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-4.87"/>
            </svg>
            Restore Defaults
          </button>
          <button class="btn btn-primary btn-sm" id="settings-save-btn" onclick="SettingsPage._save()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
              <polyline points="17 21 17 13 7 13 7 21"/>
              <polyline points="7 3 7 8 15 8"/>
            </svg>
            Save &amp; Recalculate
          </button>
        </div>
      </div>
      <div id="scoring-subtab-content">
        ${this._renderScoringSubtab(sub, c)}
      </div>
    `;
  },

  _switchScoringTab(sub) {
    this._scoringSubtab = sub;
    const content = document.getElementById('scoring-subtab-content');
    if (content) {
      content.innerHTML = this._renderScoringSubtab(sub, this._cfg);
      this._attachListeners();
    }
    // Update tab bar
    document.querySelectorAll('button[onclick*="_switchScoringTab"]').forEach(btn => {
      const id = btn.getAttribute('onclick').match(/'(\w+)'/)?.[1];
      btn.style.fontWeight = id === sub ? '600' : '500';
      btn.style.color = id === sub ? 'var(--text-primary)' : 'var(--text-muted)';
      btn.style.borderBottom = id === sub ? '2px solid var(--accent)' : '2px solid transparent';
    });
  },

  _renderScoringSubtab(sub, c) {
    switch(sub) {
      case 'operational': return this._renderScoringOperational(c);
      case 'campaigns':   return this._renderScoringCampaigns(c);
      case 'help':        return this._renderScoringHelp();
      default:            return this._renderScoringOperational(c);
    }
  },

  _renderScoringOperational(c) {
    return `
      <!-- Formula modal -->
      <div id="scoring-formula-modal" style="display:none;position:fixed;inset:0;z-index:9000;
        background:rgba(0,0,0,0.65);backdrop-filter:blur(3px)"
        onclick="if(event.target===this)SettingsPage._closeFormulaModal()">
        <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
          width:min(720px,92vw);max-height:82vh;overflow-y:auto;
          background:var(--bg-primary);border:1px solid var(--border);border-radius:10px;
          box-shadow:0 24px 64px rgba(0,0,0,0.5)">
          <div style="display:flex;align-items:center;justify-content:space-between;
            padding:18px 22px;border-bottom:1px solid var(--border)">
            <div style="font-size:13px;font-weight:600;color:var(--text-primary)">
              Scoring Formula &amp; Methodology
            </div>
            <button onclick="SettingsPage._closeFormulaModal()"
              style="background:none;border:none;color:var(--text-muted);cursor:pointer;
                     font-size:18px;line-height:1;padding:0 4px">&times;</button>
          </div>
          <div style="padding:22px;display:flex;flex-direction:column;gap:20px">

            <div>
              <div style="font-size:10px;font-weight:700;letter-spacing:0.8px;color:var(--text-muted);
                text-transform:uppercase;margin-bottom:10px">Base Score Selection</div>
              <div style="background:var(--bg-secondary);border-radius:7px;padding:14px 16px;
                font-family:monospace;font-size:11px;line-height:2.1;color:var(--text-secondary)">
                <span style="color:#60a5fa">if</span> CVSS exists → base = CVSS, base_source = <span style="color:#4ade80">"CVSS"</span><br>
                <span style="color:#60a5fa">elif</span> VPR exists → base = VPR, base_source = <span style="color:#f97316">"VPR"</span><br>
                <span style="color:#60a5fa">else</span> → base = severity_fallback, base_source = <span style="color:#a78bfa">"FALLBACK"</span>
              </div>
            </div>

            <div>
              <div style="font-size:10px;font-weight:700;letter-spacing:0.8px;color:var(--text-muted);
                text-transform:uppercase;margin-bottom:10px">Threat Bonus Layer <span style="color:#ef4444">(CVSS only)</span></div>
              <div style="background:var(--bg-secondary);border-radius:7px;padding:14px 16px;
                font-family:monospace;font-size:11px;line-height:2.1;color:var(--text-secondary)">
                bonus_raw = (EPSS × epss_multiplier) + kev_bonus + exploit_wild + public_poc + no_patch + eol<br>
                bonus_capped = min(<span style="color:#fbbf24">intelligence_cap</span>, bonus_raw)<br>
                base_ext = min(10.0, base + bonus_capped)<br>
                <span style="color:#64748b">— if base_source == "VPR": bonus = 0, base_ext = base</span>
              </div>
            </div>

            <div>
              <div style="font-size:10px;font-weight:700;letter-spacing:0.8px;color:var(--text-muted);
                text-transform:uppercase;margin-bottom:10px">Hard Floors &amp; Contextual Bonuses</div>
              <div style="display:flex;flex-direction:column;gap:6px;font-size:12px;color:var(--text-secondary)">
                ${[
                  ['A', 'KEV', 'base_ext = max(kev_floor, base_ext)', 'Always active', '#eab308'],
                  ['B', 'KEV + Internet-Facing', 'base_ext = max(kev_internet_floor, base_ext)', 'Always active', '#ef4444'],
                  ['C', 'Exploit-in-Wild + Internet-Facing', 'base_ext += exploit_internet_bonus', 'CVSS only', '#f97316'],
                  ['D', 'EPSS ≥ threshold + Prod + Reachable', 'base_ext += epss_prod_bonus', 'CVSS only', '#a78bfa'],
                ].map(([rule, cond, effect, scope, color]) => `
                  <div style="display:flex;gap:10px;align-items:baseline;padding:7px 10px;
                    background:var(--bg-secondary);border-radius:5px">
                    <span style="min-width:18px;font-weight:700;color:${color};font-size:11px">R${rule}</span>
                    <div style="flex:1">
                      <span style="color:var(--text-primary)">${cond}</span>
                      <span style="color:var(--text-muted);margin-left:6px">→ ${effect}</span>
                    </div>
                    <span style="font-size:10px;color:${color};opacity:0.8;white-space:nowrap">${scope}</span>
                  </div>
                `).join('')}
              </div>
            </div>

            <div>
              <div style="font-size:10px;font-weight:700;letter-spacing:0.8px;color:var(--text-muted);
                text-transform:uppercase;margin-bottom:10px">Context Multipliers <span style="color:#22c55e">(always active)</span></div>
              <div style="background:var(--bg-secondary);border-radius:7px;padding:14px 16px;
                font-family:monospace;font-size:12px;line-height:2;color:var(--text-secondary)">
                final = base_ext × <span style="color:#22c55e">ENV</span> × <span style="color:#ef4444">REACH</span> × <span style="color:#a78bfa">CRIT</span> × <span style="color:#3b82f6">CTRL</span><br>
                final = min(10.0, final)
              </div>
            </div>

            <div>
              <div style="font-size:10px;font-weight:700;letter-spacing:0.8px;color:var(--text-muted);
                text-transform:uppercase;margin-bottom:10px">Classification &amp; SLA</div>
              <div style="display:flex;gap:6px;flex-wrap:wrap">
                ${[['Critical','≥ 9.0','24h','#ef4444'],['High','≥ 7.0','7d','#f97316'],['Medium','≥ 4.0','30d','#eab308'],['Low','< 4.0','90d','#22c55e']]
                  .map(([cls,range,sla,col]) => `
                    <div style="flex:1;min-width:110px;padding:10px 12px;border-radius:6px;
                      background:${col}15;border:1px solid ${col}30;text-align:center">
                      <div style="font-weight:700;color:${col};font-size:12px">${cls}</div>
                      <div style="font-size:11px;color:var(--text-muted);margin-top:2px">${range}</div>
                      <div style="font-size:11px;color:var(--text-secondary);font-weight:500">SLA ${sla}</div>
                    </div>
                  `).join('')}
              </div>
            </div>

            <div>
              <div style="font-size:10px;font-weight:700;letter-spacing:0.8px;color:var(--text-muted);
                text-transform:uppercase;margin-bottom:8px">Severity Fallback (no CVSS, no VPR)</div>
              <div style="display:flex;gap:6px;flex-wrap:wrap;font-size:11px">
                ${[['Critical','9.0','#ef4444'],['High','7.5','#f97316'],['Medium','5.0','#eab308'],['Low','2.5','#22c55e'],['Info','1.0','#64748b']]
                  .map(([s,v,c]) => `<span style="padding:3px 8px;border-radius:4px;background:${c}20;color:${c};font-weight:600">${s} → ${v}</span>`).join('')}
              </div>
            </div>

          </div>
        </div>
      </div>

      <!-- Page header -->
      <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:18px;gap:16px">
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:3px">
            Risk Scoring Weights
          </div>
          <div style="font-size:11px;color:var(--text-muted);max-width:560px">
            All weights are applied in real-time when you save. Threat bonuses are automatically disabled for findings
            where the base score is derived from VPR (scanner-provided) rather than CVSS.
          </div>
        </div>
        <button onclick="SettingsPage._showFormulaModal()"
          style="flex-shrink:0;display:flex;align-items:center;gap:6px;padding:6px 12px;
            background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
            color:var(--text-secondary);font-size:11px;font-weight:500;cursor:pointer;white-space:nowrap;
            transition:border-color 0.15s,color 0.15s"
          onmouseover="this.style.borderColor='var(--accent)';this.style.color='var(--text-primary)'"
          onmouseout="this.style.borderColor='var(--border)';this.style.color='var(--text-secondary)'">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          Formula &amp; Methodology
        </button>
      </div>

      <!-- Single unified list card -->
      <div class="card" style="padding:0;overflow:hidden;max-width:840px">

        ${this._scoringSection('THREAT INTELLIGENCE', 'var(--accent)', `
          <div style="font-size:11px;color:var(--text-muted);padding:0 20px 12px;
            border-bottom:1px solid var(--border)">
            Applied only when base score source is <strong style="color:var(--accent)">CVSS</strong>.
            Automatically skipped for VPR-based findings to avoid double-counting threat context.
          </div>
        `, [
          this._listRow('intelligence_cap',   'Max bonus cap',           c.intelligence_cap   ?? 2.0, 0, 5,   0.1, 'Total ThreatBonus is capped at this value before being added to base'),
          this._listRow('epss_multiplier',    'EPSS × multiplier',       c.epss_multiplier    ?? 2.0, 0, 5,   0.1, 'EPSS exploitation probability × this multiplier'),
          this._listRow('kev_bonus',          'CISA KEV bonus',          c.kev_bonus          ?? 1.5, 0, 5,   0.1, 'Added when finding is in the CISA Known Exploited Vulnerabilities catalog'),
          this._listRow('exploit_wild_bonus', 'Exploit in the wild',     c.exploit_wild_bonus ?? 1.0, 0, 3,   0.1, 'Active exploitation observed in the wild'),
          this._listRow('exploit_poc_bonus',  'Public PoC',              c.exploit_poc_bonus  ?? 0.5, 0, 3,   0.1, 'Proof-of-concept exploit publicly available'),
          this._listRow('no_patch_bonus',     'No patch available',      c.no_patch_bonus     ?? 0.3, 0, 2,   0.1, 'Vendor has not released a patch'),
          this._listRow('eol_bonus',          'EOL / End-of-Support',    c.eol_bonus          ?? 0.5, 0, 2,   0.1, 'Asset operating system or software is past end-of-life'),
        ])}

        ${this._scoringSection('SMART FLOORS & CONTEXT', '#f97316', '', [
          this._listRow('kev_floor',             'KEV hard floor',              c.kev_floor              ?? 7.0,  0, 10, 0.5,  'Score forced ≥ this for any KEV finding regardless of base — always active'),
          this._listRow('kev_internet_floor',    'KEV + Internet-Facing floor', c.kev_internet_floor     ?? 9.5,  0, 10, 0.5,  'Score forced ≥ this when KEV AND asset is internet-facing — always active', '#ef4444'),
          this._listRow('exploit_internet_bonus','Exploit-in-Wild + Internet',  c.exploit_internet_bonus ?? 1.5,  0, 5,  0.25, 'Bonus when exploit in wild AND internet-facing (CVSS only)', '#f97316'),
          this._listRow('epss_prod_bonus',       'High EPSS + Prod + Reachable',c.epss_prod_bonus        ?? 1.0,  0, 5,  0.25, 'Bonus when EPSS ≥ threshold AND prod env AND reachable (CVSS only)', '#eab308'),
          this._listRow('epss_prod_threshold',   'EPSS threshold for prod bonus',c.epss_prod_threshold   ?? 0.70, 0, 1, 0.05, 'Minimum EPSS score to trigger the prod+reachable bonus', '#eab308'),
        ])}

        ${this._scoringSection('ENVIRONMENT (ENV ×)', '#22c55e', `
          <div style="font-size:11px;color:var(--text-muted);padding:0 20px 12px;
            border-bottom:1px solid var(--border)">
            Multiplier based on the asset's <code>environment</code> field. Always applied.
          </div>
        `, [
          this._listRow('env2_prod',    'Production',    c.env2_prod    ?? 1.10, 0.1, 2, 0.05, '', '#22c55e'),
          this._listRow('env2_uat',     'UAT / Staging', c.env2_uat     ?? 1.00, 0.1, 2, 0.05, '', '#3b82f6'),
          this._listRow('env2_dev',     'Development',   c.env2_dev     ?? 0.90, 0.1, 2, 0.05, '', '#eab308'),
          this._listRow('env2_test',    'Test / Lab',    c.env2_test    ?? 0.80, 0.1, 2, 0.05, '', '#64748b'),
          this._listRow('env2_unknown', 'Unknown',       c.env2_unknown ?? 1.00, 0.1, 2, 0.05),
        ])}

        ${this._scoringSection('REACHABILITY (REACH ×)', '#ef4444', `
          <div style="font-size:11px;color:var(--text-muted);padding:0 20px 12px;
            border-bottom:1px solid var(--border)">
            Based on <code>reachability</code> field (or derived from <code>internet_exposure</code>). Always applied.
          </div>
        `, [
          this._listRow('reach_internet',  'Internet-Facing',          c.reach_internet  ?? 1.30, 0.1, 3, 0.05, 'Directly reachable from the public internet', '#ef4444'),
          this._listRow('reach_partner',   'Partner / VPN / Reachable',c.reach_partner   ?? 1.15, 0.1, 3, 0.05, 'Reachable by partners, VPN users, or authenticated external users', '#f97316'),
          this._listRow('reach_internal',  'Internal',                  c.reach_internal  ?? 1.00, 0.1, 3, 0.05, 'Internal network only', '#3b82f6'),
          this._listRow('reach_isolated',  'Isolated / Air-Gapped',    c.reach_isolated  ?? 0.85, 0.1, 3, 0.05, 'Isolated segment or air-gapped environment', '#22c55e'),
          this._listRow('reach_unknown',   'Unknown',                   c.reach_unknown   ?? 1.00, 0.1, 3, 0.05),
        ])}

        ${this._scoringSection('ASSET CRITICALITY (CRIT ×)', '#a78bfa', `
          <div style="font-size:11px;color:var(--text-muted);padding:0 20px 12px;
            border-bottom:1px solid var(--border)">
            Based on <code>asset_tier</code> field (or derived from criticality + labels). Always applied.
          </div>
        `, [
          this._listRow('crit_tier0',     'Tier 0 — Crown Jewel',    c.crit_tier0     ?? 1.20, 0.5, 2, 0.05, 'crown_jewel or tier0 label, or explicit tier0 field', '#ef4444'),
          this._listRow('crit_prodc',     'Production Critical',      c.crit_prodc     ?? 1.15, 0.5, 2, 0.05, 'Critical criticality or business_criticality', '#f97316'),
          this._listRow('crit_important', 'Important',                c.crit_important ?? 1.05, 0.5, 2, 0.05, 'High criticality or business_criticality', '#eab308'),
          this._listRow('crit_standard',  'Standard',                 c.crit_standard  ?? 1.00, 0.5, 2, 0.05, 'Default tier for unclassified assets', '#3b82f6'),
          this._listRow('crit_low',       'Low-Value',                c.crit_low       ?? 0.90, 0.5, 2, 0.05, 'Low criticality assets — score is reduced', '#22c55e'),
          this._listRow('crit_unknown',   'Unknown',                  c.crit_unknown   ?? 1.00, 0.5, 2, 0.05),
        ])}

        ${this._scoringSection('COMPENSATING CONTROLS (CTRL ×)', '#3b82f6', `
          <div style="font-size:11px;color:var(--text-muted);padding:0 20px 12px;
            border-bottom:1px solid var(--border)">
            Based on <code>compensating_controls</code> field on the asset. Values below 1.0 reduce the score. Always applied.
          </div>
        `, [
          this._listRow('ctrl_none',          'No controls',          c.ctrl_none         ?? 1.00, 0.1, 1.2, 0.05, 'No compensating controls in place'),
          this._listRow('ctrl_one_verified',  '1 verified control',   c.ctrl_one_verified ?? 0.95, 0.1, 1.2, 0.05, 'e.g. WAF, MFA, or network segmentation'),
          this._listRow('ctrl_two_verified',  '2 verified controls',  c.ctrl_two_verified ?? 0.90, 0.1, 1.2, 0.05, 'Two independently verified mitigating controls'),
          this._listRow('ctrl_multilayer',    'Multilayer defense',   c.ctrl_multilayer   ?? 0.80, 0.1, 1.2, 0.05, 'Defense-in-depth: WAF + segmentation + EDR or equivalent'),
          this._listRow('ctrl_unknown',       'Unknown',              c.ctrl_unknown      ?? 1.00, 0.1, 1.2, 0.05),
        ])}

      </div>
    `;
  },

  _scoringSection(title, color, extraHtml, rows) {
    return `
      <div>
        <div style="display:flex;align-items:center;gap:8px;padding:11px 20px;
          background:var(--bg-secondary);border-bottom:1px solid var(--border)">
          <span style="display:inline-block;width:3px;height:14px;border-radius:2px;background:${color}"></span>
          <span style="font-size:10px;font-weight:700;letter-spacing:0.7px;color:var(--text-muted);text-transform:uppercase">
            ${title}
          </span>
        </div>
        ${extraHtml || ''}
        ${rows.join('')}
      </div>
    `;
  },

  _listRow(key, label, value, min, max, step, hint = '', color = '') {
    const accentColor = color || 'var(--accent)';
    return `
      <div style="display:flex;align-items:center;gap:0;padding:0 20px;
        border-bottom:1px solid var(--border);min-height:46px"
        onmouseover="this.style.background='var(--bg-secondary)'"
        onmouseout="this.style.background='transparent'">
        <div style="flex:1;min-width:0;padding:8px 0">
          <div style="font-size:12px;color:${color || 'var(--text-primary)'};font-weight:500">${label}</div>
          ${hint ? `<div style="font-size:10px;color:var(--text-muted);margin-top:1px">${hint}</div>` : ''}
        </div>
        <div style="display:flex;align-items:center;gap:10px;flex-shrink:0;margin-left:16px">
          <div style="width:140px">
            <input type="range" class="settings-range" data-key="${key}" data-twin="true"
              value="${value}" min="${min}" max="${max}" step="${step}"
              style="width:100%;accent-color:${accentColor}">
          </div>
          <input type="number" class="settings-input" data-key="${key}"
            value="${value}" min="${min}" max="${max}" step="${step}"
            style="width:58px;text-align:right;background:var(--bg-secondary);
                   border:1px solid var(--border);border-radius:5px;
                   padding:4px 7px;color:var(--text-primary);font-size:12px;
                   font-weight:600;outline:none"
            onfocus="this.style.borderColor='${accentColor}'"
            onblur="this.style.borderColor='var(--border)'">
        </div>
      </div>
    `;
  },

  _showFormulaModal() {
    const m = document.getElementById('scoring-formula-modal');
    if (m) m.style.display = 'block';
    document.body.style.overflow = 'hidden';
  },

  _closeFormulaModal() {
    const m = document.getElementById('scoring-formula-modal');
    if (m) m.style.display = 'none';
    document.body.style.overflow = '';
  },

  _renderScoringCampaigns(c) {
    return `
      <div style="max-width:640px;display:flex;flex-direction:column;gap:16px">
        <div class="card">
          <div class="settings-section-title">Campaign Grouping</div>
          <p class="settings-desc">
            Findings are automatically grouped into campaigns to identify coordinated attack surfaces.
          </p>
          <div style="padding:12px;background:var(--bg-secondary);border-radius:6px;font-size:12px;color:var(--text-secondary);margin-top:10px">
            <div style="font-weight:600;color:var(--text-primary);margin-bottom:6px">Grouping Priority:</div>
            <div style="display:flex;flex-direction:column;gap:4px">
              <div><span style="color:var(--accent)">1.</span> By <strong>plugin_id</strong> (Nessus/scanner plugin)</div>
              <div><span style="color:var(--accent)">2.</span> By <strong>first CVE ID</strong> in cve_ids field</div>
              <div><span style="color:var(--accent)">3.</span> By <strong>title prefix</strong> (first 40 chars)</div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="settings-section-title">Campaign Score Formula</div>
          <div class="formula-display" style="flex-direction:column;gap:6px">
            <div style="font-size:12px;color:var(--text-secondary)">
              CampaignScore = <strong>max(priority_score) × 0.5</strong> + <strong>min(3, affected_assets / 10)</strong>
            </div>
            <div style="font-size:11px;color:var(--text-muted)">
              Balances the severity of the worst finding with the breadth of impact across assets.
              A campaign with max score 9.0 affecting 30 assets scores: 9.0×0.5 + min(3, 30/10) = 4.5 + 3 = <strong>7.5</strong>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="settings-section-title">Run Campaign Analysis</div>
          <p class="settings-desc">Recalculate all scores and rebuild campaign groups. This may take a moment for large datasets.</p>
          <div style="margin-top:12px">
            <button class="btn btn-primary" onclick="SettingsPage._runCampaignRecalc()">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
              </svg>
              Run Campaign Analysis
            </button>
          </div>
        </div>
      </div>
    `;
  },

  _renderScoringHelp() {
    return `
      <div style="max-width:760px;display:flex;flex-direction:column;gap:16px">
        <div class="card">
          <div class="settings-section-title">Scoring Engine v4 — Base Score Selection</div>
          <div style="font-size:12px;color:var(--text-secondary);line-height:1.7">
            <p>The engine selects a base score in strict priority order, then tracks the source for downstream decisions:</p>
            <div style="margin:10px 0;display:flex;flex-direction:column;gap:6px">
              ${[
                ['CVSS', 'Primary source. Full threat bonus layer is applied (EPSS, KEV, exploits, PoC, no-patch, EOL).', 'var(--accent)'],
                ['VPR',  'Scanner-provided Vulnerability Priority Rating. Threat bonuses are automatically disabled — VPR already encodes exploit context, so adding bonuses would double-count.', '#f97316'],
                ['FALLBACK', 'Neither CVSS nor VPR available. Score derived from severity label: Critical=9.0, High=7.5, Medium=5.0, Low=2.5, Info=1.0. No bonuses applied.', '#a78bfa'],
              ].map(([src,desc,col]) => `
                <div style="display:flex;gap:10px;padding:9px 12px;background:var(--bg-secondary);border-radius:6px;border-left:3px solid ${col}">
                  <span style="font-weight:700;color:${col};font-size:11px;min-width:60px">${src}</span>
                  <span>${desc}</span>
                </div>
              `).join('')}
            </div>
            <p style="margin-top:6px">The <code>base_source</code> value (CVSS / VPR / FALLBACK) is stored per finding and visible in the detail panel.</p>
          </div>
        </div>

        <div class="card">
          <div class="settings-section-title">Hard Floors &amp; Contextual Bonuses</div>
          <div style="font-size:12px;color:var(--text-secondary);line-height:1.7">
            <div style="display:flex;flex-direction:column;gap:7px;margin-top:6px">
              ${[
                ['R-A', 'KEV hard floor', 'Any CISA KEV finding is forced to at least kev_floor (default 7.0). Always active — regardless of base source.', 'Always', '#eab308'],
                ['R-B', 'KEV + Internet-Facing floor', 'KEV finding on an internet-facing asset is forced to kev_internet_floor (default 9.5 → Critical). Always active.', 'Always', '#ef4444'],
                ['R-C', 'Exploit-in-Wild + Internet bonus', 'When an exploit is active in the wild AND the asset is internet-facing, an additive bonus is applied. CVSS-only to avoid double-counting.', 'CVSS', '#f97316'],
                ['R-D', 'High EPSS + Prod + Reachable bonus', 'EPSS score above threshold (default 0.70) AND production environment AND reachable asset. CVSS-only.', 'CVSS', '#a78bfa'],
              ].map(([tag,title,desc,scope,col]) => `
                <div style="display:flex;gap:10px;padding:9px 12px;background:var(--bg-secondary);border-radius:6px">
                  <span style="font-weight:700;color:${col};font-size:10px;min-width:28px;margin-top:1px">${tag}</span>
                  <div style="flex:1">
                    <div style="font-weight:600;color:var(--text-primary)">${title}
                      <span style="font-size:10px;font-weight:400;color:${col};margin-left:6px">${scope}</span>
                    </div>
                    <div style="color:var(--text-muted);margin-top:2px">${desc}</div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        <div class="card">
          <div class="settings-section-title">Context Multipliers (always active)</div>
          <p style="font-size:12px;color:var(--text-secondary);line-height:1.7">
            All four multipliers are applied to the final score regardless of base_source:
            <code>final = base_ext × ENV × REACH × CRIT × CTRL</code>.
            This ensures that asset context (environment, reachability, criticality, controls) always influences priority.
          </p>
        </div>

        <div class="card">
          <div class="settings-section-title">SLA Definitions</div>
          <div style="font-size:12px;color:var(--text-secondary)">
            <table style="width:100%;border-collapse:collapse">
              <thead><tr style="color:var(--text-muted);border-bottom:1px solid var(--border)">
                <th style="padding:4px 8px;text-align:left">Severity</th>
                <th style="padding:4px 8px;text-align:left">Score Range</th>
                <th style="padding:4px 8px;text-align:left">Default SLA</th>
              </tr></thead>
              <tbody>
                ${[['Critical','≥ 9.0','24h'],['High','≥ 7.0','7 days'],['Medium','≥ 4.0','30 days'],['Low','< 4.0','90 days']]
                  .map(([s,r,sla]) => `<tr style="border-bottom:1px solid var(--border)">
                    <td style="padding:5px 8px"><span class="sev-badge sev-${s.toLowerCase()}">${s}</span></td>
                    <td style="padding:5px 8px;color:var(--text-muted)">${r}</td>
                    <td style="padding:5px 8px;font-weight:600">${sla}</td>
                  </tr>`).join('')}
              </tbody>
            </table>
            <p style="margin-top:10px;color:var(--text-muted)">Thresholds and SLA values are configurable in the <strong style="color:var(--text-primary)">SLA Policies</strong> tab.</p>
          </div>
        </div>

        <div class="card">
          <div class="settings-section-title">Derived Fields</div>
          <p style="font-size:12px;color:var(--text-secondary);line-height:1.7">
            When explicit fields are not set, values are derived automatically:
          </p>
          <ul style="font-size:12px;color:var(--text-secondary);padding-left:20px;margin-top:6px;line-height:1.8">
            <li><strong>Reachability</strong>: from internet_exposure — exposed→internet-facing, partial→partner, internal→internal, local→isolated</li>
            <li><strong>Asset Tier</strong>: from criticality + asset_labels + business_criticality — crown_jewel/tier0 label → tier0, critical criticality → prod-critical, etc.</li>
            <li><strong>Missing data</strong>: neutral multiplier (1.0) is used — the engine never penalizes for missing context</li>
          </ul>
        </div>
      </div>
    `;
  },

  async _runCampaignRecalc() {
    try {
      const res = await API.post('/scoring/recalculate');
      toast(`Recalculated ${res.recalculated} findings. Campaign groups refreshed.`, 'success');
    } catch(e) { toast(e.message, 'error'); }
  },

  // ── Placeholder ───────────────────────────────────────────────────────────

  _renderPlaceholder(title, desc, items) {
    return `
      <div class="card" style="max-width:580px">
        <div style="display:flex;flex-direction:column;align-items:center;text-align:center;padding:28px 0 20px">
          <div style="width:48px;height:48px;border-radius:10px;background:var(--accent-glow);border:1px solid var(--border);
                      display:flex;align-items:center;justify-content:center;margin-bottom:14px">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5">
              <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <h3 style="font-size:15px;font-weight:600;color:var(--text-primary);margin-bottom:6px">${title}</h3>
          <p style="font-size:12px;color:var(--text-muted);max-width:340px">${desc}</p>
        </div>
        <div style="border-top:1px solid var(--border);padding-top:16px">
          <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:10px">Planned Features</div>
          ${items.map(item => `
            <div style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--border);font-size:12px;color:var(--text-secondary)">
              <span style="color:var(--accent)">→</span> ${item}
            </div>
          `).join('')}
        </div>
      </div>
    `;
  },

  // ── Field helpers ─────────────────────────────────────────────────────────

  _cfgVal(key) { return this._cfg?.[key] ?? '–'; },

  _fieldRow(key, label, value, min, max, step, hint = '', color = '') {
    return `
      <div class="settings-field-row">
        <div class="settings-field-label" style="${color?`color:${color}`:''}">
          ${label}
          ${hint ? `<span class="settings-hint">${hint}</span>` : ''}
        </div>
        <div class="settings-field-control">
          <input type="number" class="settings-input" data-key="${key}"
            value="${value}" min="${min}" max="${max}" step="${step}">
          <div class="settings-slider-wrap">
            <input type="range" class="settings-range" data-key="${key}" data-twin="true"
              value="${value}" min="${min}" max="${max}" step="${step}"
              style="${color?`accent-color:${color}`:''}">
          </div>
        </div>
      </div>
    `;
  },

  _fieldInline(key, value, min, max, step, unit = '') {
    return `<div style="display:flex;align-items:center;gap:6px">
      <input type="number" class="settings-input" data-key="${key}"
        value="${value}" min="${min}" max="${max}" step="${step}" style="width:70px">
      ${unit ? `<span style="font-size:11px;color:var(--text-muted)">${unit}</span>` : ''}
    </div>`;
  },

  // ── Listeners ─────────────────────────────────────────────────────────────

  _attachListeners() {
    if (this._tab !== 'scoring') return;
    // Number inputs sync to their range twin
    document.querySelectorAll('.settings-input:not(.settings-toggle)').forEach(input => {
      input.addEventListener('input', e => {
        const key = e.target.dataset.key;
        document.querySelectorAll(`.settings-range[data-key="${key}"]`).forEach(r => r.value = e.target.value);
      });
    });
    document.querySelectorAll('.settings-range').forEach(range => {
      range.addEventListener('input', e => {
        const key = e.target.dataset.key;
        document.querySelectorAll(`.settings-input[data-key="${key}"]`).forEach(i => i.value = e.target.value);
      });
    });
    // Toggle checkboxes update label text
    document.querySelectorAll('.settings-toggle').forEach(chk => {
      chk.addEventListener('change', e => {
        const label = e.target.nextElementSibling;
        if (label) label.textContent = e.target.checked ? 'Enabled' : 'Disabled';
      });
    });
  },

  // ── Save scoring ──────────────────────────────────────────────────────────

  async _save() {
    const btn = document.getElementById('settings-save-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    const payload = {};
    // Collect numeric inputs
    document.querySelectorAll('.settings-input[data-key]:not(.settings-toggle)').forEach(el => {
      const val = parseFloat(el.value);
      if (!isNaN(val)) payload[el.dataset.key] = val;
    });
    // Collect boolean toggles
    document.querySelectorAll('.settings-input.settings-toggle[data-key]').forEach(el => {
      payload[el.dataset.key] = el.checked;
    });
    try {
      this._cfg = await API.patch('/scoring/config', payload);
      toast('Scoring config saved. Recalculation running in background.', 'success');
      const el = document.getElementById('page-content');
      if (el) this.render(el);
    } catch(e) {
      toast(e.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Save & Recalculate'; }
    }
  },

  async _restoreDefaults() {
    if (!confirm('Reset all scoring weights to original defaults? This will trigger a full recalculation.')) return;
    const btn = document.getElementById('settings-restore-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Restoring…'; }
    const DEFAULTS = {
      // ThreatBonus weights
      intelligence_cap: 2.0,  epss_multiplier: 2.0,   kev_bonus: 1.5,
      kev_floor: 7.0,         exploit_wild_bonus: 1.0, exploit_poc_bonus: 0.5,
      no_patch_bonus: 0.3,    eol_bonus: 0.5,
      // SLA classification thresholds
      sla_critical_hours: 24, sla_high_days: 7, sla_medium_days: 30, sla_low_days: 90,
      threshold_critical: 9.0, threshold_high: 7.0, threshold_medium: 4.0,
      // ENV multipliers
      env2_prod: 1.10, env2_uat: 1.00, env2_dev: 0.90, env2_test: 0.80, env2_unknown: 1.00,
      // REACH multipliers
      reach_internet: 1.30, reach_partner: 1.15, reach_internal: 1.00, reach_isolated: 0.85, reach_unknown: 1.00,
      // CRIT multipliers
      crit_tier0: 1.20, crit_prodc: 1.15, crit_important: 1.05, crit_standard: 1.00, crit_low: 0.90, crit_unknown: 1.00,
      // CTRL multipliers
      ctrl_none: 1.00, ctrl_one_verified: 0.95, ctrl_two_verified: 0.90, ctrl_multilayer: 0.80, ctrl_unknown: 1.00,
      // Smart floors & contextual bonuses (v3)
      kev_internet_floor: 9.5, exploit_internet_bonus: 1.5, epss_prod_bonus: 1.0, epss_prod_threshold: 0.70,
    };
    try {
      this._cfg = await API.patch('/scoring/config', DEFAULTS);
      toast('Scoring weights restored to defaults. Recalculation running.', 'success');
      const el = document.getElementById('page-content');
      if (el) this.render(el);
    } catch(e) {
      toast(e.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Restore Defaults'; }
    }
  },
};
