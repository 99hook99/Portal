/* ============================================================
   Prioritization Page – Risk Scoring v3
   2 tabs: Dashboard / Vulnerabilities
   ============================================================ */

const PrioritizationPage = {
  _tab: 'dashboard',
  _el: null,
  _vulnState: { page: 1, per_page: 25, severity: '', env: '', reach: '', kev: '', status: 'open', search: '' },

  async render(el) {
    this._el = el;
    const tab = this._tab || 'dashboard';

    el.innerHTML = `
      <div style="border-bottom:1px solid var(--border);margin-bottom:0;display:flex;gap:0">
        ${['dashboard','vulns','recs'].map(t => {
          const labels = { dashboard: 'Dashboard', vulns: 'Vulnerabilities', recs: 'Cloud Recommendations' };
          return `<button onclick="PrioritizationPage._switchTab('${t}')" data-ptab="${t}"
            style="padding:9px 18px;font-size:12px;font-weight:${tab===t?'600':'500'};
                   color:${tab===t?'var(--text-primary)':'var(--text-muted)'};
                   background:none;border:none;
                   border-bottom:2px solid ${tab===t?'var(--accent)':'transparent'};
                   cursor:pointer;white-space:nowrap;margin-bottom:-1px;transition:color 0.15s">
            ${labels[t]}
          </button>`;
        }).join('')}
        <div style="margin-left:auto;padding:6px 0;display:flex;align-items:center;gap:8px">
          <button class="btn btn-secondary btn-sm" onclick="PrioritizationPage._recalc()" title="Recalculate all scores">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
            </svg>
            Recalculate
          </button>
        </div>
      </div>
      <div id="prio-tab-content" style="padding-top:20px"></div>
    `;

    await this._renderTab(tab);
  },

  _switchTab(tab) {
    this._tab = tab;
    document.querySelectorAll('.nav-sub-item[data-ptab]').forEach(el => {
      el.classList.toggle('active', el.dataset.ptab === tab);
    });
    document.querySelectorAll('button[data-ptab]').forEach(btn => {
      const active = btn.dataset.ptab === tab;
      btn.style.fontWeight = active ? '600' : '500';
      btn.style.color = active ? 'var(--text-primary)' : 'var(--text-muted)';
      btn.style.borderBottom = active ? '2px solid var(--accent)' : '2px solid transparent';
    });
    this._renderTab(tab);
  },

  async _renderTab(tab) {
    const content = document.getElementById('prio-tab-content');
    if (!content) return;
    content.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;
    try {
      if (tab === 'dashboard')  await this._renderDashboard(content);
      else if (tab === 'recs') await this._renderRecommendations(content);
      else                      await this._renderVulnerabilities(content);
    } catch(e) {
      content.innerHTML = `<div class="empty-state"><p>Error: ${esc(e.message)}</p></div>`;
      console.error(e);
    }
  },

  // ── TAB 1: Dashboard ──────────────────────────────────────────────────────

  async _renderDashboard(el) {
    const data = await API.get('/scoring/priority-dashboard');
    const kpis = data.kpis || {};

    el.innerHTML = `
      <!-- KPI Row -->
      <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:24px">
        ${this._kpiCard('Critical Open', kpis.critical_open, '#ef4444', 'Open critical severity findings',
            "PrioritizationPage._vulnState.severity='critical';PrioritizationPage._switchTab('vulns')")}
        ${this._kpiCard('High Open', kpis.high_open, '#f97316', 'Open high severity findings',
            "PrioritizationPage._vulnState.severity='high';PrioritizationPage._switchTab('vulns')")}
        ${this._kpiCard('KEV Open', kpis.kev_open, '#ef4444', 'CISA Known Exploited Vulnerabilities (open)',
            "PrioritizationPage._vulnState.kev='1';PrioritizationPage._switchTab('vulns')")}
        ${this._kpiCard('High EPSS ≥50%', kpis.high_epss_open, '#eab308', 'Vulnerabilities with high exploitation probability')}
        ${this._kpiCard('Internet+Prod', kpis.internet_prod_open, '#f97316', 'Internet-facing production vulnerabilities')}
        ${this._kpiCard('SLA Breached', kpis.sla_breached, '#ef4444', 'Findings past their remediation deadline')}
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px">
        <!-- Section A: Top Critical -->
        <div class="card">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
            <div>
              <div style="font-size:14px;font-weight:600;color:var(--text-primary)">Top Critical Findings</div>
              <div style="font-size:11px;color:var(--text-muted);margin-top:2px">Highest scored open critical vulnerabilities</div>
            </div>
            <button class="btn btn-secondary btn-sm"
              onclick="PrioritizationPage._vulnState.severity='critical';PrioritizationPage._switchTab('vulns')">View all →</button>
          </div>
          ${data.section_a && data.section_a.length ? `
            <div style="display:flex;flex-direction:column;gap:6px">
              ${data.section_a.map(v => this._criticalRow(v)).join('')}
            </div>
          ` : `<div style="font-size:12px;color:var(--text-muted);padding:16px 0;text-align:center">No critical findings — great posture!</div>`}
        </div>

        <!-- Section B: Top High -->
        <div class="card">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
            <div>
              <div style="font-size:14px;font-weight:600;color:var(--text-primary)">Top High Findings</div>
              <div style="font-size:11px;color:var(--text-muted);margin-top:2px">Highest scored open high severity vulnerabilities</div>
            </div>
            <button class="btn btn-secondary btn-sm"
              onclick="PrioritizationPage._vulnState.severity='high';PrioritizationPage._switchTab('vulns')">View all →</button>
          </div>
          ${data.section_b && data.section_b.length ? `
            <table style="width:100%;font-size:11px;border-collapse:collapse">
              <thead><tr style="color:var(--text-muted);border-bottom:1px solid var(--border)">
                <th style="padding:4px 6px;text-align:left">Score</th>
                <th style="padding:4px 6px;text-align:left">Title</th>
                <th style="padding:4px 6px;text-align:left">Asset</th>
                <th style="padding:4px 6px;text-align:left">EPSS</th>
                <th style="padding:4px 6px;text-align:left">SLA</th>
              </tr></thead>
              <tbody>
                ${data.section_b.map(v => `
                  <tr style="border-bottom:1px solid var(--border);cursor:pointer"
                      onclick="VulnsPage.openDetail(${v.id},${v.asset_id||'null'})">
                    <td style="padding:5px 6px">
                      <span style="font-size:13px;font-weight:700;color:#f97316">${v.priority_score != null ? v.priority_score.toFixed(1) : '–'}</span>
                    </td>
                    <td style="padding:5px 6px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                        title="${esc(v.title)}">${esc(v.title)}</td>
                    <td style="padding:5px 6px;font-family:monospace;color:var(--text-muted)">${esc(v.asset_hostname || v.asset_ip || '–')}</td>
                    <td style="padding:5px 6px">${v.epss_score != null ? (v.epss_score*100).toFixed(0)+'%' : '–'}</td>
                    <td style="padding:5px 6px">${slaCountdown(v.sla_deadline)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          ` : `<div style="font-size:12px;color:var(--text-muted);padding:12px 0;text-align:center">No high findings</div>`}
        </div>

        <!-- Top Assets by Risk -->
        <div class="card">
          <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:4px">Top Assets by Risk</div>
          <div style="font-size:11px;color:var(--text-muted);margin-bottom:14px">Cumulative exposure across open findings</div>
          ${data.top_assets && data.top_assets.length ? data.top_assets.map(a => `
            <div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border)">
              <div style="flex:1;min-width:0">
                <div style="font-size:12px;font-weight:500;color:var(--text-primary);font-family:monospace;
                            overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                  ${esc(a.hostname || a.ip_address || 'Unknown')}
                </div>
                <div style="font-size:10px;color:var(--text-muted);margin-top:2px">
                  ${a.environment ? `<span style="text-transform:uppercase">${esc(a.environment)}</span> · ` : ''}
                  ${a.vuln_count} findings
                  ${a.critical_count > 0 ? `<span style="color:#ef4444;font-weight:600"> · ${a.critical_count} crit</span>` : ''}
                  ${a.high_count > 0 ? `<span style="color:#f97316;font-weight:600"> · ${a.high_count} high</span>` : ''}
                </div>
              </div>
              <div style="text-align:right">
                <div style="font-size:14px;font-weight:700;color:var(--text-primary)">${a.cumulative_score.toFixed(1)}</div>
                <div style="font-size:9px;color:var(--text-muted)">risk score</div>
              </div>
            </div>
          `).join('') : `<div style="font-size:12px;color:var(--text-muted);padding:12px 0;text-align:center">No asset data</div>`}
        </div>

        <!-- Top Campaigns -->
        <div class="card">
          <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:4px">Top Campaigns</div>
          <div style="font-size:11px;color:var(--text-muted);margin-bottom:14px">Grouped by plugin/CVE — most impactful clusters</div>
          ${data.top_campaigns && data.top_campaigns.length ? data.top_campaigns.map(c => `
            <div style="padding:7px 0;border-bottom:1px solid var(--border)">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px">
                <div style="font-size:12px;font-weight:500;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px"
                     title="${esc(c.campaign_label)}">${esc(c.campaign_label)}</div>
                <div style="font-size:12px;font-weight:700;color:var(--text-primary)">${c.campaign_score.toFixed(2)}</div>
              </div>
              <div style="font-size:10px;color:var(--text-muted)">
                ${c.total_findings} findings · ${c.affected_assets} assets · max ${c.max_score.toFixed(1)}
                ${c.critical_count > 0 ? `<span style="color:#ef4444;font-weight:600"> · ${c.critical_count} crit</span>` : ''}
                ${c.high_count > 0 ? `<span style="color:#f97316;font-weight:600"> · ${c.high_count} high</span>` : ''}
              </div>
            </div>
          `).join('') : `<div style="font-size:12px;color:var(--text-muted);padding:12px 0;text-align:center">No campaign data</div>`}
        </div>
      </div>
    `;
  },

  _kpiCard(label, value, color, title, onclick) {
    const val = value ?? 0;
    const style = onclick ? 'cursor:pointer' : '';
    const click = onclick ? `onclick="${onclick}"` : '';
    return `
      <div class="card" style="padding:14px 16px;text-align:center;${style}" ${click} title="${esc(title)}">
        <div style="font-size:26px;font-weight:700;color:${val > 0 ? color : 'var(--text-muted)'}">${val}</div>
        <div style="font-size:10px;color:var(--text-muted);margin-top:4px;text-transform:uppercase;letter-spacing:0.3px">${esc(label)}</div>
      </div>
    `;
  },

  _criticalRow(v) {
    return `
      <div style="display:flex;align-items:center;gap:10px;padding:8px 10px;
                  background:var(--bg-secondary);border-radius:6px;border-left:3px solid #ef4444;
                  cursor:pointer"
           onclick="VulnsPage.openDetail(${v.id},${v.asset_id||'null'})">
        <div style="font-size:14px;font-weight:700;color:#ef4444;min-width:36px;text-align:center">
          ${v.priority_score != null ? v.priority_score.toFixed(1) : '–'}
        </div>
        <div style="flex:1;min-width:0">
          <div style="font-size:12px;font-weight:500;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
               title="${esc(v.title)}">${esc(v.title)}</div>
          <div style="font-size:10px;color:var(--text-muted);margin-top:2px">
            ${v.cve_ids ? `<span style="font-family:monospace;color:#60a5fa">${esc(v.cve_ids.split(',')[0].trim())}</span> · ` : ''}
            ${esc(v.asset_hostname || v.asset_ip || '–')}
            ${v.asset_env ? ` · <span style="text-transform:uppercase">${esc(v.asset_env)}</span>` : ''}
          </div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:3px;flex-shrink:0">
          ${v.cisa_kev_date ? `<span style="font-size:9px;background:#ef444420;color:#ef4444;border:1px solid #ef444440;border-radius:3px;padding:1px 4px">KEV</span>` : ''}
          ${v.exploit_available ? `<span style="font-size:9px;background:#f9731620;color:#f97316;border:1px solid #f9731640;border-radius:3px;padding:1px 4px">Exploit</span>` : ''}
          ${slaCountdown(v.sla_deadline)}
        </div>
      </div>
    `;
  },

  // ── TAB 2: Vulnerabilities ────────────────────────────────────────────────

  async _renderVulnerabilities(el) {
    const state = this._vulnState;
    el.innerHTML = `
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px">
        <input type="text" class="input" id="prio-vuln-search" placeholder="Search title or CVE…"
          style="width:180px;font-size:12px" value="${esc(state.search || '')}">
        <select class="input" id="prio-vuln-severity" style="width:130px;font-size:12px">
          <option value="">All Severities</option>
          ${['critical','high','medium','low'].map(s =>
            `<option value="${s}" ${state.severity===s?'selected':''}>${s.charAt(0).toUpperCase()+s.slice(1)}</option>`
          ).join('')}
        </select>
        <select class="input" id="prio-vuln-kev" style="width:100px;font-size:12px">
          <option value="">KEV: All</option>
          <option value="1" ${state.kev==='1'?'selected':''}>KEV Only</option>
        </select>
        <select class="input" id="prio-vuln-env" style="width:110px;font-size:12px">
          <option value="">All Envs</option>
          ${['prod','uat','dev','test'].map(e =>
            `<option value="${e}" ${state.env===e?'selected':''}>${e}</option>`
          ).join('')}
        </select>
        <select class="input" id="prio-vuln-reach" style="width:140px;font-size:12px">
          <option value="">All Reachability</option>
          <option value="internet-facing" ${state.reach==='internet-facing'?'selected':''}>Internet-Facing</option>
          <option value="partner" ${state.reach==='partner'?'selected':''}>Partner/VPN</option>
          <option value="internal" ${state.reach==='internal'?'selected':''}>Internal</option>
          <option value="isolated" ${state.reach==='isolated'?'selected':''}>Isolated</option>
        </select>
        <select class="input" id="prio-vuln-status" style="width:150px;font-size:12px">
          <option value="open" ${state.status==='open'?'selected':''}>Open + In Progress</option>
          <option value="" ${state.status===''?'selected':''}>All Statuses</option>
          <option value="accepted" ${state.status==='accepted'?'selected':''}>Accepted</option>
          <option value="remediated" ${state.status==='remediated'?'selected':''}>Remediated</option>
        </select>
        <span style="margin-left:auto;font-size:12px;color:var(--text-muted)" id="prio-vuln-count">–</span>
      </div>
      ${PrioTable.filterBarHtml()}
      <div class="table-wrap" id="prio-vuln-table-wrap">
        <div class="loader"><div class="spinner"></div></div>
      </div>
      <div id="prio-vuln-pagination"></div>
    `;

    const searchEl = document.getElementById('prio-vuln-search');
    if (searchEl) {
      let timer;
      searchEl.addEventListener('input', e => {
        clearTimeout(timer);
        timer = setTimeout(() => {
          this._vulnState.search = e.target.value;
          this._vulnState.page = 1;
          this._loadVulns();
        }, 300);
      });
    }
    const attach = (id, key) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('change', e => {
        this._vulnState[key] = e.target.value;
        this._vulnState.page = 1;
        this._loadVulns();
      });
    };
    attach('prio-vuln-severity', 'severity');
    attach('prio-vuln-kev', 'kev');
    attach('prio-vuln-env', 'env');
    attach('prio-vuln-reach', 'reach');
    attach('prio-vuln-status', 'status');

    await this._loadVulns();
  },

  async _loadVulns() {
    const wrap = document.getElementById('prio-vuln-table-wrap');
    if (!wrap) return;
    wrap.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;

    const s = this._vulnState;
    const data = await API.get('/scoring/prioritized', {
      page: s.page, per_page: s.per_page,
      severity: s.severity, status: s.status,
      kev: s.kev, env: s.env, reach: s.reach,
      search: s.search,
    });
    const items = data.items;

    const countEl = document.getElementById('prio-vuln-count');
    if (countEl) countEl.textContent = `${data.total.toLocaleString()} findings`;

    const GETTERS = {
      severity: v => v.priority_class || v.severity,
      score:    v => v.priority_score,
      cvss:     v => v.cvss_score,
      title:    v => v.title,
      cve:      v => v.cve_ids,
      asset:    v => `${v.asset_hostname||''} ${v.asset_ip||''}`,
      epss:     v => v.epss_score,
      kev:      v => v.cisa_kev_date ? 'kev' : '',
      patch:    v => v.patch_available === false ? 'no' : 'yes',
      status:   v => v.status,
      sla:      v => v.sla_deadline,
    };
    const filtered = PrioTable.applyFilters(items, GETTERS);

    if (!filtered.length) {
      wrap.innerHTML = `<div class="empty-state"><p>No findings match the current filters.</p></div>`;
      return;
    }

    wrap.innerHTML = `
      <div style="overflow-x:auto">
        <table style="table-layout:fixed;min-width:700px">
          ${PrioTable.colgroup()}
          <thead><tr id="prio-thr">${PrioTable.thead()}</tr></thead>
          <tbody>
            ${filtered.map(v => this._vulnRow(v)).join('')}
          </tbody>
        </table>
      </div>
    `;

    renderPagination('prio-vuln-pagination', s.page, s.per_page, data.total, p => {
      this._vulnState.page = p;
      this._loadVulns();
    });
  },

  _vulnRow(v) {
    const score = v.priority_score;
    const scoreColor = score >= 9 ? '#ef4444' : score >= 7 ? '#f97316' : score >= 4 ? '#eab308' : '#22c55e';
    const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
    const cls = v.priority_class || '';
    const sevColor = sevColors[cls] || '#9ca3af';

    const cells = {
      severity: `<td><span style="font-size:10px;font-weight:600;color:${sevColor};text-transform:uppercase;background:${sevColor}20;border-radius:3px;padding:2px 6px">${cls||'–'}</span></td>`,
      score:    `<td><span style="font-size:13px;font-weight:700;color:${scoreColor}">${score!=null?score.toFixed(1):'–'}</span></td>`,
      cvss:     `<td><span style="font-size:12px;color:var(--text-muted)">${v.cvss_score!=null?v.cvss_score.toFixed(1):'–'}</span></td>`,
      title:    `<td><div class="truncate" style="max-width:280px" title="${esc(v.title)}">${esc(v.title)}</div></td>`,
      cve:      `<td style="font-family:monospace;font-size:11px;color:#60a5fa">${v.cve_ids?esc(v.cve_ids.split(',')[0].trim()):'–'}</td>`,
      asset:    `<td style="font-family:monospace;font-size:11px">${esc(v.asset_hostname||v.asset_ip||'–')}</td>`,
      epss:     `<td style="font-size:12px">${v.epss_score!=null?(v.epss_score*100).toFixed(0)+'%':'–'}</td>`,
      kev:      `<td>${v.cisa_kev_date?`<span style="font-size:10px;background:#ef444420;color:#ef4444;border:1px solid #ef444440;border-radius:3px;padding:1px 4px">KEV</span>`:''}</td>`,
      patch:    `<td style="text-align:center">${v.patch_available===false?'<span style="color:#ef4444;font-size:12px" title="No patch">✗</span>':'<span style="color:#22c55e;font-size:12px" title="Patch available">✓</span>'}</td>`,
      status:   `<td><span class="status-badge status-${v.status}">${(v.status||'').replace('_',' ')}</span></td>`,
      sla:      `<td>${slaCountdown(v.sla_deadline)}</td>`,
    };
    return `<tr style="cursor:pointer" onclick="VulnsPage.openDetail(${v.id},${v.asset_id||'null'})">${PrioTable.cols.map(col => cells[col.key]||'<td></td>').join('')}</tr>`;
  },

  // ── TAB 3: Cloud Recommendations ─────────────────────────────────────────

  _recsState: { page: 1, per_page: 25, severity: '', status: 'open', search: '' },

  async _renderRecommendations(el) {
    const s = this._recsState;
    el.innerHTML = `
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:14px">
        Cloud security recommendations from CSPM, Compliance, Benchmark and Patch Management checks.
        These are separated from vulnerability findings to reduce noise.
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px">
        <input type="text" class="input" id="recs-search" placeholder="Search…"
          style="width:180px;font-size:12px" value="${esc(s.search || '')}">
        <select class="input" id="recs-severity" style="width:130px;font-size:12px">
          <option value="">All Severities</option>
          ${['critical','high','medium','low','info'].map(sv =>
            `<option value="${sv}" ${s.severity===sv?'selected':''}>${sv.charAt(0).toUpperCase()+sv.slice(1)}</option>`
          ).join('')}
        </select>
        <select class="input" id="recs-status" style="width:150px;font-size:12px">
          <option value="open" ${s.status==='open'?'selected':''}>Open + In Progress</option>
          <option value="" ${s.status===''?'selected':''}>All Statuses</option>
          <option value="remediated" ${s.status==='remediated'?'selected':''}>Remediated</option>
        </select>
        <span style="margin-left:auto;font-size:12px;color:var(--text-muted)" id="recs-count">–</span>
      </div>
      <div class="table-wrap" id="recs-table-wrap">
        <div class="loader"><div class="spinner"></div></div>
      </div>
      <div id="recs-pagination"></div>
    `;

    const searchEl = document.getElementById('recs-search');
    if (searchEl) {
      let timer;
      searchEl.addEventListener('input', e => {
        clearTimeout(timer);
        timer = setTimeout(() => { this._recsState.search = e.target.value; this._recsState.page = 1; this._loadRecs(); }, 300);
      });
    }
    [['recs-severity','severity'],['recs-status','status']].forEach(([id, key]) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('change', e => { this._recsState[key] = e.target.value; this._recsState.page = 1; this._loadRecs(); });
    });

    await this._loadRecs();
  },

  async _loadRecs() {
    const wrap = document.getElementById('recs-table-wrap');
    if (!wrap) return;
    wrap.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;

    const s = this._recsState;
    const params = { page: s.page, per_page: s.per_page, severity: s.severity, search: s.search, category: 'recommendation' };
    if (s.status === 'open') { params.status = 'open'; }
    else if (s.status) { params.status = s.status; }

    const data = await API.get('/vulnerabilities/', params);
    const items = data.items;

    const countEl = document.getElementById('recs-count');
    if (countEl) countEl.textContent = `${data.total.toLocaleString()} recommendations`;

    if (!items.length) {
      wrap.innerHTML = `<div class="empty-state"><p>No recommendations match the current filters.</p></div>`;
      return;
    }

    const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#64748b' };

    wrap.innerHTML = `
      <table>
        <thead>
          <tr>
            <th style="width:80px">Severity</th>
            <th>Title / Check</th>
            <th style="width:140px">Asset</th>
            <th style="width:140px">Family</th>
            <th style="width:90px">Status</th>
            <th style="width:90px">First Seen</th>
          </tr>
        </thead>
        <tbody>
          ${items.map(v => {
            const sc = sevColors[v.severity] || '#9ca3af';
            const firstSeen = v.first_seen ? new Date(v.first_seen).toLocaleDateString() : '–';
            return `
              <tr style="cursor:pointer" onclick="VulnsPage.openDetail(${v.id},${v.asset_id||'null'})">
                <td><span style="font-size:10px;font-weight:600;color:${sc};text-transform:uppercase;background:${sc}20;border-radius:3px;padding:2px 6px">${v.severity||'–'}</span></td>
                <td><div class="truncate" style="max-width:320px" title="${esc(v.title)}">${esc(v.title)}</div></td>
                <td style="font-family:monospace;font-size:11px">${esc(v.asset_hostname || v.asset_ip || '–')}</td>
                <td style="font-size:11px;color:var(--text-muted)">${esc(v.plugin_family || '–')}</td>
                <td><span class="status-badge status-${v.status}">${(v.status||'').replace('_',' ')}</span></td>
                <td style="font-size:11px;color:var(--text-muted)">${firstSeen}</td>
              </tr>`;
          }).join('')}
        </tbody>
      </table>
    `;

    renderPagination('recs-pagination', s.page, s.per_page, data.total, p => {
      this._recsState.page = p;
      this._loadRecs();
    });
  },

  async _recalc() {
    try {
      const res = await API.post('/scoring/recalculate');
      toast(`Recalculated ${res.recalculated} findings`, 'success');
      await this._renderTab(this._tab);
      _updateP0Badge();
    } catch(e) { toast(e.message, 'error'); }
  },
};
