/* Vulnerabilities page */

const VulnsPage = {
  state: { page: 1, per_page: 25, severity: '', status: '', source: '', search: '', asset_id: null, asset_label: '', host: '', category: 'vulnerability' },
  total: 0,

  async render(el) {
    el.innerHTML = `
      <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">
        ${[
          {label:'All', status:''},
          {label:'Open', status:'open'},
          {label:'In Progress', status:'in_progress'},
          {label:'Accepted Risk', status:'accepted'},
          {label:'Remediated ✓', status:'remediated'},
        ].map(t => `
          <button class="btn btn-sm ${this.state.status === t.status ? 'btn-primary' : 'btn-secondary'}"
            onclick="VulnsPage.setStatus('${t.status}')">${t.label}</button>
        `).join('')}
      </div>
      ${this.state.asset_id ? `
        <div style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--accent-glow);border:1px solid var(--accent);border-radius:8px;margin-bottom:10px">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2">
            <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
          </svg>
          <span style="font-size:12px;color:var(--accent);font-weight:600">Filtered by asset:</span>
          <span style="font-size:12px;color:var(--text-primary);font-family:monospace">${esc(this.state.asset_label)}</span>
          <button onclick="VulnsPage.clearAssetFilter()" style="margin-left:auto;background:none;border:1px solid var(--accent);color:var(--accent);border-radius:4px;padding:2px 8px;cursor:pointer;font-size:11px">✕ Clear filter</button>
        </div>
      ` : ''}
      <div class="filter-bar">
        <div class="search-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input class="input search-input" id="vuln-search" placeholder="Search title, CVE, description…" value="${esc(this.state.search)}">
        </div>
        <div class="search-wrap" style="min-width:160px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/>
          </svg>
          <input class="input search-input" id="vuln-host" placeholder="Filter by host / IP…" value="${esc(this.state.host)}" ${this.state.asset_id ? 'disabled style="opacity:0.4"' : ''}>
        </div>
        <select class="input" id="vuln-sev" style="width:130px">
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select class="input" id="vuln-status" style="width:130px">
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="accepted">Accepted Risk</option>
          <option value="remediated">Remediated</option>
        </select>
        <select class="input" id="vuln-source" style="width:120px">
          <option value="">All Sources</option>
          <option value="nessus">Nessus</option>
          <option value="aws">AWS</option>
          <option value="nuclei">Nuclei</option>
          <option value="mde">MDE</option>
          <option value="openvas">OpenVAS</option>
          <option value="nmap">NMAP</option>
          <option value="manual">Manual</option>
        </select>
        <span style="margin-left:auto;font-size:12px;color:var(--text-muted)" id="vuln-count">–</span>
      </div>

      ${VulnsTable.filterBarHtml()}
      <div class="table-wrap" style="overflow-x:auto">
        <table style="table-layout:fixed;min-width:600px">
          ${VulnsTable.colgroup()}
          <thead><tr id="vulns-thr">${VulnsTable.thead()}</tr></thead>
          <tbody id="vuln-tbody">
            <tr><td colspan="${VulnsTable.cols.length}"><div class="loader"><div class="spinner"></div></div></td></tr>
          </tbody>
        </table>
      </div>
      <div id="vuln-pagination"></div>
    `;

    document.getElementById('vuln-sev').value    = this.state.severity;
    document.getElementById('vuln-status').value = this.state.status;
    document.getElementById('vuln-source').value = this.state.source;

    document.getElementById('vuln-search').addEventListener('input', debounce(e => {
      this.state.search = e.target.value;
      this.state.page = 1;
      this.load();
    }, 300));

    document.getElementById('vuln-host').addEventListener('input', debounce(e => {
      this.state.host = e.target.value;
      this.state.asset_id = null;
      this.state.asset_label = '';
      this.state.page = 1;
      this.load();
    }, 300));

    ['vuln-sev','vuln-status','vuln-source'].forEach(id => {
      document.getElementById(id).addEventListener('change', e => {
        const key = id === 'vuln-sev' ? 'severity' : id === 'vuln-status' ? 'status' : 'source';
        this.state[key] = e.target.value;
        this.state.page = 1;
        this.load();
      });
    });

    this.load();
  },

  clearAssetFilter() {
    this.state.asset_id = null;
    this.state.asset_label = '';
    this.state.page = 1;
    this.render(document.getElementById('page-content'));
  },

  setStatus(s) {
    this.state.status = s;
    this.state.page = 1;
    this.render(document.getElementById('page-content'));
  },

  async load() {
    const { page, per_page, severity, status, source, search, asset_id, host, category } = this.state;
    const params = { page, per_page, severity, status, source, search, asset_id, host, category };
    const data = await API.get('/vulnerabilities/', params);
    this.total = data.total;

    const countEl = document.getElementById('vuln-count');
    if (countEl) countEl.textContent = `${data.total.toLocaleString()} findings`;

    const tbody = document.getElementById('vuln-tbody');
    const GETTERS = {
      title:     v => v.title,
      severity:  v => v.severity,
      cvss:      v => v.cvss_score,
      vpr:       v => v.vpr_score,
      asset:     v => `${v.asset_hostname||''} ${v.asset_ip||''}`,
      flags:     v => [v.cisa_kev_date?'KEV':'', v.exploit_available?'EXP':''].filter(Boolean).join(' '),
      status:    v => v.status,
      first_seen:v => v.first_seen,
    };
    const rows = VulnsTable.applyFilters(data.items, GETTERS);
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="${VulnsTable.cols.length}">${emptyState('No vulnerabilities match the current filters')}</td></tr>`;
    } else {
      tbody.innerHTML = rows.map(v => {
        const cveBadges = v.cve_ids ? v.cve_ids.split(',').slice(0,2).map(c => `<a class="cve-link" onclick="event.stopPropagation();navigate('cve');CVEPage.search('${c.trim()}')">${c.trim()}</a>`).join('') : '';
        const cells = {
          title:     `<td class="primary"><div class="truncate" style="max-width:300px" title="${esc(v.title)}">${esc(v.title)}</div><div style="margin-top:3px;display:flex;gap:4px;flex-wrap:wrap;align-items:center">${sourceBadge(v.source)}${cveBadges}</div></td>`,
          severity:  `<td>${sevBadge(v.severity)}</td>`,
          cvss:      `<td><span class="cvss-score cvss-${v.severity}">${v.cvss_score != null ? v.cvss_score.toFixed(1) : '–'}</span></td>`,
          vpr:       `<td><span style="font-size:12px;font-weight:600;color:${v.vpr_score >= 7 ? 'var(--critical)' : v.vpr_score >= 4 ? '#f97316' : 'var(--text-muted)'}">${v.vpr_score != null ? v.vpr_score.toFixed(1) : '–'}</span></td>`,
          asset:     `<td><div style="font-size:12px;color:var(--text-primary)">${esc(v.asset_hostname || v.asset_ip || '–')}</div>${v.port ? `<div style="font-size:11px;color:var(--text-muted)">${v.port}/${v.protocol||'tcp'}</div>` : ''}</td>`,
          flags:     `<td style="white-space:nowrap">${v.cisa_kev_date ? `<span style="font-size:10px;background:#ef444420;color:#ef4444;border:1px solid #ef444440;border-radius:3px;padding:1px 4px;margin-right:2px">KEV</span>` : ''}${v.exploit_available ? `<span style="font-size:10px;background:#f9731620;color:#f97316;border:1px solid #f9731640;border-radius:3px;padding:1px 4px">EXP</span>` : ''}</td>`,
          status:    `<td><span class="status-badge status-${v.status}">${v.status.replace('_',' ')}</span></td>`,
          first_seen:`<td style="font-size:11px;color:var(--text-muted)">${fmtDateShort(v.first_seen)}</td>`,
          _act:      `<td><button class="btn btn-icon btn-xs" title="View details" onclick="event.stopPropagation();VulnsPage.openDetail(${v.id})"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button></td>`,
        };
        return `<tr style="cursor:pointer" onclick="VulnsPage.openDetail(${v.id})">${VulnsTable.cols.map(col => cells[col.key] || '<td></td>').join('')}</tr>`;
      }).join('');
    }

    renderPagination('vuln-pagination', page, per_page, data.total, p => {
      this.state.page = p;
      this.load();
    });
  },

  async openDetail(id, fromAssetId) {
    const [v, bd] = await Promise.all([
      API.get(`/vulnerabilities/${id}`),
      API.get(`/scoring/breakdown/${id}`).catch(() => null),
    ]);

    const scoreColor = !v.priority_score ? 'var(--text-muted)'
      : v.priority_score >= 9 ? '#ef4444'
      : v.priority_score >= 7 ? '#f97316'
      : v.priority_score >= 4 ? '#eab308' : '#22c55e';

    openDetail(
      v.title,
      `${sevBadge(v.severity)}
       ${v.priority_score != null
         ? `<span style="font-size:13px;font-weight:700;color:${scoreColor};background:${scoreColor}18;
              padding:2px 7px;border-radius:4px;border:1px solid ${scoreColor}40">${v.priority_score.toFixed(1)}</span>`
         : v.cvss_score != null
           ? `<span class="cvss-score cvss-${v.severity}">${v.cvss_score.toFixed(1)}</span>` : ''}
       <span class="source-tag">${v.source}</span>
       <span class="status-badge status-${v.status}">${v.status.replace('_',' ')}</span>
       ${bd ? `<span style="font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;
                background:var(--accent-glow);color:var(--accent);border:1px solid var(--accent)40;cursor:pointer"
                onclick="VulnsPage._vulnTab('score')" title="View risk score breakdown">
                SCORE BREAKDOWN</span>` : ''}`,
      `
        <!-- Tab bar -->
        <div id="vd-tabbar" style="display:flex;gap:0;border-bottom:1px solid var(--border);margin:-20px -20px 20px">
          <button id="vd-tab-info" onclick="VulnsPage._vulnTab('info')"
            style="padding:9px 16px;font-size:11px;font-weight:600;color:var(--text-primary);
                   background:none;border:none;border-bottom:2px solid var(--accent);cursor:pointer">
            Details
          </button>
          <button id="vd-tab-score" onclick="VulnsPage._vulnTab('score')"
            style="padding:9px 16px;font-size:11px;font-weight:500;color:var(--text-muted);
                   background:none;border:none;border-bottom:2px solid transparent;cursor:pointer;
                   display:${bd ? 'block' : 'none'}">
            Risk Score Breakdown
          </button>
        </div>

        <!-- Details tab -->
        <div id="vd-pane-info">
          <div class="detail-section">
            <div class="detail-section-title">Details</div>
            <div class="detail-kv">
              <span class="k">Asset</span>
              <span class="v">${v.asset_hostname || '–'}${v.asset_ip ? ` <span style="font-family:monospace;font-size:11px;color:var(--text-muted)">(${v.asset_ip})</span>` : ''}</span>
              <span class="k">Port</span><span class="v">${v.port ? `${v.port}/${v.protocol||'tcp'}` : '–'}</span>
              <span class="k">Plugin</span><span class="v">${v.plugin_id || '–'}${v.plugin_family ? ` · ${v.plugin_family}` : ''}</span>
              <span class="k">CVE(s)</span><span class="v">${v.cve_ids || '–'}</span>
              <span class="k">Scan</span><span class="v">${v.scan_name || '–'}</span>
              <span class="k">First Seen</span><span class="v">${fmtDate(v.first_seen)}</span>
              <span class="k">Last Seen</span><span class="v">${fmtDate(v.last_seen)}</span>
            </div>
          </div>
          ${(v.vpr_score != null || v.epss_score != null || v.cisa_kev_date || v.exploit_available != null) ? `
          <div class="detail-section">
            <div class="detail-section-title">Risk Intelligence</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:4px">
              ${v.vpr_score != null ? `<div style="background:var(--bg-secondary);border-radius:6px;padding:10px;border:1px solid var(--border)"><div style="font-size:18px;font-weight:700;color:#f97316">${v.vpr_score.toFixed(1)}</div><div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-top:2px">VPR Score</div></div>` : ''}
              ${v.epss_score != null ? `<div style="background:var(--bg-secondary);border-radius:6px;padding:10px;border:1px solid var(--border)"><div style="font-size:18px;font-weight:700;color:#3b82f6">${(v.epss_score*100).toFixed(1)}%</div><div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-top:2px">EPSS Probability</div></div>` : ''}
              ${v.exploit_available ? `<div style="background:#f9731610;border-radius:6px;padding:10px;border:1px solid #f9731640"><div style="font-size:18px;font-weight:700;color:#f97316">YES</div><div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-top:2px">Exploit Available</div></div>` : ''}
              ${v.cisa_kev_date ? `<div style="background:#ef444420;border-radius:6px;padding:10px;border:1px solid #ef444440"><div style="font-size:12px;font-weight:700;color:#ef4444">⚠ CISA KEV</div><div style="font-size:10px;color:var(--text-muted);margin-top:2px">${v.cisa_kev_date}</div></div>` : ''}
            </div>
          </div>` : ''}
          ${v.synopsis ? `<div class="detail-section"><div class="detail-section-title">Synopsis</div><div class="detail-text" style="color:var(--text-secondary)">${esc(v.synopsis)}</div></div>` : ''}
          ${v.description ? `<div class="detail-section"><div class="detail-section-title">Description</div><div class="detail-text">${esc(v.description)}</div></div>` : ''}
          ${v.solution    ? `<div class="detail-section"><div class="detail-section-title">Remediation</div><div class="detail-text" style="color:var(--low)">${esc(v.solution)}</div></div>` : ''}
        </div>

        <!-- Risk Score Breakdown tab -->
        <div id="vd-pane-score" style="display:none">
          ${bd ? VulnsPage._renderBreakdown(bd) : '<div class="empty-state"><p>No score data available for this finding.</p></div>'}
        </div>
      `,
      `
        ${fromAssetId ? `<button class="btn btn-secondary btn-sm" onclick="AssetsPage.openDetail(${fromAssetId})">← Asset</button>` : ''}
        <select class="input" id="detail-status-select" style="width:160px">
          <option value="open"        ${v.status==='open'?'selected':''}>Open</option>
          <option value="in_progress" ${v.status==='in_progress'?'selected':''}>In Progress</option>
          <option value="accepted"    ${v.status==='accepted'?'selected':''}>Accepted Risk</option>
          <option value="remediated"  ${v.status==='remediated'?'selected':''}>Remediated</option>
        </select>
        <button class="btn btn-primary btn-sm" onclick="VulnsPage.updateStatus(${id})">Update Status</button>
        <button class="btn btn-secondary btn-sm" onclick="closeDetail()">Close</button>
      `
    );
  },

  _vulnTab(tab) {
    const info  = document.getElementById('vd-pane-info');
    const score = document.getElementById('vd-pane-score');
    const tInfo  = document.getElementById('vd-tab-info');
    const tScore = document.getElementById('vd-tab-score');
    if (!info || !score) return;
    const onInfo = tab === 'info';
    info.style.display  = onInfo ? '' : 'none';
    score.style.display = onInfo ? 'none' : '';
    if (tInfo) {
      tInfo.style.fontWeight  = onInfo ? '600' : '500';
      tInfo.style.color       = onInfo ? 'var(--text-primary)' : 'var(--text-muted)';
      tInfo.style.borderBottom = onInfo ? '2px solid var(--accent)' : '2px solid transparent';
    }
    if (tScore) {
      tScore.style.fontWeight  = !onInfo ? '600' : '500';
      tScore.style.color       = !onInfo ? 'var(--text-primary)' : 'var(--text-muted)';
      tScore.style.borderBottom = !onInfo ? '2px solid var(--accent)' : '2px solid transparent';
    }
  },

  _renderBreakdown(bd) {
    const sc = bd.final_score;
    const clsColor = sc >= 9 ? '#ef4444' : sc >= 7 ? '#f97316' : sc >= 4 ? '#eab308' : '#22c55e';
    const esc2 = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    // ── Section A: Asset + finding identity ──────────────────────────────────
    const assetLine = [
      bd.asset?.hostname,
      bd.asset?.ip ? `(${bd.asset.ip})` : null,
      bd.asset?.fqdn ? `· ${bd.asset.fqdn}` : null,
    ].filter(Boolean).join(' ');
    const cveList = (bd.cves || []).join(', ') || '–';

    const srcColor = bd.base_source === 'CVSS' ? 'var(--accent)'
      : bd.base_source === 'VPR' ? '#f97316' : '#a78bfa';
    const srcTitle = {
      CVSS: 'Threat bonuses active',
      VPR: 'Threat bonuses disabled — VPR encodes exploit context',
      FALLBACK: 'Severity-based score — no CVSS or VPR available',
    }[bd.base_source] || '';

    const sectionA = `
      <div style="background:var(--bg-secondary);border-radius:8px;padding:14px 16px;
        margin-bottom:18px;border:1px solid var(--border)">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
          <div style="flex:1;min-width:0">
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">Finding Instance</div>
            ${assetLine ? `<div style="font-size:12px;font-weight:600;color:var(--text-primary)">${esc2(assetLine)}</div>` : ''}
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px;display:flex;gap:10px;flex-wrap:wrap">
              ${bd.plugin_id ? `<span>Plugin: <strong>${esc2(bd.plugin_id)}</strong></span>` : ''}
              ${cveList !== '–' ? `<span>CVE: <strong>${esc2(cveList)}</strong></span>` : ''}
              ${bd.asset?.environment ? `<span>Env: <strong>${esc2(bd.asset.environment)}</strong></span>` : ''}
              ${bd.asset?.reachability ? `<span>Reach: <strong>${esc2(bd.asset.reachability)}</strong></span>` : ''}
            </div>
          </div>
          <div style="text-align:right;flex-shrink:0">
            <div style="font-size:28px;font-weight:800;color:${clsColor};line-height:1">${sc.toFixed(1)}</div>
            <div style="font-size:10px;color:var(--text-muted);margin-top:2px">/ 10.0</div>
            <span style="display:inline-block;margin-top:4px;font-size:10px;font-weight:700;padding:2px 7px;
              border-radius:3px;background:${clsColor}20;color:${clsColor};text-transform:uppercase;
              letter-spacing:0.4px">${bd.severity_class}</span>
            <div style="font-size:10px;color:var(--text-muted);margin-top:3px">SLA ${bd.sla}</div>
          </div>
        </div>
        <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);
          display:flex;align-items:center;gap:8px">
          <span style="font-size:10px;color:var(--text-muted)">Base source</span>
          <span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:3px;
            background:${srcColor}18;color:${srcColor};border:1px solid ${srcColor}30"
            title="${srcTitle}">${bd.base_source}</span>
          <span style="font-size:11px;color:var(--text-muted)">${srcTitle}</span>
        </div>
      </div>
    `;

    // ── Section B: Waterfall ──────────────────────────────────────────────────
    const typeConfig = {
      base:          { icon: '◉', color: 'var(--accent)',  bg: 'var(--accent)18'  },
      bonus:         { icon: '+', color: '#22c55e',        bg: '#22c55e18'        },
      bonus_disabled:{ icon: '×', color: 'var(--text-muted)', bg: 'var(--bg-secondary)' },
      floor:         { icon: '▲', color: '#eab308',        bg: '#eab30818'        },
      contextual:    { icon: '+', color: '#f97316',        bg: '#f9731618'        },
      result:        { icon: '=', color: '#3b82f6',        bg: '#3b82f618'        },
    };

    const steps = bd.breakdown_steps || [];
    const waterfallRows = steps.map(step => {
      const cfg2 = typeConfig[step.type] || typeConfig.result;
      const applied = step.applied;
      const rt = step.running_total ?? 0;
      const pct = Math.min(100, (rt / 10) * 100).toFixed(1);
      const deltaText = step.delta != null
        ? (!step.applied
            ? 'not triggered'
            : step.type === 'floor'
              ? (step.delta > 0 ? `→ ${step.running_total.toFixed(1)}` : `≥ already met`)
              : step.type === 'result'
                ? ''
                : step.delta > 0
                  ? `+${step.delta.toFixed(2)}`
                  : '+0 (at cap)')
        : '–';
      const valueColor = applied && step.delta > 0 ? cfg2.color
        : !applied ? 'var(--text-muted)' : cfg2.color;

      const signals = (step.signals || []);
      const signalInline = signals.length
        ? signals.map(s => `<span style="font-size:9px;padding:0px 4px;border-radius:2px;
            background:${cfg2.color}20;color:${cfg2.color}">${esc2(s)}</span>`).join(' ')
        : '';

      return `
        <div style="display:flex;align-items:center;gap:0;padding:5px 0;
          border-bottom:1px solid var(--border);
          ${step.type === 'result' ? 'border-top:2px solid var(--border);margin-top:2px;padding-top:6px;' : ''}">

          <!-- Icon -->
          <div style="width:20px;flex-shrink:0;text-align:center;
            font-size:10px;font-weight:700;color:${applied ? cfg2.color : 'var(--text-muted)'}">
            ${cfg2.icon}
          </div>

          <!-- Label + desc -->
          <div style="flex:1;min-width:0;padding-right:8px">
            <div style="font-size:11px;font-weight:${step.type === 'result' ? '700' : '500'};
              color:${applied ? 'var(--text-primary)' : 'var(--text-muted)'};white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
              ${esc2(step.label)}${signalInline ? ` <span style="font-weight:400">${signalInline}</span>` : ''}
            </div>
            ${step.description ? `<div style="font-size:9px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:240px">
              ${esc2(step.description)}
            </div>` : ''}
          </div>

          <!-- Bar + value -->
          <div style="flex-shrink:0;width:160px;display:flex;align-items:center;gap:6px">
            <div style="flex:1;height:4px;background:var(--bg-secondary);border-radius:2px;overflow:hidden;
              border:1px solid var(--border)">
              <div style="height:100%;width:${applied ? pct : '0'}%;
                background:${applied ? cfg2.color : 'transparent'};border-radius:2px;
                transition:width 0.4s ease"></div>
            </div>
            <div style="width:54px;text-align:right;font-size:10px;font-weight:600;
              color:${valueColor};white-space:nowrap">
              ${step.type === 'result'
                ? `<span style="font-size:12px">${rt.toFixed(2)}</span>`
                : deltaText}
            </div>
          </div>
        </div>
      `;
    }).join('');

    const sectionB = `
      <div style="margin-bottom:18px">
        <div style="font-size:10px;font-weight:700;letter-spacing:0.7px;color:var(--text-muted);
          text-transform:uppercase;margin-bottom:10px">Score Build-Up</div>
        <div style="background:var(--bg-card, var(--bg-primary));border:1px solid var(--border);
          border-radius:8px;padding:0 10px">
          ${waterfallRows}
        </div>
      </div>
    `;

    // ── Section C: Context multipliers ────────────────────────────────────────
    const ctx = bd.context || {};
    const fv  = bd.formula_view || {};

    const multLabel = {
      env_label:  { unknown:'Unknown', prod:'Production', production:'Production', uat:'UAT/Staging',
                    staging:'UAT/Staging', dev:'Development', development:'Development',
                    test:'Test/Lab', lab:'Test/Lab' },
      reach_label:{ unknown:'Unknown', 'internet-facing':'Internet-Facing', external:'Internet-Facing',
                    partner:'Partner/VPN', vpn:'Partner/VPN', 'user-reachable':'User-Reachable',
                    internal:'Internal', isolated:'Isolated', local:'Isolated' },
      crit_label: { unknown:'Unknown', tier0:'Tier 0 — Crown Jewel', 'prod-critical':'Prod-Critical',
                    important:'Important', standard:'Standard', 'low-value':'Low-Value' },
      ctrl_label: { unknown:'Unknown', none:'No Controls', one:'1 Verified Control',
                    two_plus:'2 Verified Controls', multilayer:'Multilayer Defense' },
    };

    const multColor = v => v > 1 ? '#f97316' : v < 1 ? '#22c55e' : 'var(--text-muted)';
    const multIcon  = v => v > 1 ? '▲' : v < 1 ? '▼' : '–';

    const multiplierCards = [
      { key: 'env',   label: 'ENV',   lbl: ctx.env_label,   mult: ctx.env_multiplier,   desc: 'Environment' },
      { key: 'reach', label: 'REACH', lbl: ctx.reach_label, mult: ctx.reach_multiplier, desc: 'Reachability' },
      { key: 'crit',  label: 'CRIT',  lbl: ctx.crit_label,  mult: ctx.crit_multiplier,  desc: 'Asset Criticality' },
      { key: 'ctrl',  label: 'CTRL',  lbl: ctx.ctrl_label,  mult: ctx.ctrl_multiplier,  desc: 'Compensating Controls' },
    ].map(m => {
      const displayLabel = (multLabel[`${m.key}_label`] || {})[m.lbl] || m.lbl || 'Unknown';
      const mult = m.mult ?? 1.0;
      const col  = multColor(mult);
      const ico  = multIcon(mult);
      return `
        <div style="flex:1;min-width:120px;background:var(--bg-secondary);border:1px solid var(--border);
          border-radius:7px;padding:12px 14px">
          <div style="font-size:9px;font-weight:700;letter-spacing:0.6px;color:var(--text-muted);
            text-transform:uppercase">${m.desc}</div>
          <div style="font-size:11px;font-weight:600;color:var(--text-primary);margin-top:4px">
            ${esc2(displayLabel)}
          </div>
          <div style="display:flex;align-items:baseline;gap:4px;margin-top:6px">
            <span style="font-size:18px;font-weight:800;color:${col}">×${mult.toFixed(2)}</span>
            <span style="font-size:11px;color:${col}">${ico}</span>
          </div>
        </div>
      `;
    }).join('');

    const formulaParts = [
      fv.intermediate_score?.toFixed(2) ?? '–',
      `<span style="color:#22c55e">×${(fv.env_multiplier ?? 1).toFixed(2)}</span>`,
      `<span style="color:#ef4444">×${(fv.reach_multiplier ?? 1).toFixed(2)}</span>`,
      `<span style="color:#a78bfa">×${(fv.crit_multiplier ?? 1).toFixed(2)}</span>`,
      `<span style="color:#3b82f6">×${(fv.ctrl_multiplier ?? 1).toFixed(2)}</span>`,
    ].join(' ');

    const sectionC = `
      <div style="margin-bottom:18px">
        <div style="font-size:10px;font-weight:700;letter-spacing:0.7px;color:var(--text-muted);
          text-transform:uppercase;margin-bottom:10px">Context Multipliers</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
          ${multiplierCards}
        </div>
        <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:7px;
          padding:12px 14px;font-family:monospace;font-size:12px;color:var(--text-secondary);
          display:flex;align-items:center;gap:6px;flex-wrap:wrap">
          <span>${formulaParts}</span>
          <span style="color:var(--text-muted)">=</span>
          <span style="font-size:15px;font-weight:800;color:${clsColor}">${sc.toFixed(2)}</span>
          <span style="font-size:10px;color:var(--text-muted)">(capped at 10.0)</span>
        </div>
      </div>
    `;

    // ── Section D: Summary card ───────────────────────────────────────────────
    const sectionD = `
      <div style="background:${clsColor}10;border:1px solid ${clsColor}30;border-radius:8px;
        padding:14px 16px;display:flex;gap:14px;align-items:flex-start">
        <div style="flex-shrink:0;width:44px;height:44px;border-radius:8px;
          background:${clsColor}20;border:1px solid ${clsColor}40;
          display:flex;align-items:center;justify-content:center">
          <span style="font-size:18px;font-weight:800;color:${clsColor}">${sc.toFixed(0)}</span>
        </div>
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            <span style="font-size:12px;font-weight:700;color:${clsColor};text-transform:uppercase;
              letter-spacing:0.4px">${bd.severity_class}</span>
            <span style="font-size:11px;color:var(--text-muted)">·</span>
            <span style="font-size:11px;color:var(--text-secondary)">SLA: <strong>${bd.sla}</strong></span>
          </div>
          <div style="font-size:12px;color:var(--text-secondary);line-height:1.5">
            ${esc2(bd.summary_reason || '')}
          </div>
        </div>
      </div>
    `;

    return sectionA + sectionB + sectionC + sectionD;
  },

  async updateStatus(id) {
    const sel = document.getElementById('detail-status-select');
    try {
      await API.patch(`/vulnerabilities/${id}/status`, { status: sel.value });
      toast('Status updated', 'success');
      closeDetail();
      this.load();
    } catch (e) {
      toast(e.message, 'error');
    }
  },
};

// Exposed for asset page linking
function loadVulnsByAsset(assetId, label) {
  // Reset state, keep only asset filter
  VulnsPage.state = {
    page: 1, per_page: 25, severity: '', status: '', source: '',
    search: '', host: '', asset_id: assetId, asset_label: label || String(assetId),
    category: 'vulnerability',
  };
  navigate('vulnerabilities');
}
