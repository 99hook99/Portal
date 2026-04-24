/* Inventory page – Hosts / Cloud / Applications+Systems / Web & Domains */

const AssetsPage = {
  state: {
    tab: 'hosts',
    // list filters
    page: 1, per_page: 25, criticality: '', asset_type: '', source: '', search: '',
    system_id: '', unassigned: false,
    // cached data
    assetIndex: {}, systems: [],
    // drag & drop
    dragging: null, dragTabTimer: null, _dragHappened: false,
    // system detail
    currentSystem: null, sysEnv: 'all',
  },

  async render(el) {
    this._el = el;
    el.innerHTML = `
      <div class="asset-tabs" id="asset-tabs">
        <button class="asset-tab" data-tab="hosts"
          onclick="AssetsPage.switchTab('hosts')"
          ondragover="AssetsPage._tabDragOver('hosts',this,event)"
          ondragleave="AssetsPage._tabDragLeave(this)">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="2" y="3" width="20" height="14" rx="2"/>
            <line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
          </svg>
          Hosts
        </button>
        <button class="asset-tab" data-tab="cloud"
          onclick="AssetsPage.switchTab('cloud')"
          ondragover="AssetsPage._tabDragOver('cloud',this,event)"
          ondragleave="AssetsPage._tabDragLeave(this)">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
          </svg>
          Cloud
        </button>
        <button class="asset-tab" data-tab="apps"
          onclick="AssetsPage.switchTab('apps')"
          ondragover="AssetsPage._tabDragOver('apps',this,event)"
          ondragleave="AssetsPage._tabDragLeave(this)">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="2" y="3" width="6" height="6" rx="1"/><rect x="9" y="3" width="13" height="6" rx="1"/>
            <rect x="2" y="12" width="6" height="6" rx="1"/><rect x="9" y="12" width="13" height="6" rx="1"/>
          </svg>
          Applications / Systems
        </button>
      </div>
      <div id="asset-tab-content"></div>
      <div id="asset-modal-overlay" class="asset-modal-overlay" onclick="AssetsPage._closeModal()"></div>
      <div id="asset-modal" class="asset-modal"></div>
    `;
    return this.switchTab(this.state.tab);
  },

  async switchTab(tab) {
    this.state.tab = tab;
    document.querySelectorAll('.asset-tab').forEach(b =>
      b.classList.toggle('active', b.dataset.tab === tab)
    );
    const content = document.getElementById('asset-tab-content');
    if (!content) return;
    content.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;
    if      (tab === 'hosts') return this._renderHosts(content);
    else if (tab === 'list')  return this._renderHosts(content);  // compat
    else if (tab === 'cloud') return this._renderCloud(content);
    else if (tab === 'apps')  return this._renderApps(content);
  },

  // ═══════════════════════════════════════════════════════
  // HOSTS TAB
  // ═══════════════════════════════════════════════════════

  _hostTypeInfo(a) {
    const it = (a.identity_type || '').toLowerCase();
    const t  = (a.asset_type    || '').toLowerCase();
    const os = (a.os            || '').toLowerCase();
    // identity_type is the primary signal (set by auto-detect or drag&drop)
    if (it === 'workstation' || t === 'workstation' || t === 'laptop' ||
        os.includes('windows 10') || os.includes('windows 11') ||
        os.includes('macos') || os.includes('mac os'))
      return { label: 'Workstation', icon: `<rect x="2" y="3" width="20" height="13" rx="2"/><polyline points="8 21 12 17 16 21"/>`, color: '#06b6d4' };
    if (t === 'network' || t === 'router' || t === 'switch' || t === 'firewall')
      return { label: 'Network', icon: `<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="9" y="16" width="6" height="6" rx="1"/><rect x="2" y="9" width="6" height="6" rx="1"/><rect x="16" y="9" width="6" height="6" rx="1"/><line x1="12" y1="8" x2="12" y2="9"/><line x1="12" y1="15" x2="12" y2="16"/><line x1="8" y1="12" x2="9" y2="12"/><line x1="15" y1="12" x2="16" y2="12"/>`, color: '#f97316' };
    if (t === 'container' || it === 'container')
      return { label: 'Container', icon: `<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>`, color: '#8b5cf6' };
    if (it === 'host')
      return { label: 'Host', icon: `<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>`, color: '#3b82f6' };
    // Default / server
    return { label: 'Server', icon: `<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>`, color: '#22c55e' };
  },


  async _renderHosts(el) {
    el.innerHTML = `
      <div class="filter-bar" id="list-filter-bar">
        <div class="search-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input class="input search-input" id="asset-search" placeholder="Search hostname, IP or OS…">
        </div>
        <select class="input" id="asset-type" style="width:140px">
          <option value="">All Types</option>
          <option value="server">Server</option>
          <option value="workstation">Workstation</option>
          <option value="laptop">Laptop</option>
          <option value="network">Network</option>
        </select>
        <select class="input" id="asset-source" style="width:130px">
          <option value="">All Sources</option>
          <option value="nessus">Nessus</option>
          <option value="mde">Defender</option>
          <option value="nuclei">Nuclei</option>
          <option value="aws">AWS</option>
          <option value="csv">CSV</option>
          <option value="json">JSON</option>
          <option value="manual">Manual</option>
        </select>
        <select class="input" id="asset-crit" style="width:140px">
          <option value="">All Criticalities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <div style="margin-left:auto;display:flex;align-items:center;gap:8px">
          <span style="font-size:12px;color:var(--text-muted)" id="asset-count">–</span>
          <button class="btn btn-secondary btn-sm" onclick="AssetsPage._showImportModal()" title="Import from CSV or JSON">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Import
          </button>
        </div>
      </div>
      ${HostsTable.filterBarHtml()}
      <div class="table-wrap" style="overflow-x:auto">
        <table id="host-table" style="table-layout:fixed;min-width:700px">
          ${HostsTable.colgroup()}
          <thead><tr id="hosts-thr">${HostsTable.thead()}</tr></thead>
          <tbody id="asset-tbody">
            <tr><td colspan="${HostsTable.cols.length}"><div class="loader"><div class="spinner"></div></div></td></tr>
          </tbody>
        </table>
      </div>
      <div id="asset-pagination"></div>
    `;

    const s = this.state;
    if (s.search)      document.getElementById('asset-search').value = s.search;
    if (s.asset_type)  document.getElementById('asset-type').value   = s.asset_type;
    if (s.criticality) document.getElementById('asset-crit').value   = s.criticality;
    if (s.source)      document.getElementById('asset-source').value = s.source;

    document.getElementById('asset-search').addEventListener('input', debounce(e => {
      this.state.search = e.target.value; this.state.page = 1; this._loadHosts();
    }, 300));
    document.getElementById('asset-type').addEventListener('change', e => {
      this.state.asset_type = e.target.value; this.state.page = 1; this._loadHosts();
    });
    document.getElementById('asset-crit').addEventListener('change', e => {
      this.state.criticality = e.target.value; this.state.page = 1; this._loadHosts();
    });
    document.getElementById('asset-source').addEventListener('change', e => {
      this.state.source = e.target.value; this.state.page = 1; this._loadHosts();
    });

    return this._loadHosts();
  },

  // ── Scoring cell (horizontal colored selects) ────────────
  _scoringBadge(a, field, val, colors, labels) {
    const c = (val && colors[val]) || '#475569';
    const opts = Object.keys(labels);
    const opts_html = `<option value="">Not set</option>` +
      opts.map(o => `<option value="${o}" ${o===val?'selected':''}>${labels[o]}</option>`).join('');
    const colorMapStr = opts.map(o => `'${o}':'${colors[o]||'#475569'}'`).join(',');
    return `<select title="${field.replace(/_/g,' ')}: ${val ? labels[val] : 'not set'}"
      onclick="event.stopPropagation()"
      onchange="event.stopPropagation();AssetsPage._patchAsset(${a.id},'${field}',this.value);AssetsPage._recolorSelect(this,{${colorMapStr}})"
      style="background:${c}18;color:${c};border:1px solid ${c}30;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:500;cursor:pointer;max-width:110px;text-overflow:ellipsis;transition:border-color .15s;white-space:nowrap">
      ${opts_html}
    </select>`;
  },

  _recolorSelect(el, colorMap) {
    const c = colorMap[el.value] || '#475569';
    el.style.background = `${c}18`;
    el.style.color = c;
    el.style.borderColor = `${c}40`;
  },

  async _loadHosts() {
    const { page, per_page, criticality, asset_type, source, search } = this.state;
    const params = { page, per_page, criticality, asset_type, source, search, identity_type: 'host' };

    const data = await API.get('/assets/', params);

    const countEl = document.getElementById('asset-count');
    if (countEl) countEl.textContent = `${data.total.toLocaleString()} hosts`;

    const tbody = document.getElementById('asset-tbody');
    if (!tbody) return;

    const HOSTS_GETTERS = {
      host:    a => `${a.hostname||''} ${a.ip_address||''}`,
      type:    a => a.identity_type || a.asset_type,
      os:      a => a.os,
      env:     a => a.environment,
      reach:   a => a.reachability,
      tier:    a => a.asset_tier,
      controls:a => a.compensating_controls,
      source:  a => a.source,
      vulns:   a => a.vuln_count,
      lastseen:a => a.last_seen,
    };
    const items = HostsTable.applyFilters(data.items, HOSTS_GETTERS);

    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="${HostsTable.cols.length}" style="text-align:center;padding:48px 20px">
        <div style="color:var(--text-muted);font-size:13px">${data.items.length ? 'No hosts match column filters' : 'No hosts found'}</div>
        <div style="color:var(--text-muted);font-size:11px;margin-top:6px">${data.items.length ? '' : 'Run a Nessus scan or import assets to populate this view'}</div>
      </td></tr>`;
      return;
    }

    const SOURCE_COLORS = { nessus:'#3b82f6', aws:'#f97316', nuclei:'#22c55e', mde:'#8b5cf6', openvas:'#06b6d4', manual:'#6b7280', csv:'#14b8a6', json:'#14b8a6', import:'#14b8a6' };
    const _srcBadges = (src) => (src||'–').split(',').map(s => s.trim()).filter(Boolean).map(s => {
      const c = SOURCE_COLORS[s] || '#6b7280';
      return `<span style="font-size:10px;color:${c};background:${c}18;border:1px solid ${c}30;border-radius:4px;padding:1px 5px;text-transform:capitalize;white-space:nowrap">${esc(s)}</span>`;
    }).join(' ') || '–';

    tbody.innerHTML = items.map(a => {
      const typeInfo = this._hostTypeInfo(a);
      const vulnCrit = a.critical_count > 0;
      const vulnHigh = (a.high_count || 0) > 0;
      const vulnColor = vulnCrit ? '#ef4444' : vulnHigh ? '#f97316' : a.vuln_count > 0 ? '#eab308' : 'var(--text-muted)';

      // Build cell content keyed by column
      const cells = {
        icon: `<td style="padding:8px 6px 8px 12px">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${typeInfo.color}" stroke-width="1.8" title="${typeInfo.label}">
            ${typeInfo.icon}
          </svg>
        </td>`,
        host: `<td style="max-width:${HostsTable.cols.find(c=>c.key==='host')?.w||220}px">
          <div class="primary truncate" title="${esc(a.hostname || a.ip_address || '')}">
            ${a.hostname ? `<span style="font-weight:500">${esc(a.hostname)}</span>`
              : a.ip_address ? `<span style="font-family:monospace;font-size:12px">${esc(a.ip_address)}</span>`
              : `<span style="color:var(--text-muted)">Unknown</span>`}
          </div>
          ${a.ip_address && a.hostname ? `<div style="font-family:monospace;font-size:10px;color:var(--text-muted)">${esc(a.ip_address)}</div>` : ''}
          ${a.fqdn && a.fqdn !== a.hostname ? `<div style="font-size:10px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.fqdn)}</div>` : ''}
        </td>`,
        type: `<td>
          <span style="display:inline-flex;align-items:center;gap:4px;font-size:11px;color:${typeInfo.color};
            background:${typeInfo.color}18;border:1px solid ${typeInfo.color}30;
            border-radius:5px;padding:2px 7px;white-space:nowrap">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${typeInfo.icon}</svg>
            ${typeInfo.label}
          </span>
        </td>`,
        os: `<td style="overflow:hidden">
          ${a.os
            ? `<div style="font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(a.os+(a.os_version?' '+a.os_version:''))}">${esc(a.os)}</div>
               ${a.os_version ? `<div style="font-size:10px;color:var(--text-muted)">${esc(a.os_version)}</div>` : ''}`
            : `<span style="color:var(--text-muted);font-size:12px">–</span>`}
        </td>`,
        env:      `<td>${this._scoringBadge(a, 'environment',          a.environment,          {prod:'#22c55e',uat:'#3b82f6',dev:'#eab308',test:'#94a3b8'}, {prod:'Production',uat:'UAT',dev:'Development',test:'Testing'})}</td>`,
        reach:    `<td>${this._scoringBadge(a, 'reachability',         a.reachability,         {'internet-facing':'#ef4444',partner:'#f97316',vpn:'#f97316',internal:'#22c55e',isolated:'#94a3b8'}, {'internet-facing':'Internet Facing',partner:'Partner',vpn:'VPN',internal:'Internal',isolated:'Isolated'})}</td>`,
        tier:     `<td>${this._scoringBadge(a, 'asset_tier',           a.asset_tier,           {tier0:'#ef4444','prod-critical':'#f97316',important:'#eab308',standard:'#3b82f6','low-value':'#94a3b8'}, {tier0:'Tier 0','prod-critical':'Prod Critical',important:'Important',standard:'Standard','low-value':'Low Value'})}</td>`,
        controls: `<td>${this._scoringBadge(a, 'compensating_controls',a.compensating_controls,{none:'#94a3b8',one:'#eab308',two_plus:'#22c55e',multilayer:'#22c55e'}, {none:'None',one:'One Control',two_plus:'Two or More',multilayer:'Multi-Layer'})}</td>`,
        source: `<td style="white-space:nowrap"><div style="display:flex;flex-wrap:wrap;gap:2px">${_srcBadges(a.source)}</div></td>`,
        vulns: `<td>
          ${a.vuln_count > 0 ? `
            <div style="display:flex;align-items:center;gap:5px">
              <span style="font-weight:600;font-size:13px;color:${vulnColor}">${a.vuln_count}</span>
              <div style="display:flex;gap:2px">
                ${a.critical_count > 0 ? `<span style="font-size:10px;background:#ef444420;color:#ef4444;border-radius:3px;padding:1px 4px">${a.critical_count}C</span>` : ''}
                ${(a.high_count||0) > 0 ? `<span style="font-size:10px;background:#f9731620;color:#f97316;border-radius:3px;padding:1px 4px">${a.high_count}H</span>` : ''}
              </div>
            </div>` : `<span style="color:var(--text-muted);font-size:12px">–</span>`}
        </td>`,
        lastseen: `<td style="font-size:11px;color:var(--text-muted);white-space:nowrap">${fmtDateShort(a.last_seen)}</td>`,
      };

      const tds = HostsTable.cols.map(col => cells[col.key] || '<td></td>').join('');
      return `<tr onclick="AssetsPage._rowClick(${a.id},event)" style="cursor:pointer">${tds}</tr>`;
    }).join('');

    renderPagination('asset-pagination', page, per_page, data.total, p => {
      this.state.page = p; this._loadHosts();
    });
  },

  // ═══════════════════════════════════════════════════════
  // LIST TAB (legacy – still used by detail panel etc.)
  // ═══════════════════════════════════════════════════════

  async _renderList(el, hostsOnly = false) {
    el.innerHTML = `
      <div class="filter-bar" id="list-filter-bar">
        <div class="search-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input class="input search-input" id="asset-search" placeholder="Search hostname or IP…">
        </div>
        <select class="input" id="asset-crit" style="width:140px">
          <option value="">All Criticalities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select class="input" id="asset-type" style="width:120px">
          <option value="">All Types</option>
          <option value="server">Server</option>
          <option value="workstation">Workstation</option>
          <option value="network">Network</option>
          <option value="cloud">Cloud</option>
        </select>
        <select class="input" id="asset-system" style="width:150px">
          <option value="">All Systems</option>
        </select>
        <button id="unassigned-toggle" class="btn btn-secondary btn-sm ${this.state.unassigned?'active':''}"
          onclick="AssetsPage._toggleUnassigned()"
          title="Show only assets not assigned to any system">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
          </svg>
          Unassigned
        </button>
        <div style="margin-left:auto;display:flex;align-items:center;gap:8px">
          <span style="font-size:12px;color:var(--text-muted)" id="asset-count">–</span>
          <button class="btn btn-secondary btn-sm" onclick="AssetsPage._showImportModal()" title="Import assets from CSV or JSON">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/>
              <line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Import
          </button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:20%">Host</th>
              <th>OS</th>
              <th>Criticality</th>
              <th style="width:160px">Metadata</th>
              <th>Vulns</th>
              <th>Risk Score</th>
              <th>Systems</th>
              <th>Last Seen</th>
              <th style="width:36px"></th>
            </tr>
          </thead>
          <tbody id="asset-tbody">
            <tr><td colspan="9"><div class="loader"><div class="spinner"></div></div></td></tr>
          </tbody>
        </table>
      </div>
      <div id="asset-pagination"></div>
    `;

    // Restore filter values
    const s = this.state;
    if (s.search)      document.getElementById('asset-search').value = s.search;
    if (s.criticality) document.getElementById('asset-crit').value   = s.criticality;
    if (s.asset_type)  document.getElementById('asset-type').value   = s.asset_type;

    // Attach filter listeners
    document.getElementById('asset-search').addEventListener('input', debounce(e => {
      this.state.search = e.target.value; this.state.page = 1; this.load();
    }, 300));
    ['asset-crit','asset-type'].forEach(id => {
      document.getElementById(id).addEventListener('change', e => {
        const key = id === 'asset-crit' ? 'criticality' : 'asset_type';
        this.state[key] = e.target.value; this.state.page = 1; this.load();
      });
    });
    document.getElementById('asset-system').addEventListener('change', e => {
      this.state.system_id = e.target.value;
      this.state.unassigned = false;
      document.getElementById('unassigned-toggle')?.classList.remove('active');
      this.state.page = 1; this.load();
    });

    // Load supporting data in parallel
    const [idx, systems] = await Promise.all([
      API.get('/app-systems/asset-index').catch(() => ({})),
      API.get('/app-systems/').catch(() => []),
    ]);
    this.state.assetIndex = idx;
    this.state.systems = systems;

    // Populate system filter
    const sel = document.getElementById('asset-system');
    if (sel) {
      sel.innerHTML = `<option value="">All Systems</option>` +
        systems.map(s => `<option value="${s.id}">${esc(s.name)}</option>`).join('');
      if (this.state.system_id) sel.value = this.state.system_id;
    }

    return this.load();
  },

  async load() {
    const { page, per_page, criticality, asset_type, source, search, system_id, unassigned } = this.state;
    const params = { page, per_page, criticality, asset_type, source, search };
    if (system_id) params.system_id = system_id;
    if (unassigned) params.unassigned = true;
    // legacy list tab: exclude cloud resources
    if (this.state.tab === 'list') {
      params.identity_type = 'host';
    }

    const data = await API.get('/assets/', params);

    const countEl = document.getElementById('asset-count');
    if (countEl) {
      const label = unassigned ? 'unassigned' : system_id ? 'in system' : 'assets';
      countEl.textContent = `${data.total.toLocaleString()} ${label}`;
    }

    const tbody = document.getElementById('asset-tbody');
    if (!tbody) return;
    if (!data.items.length) {
      tbody.innerHTML = `<tr><td colspan="9">${emptyState(unassigned ? 'All assets are assigned to a system' : 'No assets found')}</td></tr>`;
      return;
    }

    tbody.innerHTML = data.items.map(a => {
      const sysList = this.state.assetIndex[String(a.id)] || [];
      const sysPills = sysList.map(s =>
        `<span class="sys-pill sys-pill-${s.environment}" title="${esc(s.name)}">${esc(s.name.length > 12 ? s.name.slice(0,12)+'…' : s.name)}</span>`
      ).join('');

      const IDENTITY_COLORS = { host:'#3b82f6', server:'#22c55e', workstation:'#06b6d4', cloud_resource:'#8b5cf6', container:'#8b5cf6', image:'#ec4899', app:'#f97316', repo:'#94a3b8', web:'#10b981' };
      const identColor = IDENTITY_COLORS[a.identity_type] || '#3b82f6';

      return `<tr
          draggable="true"
          ondragstart="AssetsPage._onDragStart(event,${a.id},'${esc(a.hostname||a.ip_address||'')}')"
          ondragend="AssetsPage._onDragEnd(event)"
          onclick="AssetsPage._rowClick(${a.id},event)"
          style="cursor:pointer">
        <td style="max-width:190px">
          <div style="display:flex;align-items:flex-start;gap:5px">
            <span class="drag-handle" title="Drag to assign to a system">⠿</span>
            <div style="min-width:0;flex:1">
              <div style="display:flex;align-items:center;gap:5px">
                <span class="identity-dot" style="background:${identColor}20;color:${identColor};border-color:${identColor}40;cursor:pointer"
                  title="Type: ${(a.identity_type||'host').replace('_',' ')} — click to change"
                  onclick="event.stopPropagation();AssetsPage._showTypePicker(event,${a.id},'${a.identity_type||'host'}')">
                  ${(a.identity_type||'host').slice(0,2).toUpperCase()}
                </span>
                <div class="primary truncate" title="${esc(a.hostname||a.ip_address||'')}" style="flex:1">
                  ${a.hostname
                    ? esc(a.hostname)
                    : a.ip_address
                      ? `<span style="font-family:monospace">${esc(a.ip_address)}</span>`
                      : '<span style="color:var(--text-muted)">–</span>'}
                </div>
              </div>
              ${a.hostname && a.ip_address
                ? `<div style="font-family:monospace;font-size:10px;color:var(--text-muted);margin-left:34px">${esc(a.ip_address)}</div>` : ''}
            </div>
          </div>
        </td>
        <td>
          <div style="font-size:12px;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.os||'–'}</div>
          ${a.os_version?`<div style="font-size:11px;color:var(--text-muted)">${esc(a.os_version)}</div>`:''}
        </td>
        <td>${critBadge(a.criticality)}</td>
        <td>${this._metadataCell(a)}</td>
        <td>
          <span style="font-weight:600;color:${a.critical_count>0?'var(--critical)':'var(--text-secondary)'}">
            ${a.vuln_count}
          </span>
          ${a.critical_count>0?`<span style="font-size:11px;color:var(--critical);margin-left:3px">(${a.critical_count})</span>`:''}
        </td>
        <td style="min-width:100px">
          <div class="risk-bar-wrap">
            <div class="risk-bar">
              <div class="risk-bar-fill ${a.risk_score>60?'critical':a.risk_score>30?'high':''}"
                   style="width:${Math.min(a.risk_score,100)}%"></div>
            </div>
            <span class="risk-score-num">${a.risk_score.toFixed(0)}</span>
          </div>
        </td>
        <td style="max-width:160px">
          ${sysPills
            ? `<div style="display:flex;flex-wrap:wrap;gap:3px">${sysPills}</div>`
            : `<span style="font-size:11px;color:var(--text-muted)">–</span>`}
        </td>
        <td style="font-size:11px;color:var(--text-muted);white-space:nowrap">${fmtDateShort(a.last_seen)}</td>
        <td>
          <button class="btn-assign-quick" title="Assign to system"
            onclick="event.stopPropagation();AssetsPage._showQuickAssign(${a.id},'${esc(a.hostname||a.ip_address||'Asset #'+a.id)}')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
          </button>
        </td>
      </tr>`;
    }).join('');

    renderPagination('asset-pagination', page, per_page, data.total, p => {
      this.state.page = p; this.load();
    });
  },

  _rowClick(id, evt) {
    if (this._dragHappened) return;
    this.openDetail(id);
  },

  _metadataCell(a) {
    const parts = [];

    // ── Internet Exposure ──────────────────────────────────
    const EXP = {
      exposed:  { icon: `<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`,
                 cls: 'md-exp-exposed',  label: 'Internet Exposed' },
      partial:  { icon: `<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`,
                 cls: 'md-exp-partial',  label: 'Partially Exposed' },
      internal: { icon: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>`,
                 cls: 'md-exp-internal', label: 'Internal' },
      unknown:  { icon: `<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>`,
                 cls: 'md-exp-unknown',  label: 'Exposure Unknown' },
    };
    const exp = EXP[a.internet_exposure] || EXP.unknown;
    parts.push(`
      <div class="md-row">
        <span class="md-exp-badge ${exp.cls}">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">${exp.icon}</svg>
          ${exp.label}
        </span>
      </div>
    `);

    // ── Business Criticality stars ─────────────────────────
    const STAR_CFG = {
      critical: { filled: 4, color: '#ef4444' },
      high:     { filled: 3, color: '#f97316' },
      medium:   { filled: 2, color: '#eab308' },
      low:      { filled: 1, color: '#22c55e' },
    };
    const sc = STAR_CFG[a.business_criticality];
    if (sc) {
      const stars = Array.from({length:4}, (_,i) => i < sc.filled
        ? `<svg width="11" height="11" viewBox="0 0 24 24" fill="${sc.color}" stroke="${sc.color}" stroke-width="1">
             <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
           </svg>`
        : `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--border)" stroke-width="1.5">
             <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
           </svg>`
      ).join('');
      parts.push(`
        <div class="md-row" title="Business Criticality: ${a.business_criticality}">
          <span class="md-stars">${stars}</span>
          <span class="md-stars-label" style="color:${sc.color}">${a.business_criticality}</span>
        </div>
      `);
    }

    // ── Environment ────────────────────────────────────────
    if (a.environment) {
      const ENV_COLOR = { prod:'#22c55e', staging:'#3b82f6', uat:'#8b5cf6', dev:'#eab308', test:'#64748b' };
      const ec = ENV_COLOR[a.environment] || '#64748b';
      parts.push(`
        <div class="md-row">
          <span class="md-env-badge" style="background:${ec}18;color:${ec};border-color:${ec}40">
            <span style="width:5px;height:5px;border-radius:50%;background:${ec};flex-shrink:0;display:inline-block"></span>
            ${a.environment.toUpperCase()}
          </span>
        </div>
      `);
    }

    // ── Data classification ────────────────────────────────
    const DC = {
      public:       { label:'Public',       color:'#64748b' },
      internal:     { label:'Internal',     color:'#3b82f6' },
      confidential: { label:'Confidential', color:'#f97316' },
      restricted:   { label:'Restricted',   color:'#ef4444' },
      pii:          { label:'PII',          color:'#ec4899' },
    };
    if (a.data_classification && DC[a.data_classification]) {
      const dc = DC[a.data_classification];
      parts.push(`
        <div class="md-row" title="Data Classification: ${dc.label}">
          <span class="md-cls-badge" style="color:${dc.color};border-color:${dc.color}40;background:${dc.color}12">
            <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            ${dc.label}
          </span>
        </div>
      `);
    }

    // ── Labels ─────────────────────────────────────────────
    const LABEL_CFG = {
      crown_jewel:     { icon:`<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>`, fill:true,  color:'#f59e0b', label:'Crown Jewel' },
      regulated:       { icon:`<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`,                                                            fill:false, color:'#8b5cf6', label:'Regulated' },
      customer_facing: { icon:`<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>`,                                fill:false, color:'#3b82f6', label:'Customer Facing' },
      privileged_zone: { icon:`<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>`,                      fill:false, color:'#ef4444', label:'Privileged Zone' },
    };
    const activeLabels = (a.asset_labels||'').split(',').map(l=>l.trim()).filter(l=>LABEL_CFG[l]);
    if (activeLabels.length) {
      const icons = activeLabels.map(l => {
        const lc = LABEL_CFG[l];
        return `<span class="md-label-icon" style="color:${lc.color};border-color:${lc.color}40;background:${lc.color}12" title="${lc.label}">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="${lc.fill?lc.color:'none'}" stroke="${lc.color}" stroke-width="2">${lc.icon}</svg>
        </span>`;
      }).join('');
      parts.push(`<div class="md-row md-labels-row">${icons}</div>`);
    }

    const hasData = a.internet_exposure !== 'unknown' || a.business_criticality || a.environment || a.data_classification || activeLabels.length;
    if (!hasData) return `<span style="font-size:11px;color:var(--border)">–</span>`;

    return `<div class="md-cell">${parts.join('')}</div>`;
  },

  _toggleUnassigned() {
    this.state.unassigned = !this.state.unassigned;
    this.state.system_id = '';
    const btn = document.getElementById('unassigned-toggle');
    const sel = document.getElementById('asset-system');
    if (btn) btn.classList.toggle('active', this.state.unassigned);
    if (sel) sel.value = '';
    this.state.page = 1;
    this.load();
  },

  async openDetail(id) {
    const [a, vulns] = await Promise.all([
      API.get(`/assets/${id}`),
      API.get(`/assets/${id}/vulnerabilities`),
    ]);
    const sevCounts = { critical:0, high:0, medium:0, low:0, info:0 };
    vulns.forEach(v => { if (sevCounts[v.severity] !== undefined) sevCounts[v.severity]++; });
    const sysList = this.state.assetIndex[String(id)] || [];
    this._detailAsset = a;

    openDetail(
      a.hostname || a.ip_address || `Asset #${id}`,
      this._renderAssetMetaBadges(a),
      this._renderAssetDetailBody(a, vulns, sevCounts, sysList, id),
      `<button class="btn btn-primary btn-sm" onclick="window.open('/api/assets/${id}/report','_blank')">
         <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
           <polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>
         </svg>PDF Report
       </button>
       <button class="btn btn-secondary btn-sm" onclick="AssetsPage._showQuickAssign(${id},'${esc(a.hostname||a.ip_address||String(id))}')">Assign to System</button>
       <button class="btn btn-secondary btn-sm" onclick="closeDetail();loadVulnsByAsset(${id},'${esc(a.hostname||a.ip_address||String(id))}')">All Vulns</button>
       <button class="btn btn-secondary btn-sm" onclick="closeDetail()">Close</button>`
    );
  },

  _renderAssetMetaBadges(a) {
    const IDENTITY_ICONS = {
      host:           `<path d="M20 17a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H9.46c.35.61.54 1.3.54 2v11h10z"/><path d="M15 17v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5.46"/>`,
      cloud_resource: `<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>`,
      container:      `<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>`,
      image:          `<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>`,
      app:            `<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>`,
      repo:           `<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>`,
      web:            `<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`,
    };
    const identIcon = IDENTITY_ICONS[a.identity_type] || IDENTITY_ICONS.host;
    const identLabel = (a.identity_type || 'host').replace('_', ' ');

    return `
      <div class="asset-meta-badges">
        <span class="ameta-badge ameta-identity" title="Identity: ${identLabel}">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${identIcon}</svg>
          ${identLabel}
        </span>
        ${this._exposureBadge(a.internet_exposure)}
        ${this._envBadge(a.environment)}
        ${this._locationBadge(a.location_type)}
        ${this._dataClassBadge(a.data_classification)}
        ${this._labelBadges(a.asset_labels)}
      </div>
    `;
  },

  _exposureBadge(v) {
    const cfg = {
      exposed:  { cls:'ameta-exposed',  icon:`<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`, label:'Internet Exposed' },
      partial:  { cls:'ameta-partial',  icon:`<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`, label:'Partially Exposed' },
      internal: { cls:'ameta-internal', icon:`<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>`, label:'Internal' },
      unknown:  { cls:'ameta-unknown',  icon:`<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>`, label:'Exposure Unknown' },
    };
    const c = cfg[v] || cfg.unknown;
    return `<span class="ameta-badge ${c.cls}" title="${c.label}">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${c.icon}</svg>
      ${c.label}
    </span>`;
  },

  _envBadge(v) {
    if (!v) return '';
    const colors = { prod:'#22c55e', staging:'#3b82f6', uat:'#8b5cf6', dev:'#eab308', test:'#64748b' };
    const c = colors[v] || '#64748b';
    return `<span class="ameta-badge" style="border-color:${c}40;color:${c};background:${c}15" title="Environment: ${v}">
      <svg width="10" height="10" viewBox="0 0 24 24" fill="${c}" stroke="none"><circle cx="12" cy="12" r="4"/></svg>
      ${v.toUpperCase()}
    </span>`;
  },

  _locationBadge(v) {
    if (!v) return '';
    const icons = {
      'on-prem': `<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>`,
      cloud:     `<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>`,
      saas:      `<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>`,
      ot:        `<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33"/>`,
      hybrid:    `<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/>`,
    };
    return `<span class="ameta-badge ameta-location" title="Location: ${v}">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${icons[v]||icons['on-prem']}</svg>
      ${v}
    </span>`;
  },

  _dataClassBadge(v) {
    if (!v) return '';
    const cfg = {
      public:       { cls:'ameta-cls-public',  label:'Public' },
      internal:     { cls:'ameta-cls-internal', label:'Internal' },
      confidential: { cls:'ameta-cls-conf',    label:'Confidential' },
      restricted:   { cls:'ameta-cls-rest',    label:'Restricted' },
      pii:          { cls:'ameta-cls-pii',     label:'PII' },
    };
    const c = cfg[v] || { cls:'', label: v };
    return `<span class="ameta-badge ${c.cls}" title="Data Classification: ${c.label}">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      ${c.label}
    </span>`;
  },

  _labelBadges(v) {
    if (!v) return '';
    const cfg = {
      crown_jewel:      { icon:`<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>`, label:'Crown Jewel', cls:'ameta-crown' },
      regulated:        { icon:`<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`, label:'Regulated', cls:'ameta-regulated' },
      customer_facing:  { icon:`<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>`, label:'Customer Facing', cls:'ameta-customer' },
      privileged_zone:  { icon:`<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>`, label:'Privileged Zone', cls:'ameta-privileged' },
    };
    return v.split(',').map(l => l.trim()).filter(l => cfg[l]).map(l => {
      const c = cfg[l];
      return `<span class="ameta-badge ${c.cls}" title="${c.label}">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${c.icon}</svg>
        ${c.label}
      </span>`;
    }).join('');
  },

  _renderAssetDetailBody(a, vulns, sevCounts, sysList, id) {
    // Scoring factor helpers
    const ENV_MUL   = {prod:'×1.10',uat:'×1.00',dev:'×0.90',test:'×0.80'};
    const REACH_MUL = {'internet-facing':'×1.30',partner:'×1.15',vpn:'×1.15','user-reachable':'×1.15',internal:'×1.00',isolated:'×0.85'};
    const TIER_MUL  = {tier0:'×1.20','prod-critical':'×1.15',important:'×1.05',standard:'×1.00','low-value':'×0.90'};
    const CTRL_MUL  = {none:'×1.00',one:'×0.95',two_plus:'×0.90',multilayer:'×0.80'};
    const TIER_LABELS = {tier0:'Tier 0 (Crown Jewel)','prod-critical':'Prod-Critical',important:'Important',standard:'Standard','low-value':'Low Value'};
    const CTRL_LABELS = {none:'None',one:'1 Verified',two_plus:'2+ Verified',multilayer:'Multilayer'};
    const REACH_LABELS = {'internet-facing':'Internet-Facing',partner:'Partner/VPN',vpn:'VPN',internal:'Internal',isolated:'Isolated'};

    const _factor = (label, field, val, options, optLabels, muls, hint) => {
      const sel = options.map((o,i) => `<option value="${o}" ${o===val?'selected':''}>${optLabels?optLabels[i]:o}</option>`).join('');
      const mul = val && muls ? muls[val] : null;
      return `
        <div style="display:flex;align-items:center;padding:7px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:11px;color:var(--text-muted);width:110px;flex-shrink:0">${label}</span>
          <select id="${field}-val" style="flex:1;font-size:12px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:5px;padding:3px 6px;color:var(--text-primary);cursor:pointer"
            onchange="AssetsPage._saveInline('${field}','${id}',this)">
            <option value="">– not set –</option>${sel}
          </select>
          ${mul ? `<span style="font-size:11px;color:${mul.startsWith('×1.0')?'var(--text-muted)':mul>'×1'?'#f97316':'#22c55e'};font-family:monospace;margin-left:8px;min-width:36px">${mul}</span>` : `<span style="min-width:44px"></span>`}
          ${hint ? `<span style="font-size:9px;color:var(--text-muted);margin-left:4px" title="${hint}">ℹ</span>` : ''}
        </div>`;
    };

    // Exposure bar
    const expScore = a.risk_score || 0;
    const expColor = expScore > 60 ? '#ef4444' : expScore > 30 ? '#f97316' : expScore > 10 ? '#eab308' : '#22c55e';

    return `
      <!-- ── Exposure summary strip ── -->
      <div style="display:flex;align-items:center;gap:20px;padding:12px 16px;background:var(--bg-secondary);border-radius:8px;margin-bottom:16px;border:1px solid var(--border)">
        <div style="flex:1">
          <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">
            Exposure Score
            <span title="Weighted sum of open vulnerability severities: Critical×10 + High×7 + Medium×4 + Low×1, capped at 100. Indicates total vulnerability load on this asset." style="cursor:help;opacity:.6">ℹ</span>
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <div style="flex:1;height:6px;background:var(--bg-tertiary,#1e293b);border-radius:3px;max-width:160px">
              <div style="height:6px;border-radius:3px;background:${expColor};width:${Math.min(expScore,100)}%;transition:width .3s"></div>
            </div>
            <span style="font-size:18px;font-weight:700;color:${expColor}">${expScore.toFixed(0)}</span>
            <span style="font-size:10px;color:var(--text-muted)">/100</span>
          </div>
        </div>
        <div style="display:flex;gap:12px">
          ${['critical','high','medium','low'].map(s => `
            <div style="text-align:center">
              <div style="font-size:16px;font-weight:700;color:${{critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e'}[s]}">${sevCounts[s]}</div>
              <div style="font-size:9px;color:var(--text-muted);text-transform:uppercase">${s}</div>
            </div>`).join('')}
        </div>
        <div style="font-size:11px;color:var(--text-muted);text-align:right">
          <div>First: ${fmtDate(a.first_seen)}</div>
          <div>Last: ${fmtDate(a.last_seen)}</div>
          <div style="margin-top:2px"><span class="status-badge status-${a.status==='active'?'remediated':'accepted'}" style="font-size:10px">${a.status||'active'}</span></div>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">

        <!-- Identity -->
        <div class="detail-card">
          <div class="detail-card-title">Identity</div>
          <div class="detail-kv">
            <span class="k">Hostname</span><span class="v mono">${esc(a.hostname||'–')}</span>
            <span class="k">IP Address</span><span class="v mono">${esc(a.ip_address||'–')}</span>
            ${a.fqdn?`<span class="k">FQDN</span><span class="v mono" style="font-size:11px">${esc(a.fqdn)}</span>`:''}
            ${a.mac_address?`<span class="k">MAC</span><span class="v mono">${esc(a.mac_address)}</span>`:''}
            ${a.cloud_resource_id?`<span class="k">Cloud ID</span><span class="v mono" style="font-size:10px;word-break:break-all">${esc(a.cloud_resource_id)}</span>`:''}
            <span class="k">OS</span><span class="v">${esc(a.os||'–')}${a.os_version?' '+esc(a.os_version):''}</span>
            <span class="k">Type</span>
            <span class="v">
              <select id="identity_type-val"
                style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:5px;padding:3px 6px;font-size:12px;color:var(--text-primary);cursor:pointer;width:100%"
                onchange="AssetsPage._saveInline('identity_type','${id}',this)">
                <option value="host"          ${(a.identity_type||'host')==='host'          ?'selected':''}>Host</option>
                <option value="server"        ${(a.identity_type||'')==='server'            ?'selected':''}>Server</option>
                <option value="workstation"   ${(a.identity_type||'')==='workstation'       ?'selected':''}>Workstation</option>
                <option value="web"           ${(a.identity_type||'')==='web'               ?'selected':''}>Web / Domain</option>
                <option value="cloud_resource"${(a.identity_type||'')==='cloud_resource'    ?'selected':''}>Cloud</option>
                <option value="container"     ${(a.identity_type||'')==='container'         ?'selected':''}>Container</option>
                <option value="app"           ${(a.identity_type||'')==='app'               ?'selected':''}>Application</option>
                <option value="repo"          ${(a.identity_type||'')==='repo'              ?'selected':''}>Repository</option>
              </select>
            </span>
            <span class="k">Source</span><span class="v" style="display:flex;flex-wrap:wrap;gap:3px">${(a.source||'–').split(',').map(s=>s.trim()).filter(Boolean).map(s=>`<span class="source-tag">${esc(s)}</span>`).join('')||'–'}</span>
          </div>
        </div>

        <!-- Scoring Factors -->
        <div class="detail-card">
          <div class="detail-card-title" style="display:flex;align-items:center;gap:6px">
            Scoring Factors
            <span style="font-size:9px;color:var(--accent);background:var(--accent-glow);border:1px solid var(--accent)40;border-radius:3px;padding:1px 5px">affect priority score</span>
          </div>
          <div style="font-size:10px;color:var(--text-muted);margin-bottom:8px">These fields are used in the priority scoring formula. Set them accurately for correct risk scoring.</div>

          ${_factor('Environment','environment', a.environment||'',
            ['prod','uat','dev','test'], ['Production','UAT / Staging','Development','Test / Lab'],
            ENV_MUL, 'ENV multiplier applied to all vulnerability scores on this asset')}

          ${_factor('Reachability','reachability', a.reachability||'',
            ['internet-facing','partner','internal','isolated'],
            ['Internet-Facing','Partner / VPN','Internal','Isolated / Air-Gapped'],
            REACH_MUL, 'REACH multiplier — how accessible is this asset from outside')}

          ${_factor('Asset Tier','asset_tier', a.asset_tier||'',
            ['tier0','prod-critical','important','standard','low-value'],
            ['Tier 0 — Crown Jewel','Prod-Critical','Important','Standard','Low Value'],
            TIER_MUL, 'CRIT multiplier — business criticality of this asset')}

          ${_factor('Controls','compensating_controls', a.compensating_controls||'',
            ['none','one','two_plus','multilayer'],
            ['None','1 Verified Control','2+ Verified Controls','Multilayer Defense'],
            CTRL_MUL, 'CTRL multiplier — reduces score when compensating controls are in place')}

          <div style="display:flex;align-items:center;padding:7px 0">
            <span style="font-size:11px;color:var(--text-muted);width:110px;flex-shrink:0">EOL Status</span>
            <select id="eol_status-val" style="flex:1;font-size:12px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:5px;padding:3px 6px;color:var(--text-primary);cursor:pointer"
              onchange="AssetsPage._saveInline('eol_status','${id}',this)">
              <option value="">– not set –</option>
              <option value="active" ${(a.eol_status||'')==='active'?'selected':''}>Active</option>
              <option value="eol" ${(a.eol_status||'')==='eol'?'selected':''}>EOL</option>
              <option value="eos" ${(a.eol_status||'')==='eos'?'selected':''}>EOS</option>
            </select>
            <span style="font-size:11px;color:${a.eol_status&&a.eol_status!=='active'?'#ef4444':'var(--text-muted)'};font-family:monospace;margin-left:8px;min-width:36px">${a.eol_status&&a.eol_status!=='active'?'+0.5 bonus':''}</span>
            <span style="font-size:9px;color:var(--text-muted);margin-left:4px" title="Adds +0.5 to CVSS-based scores for EOL/EOS assets">ℹ</span>
          </div>
        </div>
      </div>

      <!-- Ownership + Labels in one row -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
        <div class="detail-card">
          <div class="detail-card-title">Ownership</div>
          <div class="detail-kv">
            <span class="k">Owner</span>
            <span class="v"><span class="inline-edit-val" id="owner-val"
              onclick="AssetsPage._inlineEdit('owner','${id}',this)" title="Click to edit">${a.owner?esc(a.owner):'<span class=\'unset\'>+ Add owner</span>'}</span></span>
            <span class="k">Sec. Owner</span>
            <span class="v"><span class="inline-edit-val" id="secondary_owner-val"
              onclick="AssetsPage._inlineEdit('secondary_owner','${id}',this)" title="Click to edit">${a.secondary_owner?esc(a.secondary_owner):'<span class=\'unset\'>+ Add</span>'}</span></span>
            <span class="k">Business Svc</span>
            <span class="v"><span class="inline-edit-val" id="business_service-val"
              onclick="AssetsPage._inlineEdit('business_service','${id}',this)" title="Click to edit">${a.business_service?esc(a.business_service):'<span class=\'unset\'>+ Add</span>'}</span></span>
          </div>
        </div>

        <div class="detail-card">
          <div class="detail-card-title" style="display:flex;justify-content:space-between">
            Labels
            <button class="btn btn-secondary btn-sm" style="font-size:10px;padding:2px 8px"
              onclick="AssetsPage._editLabels(${id},'${esc(a.asset_labels||'')}')">Edit</button>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;min-height:28px;align-items:flex-start">
            ${this._labelBadges(a.asset_labels) || '<span style="font-size:12px;color:var(--text-muted)">No labels assigned</span>'}
          </div>
          <div id="detail-systems-card" style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border)">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
              <span style="font-size:11px;font-weight:600;color:var(--text-secondary)">Systems</span>
              <button class="btn btn-secondary btn-sm" style="font-size:10px;padding:2px 6px"
                onclick="AssetsPage._assignToSystem(${id})">+ Assign</button>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:4px" id="detail-sys-pills">
              ${sysList.length
                ? sysList.map(s=>`<span class="sys-pill sys-pill-${s.environment}" style="display:inline-flex;align-items:center;gap:3px;font-size:11px">
                    ${esc(s.name)}<span style="font-size:9px;opacity:.6">${s.environment||''}</span>
                    <span style="cursor:pointer;opacity:.5;font-size:12px" onclick="AssetsPage._removeFromSystem(${id},${s.id},${s.link_id||0})" title="Remove">×</span>
                  </span>`).join('')
                : '<span style="font-size:11px;color:var(--text-muted)">Not assigned</span>'}
            </div>
          </div>
        </div>
      </div>

      <!-- Vulns -->
      <div class="detail-section">
        <div class="detail-section-title" style="display:flex;align-items:center;justify-content:space-between">
          <span>Vulnerabilities (${vulns.length})</span>
          <button class="btn btn-secondary btn-sm" style="font-size:10px"
            onclick="closeDetail();loadVulnsByAsset(${id},'${esc(a.hostname||a.ip_address||String(id))}')">View all →</button>
        </div>
        ${vulns.slice(0,25).map(v=>`
          <div onclick="VulnsPage.openDetail(${v.id},${id})"
            style="display:flex;align-items:center;gap:8px;padding:7px 6px;border-bottom:1px solid var(--border);cursor:pointer;border-radius:4px;margin:0 -6px;transition:background 120ms"
            onmouseover="this.style.background='var(--bg-secondary)'" onmouseout="this.style.background=''">
            ${sevBadge(v.severity)}
            <span style="font-size:12px;flex:1;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(v.title)}</span>
            ${v.priority_score!=null?`<span style="font-size:11px;font-weight:700;color:${v.priority_score>=9?'#ef4444':v.priority_score>=7?'#f97316':v.priority_score>=4?'#eab308':'#22c55e'}" title="Priority Score">${v.priority_score.toFixed(1)}</span>`:''}
            ${v.cisa_kev_date?`<span style="font-size:10px;background:#ef444420;color:#ef4444;border:1px solid #ef444440;border-radius:3px;padding:1px 5px">KEV</span>`:''}
            ${v.exploit_available?`<span style="font-size:10px;background:#f9731620;color:#f97316;border:1px solid #f9731640;border-radius:3px;padding:1px 5px">EXP</span>`:''}
            ${v.cvss_score!=null?`<span style="font-size:10px;color:var(--text-muted)" title="CVSS">${v.cvss_score.toFixed(1)}</span>`:''}
            <span class="status-badge status-${v.status}" style="font-size:10px">${v.status.replace('_',' ')}</span>
          </div>
        `).join('')}
        ${vulns.length>25?`<div style="font-size:12px;color:var(--text-muted);margin-top:8px;padding:8px 0">… and ${vulns.length-25} more findings</div>`:''}
      </div>
    `;
  },

  // ── Direct patch (table inline selects) ──────────────────

  async _patchAsset(assetId, field, value) {
    try {
      await API.patch(`/assets/${assetId}`, { [field]: value || null });
      const SCORING_FIELDS = ['environment','reachability','asset_tier','compensating_controls','eol_status','criticality','internet_exposure'];
      if (SCORING_FIELDS.includes(field)) {
        API.post('/scoring/recalculate').catch(() => {});
      }
    } catch(e) { toast(e.message, 'error'); }
  },

  // ── Inline editing ────────────────────────────────────────

  async _inlineEdit(field, assetId, el) {
    const current = this._detailAsset?.[field] || '';
    const placeholder = { owner:'e.g. john.doe@company.com', secondary_owner:'e.g. jane.smith@company.com', business_service:'e.g. Payment Platform' }[field] || '';
    el.outerHTML = `<input class="inline-edit-input" id="inline-input-${field}"
      value="${esc(current)}" placeholder="${placeholder}"
      onblur="AssetsPage._saveInline('${field}','${assetId}',this)"
      onkeydown="if(event.key==='Enter')this.blur();if(event.key==='Escape'){AssetsPage.openDetail(${assetId});}"
      autofocus>`;
    document.getElementById(`inline-input-${field}`)?.focus();
  },

  async _inlineEditSelect(field, assetId, el, options) {
    const current = this._detailAsset?.[field] || '';
    el.outerHTML = `<select class="inline-edit-select" id="inline-sel-${field}"
      onchange="AssetsPage._saveInline('${field}','${assetId}',this)"
      onblur="AssetsPage._saveInline('${field}','${assetId}',this)">
      <option value="">– clear –</option>
      ${options.map(o=>`<option value="${o}" ${o===current?'selected':''}>${o}</option>`).join('')}
    </select>`;
    document.getElementById(`inline-sel-${field}`)?.focus();
  },

  async _saveInline(field, assetId, el) {
    const value = el.value || null;
    try {
      const updated = await API.patch(`/assets/${assetId}`, { [field]: value });
      if (this._detailAsset) this._detailAsset[field] = updated[field];
      // Re-render just the meta badges
      const metaEl = document.getElementById('detail-meta');
      if (metaEl) metaEl.innerHTML = this._renderAssetMetaBadges(this._detailAsset);
      // Refresh the changed field display
      const valEl = document.getElementById(`${field}-val`);
      if (valEl) {
        if (field === 'criticality' || field === 'business_criticality') {
          valEl.innerHTML = value ? critBadge(value) : `<span class='unset'>+ Set</span>`;
        } else if (field === 'data_classification') {
          valEl.innerHTML = value ? `<span class="ameta-badge ameta-cls-${value}" style="font-size:10px">${value}</span>` : `<span class='unset'>+ Set</span>`;
        } else if (field === 'environment') {
          valEl.innerHTML = value ? this._envBadge(value) : `<span class='unset'>+ Set</span>`;
        } else if (field === 'internet_exposure') {
          valEl.innerHTML = value && value !== 'unknown' ? this._exposureBadge(value) : `<span class='unset'>+ Set</span>`;
        } else if (field === 'location_type') {
          valEl.innerHTML = value ? this._locationBadge(value) : `<span class='unset'>+ Set</span>`;
        } else if (field === 'compensating_controls') {
          valEl.innerHTML = value ? `<span style="font-size:11px;color:var(--low)">${{none:'None',one:'1 control',two_plus:'2+ controls',multilayer:'Multilayer'}[value]||value}</span>` : `<span class='unset'>+ Set</span>`;
        } else {
          valEl.textContent = value || '';
          if (!value) valEl.innerHTML = `<span class='unset'>+ Add ${field.replace('_',' ')}</span>`;
        }
      }
      // Re-score if the changed field affects priority scoring
      const SCORING_FIELDS = ['environment','reachability','asset_tier','compensating_controls','eol_status','internet_exposure','criticality'];
      if (SCORING_FIELDS.includes(field)) {
        API.post('/scoring/recalculate').catch(()=>{});
      }
      // Refresh list when identity_type changes (asset may move to a different tab/page)
      if (field === 'identity_type') {
        if (this.state.tab === 'hosts') this._loadHosts();
      }
    } catch(e) { toast(e.message, 'error'); }
  },

  _editLabels(assetId, current) {
    const all = ['crown_jewel','regulated','customer_facing','privileged_zone'];
    const active = new Set((current||'').split(',').map(l=>l.trim()).filter(Boolean));
    const modal = document.getElementById('asset-modal');
    if (!modal) return;
    modal.innerHTML = `
      <div class="asset-modal-header">
        <span class="asset-modal-title">Edit Labels</span>
        <button class="btn-icon" style="width:28px;height:28px;font-size:16px" onclick="AssetsPage._closeModal()">×</button>
      </div>
      <div class="asset-modal-body">
        ${all.map(l => `
          <label style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);cursor:pointer">
            <input type="checkbox" id="lbl-${l}" ${active.has(l)?'checked':''} style="width:15px;height:15px;accent-color:var(--accent)">
            <span style="font-size:13px;color:var(--text-primary)">${l.replace('_',' ').replace(/\b\w/g,c=>c.toUpperCase())}</span>
          </label>
        `).join('')}
      </div>
      <div class="asset-modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="AssetsPage._closeModal()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="AssetsPage._saveLabels(${assetId})">Save</button>
      </div>
    `;
    this._openModal();
  },

  async _saveLabels(assetId) {
    const all = ['crown_jewel','regulated','customer_facing','privileged_zone'];
    const selected = all.filter(l => document.getElementById(`lbl-${l}`)?.checked);
    const value = selected.join(',') || null;
    try {
      await API.patch(`/assets/${assetId}`, { asset_labels: value });
      if (this._detailAsset) this._detailAsset.asset_labels = value;
      this._closeModal();
      // Refresh labels in detail
      const labelsDiv = document.querySelector('.detail-card:has(.detail-card-title)');
      toast('Labels updated', 'success');
      this.openDetail(assetId);
    } catch(e) { toast(e.message, 'error'); }
  },

  async _assignToSystem(assetId) {
    const systems = await API.get('/app-systems/');
    const modal = document.getElementById('asset-modal');
    if (!modal) return;
    modal.innerHTML = `
      <div class="asset-modal-header">
        <span class="asset-modal-title">Assign to System</span>
        <button class="btn-icon" style="width:28px;height:28px;font-size:16px" onclick="AssetsPage._closeModal()">×</button>
      </div>
      <div class="asset-modal-body" style="max-height:320px;overflow-y:auto">
        ${systems.length === 0
          ? `<p style="color:var(--text-muted);font-size:13px">No systems defined yet. Create one in the Applications/Systems tab.</p>`
          : systems.map(s => `
            <label style="display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--border);cursor:pointer">
              <input type="radio" name="assign-sys" value="${s.id}" style="accent-color:var(--accent)">
              <span style="flex:1;font-size:13px;color:var(--text-primary)">${esc(s.name)}</span>
              <span style="font-size:11px;color:var(--text-muted)">${s.unique_asset_count||0} assets</span>
            </label>`).join('')}
      </div>
      <div style="padding:12px 16px 4px;display:flex;align-items:center;gap:10px">
        <span style="font-size:12px;color:var(--text-muted);white-space:nowrap">Environment:</span>
        <select class="input" id="assign-env" style="flex:1;font-size:12px">
          <option value="prod">Production</option>
          <option value="uat">UAT / Staging</option>
          <option value="dev">Development</option>
          <option value="test">Test</option>
        </select>
      </div>
      <div class="asset-modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="AssetsPage._closeModal()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="AssetsPage._doAssign(${assetId})">Assign</button>
      </div>
    `;
    this._openModal();
  },

  async _doAssign(assetId) {
    const sysRadio = document.querySelector('input[name="assign-sys"]:checked');
    if (!sysRadio) { toast('Select a system first', 'error'); return; }
    const systemId = sysRadio.value;
    const env = document.getElementById('assign-env')?.value || 'prod';
    try {
      const link = await API.post(`/app-systems/${systemId}/assets`, { asset_id: assetId, environment: env });
      this._closeModal();
      // Refresh asset index entry
      const idx = this.state.assetIndex;
      if (!idx[String(assetId)]) idx[String(assetId)] = [];
      const sysName = document.querySelector(`input[name="assign-sys"][value="${systemId}"]`)?.closest('label')?.querySelector('span')?.textContent || `System #${systemId}`;
      idx[String(assetId)].push({ id: parseInt(systemId), name: sysName, environment: env, link_id: link.id });
      // Refresh systems pills in open detail
      const sysList = idx[String(assetId)];
      const pillsEl = document.getElementById('detail-sys-pills');
      if (pillsEl) {
        pillsEl.innerHTML = sysList.map(s => `
          <span class="sys-pill sys-pill-${s.environment}" style="display:inline-flex;align-items:center;gap:4px">
            ${esc(s.name)}
            <span style="font-size:9px;opacity:.6;margin-left:2px">${s.environment||''}</span>
            <span style="cursor:pointer;opacity:.5;font-size:13px;line-height:1;margin-left:1px"
              onclick="AssetsPage._removeFromSystem(${assetId},${s.id},${s.link_id||0})"
              title="Remove from system">×</span>
          </span>`).join('');
      }
      toast('Assigned successfully', 'success');
    } catch(e) { toast(e.message, 'error'); }
  },

  async _removeFromSystem(assetId, systemId, linkId) {
    if (!linkId) { toast('Cannot remove — link ID unknown', 'error'); return; }
    try {
      await API.delete(`/app-systems/${systemId}/assets/${linkId}`);
      const idx = this.state.assetIndex;
      if (idx[String(assetId)]) {
        idx[String(assetId)] = idx[String(assetId)].filter(s => s.link_id !== linkId);
      }
      const sysList = idx[String(assetId)] || [];
      const pillsEl = document.getElementById('detail-sys-pills');
      if (pillsEl) {
        pillsEl.innerHTML = sysList.length
          ? sysList.map(s => `
              <span class="sys-pill sys-pill-${s.environment}" style="display:inline-flex;align-items:center;gap:4px">
                ${esc(s.name)}
                <span style="font-size:9px;opacity:.6;margin-left:2px">${s.environment||''}</span>
                <span style="cursor:pointer;opacity:.5;font-size:13px;line-height:1;margin-left:1px"
                  onclick="AssetsPage._removeFromSystem(${assetId},${s.id},${s.link_id||0})"
                  title="Remove from system">×</span>
              </span>`).join('')
          : '<span style="font-size:12px;color:var(--text-muted)">Not assigned to any system</span>';
      }
      toast('Removed from system', 'success');
    } catch(e) { toast(e.message, 'error'); }
  },

  // ═══════════════════════════════════════════════════════
  // DRAG & DROP
  // ═══════════════════════════════════════════════════════

  _onDragStart(evt, id, name) {
    this.state.dragging = { id, name };
    this._dragHappened = true;
    evt.dataTransfer.effectAllowed = 'move';
    evt.dataTransfer.setData('text/plain', String(id));
    evt.currentTarget.style.opacity = '0.5';
    if (this.state.tab === 'hosts') this._showDragPalette();
  },

  _showDragPalette() {
    let fp = document.getElementById('type-palette-fixed');
    if (!fp) {
      fp = document.createElement('div');
      fp.id = 'type-palette-fixed';
      fp.className = 'type-palette-fixed';
      fp.innerHTML = `
        <span class="type-palette-label">Drop here to reclassify:</span>
        ${this._TYPE_OPTS.map(b => `
          <div class="type-bucket" data-type="${b.t}" style="--bucket-color:${b.c}"
            ondragover="AssetsPage._typeBucketOver(this,event)"
            ondragleave="AssetsPage._typeBucketLeave(this)"
            ondrop="AssetsPage._typeBucketDrop(this,'${b.t}',event)">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${b.c}" stroke-width="2">${b.icon}</svg>
            ${b.label}
          </div>`).join('')}
      `;
      document.body.appendChild(fp);
    }
    fp.style.display = 'flex';
  },

  _onDragEnd(evt) {
    if (evt?.currentTarget) evt.currentTarget.style.opacity = '';
    this.state.dragging = null;
    clearTimeout(this.state.dragTabTimer);
    document.querySelectorAll('.sys-card').forEach(c => c.classList.remove('drag-over'));
    document.querySelectorAll('.asset-tab').forEach(t => t.classList.remove('drag-highlight'));
    document.querySelectorAll('.type-bucket').forEach(b => b.classList.remove('drag-over'));
    const fp = document.getElementById('type-palette-fixed');
    if (fp) fp.style.display = 'none';
    setTimeout(() => { this._dragHappened = false; }, 150);
  },

  _typeBucketOver(el, evt) {
    evt.preventDefault();
    evt.dataTransfer.dropEffect = 'move';
    el.classList.add('drag-over');
  },

  _typeBucketLeave(el) {
    el.classList.remove('drag-over');
  },

  async _typeBucketDrop(el, newType, evt) {
    evt.preventDefault();
    el.classList.remove('drag-over');
    const assetId = this.state.dragging?.id;
    if (!assetId) return;
    const name = this.state.dragging?.name || `Asset #${assetId}`;
    await this._setAssetType(assetId, name, newType);
  },

  // ── Type picker (click on identity badge) ─────────────────
  _TYPE_OPTS: [
    { t:'host',        c:'#3b82f6', label:'Host',        icon:'<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>' },
    { t:'server',      c:'#22c55e', label:'Server',      icon:'<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>' },
    { t:'workstation', c:'#06b6d4', label:'Workstation', icon:'<rect x="2" y="3" width="20" height="13" rx="2"/><polyline points="8 21 12 17 16 21"/>' },
    { t:'web',         c:'#10b981', label:'Web / Domain',icon:'<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>' },
    { t:'cloud_resource', c:'#8b5cf6', label:'Cloud',    icon:'<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>' },
  ],

  _showTypePicker(evt, assetId, currentType) {
    // Remove any existing picker
    document.getElementById('type-picker-popup')?.remove();

    const rect = evt.currentTarget.getBoundingClientRect();
    const popup = document.createElement('div');
    popup.id = 'type-picker-popup';
    popup.className = 'type-picker-popup';
    popup.style.cssText = `position:fixed;top:${rect.bottom+4}px;left:${rect.left}px;z-index:9999`;

    popup.innerHTML = `
      <div class="type-picker-header">Change type</div>
      ${this._TYPE_OPTS.map(o => `
        <div class="type-picker-item ${o.t === currentType ? 'active' : ''}"
          onclick="AssetsPage._setAssetType(${assetId},'','${o.t}')">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${o.c}" stroke-width="2">${o.icon}</svg>
          <span style="color:${o.c}">${o.label}</span>
          ${o.t === currentType ? '<span class="type-picker-check">✓</span>' : ''}
        </div>`).join('')}
    `;

    document.body.appendChild(popup);

    // Close on outside click
    const close = e => {
      if (!popup.contains(e.target)) { popup.remove(); document.removeEventListener('click', close); }
    };
    setTimeout(() => document.addEventListener('click', close), 0);
  },

  async _setAssetType(assetId, name, newType) {
    document.getElementById('type-picker-popup')?.remove();
    try {
      await API.patch(`/assets/${assetId}`, { identity_type: newType });
      const label = this._TYPE_OPTS.find(o => o.t === newType)?.label || newType;
      toast(`Type → ${label}`, 'success');
      this._loadHosts();
    } catch(e) { toast(e.message, 'error'); }
  },

  _tabDragOver(tab, el, evt) {
    evt.preventDefault();                      // ← required for drop to fire
    evt.dataTransfer.dropEffect = 'link';
    if (!this.state.dragging) return;
    el.classList.add('drag-highlight');
    if (this.state.tab !== tab) {
      clearTimeout(this.state.dragTabTimer);
      this.state.dragTabTimer = setTimeout(() => {
        if (this.state.dragging) this.switchTab(tab);
      }, 600);
    }
  },

  _tabDragLeave(el) {
    el.classList.remove('drag-highlight');
    clearTimeout(this.state.dragTabTimer);
  },

  _sysCardDragOver(evt, el) {
    evt.preventDefault();
    evt.dataTransfer.dropEffect = 'link';
    if (!this.state.dragging) return;
    el.classList.add('drag-over');
  },

  _sysCardDragLeave(el) {
    el.classList.remove('drag-over');
  },

  _sysCardDrop(evt, systemId) {
    evt.preventDefault();
    evt.currentTarget.classList.remove('drag-over');
    if (!this.state.dragging) return;
    this._showDropConfirm(this.state.dragging, systemId);
  },

  // ═══════════════════════════════════════════════════════
  // APPS TAB  – enterprise cards
  // ═══════════════════════════════════════════════════════

  async _renderApps(el) {
    el.innerHTML = `
      <div class="filter-bar">
        <span style="font-size:13px;font-weight:600;color:var(--text-primary)">Application Systems</span>
        <span style="font-size:12px;color:var(--text-muted);margin-left:6px" id="sys-count">–</span>
        <button class="btn btn-primary btn-sm" style="margin-left:auto" onclick="AssetsPage._showCreateModal()">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          New System
        </button>
      </div>
      <div id="sys-grid" class="sys-grid">
        <div class="loader"><div class="spinner"></div></div>
      </div>
    `;
    return this._loadApps();
  },

  async _loadApps() {
    const systems = await API.get('/app-systems/');
    const countEl = document.getElementById('sys-count');
    if (countEl) countEl.textContent = `${systems.length} system${systems.length!==1?'s':''}`;
    const grid = document.getElementById('sys-grid');
    if (!grid) return;

    if (!systems.length) {
      grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="2" y="3" width="6" height="6" rx="1"/><rect x="9" y="3" width="13" height="6" rx="1"/>
          <rect x="2" y="12" width="6" height="6" rx="1"/><rect x="9" y="12" width="13" height="6" rx="1"/>
        </svg>
        <h3>No systems yet</h3>
        <p>Click <strong>New System</strong> to create your first application system.<br>
           You can then assign assets from the <strong>List</strong> tab via drag & drop or the + button.</p>
      </div>`;
      return;
    }
    grid.innerHTML = systems.map(s => this._sysCardHTML(s)).join('');
  },

  _sysCardHTML(s) {
    const vc = s.vuln_counts || { critical:0, high:0, medium:0, low:0 };
    const riskClass = s.risk_score > 60 ? 'critical' : s.risk_score > 30 ? 'high' : '';
    const envOrder = ['prod','uat','dev','test'];
    const envPills = envOrder
      .filter(e => s.env_counts[e] > 0)
      .map(e => `<span class="env-pill env-${e}">${e.toUpperCase()} <strong>${s.env_counts[e]}</strong></span>`)
      .join('');

    const vulnRow = ['critical','high','medium','low']
      .filter(sv => vc[sv] > 0)
      .map(sv => `<span class="sev-badge sev-${sv}" style="font-size:10px">${vc[sv]}</span>`)
      .join('');

    return `
      <div class="sys-card"
           onclick="AssetsPage._openSysDetail(${s.id})"
           ondragover="AssetsPage._sysCardDragOver(event,this)"
           ondragleave="AssetsPage._sysCardDragLeave(this)"
           ondrop="AssetsPage._sysCardDrop(event,${s.id})">

        <div class="sys-card-header">
          <div class="sys-card-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="2" y="3" width="6" height="6" rx="1"/><rect x="9" y="3" width="13" height="6" rx="1"/>
              <rect x="2" y="12" width="6" height="6" rx="1"/><rect x="9" y="12" width="13" height="6" rx="1"/>
            </svg>
          </div>
          <div style="flex:1;min-width:0">
            <div class="sys-card-name truncate">${esc(s.name)}</div>
            ${s.description?`<div class="sys-card-desc truncate">${esc(s.description)}</div>`:''}
          </div>
          <button class="sys-card-delete" title="Delete system"
            onclick="event.stopPropagation();AssetsPage._deleteSystem(${s.id})">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
              <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
            </svg>
          </button>
        </div>

        <div class="sys-card-risk-row">
          <div class="risk-bar-wrap" style="flex:1">
            <div class="risk-bar">
              <div class="risk-bar-fill ${riskClass}" style="width:${Math.min(s.risk_score,100)}%"></div>
            </div>
            <span class="risk-score-num">${s.risk_score.toFixed(0)}</span>
          </div>
          <span class="sys-card-asset-badge">${s.unique_asset_count} asset${s.unique_asset_count!==1?'s':''}</span>
        </div>

        <div class="sys-card-bottom">
          <div class="sys-card-vulns">
            ${vulnRow || `<span style="font-size:11px;color:var(--low)">✓ No open vulns</span>`}
          </div>
          <div class="sys-card-envs">
            ${envPills || `<span style="font-size:11px;color:var(--text-muted)">No assets</span>`}
          </div>
        </div>

        <div class="sys-card-drop-hint">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
          Drop to assign
        </div>
      </div>
    `;
  },

  async _openSysDetail(id) {
    const data = await API.get(`/app-systems/${id}`);
    this.state.currentSystem = data;
    this.state.sysEnv = 'all';
    this._renderSysPanel(data);
  },

  _renderSysPanel(data) {
    const envOrder = ['all','prod','uat','dev','test'];
    const envCounts = { all: data.asset_count, ...data.env_counts };

    const tabs = envOrder.map(e => {
      const cnt = envCounts[e] || 0;
      return `<button class="sys-env-tab ${this.state.sysEnv===e?'active':''}" data-env="${e}"
        onclick="AssetsPage._switchSysEnv('${e}')">${e==='all'?'All':e.toUpperCase()}
        <span class="sys-env-tab-count">${cnt}</span></button>`;
    }).join('');

    openDetail(
      esc(data.name),
      data.description
        ? `<span style="font-size:12px;color:var(--text-muted)">${esc(data.description)}</span>`
        : `<span class="source-tag">Application System</span>`,
      `<div style="display:flex;gap:0;margin-bottom:16px;border-bottom:1px solid var(--border)">${tabs}</div>
       <div id="sys-detail-assets">${this._sysAssetsHTML(data)}</div>`,
      `<button class="btn btn-primary btn-sm" onclick="AssetsPage._showAddAssetModal(${data.id})">
         <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
           <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
         </svg>Add Asset
       </button>
       <button class="btn btn-danger btn-sm" onclick="AssetsPage._deleteSystem(${data.id})">Delete System</button>
       <button class="btn btn-secondary btn-sm" onclick="closeDetail()">Close</button>`
    );
  },

  _sysAssetsHTML(data) {
    const env = this.state.sysEnv;
    const assets = env === 'all'
      ? Object.values(data.assets_by_env).flat()
      : (data.assets_by_env[env] || []);

    if (!assets.length) {
      return `<div style="padding:32px 0;color:var(--text-muted);font-size:13px;text-align:center">
        ${env==='all'?'No assets assigned to this system yet.':'No assets in this environment.'}</div>`;
    }
    return assets.map(a => `
      <div style="display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--border)">
        ${critBadge(a.criticality)}
        <div style="flex:1;min-width:0;cursor:pointer" onclick="closeDetail();AssetsPage.openDetail(${a.id})">
          <div style="font-size:13px;color:var(--text-primary);font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
            ${esc(a.hostname||a.ip_address||`Asset #${a.id}`)}
          </div>
          <div style="font-size:11px;color:var(--text-muted)">${a.asset_type} · ${a.os||'–'}</div>
        </div>
        <span class="env-pill env-${a.environment}">${a.environment.toUpperCase()}</span>
        <div class="risk-bar-wrap" style="width:80px">
          <div class="risk-bar">
            <div class="risk-bar-fill ${a.risk_score>60?'critical':a.risk_score>30?'high':''}"
                 style="width:${Math.min(a.risk_score,100)}%"></div>
          </div>
          <span class="risk-score-num">${a.risk_score.toFixed(0)}</span>
        </div>
        <span style="font-size:11px;color:var(--text-secondary);min-width:46px;text-align:right">${a.vuln_count}v</span>
        <button class="btn btn-danger btn-xs" title="Remove from system"
          onclick="event.stopPropagation();AssetsPage._removeAsset(${data.id},${a.link_id})">×</button>
      </div>
    `).join('');
  },

  _switchSysEnv(env) {
    this.state.sysEnv = env;
    document.querySelectorAll('.sys-env-tab').forEach(t =>
      t.classList.toggle('active', t.dataset.env === env)
    );
    const el = document.getElementById('sys-detail-assets');
    if (el && this.state.currentSystem) el.innerHTML = this._sysAssetsHTML(this.state.currentSystem);
  },

  // ═══════════════════════════════════════════════════════
  // MODALS
  // ═══════════════════════════════════════════════════════

  _openModal() {
    document.getElementById('asset-modal-overlay')?.classList.add('open');
    document.getElementById('asset-modal')?.classList.add('open');
  },
  _closeModal() {
    document.getElementById('asset-modal-overlay')?.classList.remove('open');
    document.getElementById('asset-modal')?.classList.remove('open');
  },

  _showCreateModal() {
    const modal = document.getElementById('asset-modal');
    if (!modal) return;
    modal.innerHTML = `
      <div class="asset-modal-header">
        <span class="asset-modal-title">New Application System</span>
        <button class="btn-icon" style="width:28px;height:28px;font-size:16px" onclick="AssetsPage._closeModal()">×</button>
      </div>
      <div class="asset-modal-body">
        <label class="form-label">System Name *</label>
        <input class="input" id="sys-name-input" placeholder="e.g. E-Commerce Platform" style="margin-bottom:12px">
        <label class="form-label">Description</label>
        <input class="input" id="sys-desc-input" placeholder="Optional description">
      </div>
      <div class="asset-modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="AssetsPage._closeModal()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="AssetsPage._createSystem()">Create System</button>
      </div>
    `;
    this._openModal();
    setTimeout(() => document.getElementById('sys-name-input')?.focus(), 50);
  },

  async _createSystem() {
    const name = document.getElementById('sys-name-input')?.value.trim();
    const desc = document.getElementById('sys-desc-input')?.value.trim();
    if (!name) { toast('System name is required', 'error'); return; }
    try {
      await API.post('/app-systems/', { name, description: desc || null });
      this._closeModal();
      toast(`System "${name}" created`, 'success');
      this._loadApps();
    } catch(e) { toast(e.message, 'error'); }
  },

  async _deleteSystem(id) {
    if (!confirm('Delete this system? Assets will not be deleted, only the grouping.')) return;
    try {
      await API.delete(`/app-systems/${id}`);
      closeDetail();
      toast('System deleted', 'success');
      this._loadApps();
      // refresh asset-index if on list tab
      if (this.state.tab === 'list') {
        API.get('/app-systems/asset-index').then(idx => { this.state.assetIndex = idx; this.load(); });
      }
    } catch(e) { toast(e.message, 'error'); }
  },

  async _showAddAssetModal(systemId) {
    const modal = document.getElementById('asset-modal');
    if (!modal) return;
    modal.innerHTML = `
      <div class="asset-modal-header">
        <span class="asset-modal-title">Add Asset to System</span>
        <button class="btn-icon" style="width:28px;height:28px;font-size:16px" onclick="AssetsPage._closeModal()">×</button>
      </div>
      <div class="asset-modal-body">
        <label class="form-label">Search Asset</label>
        <input class="input" id="add-asset-search" placeholder="Type hostname or IP…" style="margin-bottom:8px"
          oninput="AssetsPage._filterAddAssetList(this.value)">
        <div id="add-asset-list" style="max-height:200px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px">
          <div class="loader" style="padding:20px"><div class="spinner"></div></div>
        </div>
        <label class="form-label">Environment</label>
        <select class="input" id="add-env-select">
          <option value="prod">Production</option>
          <option value="uat">UAT</option>
          <option value="dev">Development</option>
          <option value="test">Test</option>
        </select>
      </div>
      <div class="asset-modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="AssetsPage._closeModal()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="AssetsPage._addAsset(${systemId})">Add Asset</button>
      </div>
    `;
    this._openModal();
    this._addAssetAllItems = [];
    try {
      const data = await API.get('/assets/', { per_page: 200 });
      this._addAssetAllItems = data.items;
      this._renderAddAssetList(data.items);
    } catch(e) { toast(e.message, 'error'); this._closeModal(); }
  },

  _renderAddAssetList(items) {
    const el = document.getElementById('add-asset-list');
    if (!el) return;
    if (!items.length) { el.innerHTML = `<div style="padding:12px;color:var(--text-muted);font-size:12px;text-align:center">No assets found</div>`; return; }
    el.innerHTML = items.map(a => `
      <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;cursor:pointer;border-bottom:1px solid var(--border);font-size:12px"
        onmouseover="this.style.background='var(--bg-secondary)'" onmouseout="this.style.background=''">
        <input type="radio" name="add-asset-radio" value="${a.id}" style="accent-color:var(--accent)">
        <div>
          <div style="color:var(--text-primary);font-weight:500">${esc(a.hostname||a.ip_address||`Asset #${a.id}`)}</div>
          <div style="color:var(--text-muted);font-size:11px">${a.asset_type} · ${a.os||'–'} · ${critBadge(a.criticality)}</div>
        </div>
      </label>
    `).join('');
  },

  _filterAddAssetList(q) {
    const filtered = q
      ? this._addAssetAllItems.filter(a =>
          (a.hostname||'').toLowerCase().includes(q.toLowerCase()) ||
          (a.ip_address||'').toLowerCase().includes(q.toLowerCase())
        )
      : this._addAssetAllItems;
    this._renderAddAssetList(filtered);
  },

  async _addAsset(systemId) {
    const radio = document.querySelector('input[name="add-asset-radio"]:checked');
    if (!radio) { toast('Select an asset first', 'error'); return; }
    const assetId = parseInt(radio.value);
    const env = document.getElementById('add-env-select')?.value || 'prod';
    try {
      await API.post(`/app-systems/${systemId}/assets`, { asset_id: assetId, environment: env });
      this._closeModal();
      toast('Asset added', 'success');
      const updated = await API.get(`/app-systems/${systemId}`);
      this.state.currentSystem = updated;
      this._renderSysPanel(updated);
      this._loadApps();
      API.get('/app-systems/asset-index').then(idx => { this.state.assetIndex = idx; });
    } catch(e) { toast(e.message, 'error'); }
  },

  async _removeAsset(systemId, linkId) {
    try {
      await API.delete(`/app-systems/${systemId}/assets/${linkId}`);
      toast('Asset removed', 'success');
      const updated = await API.get(`/app-systems/${systemId}`);
      this.state.currentSystem = updated;
      // Update env tab counts
      const envCounts = { all: updated.asset_count, ...updated.env_counts };
      document.querySelectorAll('.sys-env-tab').forEach(t => {
        const c = t.querySelector('.sys-env-tab-count');
        if (c) c.textContent = envCounts[t.dataset.env] || 0;
      });
      const el = document.getElementById('sys-detail-assets');
      if (el) el.innerHTML = this._sysAssetsHTML(updated);
      this._loadApps();
      API.get('/app-systems/asset-index').then(idx => { this.state.assetIndex = idx; });
    } catch(e) { toast(e.message, 'error'); }
  },

  async _showQuickAssign(assetId, assetName) {
    const modal = document.getElementById('asset-modal');
    if (!modal) return;
    let systems = this.state.systems;
    if (!systems.length) systems = await API.get('/app-systems/').catch(() => []);

    if (!systems.length) {
      toast('No systems yet — create one first in Applications / Systems tab', 'info'); return;
    }
    modal.innerHTML = `
      <div class="asset-modal-header">
        <span class="asset-modal-title">Assign to System</span>
        <button class="btn-icon" style="width:28px;height:28px;font-size:16px" onclick="AssetsPage._closeModal()">×</button>
      </div>
      <div class="asset-modal-body">
        <p style="font-size:12px;color:var(--text-secondary);margin-bottom:12px">
          Assigning <strong style="color:var(--text-primary)">${esc(assetName)}</strong>
        </p>
        <label class="form-label">System</label>
        <select class="input" id="quick-sys-select" style="margin-bottom:12px">
          ${systems.map(s=>`<option value="${s.id}">${esc(s.name)}</option>`).join('')}
        </select>
        <label class="form-label">Environment</label>
        <select class="input" id="quick-env-select">
          <option value="prod">Production</option>
          <option value="uat">UAT</option>
          <option value="dev">Development</option>
          <option value="test">Test</option>
        </select>
      </div>
      <div class="asset-modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="AssetsPage._closeModal()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="AssetsPage._confirmQuickAssign(${assetId})">Assign</button>
      </div>
    `;
    this._openModal();
  },

  async _confirmQuickAssign(assetId) {
    const systemId = parseInt(document.getElementById('quick-sys-select')?.value);
    const env = document.getElementById('quick-env-select')?.value || 'prod';
    try {
      await API.post(`/app-systems/${systemId}/assets`, { asset_id: assetId, environment: env });
      this._closeModal();
      toast('Asset assigned', 'success');
      const [idx, systems] = await Promise.all([
        API.get('/app-systems/asset-index').catch(() => ({})),
        API.get('/app-systems/').catch(() => []),
      ]);
      this.state.assetIndex = idx;
      this.state.systems = systems;
      if (this.state.tab === 'list') this.load();
    } catch(e) { toast(e.message, 'error'); }
  },

  _showDropConfirm(asset, systemId) {
    const modal = document.getElementById('asset-modal');
    if (!modal) return;
    const sysName = this.state.systems.find(s => s.id === systemId)?.name || `System #${systemId}`;
    modal.innerHTML = `
      <div class="asset-modal-header">
        <span class="asset-modal-title">Assign to System</span>
        <button class="btn-icon" style="width:28px;height:28px;font-size:16px" onclick="AssetsPage._closeModal()">×</button>
      </div>
      <div class="asset-modal-body">
        <p style="font-size:13px;color:var(--text-secondary);margin-bottom:14px">
          Add <strong style="color:var(--text-primary)">${esc(asset.name||`Asset #${asset.id}`)}</strong>
          to <strong style="color:var(--text-primary)">${esc(sysName)}</strong>?
        </p>
        <label class="form-label">Environment</label>
        <select class="input" id="drop-env-select">
          <option value="prod">Production</option>
          <option value="uat">UAT</option>
          <option value="dev">Development</option>
          <option value="test">Test</option>
        </select>
      </div>
      <div class="asset-modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="AssetsPage._closeModal()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="AssetsPage._confirmDropAdd(${asset.id},${systemId})">Assign</button>
      </div>
    `;
    this._openModal();
  },

  async _confirmDropAdd(assetId, systemId) {
    const env = document.getElementById('drop-env-select')?.value || 'prod';
    try {
      await API.post(`/app-systems/${systemId}/assets`, { asset_id: assetId, environment: env });
      this._closeModal();
      toast('Asset assigned', 'success');
      const [idx, systems] = await Promise.all([
        API.get('/app-systems/asset-index').catch(() => ({})),
        API.get('/app-systems/').catch(() => []),
      ]);
      this.state.assetIndex = idx;
      this.state.systems = systems;
      if (this.state.tab === 'apps') this._loadApps();
      else if (this.state.tab === 'list') this.load();
    } catch(e) { toast(e.message, 'error'); }
  },



  // ═══════════════════════════════════════════════════════
  // IMPORT ASSETS
  // ═══════════════════════════════════════════════════════

  _showImportModal() {
    const modal = document.getElementById('asset-modal');
    if (!modal) return;
    modal.innerHTML = `
      <div class="asset-modal-header">
        <span class="asset-modal-title">Import Assets</span>
        <button class="btn-icon" style="width:28px;height:28px;font-size:16px" onclick="AssetsPage._closeModal()">×</button>
      </div>
      <div class="asset-modal-body" style="max-height:70vh;overflow-y:auto">

        <div class="import-dropzone" id="import-dropzone"
          ondragover="event.preventDefault();this.classList.add('drag-over')"
          ondragleave="this.classList.remove('drag-over')"
          ondrop="AssetsPage._onImportDrop(event)">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/>
            <line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
          <div style="font-size:13px;color:var(--text-secondary);margin-top:8px">Drop CSV or JSON file here</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px">or</div>
          <label class="btn btn-secondary btn-sm" style="margin-top:8px;cursor:pointer">
            Browse File
            <input type="file" id="import-file-input" accept=".csv,.json" style="display:none"
              onchange="AssetsPage._onImportFileSelect(this)">
          </label>
          <div id="import-filename" style="font-size:11px;color:var(--accent);margin-top:6px"></div>
        </div>

        <div style="margin-top:16px">
          <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">
            Required fields (at least one)
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
            <span class="import-field required">hostname</span>
            <span class="import-field required">ip_address</span>
          </div>
          <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">
            Optional fields
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <span class="import-field">os</span>
            <span class="import-field">os_version</span>
            <span class="import-field">mac_address</span>
            <span class="import-field">criticality</span>
            <span class="import-field">asset_type</span>
            <span class="import-field">tags</span>
          </div>
        </div>

        <div style="margin-top:16px;border:1px solid var(--border);border-radius:8px;overflow:hidden">
          <div style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:8px 12px;font-size:11px;color:var(--text-muted);display:flex;justify-content:space-between;align-items:center">
            <span>Example CSV</span>
            <button class="btn btn-secondary btn-sm" style="padding:2px 8px;font-size:11px"
              onclick="AssetsPage._downloadTemplate()">Download Template</button>
          </div>
          <pre style="font-size:11px;color:var(--text-secondary);padding:12px;margin:0;overflow-x:auto;background:var(--bg-main)">hostname,ip_address,os,os_version,mac_address,criticality,asset_type,tags
web-prod-01,10.0.1.10,Linux,Ubuntu 22.04,aa:bb:cc:dd:ee:01,high,server,web;prod
db-prod-01,10.0.1.20,Linux,RHEL 8.6,aa:bb:cc:dd:ee:02,critical,server,db;prod
win-ws-01,192.168.1.50,Windows,10 22H2,,medium,workstation,
,192.168.1.1,,,, low,network,router</pre>
        </div>

        <div style="margin-top:12px;border:1px solid var(--border);border-radius:8px;overflow:hidden">
          <div style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:8px 12px;font-size:11px;color:var(--text-muted)">
            Example JSON
          </div>
          <pre style="font-size:11px;color:var(--text-secondary);padding:12px;margin:0;overflow-x:auto;background:var(--bg-main)">[
  { "hostname": "web-prod-01", "ip_address": "10.0.1.10", "criticality": "high" },
  { "hostname": "db-prod-01",  "ip_address": "10.0.1.20", "criticality": "critical", "os": "RHEL 8.6" },
  { "ip_address": "192.168.1.1", "asset_type": "network" }
]</pre>
        </div>

        <div style="margin-top:12px;padding:10px 12px;border-radius:6px;background:var(--accent-glow);border:1px solid var(--border);font-size:12px;color:var(--text-secondary)">
          <strong style="color:var(--text-primary)">Deduplication:</strong>
          Existing assets are matched by <strong>hostname</strong> first, then <strong>IP address</strong>.
          Matches are updated (not duplicated). New entries are created.
        </div>

        <div id="import-result" style="margin-top:12px"></div>
      </div>
      <div class="asset-modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="AssetsPage._closeModal()">Close</button>
        <button class="btn btn-primary btn-sm" id="import-submit-btn" onclick="AssetsPage._submitImport()" disabled>
          Import
        </button>
      </div>
    `;
    this._importFile = null;
    this._openModal();
  },

  _onImportDrop(evt) {
    evt.preventDefault();
    document.getElementById('import-dropzone')?.classList.remove('drag-over');
    const file = evt.dataTransfer?.files?.[0];
    if (file) this._setImportFile(file);
  },

  _onImportFileSelect(input) {
    const file = input.files?.[0];
    if (file) this._setImportFile(file);
  },

  _setImportFile(file) {
    this._importFile = file;
    const nameEl = document.getElementById('import-filename');
    if (nameEl) nameEl.textContent = file.name;
    const btn = document.getElementById('import-submit-btn');
    if (btn) btn.disabled = false;
    document.getElementById('import-result').innerHTML = '';
  },

  _downloadTemplate() {
    const csv = 'hostname,ip_address,os,os_version,mac_address,criticality,asset_type,tags\nweb-prod-01,10.0.1.10,Linux,Ubuntu 22.04,aa:bb:cc:dd:ee:01,high,server,web\ndb-prod-01,10.0.1.20,Linux,RHEL 8.6,,critical,server,db\n';
    const a = document.createElement('a');
    a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
    a.download = 'assets_template.csv';
    a.click();
  },

  async _submitImport() {
    if (!this._importFile) return;
    const btn = document.getElementById('import-submit-btn');
    const resultEl = document.getElementById('import-result');
    if (btn) { btn.disabled = true; btn.textContent = 'Importing…'; }

    try {
      const form = new FormData();
      form.append('file', this._importFile);
      const res = await fetch('/api/assets/import', { method: 'POST', body: form });
      const data = await res.json();

      if (!res.ok) throw new Error(data.detail || 'Import failed');

      const hasErrors = data.errors?.length > 0;
      resultEl.innerHTML = `
        <div style="border-radius:8px;border:1px solid var(--border);overflow:hidden">
          <div style="padding:10px 14px;background:var(--bg-card);display:flex;gap:16px;flex-wrap:wrap">
            <span style="font-size:13px;color:var(--low);font-weight:600">✓ ${data.created} created</span>
            <span style="font-size:13px;color:var(--accent);font-weight:600">↑ ${data.updated} updated</span>
            ${data.skipped > 0 ? `<span style="font-size:13px;color:var(--text-muted)">⊘ ${data.skipped} skipped</span>` : ''}
          </div>
          ${hasErrors ? `
            <div style="padding:10px 14px;border-top:1px solid var(--border)">
              <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px">Row errors:</div>
              ${data.errors.map(e => `
                <div style="font-size:11px;color:var(--critical);padding:2px 0">Row ${e.row}: ${esc(e.error)}</div>
              `).join('')}
            </div>
          ` : ''}
        </div>
      `;

      toast(`Import complete: ${data.created} created, ${data.updated} updated`, 'success');
      this._importFile = null;
      if (this.state.tab === 'list') {
        const [idx, systems] = await Promise.all([
          API.get('/app-systems/asset-index').catch(() => ({})),
          API.get('/app-systems/').catch(() => []),
        ]);
        this.state.assetIndex = idx;
        this.state.systems = systems;
        this.load();
      }
    } catch(e) {
      resultEl.innerHTML = `<div style="padding:10px;background:var(--critical-glow,#ef444420);border:1px solid var(--critical);border-radius:6px;font-size:12px;color:var(--critical)">${esc(e.message)}</div>`;
      toast(e.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Import'; }
    }
  },

  // ═══════════════════════════════════════════════════════
  // CLOUD TAB
  // ═══════════════════════════════════════════════════════

  _cloudState: {
    search: '', resourceType: '', region: '', healthStatus: '', environment: '',
    platform: '', account: '', runState: '',
    page: 1, per_page: 50,
  },
  _cloudAssets: null,

  async _renderCloud(el) {
    el.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;

    let data;
    try {
      data = await API.get('/assets/', { per_page: 500, location_type: 'cloud' });
    } catch (e) {
      el.innerHTML = `<div style="text-align:center;padding:60px 20px;color:var(--text-muted)">${esc(e.message)}</div>`;
      return;
    }

    if (!data.items.length) {
      el.innerHTML = `
        <div style="text-align:center;padding:60px 20px">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.2" style="margin-bottom:16px">
            <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
          </svg>
          <div style="font-size:14px;color:var(--text-secondary);margin-bottom:8px">No cloud assets found</div>
          <div style="font-size:12px;color:var(--text-muted)">Run an AWS sync to import cloud inventory</div>
          <button class="btn btn-primary btn-sm" style="margin-top:16px" onclick="navigateSettings('integrations')">Go to Integrations</button>
        </div>`;
      return;
    }

    // Enrich assets with parsed metadata
    const assets = data.items.map(a => ({
      ...a,
      _resourceType: a.asset_type || this._parseResourceType(a.cloud_resource_id, a.os),
      _region:       a.region || this._parseRegion(a.cloud_resource_id),
      _platform:     this._detectPlatform(a),
      _health:       this._healthStatus(a),
      _tags:         this._parseTags(a.tags),
    }));

    // Build filter options
    const platforms = [...new Set(assets.map(a => a._platform))].sort();
    const types     = [...new Set(assets.map(a => a._resourceType))].sort();
    const regions   = [...new Set(assets.map(a => a._region).filter(r => r && r !== '–'))].sort();
    const accounts  = [...new Set(assets.map(a => a.cloud_account_name || a.cloud_account_id).filter(Boolean))].sort();
    const envs      = [...new Set(assets.map(a => a.environment).filter(Boolean))].sort();

    // Default platform to AWS if present
    if (!this._cloudState.platform && platforms.includes('AWS')) {
      this._cloudState.platform = 'AWS';
    }

    el.innerHTML = `
      <!-- Platform sub-tabs -->
      <div style="display:flex;gap:2px;margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:0">
        <button class="cloud-ptab ${!this._cloudState.platform?'active':''}"
          onclick="AssetsPage._setCloudPlatform('')">All</button>
        ${platforms.map(p => `
          <button class="cloud-ptab ${this._cloudState.platform===p?'active':''}"
            onclick="AssetsPage._setCloudPlatform('${esc(p)}')">${esc(p)}</button>
        `).join('')}
      </div>

      <div class="filter-bar" style="margin-bottom:14px">
        <div class="search-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input class="input search-input" id="cloud-search" placeholder="Search name, ARN, tags…"
            value="${esc(this._cloudState.search)}">
        </div>
        <select class="input" id="cloud-type" style="width:170px">
          <option value="">All Types</option>
          ${types.map(t => `<option value="${esc(t)}" ${this._cloudState.resourceType===t?'selected':''}>${esc(t)}</option>`).join('')}
        </select>
        <select class="input" id="cloud-region" style="width:150px">
          <option value="">All Regions</option>
          ${regions.map(r => `<option value="${esc(r)}" ${this._cloudState.region===r?'selected':''}>${esc(r)}</option>`).join('')}
        </select>
        ${accounts.length > 1 ? `
        <select class="input" id="cloud-account" style="width:150px">
          <option value="">All Accounts</option>
          ${accounts.map(a => `<option value="${esc(a)}" ${this._cloudState.account===a?'selected':''}>${esc(a)}</option>`).join('')}
        </select>` : ''}
        <select class="input" id="cloud-state" style="width:120px">
          <option value="">All States</option>
          ${[...new Set(assets.map(a=>a.run_state).filter(Boolean))].sort()
            .map(s=>`<option value="${esc(s)}" ${this._cloudState.runState===s?'selected':''}>${esc(s)}</option>`).join('')}
        </select>
        <select class="input" id="cloud-health" style="width:130px">
          <option value="">All Health</option>
          <option value="critical" ${this._cloudState.healthStatus==='critical'?'selected':''}>Critical</option>
          <option value="high"     ${this._cloudState.healthStatus==='high'?'selected':''}>High Risk</option>
          <option value="warning"  ${this._cloudState.healthStatus==='warning'?'selected':''}>Vulnerable</option>
          <option value="healthy"  ${this._cloudState.healthStatus==='healthy'?'selected':''}>Healthy</option>
        </select>
        ${envs.length ? `
        <select class="input" id="cloud-env" style="width:110px">
          <option value="">All Envs</option>
          ${envs.map(e=>`<option value="${esc(e)}" ${this._cloudState.environment===e?'selected':''}>${esc(e)}</option>`).join('')}
        </select>` : ''}
        <span style="font-size:12px;color:var(--text-muted)" id="cloud-count"></span>
        <button class="btn btn-secondary btn-sm" style="margin-left:auto" onclick="AssetsPage._exportCloudCSV()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Export CSV
        </button>
      </div>

      ${CloudTable.filterBarHtml()}
      <div id="cloud-grid"></div>
    `;

    // Store assets for platform switching
    this._cloudAssets = assets;

    const refilter = () => {
      this._cloudState.search       = document.getElementById('cloud-search')?.value   || '';
      this._cloudState.resourceType = document.getElementById('cloud-type')?.value     || '';
      this._cloudState.region       = document.getElementById('cloud-region')?.value   || '';
      this._cloudState.account      = document.getElementById('cloud-account')?.value  || '';
      this._cloudState.runState     = document.getElementById('cloud-state')?.value    || '';
      this._cloudState.healthStatus = document.getElementById('cloud-health')?.value   || '';
      this._cloudState.environment  = document.getElementById('cloud-env')?.value      || '';
      this._renderCloudGrid(assets);
    };

    document.getElementById('cloud-search')?.addEventListener('input', debounce(refilter, 250));
    ['cloud-type','cloud-region','cloud-account','cloud-state','cloud-health','cloud-env'].forEach(id => {
      document.getElementById(id)?.addEventListener('change', refilter);
    });

    this._renderCloudGrid(assets);
  },

  _setCloudPlatform(p) {
    this._cloudState.platform = p;
    if (this._cloudAssets) this._renderCloudGrid(this._cloudAssets);
    // Update in-page tab buttons
    document.querySelectorAll('.cloud-ptab').forEach(b => {
      const bp = b.textContent.trim();
      b.classList.toggle('active', p === '' ? bp === 'All' : bp === p);
    });
    // Sync sidebar cloud sub-nav
    document.querySelectorAll('#nav-cloud-sub .nav-sub-sub-item').forEach(el => {
      el.classList.toggle('active', p !== '' && el.dataset.cloudplatform === p);
    });
  },

  _renderCloudGrid(assets) {
    const { search, resourceType, region, healthStatus, environment, platform, account, runState } = this._cloudState;
    const term = search.toLowerCase();

    const filtered = assets.filter(a => {
      if (platform && a._platform !== platform) return false;
      if (term && !a.hostname?.toLowerCase().includes(term) &&
          !a.cloud_resource_id?.toLowerCase().includes(term) &&
          !(a.tags || '').toLowerCase().includes(term)) return false;
      if (resourceType && a._resourceType !== resourceType) return false;
      if (region && a._region !== region) return false;
      if (environment && a.environment !== environment) return false;
      if (account) {
        const acct = a.cloud_account_name || a.cloud_account_id || '';
        if (acct !== account) return false;
      }
      if (runState && a.run_state !== runState) return false;
      if (healthStatus) {
        if (healthStatus === 'critical' && a.critical_count === 0) return false;
        if (healthStatus === 'high'     && (a.critical_count > 0 || (a.high_count||0) === 0)) return false;
        if (healthStatus === 'warning'  && (a.critical_count > 0 || (a.high_count||0) > 0 || a.vuln_count === 0)) return false;
        if (healthStatus === 'healthy'  && a.vuln_count > 0) return false;
      }
      return true;
    });

    const countEl = document.getElementById('cloud-count');
    if (countEl) countEl.textContent = `${filtered.length} / ${assets.length} resources`;

    const grid = document.getElementById('cloud-grid');
    if (!grid) return;

    const CLOUD_GETTERS = {
      type:      a => a._resourceType,
      name:      a => `${a.hostname||''} ${a.cloud_resource_id||''}`,
      region:    a => a._region,
      account:   a => a.cloud_account_name || a.cloud_account_id,
      itype:     a => a.instance_type,
      state:     a => a.run_state,
      env:       a => a.environment,
      exposure:  a => a.internet_exposure,
      health:    a => a._health?.label,
      cves:      a => (a.critical_count||0)+(a.high_count||0)+(a.medium_count||0)+(a.low_count||0),
      misconfigs:a => a.rec_count,
      lastseen:  a => a.last_seen,
    };
    const displayItems = CloudTable.applyFilters(filtered, CLOUD_GETTERS);

    if (!displayItems.length) {
      grid.innerHTML = emptyState('No resources match filters');
      return;
    }

    grid.innerHTML = `
      <div style="overflow-x:auto">
        <table style="table-layout:fixed;min-width:700px">
          ${CloudTable.colgroup()}
          <thead><tr id="cloud-thr">${CloudTable.thead()}</tr></thead>
          <tbody>
            ${displayItems.map(a => this._cloudRow(a)).join('')}
          </tbody>
        </table>
      </div>`;
  },

  _cloudRow(a) {
    const h = a._health;
    const typeIcon = this._resourceTypeIcon(a._resourceType);
    const nameDisplay = a.hostname || a.cloud_resource_id?.split(':').pop() || '–';
    const nameShort = nameDisplay.length > 36 ? nameDisplay.slice(0,34) + '…' : nameDisplay;
    const accountDisplay = a.cloud_account_name || a.cloud_account_id || '–';

    // CVEs vs misconfigs split
    const cveCount = (a.critical_count||0) + (a.high_count||0) + (a.medium_count||0) + (a.low_count||0);
    const miscCount = a.rec_count || 0;

    const cveCell = cveCount > 0
      ? `<span style="font-weight:600;color:${a.critical_count>0?'var(--critical)':a.high_count>0?'#f97316':'var(--text-secondary)'}">${cveCount}</span>`
      : `<span style="color:var(--text-muted)">–</span>`;
    const miscCell = miscCount > 0
      ? `<span style="font-weight:600;color:#fbbf24">${miscCount}</span>`
      : `<span style="color:var(--text-muted)">–</span>`;

    const expBadge = {
      exposed: `<span style="font-size:10px;color:#ef4444;font-weight:600">Internet</span>`,
      internal: `<span style="font-size:10px;color:var(--text-muted)">Internal</span>`,
      unknown:  `<span style="font-size:10px;color:var(--text-muted)">–</span>`,
    }[a.internet_exposure] || `<span style="font-size:10px;color:var(--text-muted)">${esc(a.internet_exposure||'–')}</span>`;

    const stateCls = a.run_state === 'running' || a.run_state === 'active' || a.run_state === 'available'
      ? 'color:#22c55e' : a.run_state === 'stopped' ? 'color:#ef4444' : 'color:var(--text-muted)';

    const cells = {
      type:      `<td style="white-space:nowrap"><div style="display:flex;align-items:center;gap:6px"><span style="font-size:14px">${typeIcon}</span><span style="font-size:11px;color:var(--text-secondary)">${esc(a._resourceType)}</span></div></td>`,
      name:      `<td class="primary"><div class="truncate" style="font-size:12px;font-weight:500" title="${esc(a.hostname||a.cloud_resource_id||'')}">${esc(nameShort)}</div>${a.cloud_resource_id?`<div style="font-size:9px;color:var(--text-muted);font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(a.cloud_resource_id)}">${esc(a.cloud_resource_id.length>40?a.cloud_resource_id.slice(-38)+'…':a.cloud_resource_id)}</div>`:''}</td>`,
      region:    `<td><span style="font-size:11px;color:var(--text-secondary);font-family:monospace">${esc(a._region||'–')}</span></td>`,
      account:   `<td><span style="font-size:11px;color:var(--text-muted)" title="${esc(a.cloud_account_id||'')}">${esc(accountDisplay.length>16?accountDisplay.slice(0,15)+'…':accountDisplay)}</span></td>`,
      itype:     `<td><span style="font-size:11px;color:var(--text-secondary);font-family:monospace">${esc(a.instance_type||'–')}</span></td>`,
      state:     `<td><span style="font-size:11px;${stateCls};font-weight:500">${esc(a.run_state||'–')}</span></td>`,
      env:       `<td>${a.environment?`<span style="font-size:10px;padding:2px 6px;border-radius:3px;background:var(--bg-secondary);border:1px solid var(--border);color:var(--text-secondary)">${esc(a.environment)}</span>`:'–'}</td>`,
      exposure:  `<td>${expBadge}</td>`,
      health:    `<td><span class="status-badge ${h.cls}" style="font-size:10px">${h.label}</span></td>`,
      cves:      `<td style="text-align:center">${cveCell}</td>`,
      misconfigs:`<td style="text-align:center">${miscCell}</td>`,
      lastseen:  `<td style="font-size:11px;color:var(--text-muted)">${fmtDateShort(a.last_seen)}</td>`,
      _act:      `<td><button class="btn btn-icon btn-xs" onclick="event.stopPropagation();AssetsPage.openDetail(${a.id})"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button></td>`,
    };
    return `<tr style="cursor:pointer" onclick="AssetsPage.openDetail(${a.id})">${CloudTable.cols.map(col => cells[col.key]||'<td></td>').join('')}</tr>`;
  },

  _detectPlatform(a) {
    if (a.source === 'aws' || (a.cloud_resource_id || '').startsWith('arn:aws:')) return 'AWS';
    if (a.source === 'azure' || (a.cloud_resource_id || '').startsWith('/subscriptions/')) return 'Azure';
    if (a.source === 'k8s' || a.source === 'kubernetes') return 'Kubernetes';
    if (a.location_type === 'cloud') return 'AWS'; // default
    return 'Other';
  },

  _parseTags(tagsStr) {
    if (!tagsStr) return {};
    try { return JSON.parse(tagsStr); } catch { return {}; }
  },

  _exportCloudCSV() {
    if (!this._cloudAssets) return;
    const { search, resourceType, region, healthStatus, environment, platform, account, runState } = this._cloudState;
    const term = search.toLowerCase();
    const filtered = this._cloudAssets.filter(a => {
      if (platform && a._platform !== platform) return false;
      if (term && !a.hostname?.toLowerCase().includes(term) &&
          !a.cloud_resource_id?.toLowerCase().includes(term) &&
          !(a.tags || '').toLowerCase().includes(term)) return false;
      if (resourceType && a._resourceType !== resourceType) return false;
      if (region && a._region !== region) return false;
      if (environment && a.environment !== environment) return false;
      if (account && (a.cloud_account_name || a.cloud_account_id || '') !== account) return false;
      if (runState && a.run_state !== runState) return false;
      return true;
    });

    const cols = ['id','hostname','cloud_resource_id','asset_type','region','cloud_account_id','cloud_account_name',
                  'instance_type','run_state','internet_exposure','environment','criticality','vuln_count',
                  'critical_count','ip_address','os','source','first_seen','last_seen','tags'];
    const escape = v => {
      if (v == null) return '';
      const s = String(v);
      return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g,'""')}"` : s;
    };
    const rows = [cols.join(','), ...filtered.map(a => cols.map(c => escape(a[c])).join(','))];
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `cloud-assets-${new Date().toISOString().slice(0,10)}.csv`;
    a.click(); URL.revokeObjectURL(url);
  },

  _parseResourceType(arn, os) {
    if (!arn || !arn.startsWith('arn:')) {
      if (os) {
        if (os.startsWith('Lambda')) return 'Lambda Function';
        if (os.startsWith('RDS'))    return 'RDS Instance';
        if (os === 'S3 Bucket')      return 'S3 Bucket';
      }
      return 'Cloud Resource';
    }
    const parts = arn.split(':');
    const svc   = parts[2] || '';
    const res   = parts.slice(5).join(':') || '';
    if (svc === 'ec2') {
      if (res.startsWith('instance/'))       return 'EC2 Instance';
      if (res.startsWith('vpc/'))            return 'VPC';
      if (res.startsWith('subnet/'))         return 'Subnet';
      if (res.startsWith('security-group/')) return 'Security Group';
      if (res.startsWith('volume/'))         return 'EBS Volume';
      return 'EC2 Resource';
    }
    if (svc === 'lambda')                    return 'Lambda Function';
    if (svc === 'rds')                       return 'RDS Instance';
    if (svc === 's3')                        return 'S3 Bucket';
    if (svc === 'ecs')                       return 'ECS';
    if (svc === 'eks')                       return 'EKS Cluster';
    if (svc === 'elasticloadbalancing')      return 'Load Balancer';
    if (svc === 'cloudfront')                return 'CloudFront';
    if (svc === 'iam')                       return 'IAM';
    return `AWS ${svc.toUpperCase()}`;
  },

  _parseRegion(arn) {
    if (!arn || !arn.startsWith('arn:')) return '–';
    const r = arn.split(':')[3];
    return r || '–';
  },

  _healthStatus(a) {
    if (a.critical_count > 0)   return { label: 'Critical',    cls: 'status-open' };
    if ((a.high_count||0) > 0)  return { label: 'High Risk',   cls: 'status-in_progress' };
    if (a.vuln_count > 0)       return { label: 'Vulnerable',  cls: 'status-accepted' };
    return                             { label: 'Healthy',      cls: 'status-remediated' };
  },

  _resourceTypeIcon(type) {
    const map = {
      'EC2 Instance':    '🖥️',
      'Lambda Function': 'λ',
      'RDS Instance':    '🗄️',
      'S3 Bucket':       '🪣',
      'VPC':             '🔗',
      'ECS':             '📦',
      'EKS Cluster':     '⎈',
      'Load Balancer':   '⚖️',
      'CloudFront':      '🌐',
      'Security Group':  '🔒',
    };
    return map[type] || '☁️';
  },

};

// Global hook used by dashboard and other pages
function loadAssetDetail(id) {
  navigate('assets');
  setTimeout(() => AssetsPage.openDetail(id), 200);
}
