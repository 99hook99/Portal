/* CVE Database — Local Records / NVD / CISA KEV */

const CVEPage = {
  _tab: 'local',

  // per-tab state
  _local: { page: 1, per_page: 25, severity: '', search: '' },
  _nvd:   { page: 1, per_page: 25, severity: '', search: '', sort_by: 'published',  sort_dir: 'desc' },
  _kev:   { page: 1, per_page: 25, search: '',              sort_by: 'date_added',  sort_dir: 'desc' },

  _nvdPollTimer: null,
  _kevPollTimer: null,

  async render(el) {
    el.innerHTML = `
      <div class="page-subtabs" id="cve-tabs">
        <button class="page-subtab active" data-tab="local" onclick="CVEPage._switch('local')">Local CVE Records</button>
        <button class="page-subtab" data-tab="nvd"   onclick="CVEPage._switch('nvd')">NVD Database</button>
        <button class="page-subtab" data-tab="kev"   onclick="CVEPage._switch('kev')">CISA KEV</button>
      </div>
      <div id="cve-tab-body"></div>
    `;
    this._renderTab();
  },

  _switch(tab) {
    if (this._tab === tab) return;
    this._tab = tab;
    document.querySelectorAll('#cve-tabs .page-subtab').forEach(b =>
      b.classList.toggle('active', b.dataset.tab === tab)
    );
    this._renderTab();
  },

  _renderTab() {
    const el = document.getElementById('cve-tab-body');
    if (!el) return;
    if      (this._tab === 'local') this._renderLocal(el);
    else if (this._tab === 'nvd')   this._renderNVD(el);
    else if (this._tab === 'kev')   this._renderKEV(el);
  },

  // ── LOCAL ────────────────────────────────────────────────────

  _renderLocal(el) {
    const s = this._local;
    el.innerHTML = `
      <div class="filter-bar">
        <div class="search-wrap">
          ${_searchIcon()}
          <input class="input search-input" id="cve-search" placeholder="Search CVE ID or description…" value="${esc(s.search)}">
        </div>
        <select class="input" id="cve-sev" style="width:130px">
          <option value="">All Severities</option>
          ${_sevOptions(s.severity)}
        </select>
        <span style="margin-left:auto;font-size:12px;color:var(--text-muted)" id="cve-count">–</span>
      </div>
      ${CVETable.filterBarHtml()}
      <div class="table-wrap" style="overflow-x:auto">
        <table style="table-layout:fixed;min-width:500px">
          ${CVETable.colgroup()}
          <thead><tr id="cve-thr">${CVETable.thead()}</tr></thead>
          <tbody id="cve-tbody">
            ${_loadingRow(CVETable.cols.length)}
          </tbody>
        </table>
      </div>
      <div id="cve-pagination"></div>`;

    document.getElementById('cve-search').addEventListener('input', debounce(e => {
      this._local.search = e.target.value; this._local.page = 1; this.load();
    }, 300));
    document.getElementById('cve-sev').addEventListener('change', e => {
      this._local.severity = e.target.value; this._local.page = 1; this.load();
    });
    this.load();
  },

  async load() {
    if (this._tab !== 'local') return;
    const s = this._local;
    const data = await API.get('/cve/', { page: s.page, per_page: s.per_page, severity: s.severity, search: s.search });
    const tbody = document.getElementById('cve-tbody');
    if (!tbody) return;
    _setCount('cve-count', data.total);

    const GETTERS = {
      cve_id: c => c.cve_id, description: c => c.description,
      severity: c => c.severity, cvss_v3: c => c.cvss_v3_score, published: c => c.published_date,
    };
    const rows = CVETable.applyFilters(data.items, GETTERS);
    if (!rows.length) { tbody.innerHTML = _emptyRow(CVETable.cols.length, 'No CVE records found'); return; }

    tbody.innerHTML = rows.map(c => {
      const sv = c.severity || 'info';
      const cells = {
        cve_id:      `<td><span class="mono-link">${c.cve_id}</span></td>`,
        description: `<td><div class="truncate" style="font-size:12.5px;color:var(--text-secondary)" title="${esc(c.description||'')}">${esc(c.description||'–')}</div></td>`,
        severity:    `<td>${sevBadge(sv)}</td>`,
        cvss_v3:     `<td>${_cvssRing(c.cvss_v3_score, sv)}</td>`,
        published:   `<td class="muted-date">${c.published_date ? c.published_date.slice(0,10) : '–'}</td>`,
      };
      return `<tr class="clickrow" onclick="CVEPage.openDetail('${c.cve_id}')">${CVETable.cols.map(col => cells[col.key]||'<td></td>').join('')}</tr>`;
    }).join('');

    renderPagination('cve-pagination', s.page, s.per_page, data.total, p => { this._local.page = p; this.load(); });
  },

  // ── NVD ──────────────────────────────────────────────────────

  _renderNVD(el) {
    el.innerHTML = `
      <div class="filter-bar">
        <div class="search-wrap">
          ${_searchIcon()}
          <input class="input search-input" id="nvd-search" placeholder="Search CVE ID or description…">
        </div>
        <select class="input" id="nvd-sev" style="width:130px">
          <option value="">All Severities</option>
          ${_sevOptions('')}
          <option value="none">None</option>
        </select>
        <div style="margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <select class="input" id="nvd-days" style="width:115px;font-size:12px">
            <option value="1">Last 24 h</option>
            <option value="7">Last 7 days</option>
            <option value="30" selected>Last 30 days</option>
            <option value="90">Last 90 days</option>
            <option value="365">Last year</option>
          </select>
          <button class="btn btn-secondary btn-sm" id="nvd-sync-btn" onclick="CVEPage._syncNVD()">
            ${_syncIcon()} Sync now
          </button>
          <span id="nvd-status-txt" style="font-size:11px;color:var(--text-muted)"></span>
          <span style="font-size:12px;color:var(--text-muted)" id="nvd-count">–</span>
        </div>
      </div>
      ${NVDTable.filterBarHtml()}
      <div class="table-wrap" style="overflow-x:auto">
        <table style="table-layout:fixed;min-width:600px">
          ${NVDTable.colgroup()}
          <thead><tr id="nvd-thr">${NVDTable.thead()}</tr></thead>
          <tbody id="nvd-tbody">
            ${_loadingRow(NVDTable.cols.length)}
          </tbody>
        </table>
      </div>
      <div id="nvd-pagination"></div>`;

    document.getElementById('nvd-search').addEventListener('input', debounce(e => {
      this._nvd.search = e.target.value; this._nvd.page = 1; this._loadNVD();
    }, 300));
    document.getElementById('nvd-sev').addEventListener('change', e => {
      this._nvd.severity = e.target.value; this._nvd.page = 1; this._loadNVD();
    });
    this._loadNVD();
    this._checkNVDStatus();
  },

  async _loadNVD() {
    const s = this._nvd;
    const tbody = document.getElementById('nvd-tbody');
    if (!tbody) return;
    if (NVDTable.sortKey) { s.sort_by = NVDTable.sortKey; s.sort_dir = NVDTable.sortDir; }

    const data = await API.get('/cve/nvd', {
      page: s.page, per_page: s.per_page,
      severity: s.severity, search: s.search,
      sort_by: s.sort_by, sort_dir: s.sort_dir,
    });
    _setCount('nvd-count', data.total);
    this._applyNVDStatus(data.sync_status);

    const GETTERS = {
      cve_id: n => n.cve_id, description: n => n.description,
      severity: n => n.cvss_v3_severity, cvss_v3: n => n.cvss_v3_score,
      cwe: n => n.cwe, published: n => n.published, last_modified: n => n.last_modified,
    };
    const rows = NVDTable.applyFilters(data.items, GETTERS);
    if (!rows.length) {
      const isSyncing = data.sync_status?.running;
      const msg = (data.total === 0)
        ? (isSyncing ? '⟳ Initial NVD sync in progress — data will appear shortly…' : 'NVD data not yet loaded. Auto-sync starts on server startup.')
        : 'No matches';
      tbody.innerHTML = _emptyRow(NVDTable.cols.length, msg);
      renderPagination('nvd-pagination', s.page, s.per_page, 0, () => {});
      return;
    }

    tbody.innerHTML = rows.map(n => {
      const sv = n.cvss_v3_severity || _scoreToSev(n.cvss_v3_score);
      const cells = {
        cve_id:        `<td><span class="mono-link">${n.cve_id}</span></td>`,
        description:   `<td><div class="truncate" style="font-size:12px;color:var(--text-secondary)" title="${esc(n.description||'')}">${esc(n.description||'–')}</div></td>`,
        severity:      `<td>${sevBadge(sv)}</td>`,
        cvss_v3:       `<td>${_cvssRing(n.cvss_v3_score, sv, 40, 12)}</td>`,
        cwe:           `<td style="font-size:11px;font-family:monospace;color:var(--text-muted)">${esc(n.cwe||'–')}</td>`,
        published:     `<td class="muted-date">${n.published ? n.published.slice(0,10) : '–'}</td>`,
        last_modified: `<td class="muted-date">${n.last_modified ? n.last_modified.slice(0,10) : '–'}</td>`,
      };
      return `<tr class="clickrow" onclick="CVEPage._openNVDDetail('${n.cve_id}')">${NVDTable.cols.map(col => cells[col.key]||'<td></td>').join('')}</tr>`;
    }).join('');

    renderPagination('nvd-pagination', s.page, s.per_page, data.total, p => { this._nvd.page = p; this._loadNVD(); });
  },

  async _syncNVD() {
    const days = document.getElementById('nvd-days')?.value || '30';
    const btn  = document.getElementById('nvd-sync-btn');
    if (btn) btn.disabled = true;
    try {
      await API.post(`/cve/nvd/sync?days=${days}`, {});
      this._pollNVDStatus();
    } catch (e) {
      _setStatusTxt('nvd-status-txt', 'error', e.message || 'Failed');
      if (btn) btn.disabled = false;
    }
  },

  async _checkNVDStatus() {
    try {
      const st = await API.get('/cve/nvd/status');
      this._applyNVDStatus(st);
      if (st.running) this._pollNVDStatus();
    } catch (_) {}
  },

  _pollNVDStatus() {
    clearTimeout(this._nvdPollTimer);
    const tick = async () => {
      try {
        const st = await API.get('/cve/nvd/status');
        this._applyNVDStatus(st);
        if (st.running) {
          this._nvdPollTimer = setTimeout(tick, 3000);
        } else {
          const btn = document.getElementById('nvd-sync-btn');
          if (btn) btn.disabled = false;
          if (st.last_count > 0) this._loadNVD();
        }
      } catch (_) {}
    };
    this._nvdPollTimer = setTimeout(tick, 1000);
  },

  _applyNVDStatus(st) {
    if (!st) return;
    const btn = document.getElementById('nvd-sync-btn');
    if (btn) btn.disabled = !!st.running;
    let txt = '';
    if      (st.running)     txt = '<span style="color:var(--warn)">⟳ Syncing…</span>';
    else if (st.error)       txt = `<span style="color:var(--danger)" title="${esc(st.error)}">Sync error — hover for details</span>`;
    else if (st.last_synced) txt = `Last sync: ${st.last_synced.slice(0,10)} · auto-syncs every 24h`;
    else                     txt = 'Auto-sync on startup…';
    _setStatusTxt('nvd-status-txt', '', txt, true);
  },

  async _openNVDDetail(cveId) {
    const n  = await API.get(`/cve/nvd/${cveId}`);
    const sv = n.cvss_v3_severity || _scoreToSev(n.cvss_v3_score);
    const refs = (n.references || []).slice(0, 12);
    const prods = (n.affected_products || []).slice(0, 20);
    openDetail(
      n.cve_id,
      `${sevBadge(sv)} ${_cvssRing(n.cvss_v3_score, sv, 40, 13)}`,
      `<div class="detail-section">
        <div class="detail-section-title">Description</div>
        <div class="detail-text">${esc(n.description || '–')}</div>
       </div>
       <div class="detail-section">
        <div class="detail-section-title">Scoring</div>
        <div class="detail-kv">
          <span class="k">CVSS v3 Score</span><span class="v">${n.cvss_v3_score != null ? n.cvss_v3_score.toFixed(1) : '–'}</span>
          <span class="k">CVSS v3 Severity</span><span class="v">${n.cvss_v3_severity ? n.cvss_v3_severity.toUpperCase() : '–'}</span>
          <span class="k">CVSS v3 Vector</span><span class="v" style="font-family:monospace;font-size:11px;word-break:break-all">${n.cvss_v3_vector || '–'}</span>
          <span class="k">CVSS v2 Score</span><span class="v">${n.cvss_v2_score != null ? n.cvss_v2_score.toFixed(1) : '–'}</span>
          <span class="k">CWE</span><span class="v" style="font-family:monospace">${esc(n.cwe || '–')}</span>
          <span class="k">Published</span><span class="v">${n.published ? n.published.slice(0,10) : '–'}</span>
          <span class="k">Last Modified</span><span class="v">${n.last_modified ? n.last_modified.slice(0,10) : '–'}</span>
        </div>
       </div>
       ${prods.length ? `<div class="detail-section">
        <div class="detail-section-title">Affected Products (CPE)</div>
        <div style="max-height:130px;overflow-y:auto;display:flex;flex-direction:column;gap:2px">
          ${prods.map(p => `<span style="font-size:11px;font-family:monospace;color:var(--text-secondary)">${esc(p)}</span>`).join('')}
        </div></div>` : ''}
       ${refs.length ? `<div class="detail-section">
        <div class="detail-section-title">References</div>
        <div style="display:flex;flex-direction:column;gap:4px">
          ${refs.map(r => `<a href="${esc(r)}" target="_blank" style="font-size:12px;color:var(--accent);word-break:break-all">${esc(r)}</a>`).join('')}
        </div></div>` : ''}`,
      `<button class="btn btn-secondary btn-sm" onclick="closeDetail()">Close</button>`
    );
  },

  // ── KEV ──────────────────────────────────────────────────────

  _renderKEV(el) {
    el.innerHTML = `
      <div class="filter-bar">
        <div class="search-wrap">
          ${_searchIcon()}
          <input class="input search-input" id="kev-search" placeholder="Search CVE ID, vendor, product…">
        </div>
        <div style="margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <button class="btn btn-secondary btn-sm" id="kev-sync-btn" onclick="CVEPage._syncKEV()">
            ${_syncIcon()} Sync now
          </button>
          <span id="kev-status-txt" style="font-size:11px;color:var(--text-muted)"></span>
          <span style="font-size:12px;color:var(--text-muted)" id="kev-count">–</span>
        </div>
      </div>
      ${KEVTable.filterBarHtml()}
      <div class="table-wrap" style="overflow-x:auto">
        <table style="table-layout:fixed;min-width:600px">
          ${KEVTable.colgroup()}
          <thead><tr id="kev-thr">${KEVTable.thead()}</tr></thead>
          <tbody id="kev-tbody">
            ${_loadingRow(KEVTable.cols.length)}
          </tbody>
        </table>
      </div>
      <div id="kev-pagination"></div>`;

    document.getElementById('kev-search').addEventListener('input', debounce(e => {
      this._kev.search = e.target.value; this._kev.page = 1; this._loadKEV();
    }, 300));
    this._loadKEV();
    this._checkKEVStatus();
  },

  async _loadKEV() {
    const s = this._kev;
    const tbody = document.getElementById('kev-tbody');
    if (!tbody) return;
    if (KEVTable.sortKey) { s.sort_by = KEVTable.sortKey; s.sort_dir = KEVTable.sortDir; }

    const data = await API.get('/cve/kev', {
      page: s.page, per_page: s.per_page,
      search: s.search, sort_by: s.sort_by, sort_dir: s.sort_dir,
    });
    _setCount('kev-count', data.total);
    this._applyKEVStatus(data.sync_status);

    const GETTERS = {
      cve_id: k => k.cve_id, vendor: k => k.vendor_project,
      product: k => k.product, name: k => k.vulnerability_name,
      added: k => k.date_added, due: k => k.due_date,
      ransomware: k => k.known_ransomware,
    };
    const rows = KEVTable.applyFilters(data.items, GETTERS);
    if (!rows.length) {
      const isKevSyncing = data.sync_status?.running;
      const msg = (data.total === 0)
        ? (isKevSyncing ? '⟳ Initial KEV sync in progress…' : 'KEV data not yet loaded. Auto-sync starts on server startup.')
        : 'No matches';
      tbody.innerHTML = _emptyRow(KEVTable.cols.length, msg);
      renderPagination('kev-pagination', s.page, s.per_page, 0, () => {});
      return;
    }

    tbody.innerHTML = rows.map(k => {
      const isRan = k.known_ransomware === 'Known';
      const cells = {
        cve_id:     `<td><span class="mono-link">${k.cve_id}</span></td>`,
        vendor:     `<td style="font-size:12px;font-weight:500">${esc(k.vendor_project||'–')}</td>`,
        product:    `<td style="font-size:12px">${esc(k.product||'–')}</td>`,
        name:       `<td><div class="truncate" style="font-size:12px" title="${esc(k.vulnerability_name||'')}">${esc(k.vulnerability_name||'–')}</div></td>`,
        added:      `<td class="muted-date">${k.date_added ? k.date_added.slice(0,10) : '–'}</td>`,
        due:        `<td class="muted-date">${k.due_date   ? k.due_date.slice(0,10)   : '–'}</td>`,
        ransomware: `<td>${isRan ? '<span class="badge badge-critical" style="font-size:10px">Ransomware</span>' : '<span style="color:var(--text-muted);font-size:11px">–</span>'}</td>`,
      };
      return `<tr class="clickrow" onclick="CVEPage._openKEVDetail('${k.cve_id}')">${KEVTable.cols.map(col => cells[col.key]||'<td></td>').join('')}</tr>`;
    }).join('');

    renderPagination('kev-pagination', s.page, s.per_page, data.total, p => { this._kev.page = p; this._loadKEV(); });
  },

  async _syncKEV() {
    const btn = document.getElementById('kev-sync-btn');
    if (btn) btn.disabled = true;
    try {
      await API.post('/cve/kev/sync', {});
      this._pollKEVStatus();
    } catch (e) {
      _setStatusTxt('kev-status-txt', 'error', e.message || 'Failed');
      if (btn) btn.disabled = false;
    }
  },

  async _checkKEVStatus() {
    try {
      const st = await API.get('/cve/kev/status');
      this._applyKEVStatus(st);
      if (st.running) this._pollKEVStatus();
    } catch (_) {}
  },

  _pollKEVStatus() {
    clearTimeout(this._kevPollTimer);
    const tick = async () => {
      try {
        const st = await API.get('/cve/kev/status');
        this._applyKEVStatus(st);
        if (st.running) {
          this._kevPollTimer = setTimeout(tick, 2000);
        } else {
          const btn = document.getElementById('kev-sync-btn');
          if (btn) btn.disabled = false;
          if (st.last_count > 0) this._loadKEV();
        }
      } catch (_) {}
    };
    this._kevPollTimer = setTimeout(tick, 800);
  },

  _applyKEVStatus(st) {
    if (!st) return;
    const btn = document.getElementById('kev-sync-btn');
    if (btn) btn.disabled = !!st.running;
    let txt = '';
    if      (st.running)     txt = '<span style="color:var(--warn)">⟳ Syncing…</span>';
    else if (st.error)       txt = `<span style="color:var(--danger)" title="${esc(st.error)}">Sync error — hover for details</span>`;
    else if (st.last_synced) txt = `Last sync: ${st.last_synced.slice(0,10)} · auto-syncs every 24h`;
    else                     txt = 'Auto-sync on startup…';
    _setStatusTxt('kev-status-txt', '', txt, true);
  },

  async _openKEVDetail(cveId) {
    const k = await API.get(`/cve/kev/${cveId}`);
    const isRan = k.known_ransomware === 'Known';
    openDetail(
      k.cve_id,
      `<span style="font-size:12px;font-weight:600;color:var(--text-muted)">CISA KEV</span>${isRan ? ' <span class="badge badge-critical" style="font-size:10px">Ransomware</span>' : ''}`,
      `<div class="detail-section">
        <div class="detail-section-title">Vulnerability Details</div>
        <div class="detail-kv">
          <span class="k">Vendor / Project</span><span class="v">${esc(k.vendor_project||'–')}</span>
          <span class="k">Product</span><span class="v">${esc(k.product||'–')}</span>
          <span class="k">Vulnerability Name</span><span class="v">${esc(k.vulnerability_name||'–')}</span>
          <span class="k">Date Added to KEV</span><span class="v">${k.date_added ? k.date_added.slice(0,10) : '–'}</span>
          <span class="k">Remediation Due Date</span><span class="v">${k.due_date ? k.due_date.slice(0,10) : '–'}</span>
          <span class="k">Known Ransomware Use</span><span class="v">${isRan ? '<span style="color:var(--danger);font-weight:600">Yes</span>' : 'No'}</span>
        </div>
       </div>
       ${k.short_description ? `<div class="detail-section">
        <div class="detail-section-title">Description</div>
        <div class="detail-text">${esc(k.short_description)}</div></div>` : ''}
       ${k.required_action ? `<div class="detail-section">
        <div class="detail-section-title">Required Action</div>
        <div class="detail-text">${esc(k.required_action)}</div></div>` : ''}
       ${k.notes ? `<div class="detail-section">
        <div class="detail-section-title">Notes</div>
        <div class="detail-text">${esc(k.notes)}</div></div>` : ''}`,
      `<button class="btn btn-secondary btn-sm" onclick="closeDetail()">Close</button>`
    );
  },

  // ── Local CVE detail ─────────────────────────────────────────

  async openDetail(cveId) {
    const c = await API.get(`/cve/${cveId}`);
    const sv = c.severity || 'info';
    openDetail(
      c.cve_id,
      `${sevBadge(sv)} ${_cvssRing(c.cvss_v3_score, sv, 40, 13)}`,
      `<div class="detail-section">
        <div class="detail-section-title">Description</div>
        <div class="detail-text">${esc(c.description || '–')}</div>
       </div>
       <div class="detail-section">
        <div class="detail-section-title">Scoring</div>
        <div class="detail-kv">
          <span class="k">CVSS v3 Score</span><span class="v">${c.cvss_v3_score != null ? c.cvss_v3_score.toFixed(1) : '–'}</span>
          <span class="k">CVSS v3 Vector</span><span class="v" style="font-family:monospace;font-size:11px;word-break:break-all">${c.cvss_v3_vector || '–'}</span>
          <span class="k">CVSS v2 Score</span><span class="v">${c.cvss_v2_score != null ? c.cvss_v2_score.toFixed(1) : '–'}</span>
          <span class="k">Published</span><span class="v">${c.published_date ? c.published_date.slice(0,10) : '–'}</span>
          <span class="k">Modified</span><span class="v">${c.modified_date  ? c.modified_date.slice(0,10)  : '–'}</span>
        </div>
       </div>
       ${c.references ? `<div class="detail-section">
        <div class="detail-section-title">References</div>
        <div style="display:flex;flex-direction:column;gap:4px">
          ${c.references.split('\n').filter(Boolean).map(r =>
            `<a href="${esc(r)}" target="_blank" style="font-size:12px;color:var(--accent);word-break:break-all">${esc(r)}</a>`
          ).join('')}
        </div></div>` : ''}`,
      `<button class="btn btn-secondary btn-sm" onclick="closeDetail()">Close</button>`
    );
  },

  // ── External search entry (called from vulnerability links) ──

  search(term) {
    const inp = document.getElementById('cve-search');
    if (inp) { inp.value = term; this._local.search = term; this._local.page = 1; this.load(); }
  },
};

// ── Module-private helpers ────────────────────────────────────────────────────

function _searchIcon() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>`;
}

function _syncIcon() {
  return `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-right:4px">
    <polyline points="1 4 1 10 7 10"/>
    <path d="M3.51 15a9 9 0 1 0 .49-3.6"/>
  </svg>`;
}

function _sevOptions(selected) {
  return ['critical','high','medium','low'].map(s =>
    `<option value="${s}"${selected===s?' selected':''}>${s[0].toUpperCase()+s.slice(1)}</option>`
  ).join('');
}

function _cvssRing(score, sev, size = 44, fontSize = 13) {
  return `<div class="cvss-ring ${sev||'info'}" style="width:${size}px;height:${size}px;font-size:${fontSize}px;border-width:2px">${score != null ? score.toFixed(1) : '–'}</div>`;
}

function _scoreToSev(score) {
  if (score == null) return 'info';
  if (score >= 9)    return 'critical';
  if (score >= 7)    return 'high';
  if (score >= 4)    return 'medium';
  return 'low';
}

function _loadingRow(cols) {
  return `<tr><td colspan="${cols}"><div class="loader"><div class="spinner"></div></div></td></tr>`;
}

function _emptyRow(cols, msg) {
  return `<tr><td colspan="${cols}">${emptyState(msg)}</td></tr>`;
}

function _setCount(id, total) {
  const el = document.getElementById(id);
  if (el) el.textContent = `${(total||0).toLocaleString()} entries`;
}

function _setStatusTxt(id, _cls, html, raw = false) {
  const el = document.getElementById(id);
  if (!el) return;
  if (raw) el.innerHTML = html;
  else     el.textContent = html;
}
