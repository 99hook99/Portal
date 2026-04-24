/* Recommendations page – CSPM / Cloud Security / Compliance findings */

const RecommendationsPage = {
  state: {
    page: 1, per_page: 25,
    severity: '', status: '', source: '', search: '', host: '',
  },
  total: 0,

  async render(el) {
    el.innerHTML = `
      <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">
        ${[
          { label: 'All',           status: '' },
          { label: 'Open',          status: 'open' },
          { label: 'In Progress',   status: 'in_progress' },
          { label: 'Accepted Risk', status: 'accepted' },
          { label: 'Resolved ✓',   status: 'remediated' },
        ].map(t => `
          <button class="btn btn-sm ${this.state.status === t.status ? 'btn-primary' : 'btn-secondary'}"
            onclick="RecommendationsPage.setStatus('${t.status}')">${t.label}</button>
        `).join('')}
      </div>

      <div style="background:rgba(251,191,36,0.06);border:1px solid rgba(251,191,36,0.2);border-radius:8px;
                  padding:10px 14px;margin-bottom:14px;display:flex;align-items:center;gap:10px">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2">
          <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
          <polyline points="9 22 9 12 15 12 15 22"/>
        </svg>
        <span style="font-size:12px;color:#fbbf24;font-weight:600">Cloud Security Recommendations</span>
        <span style="font-size:11px;color:var(--text-muted)">CSPM misconfigurations, CIS Benchmarks, compliance findings from AWS Security Hub and other sources</span>
      </div>

      <div class="filter-bar">
        <div class="search-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input class="input search-input" id="rec-search" placeholder="Search title, description…"
            value="${esc(this.state.search)}">
        </div>
        <div class="search-wrap" style="min-width:160px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/>
          </svg>
          <input class="input search-input" id="rec-host" placeholder="Filter by resource…"
            value="${esc(this.state.host)}">
        </div>
        <select class="input" id="rec-sev" style="width:130px">
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select class="input" id="rec-source" style="width:120px">
          <option value="">All Sources</option>
          <option value="aws">AWS</option>
          <option value="nessus">Nessus</option>
          <option value="manual">Manual</option>
        </select>
        <span style="margin-left:auto;font-size:12px;color:var(--text-muted)" id="rec-count">–</span>
      </div>

      ${RecsTable.filterBarHtml()}
      <div class="table-wrap" style="overflow-x:auto">
        <table style="table-layout:fixed;min-width:600px">
          ${RecsTable.colgroup()}
          <thead><tr id="recs-thr">${RecsTable.thead()}</tr></thead>
          <tbody id="rec-tbody">
            <tr><td colspan="${RecsTable.cols.length}"><div class="loader"><div class="spinner"></div></div></td></tr>
          </tbody>
        </table>
      </div>
      <div id="rec-pagination"></div>
    `;

    document.getElementById('rec-sev').value    = this.state.severity;
    document.getElementById('rec-source').value = this.state.source;

    document.getElementById('rec-search').addEventListener('input', debounce(e => {
      this.state.search = e.target.value; this.state.page = 1; this.load();
    }, 300));
    document.getElementById('rec-host').addEventListener('input', debounce(e => {
      this.state.host = e.target.value; this.state.page = 1; this.load();
    }, 300));
    ['rec-sev', 'rec-source'].forEach(id => {
      document.getElementById(id).addEventListener('change', e => {
        this.state[id === 'rec-sev' ? 'severity' : 'source'] = e.target.value;
        this.state.page = 1; this.load();
      });
    });

    this.load();
  },

  setStatus(s) {
    this.state.status = s; this.state.page = 1;
    this.render(document.getElementById('page-content'));
  },

  async load() {
    const { page, per_page, severity, status, source, search, host } = this.state;
    const data = await API.get('/vulnerabilities/', {
      page, per_page, severity, status, source, search, host,
      category: 'recommendation',
    });
    this.total = data.total;

    const countEl = document.getElementById('rec-count');
    if (countEl) countEl.textContent = `${data.total.toLocaleString()} recommendations`;

    const tbody = document.getElementById('rec-tbody');
    const GETTERS = {
      title:     v => v.title,
      severity:  v => v.severity,
      family:    v => v.plugin_family,
      resource:  v => `${v.asset_hostname||''} ${v.asset_ip||''}`,
      source:    v => v.source,
      status:    v => v.status,
      first_seen:v => v.first_seen,
    };
    const rows = RecsTable.applyFilters(data.items, GETTERS);
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="${RecsTable.cols.length}">${emptyState('No recommendations match the current filters')}</td></tr>`;
      renderPagination('rec-pagination', page, per_page, 0, () => {});
      return;
    }

    tbody.innerHTML = rows.map(v => {
      const family = v.plugin_family || '–';
      const resource = v.asset_hostname || v.asset_ip || '–';
      const cells = {
        title:     `<td class="primary"><div class="truncate" style="max-width:340px" title="${esc(v.title)}">${esc(v.title)}</div><div style="margin-top:3px">${sourceBadge(v.source)}</div></td>`,
        severity:  `<td>${sevBadge(v.severity)}</td>`,
        family:    `<td><span style="font-size:11px;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block" title="${esc(family)}">${esc(family)}</span></td>`,
        resource:  `<td><span style="font-family:monospace;font-size:11px;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block" title="${esc(resource)}">${esc(resource)}</span></td>`,
        source:    `<td>${sourceBadge(v.source)}</td>`,
        status:    `<td><span class="status-badge status-${v.status}">${v.status.replace('_',' ')}</span></td>`,
        first_seen:`<td style="font-size:11px;color:var(--text-muted)">${fmtDateShort(v.first_seen)}</td>`,
        _act:      `<td><button class="btn btn-icon btn-xs" onclick="event.stopPropagation();RecommendationsPage.openDetail(${v.id})"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button></td>`,
      };
      return `<tr style="cursor:pointer" onclick="RecommendationsPage.openDetail(${v.id})">${RecsTable.cols.map(col => cells[col.key] || '<td></td>').join('')}</tr>`;
    }).join('');

    renderPagination('rec-pagination', page, per_page, data.total, p => {
      this.state.page = p; this.load();
    });
  },

  async openDetail(id) {
    const v = await API.get(`/vulnerabilities/${id}`);
    const family = v.plugin_family || '';

    openDetail(
      v.title,
      `${sevBadge(v.severity)} ${sourceBadge(v.source)}
       <span class="status-badge status-${v.status}">${v.status.replace('_',' ')}</span>`,
      `
        <div class="detail-section">
          <div class="detail-section-title">Recommendation Details</div>
          <div class="detail-kv">
            <span class="k">Resource</span>
            <span class="v" style="font-family:monospace;font-size:11px">${esc(v.asset_hostname || '–')}</span>
            <span class="k">Standard / Family</span>
            <span class="v">${esc(family || '–')}</span>
            <span class="k">Source</span>
            <span class="v">${sourceBadge(v.source)}</span>
            <span class="k">Finding ID</span>
            <span class="v" style="font-family:monospace;font-size:10px">${esc(v.plugin_id || '–')}</span>
            <span class="k">First Seen</span><span class="v">${fmtDate(v.first_seen)}</span>
            <span class="k">Last Seen</span><span class="v">${fmtDate(v.last_seen)}</span>
          </div>
        </div>
        ${v.description ? `
        <div class="detail-section">
          <div class="detail-section-title">Description</div>
          <div class="detail-text">${esc(v.description)}</div>
        </div>` : ''}
        ${v.solution ? `
        <div class="detail-section">
          <div class="detail-section-title">Remediation Steps</div>
          <div class="detail-text" style="color:var(--low)">${esc(v.solution)}</div>
        </div>` : ''}
      `,
      `
        <select class="input" id="rec-detail-status" style="width:160px">
          <option value="open"        ${v.status==='open'?'selected':''}>Open</option>
          <option value="in_progress" ${v.status==='in_progress'?'selected':''}>In Progress</option>
          <option value="accepted"    ${v.status==='accepted'?'selected':''}>Accepted Risk</option>
          <option value="remediated"  ${v.status==='remediated'?'selected':''}>Resolved</option>
        </select>
        <button class="btn btn-primary btn-sm" onclick="RecommendationsPage.updateStatus(${id})">Update</button>
        <button class="btn btn-secondary btn-sm" onclick="closeDetail()">Close</button>
      `
    );
  },

  async updateStatus(id) {
    const sel = document.getElementById('rec-detail-status');
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
