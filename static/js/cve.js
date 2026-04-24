/* CVE Database page */

const CVEPage = {
  state: { page: 1, per_page: 25, severity: '', search: '' },

  async render(el) {
    el.innerHTML = `
      <div class="filter-bar">
        <div class="search-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input class="input search-input" id="cve-search" placeholder="Search CVE ID or description…" value="${this.state.search}">
        </div>
        <select class="input" id="cve-sev" style="width:130px">
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <span style="margin-left:auto;font-size:12px;color:var(--text-muted)" id="cve-count">–</span>
      </div>

      ${CVETable.filterBarHtml()}
      <div class="table-wrap" style="overflow-x:auto">
        <table style="table-layout:fixed;min-width:500px">
          ${CVETable.colgroup()}
          <thead><tr id="cve-thr">${CVETable.thead()}</tr></thead>
          <tbody id="cve-tbody">
            <tr><td colspan="${CVETable.cols.length}"><div class="loader"><div class="spinner"></div></div></td></tr>
          </tbody>
        </table>
      </div>
      <div id="cve-pagination"></div>
    `;

    document.getElementById('cve-search').addEventListener('input', debounce(e => {
      this.state.search = e.target.value;
      this.state.page = 1;
      this.load();
    }, 300));

    document.getElementById('cve-sev').addEventListener('change', e => {
      this.state.severity = e.target.value;
      this.state.page = 1;
      this.load();
    });

    this.load();
  },

  async load() {
    const { page, per_page, severity, search } = this.state;
    const data = await API.get('/cve/', { page, per_page, severity, search });

    const countEl = document.getElementById('cve-count');
    if (countEl) countEl.textContent = `${data.total.toLocaleString()} entries`;

    const tbody = document.getElementById('cve-tbody');
    const GETTERS = {
      cve_id:      c => c.cve_id,
      description: c => c.description,
      severity:    c => c.severity,
      cvss_v3:     c => c.cvss_v3_score,
      published:   c => c.published_date,
    };
    const rows = CVETable.applyFilters(data.items, GETTERS);
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="${CVETable.cols.length}">${emptyState('No CVE records found')}</td></tr>`;
      return;
    }

    tbody.innerHTML = rows.map(c => {
      const cells = {
        cve_id:      `<td><span style="font-family:monospace;font-weight:600;color:var(--accent);font-size:12.5px">${c.cve_id}</span></td>`,
        description: `<td><div class="truncate" style="font-size:12.5px;color:var(--text-secondary)" title="${esc(c.description||'')}">${esc(c.description||'–')}</div></td>`,
        severity:    `<td>${sevBadge(c.severity||'info')}</td>`,
        cvss_v3:     `<td><div class="cvss-ring ${c.severity||'info'}" style="width:44px;height:44px;font-size:13px;border-width:2px">${c.cvss_v3_score!=null?c.cvss_v3_score.toFixed(1):'–'}</div></td>`,
        published:   `<td style="font-size:11px;color:var(--text-muted)">${c.published_date?c.published_date.slice(0,10):'–'}</td>`,
      };
      return `<tr style="cursor:pointer" onclick="CVEPage.openDetail('${c.cve_id}')">${CVETable.cols.map(col => cells[col.key]||'<td></td>').join('')}</tr>`;
    }).join('');

    renderPagination('cve-pagination', page, per_page, data.total, p => {
      this.state.page = p;
      this.load();
    });
  },

  async openDetail(cveId) {
    const c = await API.get(`/cve/${cveId}`);
    openDetail(
      c.cve_id,
      `${sevBadge(c.severity || 'info')}
       <span class="cvss-ring ${c.severity||'info'}" style="width:40px;height:40px;font-size:13px;border-width:2px">
         ${c.cvss_v3_score != null ? c.cvss_v3_score.toFixed(1) : '–'}
       </span>`,
      `
        <div class="detail-section">
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
        ${c.references ? `
          <div class="detail-section">
            <div class="detail-section-title">References</div>
            <div style="display:flex;flex-direction:column;gap:4px">
              ${c.references.split('\n').filter(Boolean).map(r =>
                `<a href="${r}" target="_blank" style="font-size:12px;color:var(--accent);word-break:break-all">${r}</a>`
              ).join('')}
            </div>
          </div>` : ''}
      `,
      `<button class="btn btn-secondary btn-sm" onclick="closeDetail()">Close</button>`
    );
  },

  search(term) {
    const inp = document.getElementById('cve-search');
    if (inp) {
      inp.value = term;
      this.state.search = term;
      this.state.page = 1;
      this.load();
    }
  },
};
