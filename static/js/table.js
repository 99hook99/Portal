/* table.js — shared resizable/reorderable table + enterprise column filter */

class PortalTable {
  /**
   * @param {string}   id       unique DOM-id prefix
   * @param {string}   ns       global JS variable name (for inline event handlers)
   * @param {Array}    cols     [{key, label, w, fixed?, title?}]
   * @param {Function} onReload called after column reorder or filter change
   */
  constructor(id, ns, cols, onReload) {
    this.id      = id;
    this.ns      = ns;
    this.cols    = cols.map(c => ({ ...c }));
    this._reload = onReload || (() => {});
    this._dragSrc = null;
    this.filters  = [];
    this.sortKey  = null;
    this.sortDir  = 'desc';
  }

  // ─── Column HTML ──────────────────────────────────────────────

  colgroup() {
    return `<colgroup id="${this.id}-cg">${
      this.cols.map(c => `<col data-col="${c.key}" style="width:${c.w}px">`).join('')
    }</colgroup>`;
  }

  thead() {
    const ns = this.ns;
    return this.cols.map(col => {
      if (col.fixed) return `<th style="width:${col.w}px;padding-left:12px"></th>`;
      const rz = `<div class="col-rz" onmousedown="event.stopPropagation();event.preventDefault();${ns}.onResizeStart(event,'${col.key}')" onclick="event.stopPropagation()"></div>`;
      const sortable = !!col.sort;
      const isActive = sortable && this.sortKey === col.sort;
      const arrow = isActive ? (this.sortDir === 'asc' ? '▲' : '▼') : (sortable ? '⇅' : '');
      const arrowHtml = arrow ? `<span style="font-size:9px;margin-left:4px;color:${isActive ? 'var(--accent)' : 'var(--text-muted)'};pointer-events:none">${arrow}</span>` : '';
      const cursor = sortable ? 'cursor:pointer' : 'cursor:grab';
      const sortClick = sortable ? ` onclick="${ns}.sort('${col.sort}')"` : '';
      return `<th data-col="${col.key}" style="position:relative;${cursor};white-space:nowrap;overflow:hidden;text-overflow:ellipsis"${col.title ? ` title="${col.title}"` : ''} draggable="true" ondragstart="${ns}.onColDragStart(event,'${col.key}')" ondragover="${ns}.onColDragOver(event,'${col.key}')" ondragleave="${ns}.onColDragLeave(event)" ondrop="${ns}.onColDrop(event,'${col.key}')"${sortClick}><span style="user-select:none;pointer-events:none">${col.label}${arrowHtml}</span>${rz}</th>`;
    }).join('');
  }

  // ─── Filter bar ───────────────────────────────────────────────

  filterBarHtml() {
    return `<div id="${this.id}-fbar" class="filter-col-bar">${this._fbarContent()}</div>`;
  }

  _fbarContent() {
    const ns = this.ns;
    const SYM = { 'is':'=', 'is not':'≠', 'contains':'~', 'not contains':'!~', '>':'>', '<':'<' };
    const chips = this.filters.map((f, i) => {
      const col = this.cols.find(c => c.key === f.field);
      const label = col ? col.label : f.field;
      return `<span class="filter-chip"><span class="filter-chip-label">${label}</span><span class="filter-chip-op">${SYM[f.op] || f.op}</span><span class="filter-chip-val">${this._esc(f.value)}</span><button class="filter-chip-rm" onclick="${ns}.removeFilter(${i})" title="Remove">×</button></span>`;
    }).join('');
    const clearBtn = this.filters.length > 1
      ? `<button class="btn btn-sm btn-secondary" style="height:24px;padding:0 8px;font-size:11px" onclick="${ns}.clearFilters()">Clear all</button>`
      : '';
    return `${chips}<button class="btn btn-sm btn-secondary" id="${this.id}-add-filter" style="height:24px;padding:0 8px;font-size:11px" onclick="${ns}.openFilterBuilder(this)"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" style="margin-right:3px"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Filter</button>${clearBtn}`;
  }

  _refreshFbar() {
    const el = document.getElementById(`${this.id}-fbar`);
    if (el) el.innerHTML = this._fbarContent();
  }

  _esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ─── Client-side filtering ────────────────────────────────────

  applyFilters(items, getters) {
    if (!this.filters.length) return items;
    return items.filter(row =>
      this.filters.every(f => {
        const raw = getters[f.field] ? getters[f.field](row) : '';
        const val = String(raw ?? '').toLowerCase();
        const v   = String(f.value).toLowerCase();
        switch (f.op) {
          case 'is':           return val === v;
          case 'is not':       return val !== v;
          case 'contains':     return val.includes(v);
          case 'not contains': return !val.includes(v);
          case '>':            return parseFloat(val) > parseFloat(v);
          case '<':            return parseFloat(val) < parseFloat(v);
          default:             return true;
        }
      })
    );
  }

  removeFilter(i) {
    this.filters.splice(i, 1);
    this._refreshFbar();
    this._reload();
  }

  clearFilters() {
    this.filters = [];
    this._refreshFbar();
    this._reload();
  }

  // ─── Filter builder popup ─────────────────────────────────────

  openFilterBuilder(anchor) {
    document.getElementById(`${this.id}-fb-popup`)?.remove();
    const filterable = this.cols.filter(c => !c.fixed);
    const popup = document.createElement('div');
    popup.id = `${this.id}-fb-popup`;
    popup.className = 'filter-builder-popup';
    popup.innerHTML = `
      <div class="filter-builder-title">Add Column Filter</div>
      <div class="filter-builder-fields">
        <select id="${this.id}-fb-field" class="input" style="height:28px;font-size:12px">
          ${filterable.map(c => `<option value="${c.key}">${c.label}</option>`).join('')}
        </select>
        <select id="${this.id}-fb-op" class="input" style="height:28px;font-size:12px">
          <option value="contains">contains</option>
          <option value="is">is (exact)</option>
          <option value="is not">is not</option>
          <option value="not contains">not contains</option>
          <option value=">">&gt; (greater than)</option>
          <option value="<">&lt; (less than)</option>
        </select>
        <input id="${this.id}-fb-val" class="input" placeholder="Value…" style="height:28px;font-size:12px"
          onkeydown="if(event.key==='Enter'){${this.ns}._applyFromPopup();}">
      </div>
      <div class="filter-builder-actions">
        <button class="btn btn-secondary btn-sm" onclick="document.getElementById('${this.id}-fb-popup')?.remove()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="${this.ns}._applyFromPopup()">Apply</button>
      </div>`;
    document.body.appendChild(popup);
    const rect = anchor.getBoundingClientRect();
    popup.style.top  = (rect.bottom + 6) + 'px';
    popup.style.left = Math.min(rect.left, window.innerWidth - 260) + 'px';
    setTimeout(() => document.getElementById(`${this.id}-fb-val`)?.focus(), 50);
    const closer = e => {
      if (!popup.contains(e.target) && !anchor.contains(e.target)) {
        popup.remove();
        document.removeEventListener('click', closer, true);
      }
    };
    setTimeout(() => document.addEventListener('click', closer, true), 10);
  }

  _applyFromPopup() {
    const field = document.getElementById(`${this.id}-fb-field`)?.value;
    const op    = document.getElementById(`${this.id}-fb-op`)?.value || 'contains';
    const value = (document.getElementById(`${this.id}-fb-val`)?.value || '').trim();
    if (!field || !value) return;
    this.filters.push({ field, op, value });
    document.getElementById(`${this.id}-fb-popup`)?.remove();
    this._refreshFbar();
    this._reload();
  }

  // ─── Sort ─────────────────────────────────────────────────────

  sort(sortField) {
    if (this.sortKey === sortField) {
      this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortKey = sortField;
      this.sortDir = 'desc';
    }
    const tr = document.getElementById(`${this.id}-thr`);
    if (tr) tr.innerHTML = this.thead();
    this._reload();
  }

  // ─── Column resize ─────────────────────────────────────────────

  onResizeStart(e, key) {
    const col = this.cols.find(c => c.key === key);
    if (!col) return;
    const startX = e.clientX, startW = col.w;
    const colEl = document.querySelector(`#${this.id}-cg col[data-col="${key}"]`);
    document.body.style.cursor = 'col-resize';
    const onMove = ev => {
      col.w = Math.max(50, startW + ev.clientX - startX);
      if (colEl) colEl.style.width = col.w + 'px';
    };
    const onUp = () => {
      document.body.style.cursor = '';
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }

  // ─── Column drag-to-reorder ───────────────────────────────────

  onColDragStart(e, key) {
    this._dragSrc = key;
    e.dataTransfer.effectAllowed = 'move';
    e.target.style.opacity = '0.4';
  }

  onColDragOver(e, key) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    document.querySelectorAll(`#${this.id}-thr th[data-col]`).forEach(th => th.style.borderLeft = '');
    if (key !== this._dragSrc) {
      const th = document.querySelector(`#${this.id}-thr th[data-col="${key}"]`);
      if (th) th.style.borderLeft = '2px solid var(--accent)';
    }
  }

  onColDragLeave(e) {
    const th = e.target.closest?.('th');
    if (th) th.style.borderLeft = '';
  }

  onColDrop(e, targetKey) {
    e.preventDefault();
    document.querySelectorAll(`#${this.id}-thr th[data-col]`).forEach(th => {
      th.style.opacity = ''; th.style.borderLeft = '';
    });
    const src = this._dragSrc; this._dragSrc = null;
    if (!src || src === targetKey) return;
    const si = this.cols.findIndex(c => c.key === src);
    const ti = this.cols.findIndex(c => c.key === targetKey);
    if (si < 0 || ti < 0) return;
    const [moved] = this.cols.splice(si, 1);
    this.cols.splice(ti, 0, moved);
    const cg = document.getElementById(`${this.id}-cg`);
    if (cg) cg.innerHTML = this.cols.map(c => `<col data-col="${c.key}" style="width:${c.w}px">`).join('');
    const tr = document.getElementById(`${this.id}-thr`);
    if (tr) tr.innerHTML = this.thead();
    this._reload();
  }
}

// ── Shared table instances ────────────────────────────────────────

const VulnsTable = new PortalTable('vulns', 'VulnsTable', [
  { key:'title',      label:'Title',      w:300, sort:'title'      },
  { key:'severity',   label:'Severity',   w:90,  sort:'severity'   },
  { key:'cvss',       label:'CVSS',       w:65,  sort:'cvss'       },
  { key:'vpr',        label:'VPR',        w:60,  sort:'vpr'        },
  { key:'asset',      label:'Asset',      w:160                    },
  { key:'flags',      label:'Flags',      w:70                     },
  { key:'status',     label:'Status',     w:110, sort:'status'     },
  { key:'first_seen', label:'First Seen', w:90,  sort:'first_seen' },
  { key:'_act',       label:'',           w:36, fixed:true         },
], () => typeof VulnsPage !== 'undefined' && VulnsPage.load?.());

const RecsTable = new PortalTable('recs', 'RecsTable', [
  { key:'title',      label:'Recommendation',    w:300 },
  { key:'severity',   label:'Severity',          w:90  },
  { key:'family',     label:'Standard / Family', w:150 },
  { key:'resource',   label:'Resource',          w:150 },
  { key:'source',     label:'Source',            w:100 },
  { key:'status',     label:'Status',            w:110 },
  { key:'first_seen', label:'First Seen',        w:90  },
  { key:'_act',       label:'',                  w:36, fixed:true },
], () => typeof RecommendationsPage !== 'undefined' && RecommendationsPage.load?.());

const CVETable = new PortalTable('cve', 'CVETable', [
  { key:'cve_id',      label:'CVE ID',      w:140 },
  { key:'description', label:'Description', w:380 },
  { key:'severity',    label:'Severity',    w:90  },
  { key:'cvss_v3',     label:'CVSS v3',     w:80  },
  { key:'published',   label:'Published',   w:90  },
], () => typeof CVEPage !== 'undefined' && CVEPage.load?.());

const WebDomainsTable = new PortalTable('wd', 'WebDomainsTable', [
  { key:'domain',   label:'Domain / Hostname', w:250 },
  { key:'ip',       label:'IP Address',        w:130 },
  { key:'exposure', label:'Exposure',          w:140 },
  { key:'crit',     label:'Criticality',       w:110 },
  { key:'vulns',    label:'Vulns',             w:70  },
  { key:'source',   label:'Source',            w:100 },
  { key:'_act',     label:'',                  w:60, fixed:true },
], () => typeof WebDomainsPage !== 'undefined' && WebDomainsPage._load?.());

const HostsTable = new PortalTable('hosts', 'HostsTable', [
  { key:'icon',    label:'',               w:36,  fixed:true },
  { key:'host',    label:'Host',           w:220 },
  { key:'type',    label:'Type',           w:100 },
  { key:'os',      label:'OS',             w:130 },
  { key:'env',     label:'Environment',    w:115, title:'Environment — affects priority score' },
  { key:'reach',   label:'Reachability',   w:125, title:'Reachability — affects priority score' },
  { key:'tier',    label:'Tier',           w:110, title:'Asset tier — affects priority score' },
  { key:'controls',label:'Controls',       w:115, title:'Compensating controls — affects priority score' },
  { key:'source',  label:'Source',         w:130 },
  { key:'vulns',   label:'Findings',       w:90  },
  { key:'lastseen',label:'Last Seen',      w:82  },
], () => typeof AssetsPage !== 'undefined' && AssetsPage._loadHosts?.());

const CloudTable = new PortalTable('cloud', 'CloudTable', [
  { key:'type',      label:'Type',          w:110 },
  { key:'name',      label:'Name / ID',     w:200 },
  { key:'region',    label:'Region',        w:110 },
  { key:'account',   label:'Account',       w:130 },
  { key:'itype',     label:'Instance Type', w:120 },
  { key:'state',     label:'State',         w:80  },
  { key:'env',       label:'Env',           w:80  },
  { key:'exposure',  label:'Exposure',      w:100 },
  { key:'health',    label:'Health',        w:90  },
  { key:'cves',      label:'CVEs',          w:60  },
  { key:'misconfigs',label:'Misconfigs',    w:85  },
  { key:'lastseen',  label:'Last Seen',     w:90  },
  { key:'_act',      label:'',              w:36, fixed:true },
], () => typeof AssetsPage !== 'undefined' && AssetsPage._cloudAssets && AssetsPage._renderCloudGrid(AssetsPage._cloudAssets));

const PrioTable = new PortalTable('prio', 'PrioTable', [
  { key:'severity',  label:'Severity',  w:80  },
  { key:'score',     label:'Score',     w:55, title:'Priority Score' },
  { key:'cvss',      label:'CVSS',      w:50, title:'CVSS Base Score' },
  { key:'title',     label:'Title',     w:260 },
  { key:'cve',       label:'CVE',       w:120 },
  { key:'asset',     label:'Asset',     w:140 },
  { key:'epss',      label:'EPSS',      w:60  },
  { key:'kev',       label:'KEV',       w:42  },
  { key:'patch',     label:'Patch',     w:42  },
  { key:'status',    label:'Status',    w:90  },
  { key:'sla',       label:'SLA',       w:75  },
], () => typeof PrioritizationPage !== 'undefined' && PrioritizationPage._loadVulns?.());
