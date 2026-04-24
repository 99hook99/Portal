/* ============================================================
   Web & Domains page – standalone top-level inventory page
   ============================================================ */

const WebDomainsPage = {
  state: { page: 1, per_page: 25, search: '', criticality: '', source: '', exposure: '' },

  // Type options for reclassifying (move OUT of web to another type)
  _TYPE_OPTS: [
    { t:'host',        c:'#3b82f6', label:'Host',        icon:'<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>' },
    { t:'server',      c:'#22c55e', label:'Server',      icon:'<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>' },
    { t:'workstation', c:'#06b6d4', label:'Workstation', icon:'<rect x="2" y="3" width="20" height="13" rx="2"/><polyline points="8 21 12 17 16 21"/>' },
    { t:'web',         c:'#10b981', label:'Web / Domain',icon:'<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>' },
    { t:'cloud_resource', c:'#8b5cf6', label:'Cloud',    icon:'<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>' },
  ],

  async render(el) {
    el.innerHTML = `
      <div class="filter-bar" style="flex-wrap:wrap;gap:8px;padding-bottom:10px">
        <div class="search-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input class="input search-input" id="wd-search" placeholder="Search domain, hostname or IP…">
        </div>
        <select class="input" id="wd-exposure" style="width:155px">
          <option value="">All Exposure</option>
          <option value="exposed">Internet Exposed</option>
          <option value="partial">Partial</option>
          <option value="internal">Internal</option>
          <option value="unknown">Unknown</option>
        </select>
        <select class="input" id="wd-crit" style="width:140px">
          <option value="">All Criticality</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select class="input" id="wd-src" style="width:130px">
          <option value="">All Sources</option>
          <option value="nessus">Nessus</option>
          <option value="nuclei">Nuclei</option>
          <option value="aws">AWS</option>
          <option value="manual">Manual</option>
        </select>
        <div style="margin-left:auto;display:flex;align-items:center;gap:8px">
          <span style="font-size:12px;color:var(--text-muted)" id="wd-count">–</span>
        </div>
      </div>
      ${WebDomainsTable.filterBarHtml()}
      <div id="wd-content"><div class="loader"><div class="spinner"></div></div></div>
    `;

    const s = this.state;
    document.getElementById('wd-search').addEventListener('input', debounce(e => {
      s.search = e.target.value; s.page = 1; this._load();
    }, 300));
    const bind = (id, key) => {
      const el2 = document.getElementById(id);
      if (!el2) return;
      el2.value = s[key] || '';
      el2.addEventListener('change', e => { s[key] = e.target.value; s.page = 1; this._load(); });
    };
    bind('wd-exposure', 'exposure');
    bind('wd-crit',     'criticality');
    bind('wd-src',      'source');

    return this._load();
  },

  async _load() {
    const { page, per_page, search, criticality, source, exposure } = this.state;
    const params = { page, per_page, identity_type: 'web' };
    if (search)      params.search      = search;
    if (criticality) params.criticality = criticality;
    if (source)      params.source      = source;
    if (exposure)    params.internet_exposure = exposure;

    const wrap = document.getElementById('wd-content');
    if (!wrap) return;

    const data = await API.get('/assets/', params);
    const cnt  = document.getElementById('wd-count');
    if (cnt) cnt.textContent = `${data.total || 0} domain${(data.total||0)!==1?'s':''}`;

    if (!data.items?.length) {
      wrap.innerHTML = `
        <div style="text-align:center;padding:64px 20px;color:var(--text-muted)">
          <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"
            style="opacity:.3;margin-bottom:14px;display:block;margin-left:auto;margin-right:auto">
            <circle cx="12" cy="12" r="10"/>
            <line x1="2" y1="12" x2="22" y2="12"/>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </svg>
          <div style="font-size:14px;font-weight:500;margin-bottom:8px">No web assets found</div>
          <div style="font-size:12px;max-width:420px;margin:0 auto;line-height:1.7">
            Assets auto-classify as <strong>web</strong> when:<br>
            hostname starts with <code>www.</code> &nbsp;·&nbsp;
            <code>asset_type</code> is <code>web / website / domain / webapp</code><br>
            tags contain <code>website</code>, <code>domain</code>, or <code>webapp</code>
          </div>
        </div>`;
      return;
    }

    const EXP_CFG = {
      exposed:  { label:'Internet Exposed', color:'#ef4444' },
      partial:  { label:'Partial',          color:'#f97316' },
      internal: { label:'Internal',         color:'#22c55e' },
      unknown:  { label:'Unknown',          color:'#64748b' },
    };
    const CRIT_COLOR = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--low)' };
    const SRC_COLOR  = { nessus:'#3b82f6', nuclei:'#22c55e', aws:'#f97316', mde:'#8b5cf6' };

    const WD_GETTERS = {
      domain:   a => a.fqdn || a.hostname || a.ip_address,
      ip:       a => a.ip_address,
      exposure: a => a.internet_exposure,
      crit:     a => a.business_criticality,
      vulns:    a => (a.critical_count||0) + (a.high_count||0),
      source:   a => a.source,
    };
    const filtered = WebDomainsTable.applyFilters(data.items, WD_GETTERS);

    const rows = filtered.map(a => {
      const domain   = a.fqdn || a.hostname || a.ip_address || `Asset #${a.id}`;
      const ip       = a.ip_address || '–';
      const expCfg   = EXP_CFG[a.internet_exposure] || EXP_CFG.unknown;
      const critC    = CRIT_COLOR[a.business_criticality] || '#64748b';
      const srcC     = SRC_COLOR[(a.source||'').toLowerCase()] || '#64748b';
      const vulnHigh = (a.critical_count||0) + (a.high_count||0);

      const cells = {
        domain:   `<td><div style="display:flex;align-items:center;gap:9px"><span style="width:26px;height:26px;border-radius:7px;background:#10b98115;border:1px solid #10b98130;color:#10b981;display:flex;align-items:center;justify-content:center;flex-shrink:0;cursor:pointer" title="Type: Web / Domain — click to change" onclick="event.stopPropagation();WebDomainsPage._showTypePicker(event,${a.id},'web')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span><div style="min-width:0"><div style="font-weight:500;font-size:13px;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(domain)}</div>${a.fqdn && a.hostname && a.fqdn !== a.hostname ? `<div style="font-size:10px;color:var(--text-muted);margin-top:1px">${esc(a.hostname)}</div>` : ''}</div></div></td>`,
        ip:       `<td style="font-family:monospace;font-size:11px;color:var(--text-muted)">${esc(ip)}</td>`,
        exposure: `<td><span style="font-size:11px;padding:2px 8px;border-radius:4px;border:1px solid ${expCfg.color}40;color:${expCfg.color};background:${expCfg.color}12">${expCfg.label}</span></td>`,
        crit:     `<td>${a.business_criticality ? `<span style="font-size:11px;padding:2px 8px;border-radius:4px;border:1px solid ${critC}40;color:${critC};background:${critC}12">${a.business_criticality}</span>` : `<span style="color:var(--text-muted);font-size:12px">–</span>`}</td>`,
        vulns:    `<td>${vulnHigh > 0 ? `<span class="sev-badge sev-high" style="font-size:11px">${vulnHigh} High+</span>` : `<span style="font-size:11px;color:var(--low)">✓ Clean</span>`}</td>`,
        source:   `<td>${a.source ? `<span style="font-size:11px;padding:2px 8px;border-radius:4px;border:1px solid ${srcC}40;color:${srcC};background:${srcC}12">${esc(a.source)}</span>` : '<span style="color:var(--text-muted)">–</span>'}</td>`,
        _act:     `<td><button class="btn btn-secondary btn-sm" style="padding:3px 10px;font-size:11px" onclick="event.stopPropagation();showAssetDetail(${a.id})">View</button></td>`,
      };
      return `<tr class="asset-row" draggable="true" ondragstart="WebDomainsPage._dragStart(event,${a.id},'${esc(domain)}')" ondragend="WebDomainsPage._dragEnd(event)" onclick="if(!WebDomainsPage._dragHappened) showAssetDetail(${a.id})" style="cursor:pointer">${WebDomainsTable.cols.map(col => cells[col.key]||'<td></td>').join('')}</tr>`;
    }).join('');

    const total = data.total || 0;
    const pages = Math.ceil(total / per_page);
    const pager = pages > 1 ? `
      <div style="display:flex;align-items:center;gap:8px;padding:10px 0;justify-content:flex-end">
        <button class="btn btn-secondary btn-sm" ${page<=1?'disabled':''} onclick="WebDomainsPage.state.page=${page-1};WebDomainsPage._load()">‹ Prev</button>
        <span style="font-size:12px;color:var(--text-muted)">Page ${page} / ${pages}</span>
        <button class="btn btn-secondary btn-sm" ${page>=pages?'disabled':''} onclick="WebDomainsPage.state.page=${page+1};WebDomainsPage._load()">Next ›</button>
      </div>` : '';

    wrap.innerHTML = `
      <div style="overflow-x:auto">
        <table style="table-layout:fixed;min-width:500px">
          ${WebDomainsTable.colgroup()}
          <thead><tr id="wd-thr">${WebDomainsTable.thead()}</tr></thead>
          <tbody>${rows.length ? rows : `<tr><td colspan="${WebDomainsTable.cols.length}">${emptyState('No web assets match the current filters')}</td></tr>`}</tbody>
        </table>
      </div>
      ${pager}`;
  },

  // ── Type picker (click on web icon) ─────────────────────────
  _showTypePicker(evt, assetId, currentType) {
    document.getElementById('type-picker-popup')?.remove();

    const rect = evt.currentTarget.getBoundingClientRect();
    const popup = document.createElement('div');
    popup.id = 'type-picker-popup';
    popup.className = 'type-picker-popup';

    // Position: below the badge, left-aligned; clamp to viewport right edge
    const left = Math.min(rect.left, window.innerWidth - 190);
    popup.style.cssText = `position:fixed;top:${rect.bottom+4}px;left:${left}px;z-index:9999`;

    popup.innerHTML = `
      <div class="type-picker-header">Move to category</div>
      ${this._TYPE_OPTS.map(o => `
        <div class="type-picker-item ${o.t === currentType ? 'active' : ''}"
          onclick="WebDomainsPage._setAssetType(${assetId},'${o.t}')">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${o.c}" stroke-width="2">${o.icon}</svg>
          <span style="color:${o.t === currentType ? 'var(--text-primary)' : o.c}">${o.label}</span>
          ${o.t === currentType ? '<span class="type-picker-check">✓ current</span>' : ''}
        </div>`).join('')}
    `;

    document.body.appendChild(popup);

    const close = e => {
      if (!popup.contains(e.target)) { popup.remove(); document.removeEventListener('click', close); }
    };
    setTimeout(() => document.addEventListener('click', close), 0);
  },

  async _setAssetType(assetId, newType) {
    document.getElementById('type-picker-popup')?.remove();
    try {
      await API.patch(`/assets/${assetId}`, { identity_type: newType });
      const label = this._TYPE_OPTS.find(o => o.t === newType)?.label || newType;
      toast(`Moved to ${label}`, 'success');
      this._load();
    } catch(e) { toast(e.message, 'error'); }
  },

  // ── Drag & drop (fixed palette at bottom) ───────────────────
  _dragging: null,
  _dragHappened: false,

  _dragStart(evt, id, name) {
    this._dragging = { id, name };
    this._dragHappened = true;
    evt.dataTransfer.effectAllowed = 'move';
    evt.dataTransfer.setData('text/plain', String(id));
    evt.currentTarget.style.opacity = '0.5';
    this._showDragPalette();
  },

  _showDragPalette() {
    let fp = document.getElementById('wd-palette-fixed');
    if (!fp) {
      fp = document.createElement('div');
      fp.id = 'wd-palette-fixed';
      fp.className = 'type-palette-fixed';
      fp.innerHTML = `
        <span class="type-palette-label">Drop to move to:</span>
        ${this._TYPE_OPTS.filter(b => b.t !== 'web').map(b => `
          <div class="type-bucket" data-type="${b.t}" style="--bucket-color:${b.c}"
            ondragover="WebDomainsPage._bucketOver(this,event)"
            ondragleave="WebDomainsPage._bucketLeave(this)"
            ondrop="WebDomainsPage._bucketDrop(this,'${b.t}',event)">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${b.c}" stroke-width="2">${b.icon}</svg>
            ${b.label}
          </div>`).join('')}
      `;
      document.body.appendChild(fp);
    }
    fp.style.display = 'flex';
  },

  _dragEnd(evt) {
    if (evt?.currentTarget) evt.currentTarget.style.opacity = '';
    this._dragging = null;
    document.querySelectorAll('#wd-palette-fixed .type-bucket').forEach(b => b.classList.remove('drag-over'));
    const fp = document.getElementById('wd-palette-fixed');
    if (fp) fp.style.display = 'none';
    setTimeout(() => { this._dragHappened = false; }, 150);
  },

  _bucketOver(el, evt) {
    evt.preventDefault();
    evt.dataTransfer.dropEffect = 'move';
    el.classList.add('drag-over');
  },

  _bucketLeave(el) {
    el.classList.remove('drag-over');
  },

  async _bucketDrop(el, newType, evt) {
    evt.preventDefault();
    el.classList.remove('drag-over');
    const assetId = this._dragging?.id;
    if (!assetId) return;
    await this._setAssetType(assetId, newType);
  },
};
