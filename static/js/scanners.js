/* Scanners page */

const ScannersPage = {
  _nessusScannerId: null,
  _nucleiScannerId: null,
  _nucleiFile: null,
  _configScannerId: null,   // scanner id being configured (null = creating new)

  // ── Integration catalog ────────────────────────────────────────────────────
  _CATALOG: [
    // Implemented
    { type: 'nessus',   icon: '🔵', label: 'Nessus Professional',       vendor: 'Tenable',           desc: 'Industry-leading enterprise vulnerability scanner with VPR, EPSS & KEV enrichment.',      action: 'nessus' },
    { type: 'nuclei',   icon: '☢️', label: 'Nuclei',                    vendor: 'ProjectDiscovery',  desc: 'Fast, template-based open-source scanner. Push results via file upload or CLI pipe.',     action: 'nuclei' },
    { type: 'mde',      icon: '🔷', label: 'Defender for Endpoint',     vendor: 'Microsoft',         desc: 'Endpoint vulnerability management from Microsoft 365 Defender.',                         action: 'env', envVars: 'MDE_TENANT_ID · MDE_CLIENT_ID · MDE_CLIENT_SECRET' },
    { type: 'openvas',  icon: '🟢', label: 'OpenVAS / Greenbone',       vendor: 'Greenbone',         desc: 'Open-source vulnerability scanner. Self-hosted, full network coverage.',                  action: 'env', envVars: 'OPENVAS_HOST · OPENVAS_USERNAME · OPENVAS_PASSWORD' },
    { type: 'nmap',     icon: '🟡', label: 'NMAP',                      vendor: 'Open Source',       desc: 'Network discovery and port scanning to detect open services.',                           action: 'env', envVars: 'NMAP_TARGETS (comma-separated IPs/CIDRs)' },
    { type: 'pac',      icon: '🟣', label: 'PAC Scanner',               vendor: 'Custom',            desc: 'Custom PAC security scanner integration.',                                               action: 'env', envVars: 'PAC_URL · PAC_API_KEY' },
    // Coming soon
    { type: 'qualys',   icon: '🟠', label: 'Qualys VMDR',              vendor: 'Qualys',             desc: 'Cloud-based vulnerability management, detection & response.',                            soon: true },
    { type: 'rapid7',   icon: '🔴', label: 'Rapid7 InsightVM',         vendor: 'Rapid7',             desc: 'Risk-based vulnerability management with live dashboards.',                              soon: true },
    { type: 'tenableio',icon: '🔵', label: 'Tenable.io',               vendor: 'Tenable',            desc: 'Cloud-hosted vulnerability management platform (Tenable cloud).',                        soon: true },
    { type: 'wiz',      icon: '🔷', label: 'Wiz',                      vendor: 'Wiz',                desc: 'Agentless cloud security posture management (CSPM).',                                     soon: true },
    { type: 'aws',      icon: '🟧', label: 'AWS Security',              vendor: 'Amazon Web Services', desc: 'Asset inventory across all regions (EC2, Lambda, RDS, S3, ECS, EKS, ALB…) + Inspector (CVEs) + Security Hub (CSPM).', action: 'aws' },
    { type: 'burp',     icon: '🟥', label: 'Burp Suite Enterprise',    vendor: 'PortSwigger',        desc: 'Automated web application vulnerability scanning at scale.',                              soon: true },
    { type: 'github',   icon: '⚫', label: 'GitHub Advanced Security', vendor: 'GitHub',             desc: 'Code scanning, secret detection & dependency vulnerability alerts.',                      soon: true },
    { type: 'lacework', icon: '🔶', label: 'Lacework',                 vendor: 'Lacework',           desc: 'Cloud workload security & compliance monitoring.',                                        soon: true },
  ],

  async render(el) {
    el.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;
    const scanners = await API.get('/scanners/');
    const jobs = await Promise.all(
      scanners.map(s => API.get(`/scanners/${s.id}/jobs`, { limit: 5 }).catch(() => []))
    );

    const icons = { nessus: 'N', mde: 'D', openvas: 'O', nmap: 'NM', pac: 'P', nuclei: 'Nu', aws: 'AWS' };
    const typeLabels = {
      nessus: 'Nessus / Tenable', mde: 'MS Defender for Endpoint',
      openvas: 'OpenVAS / Greenbone', nmap: 'NMAP', pac: 'PAC Scanner',
      nuclei: 'Nuclei (ProjectDiscovery)',
      aws: 'AWS Inspector + Config + Security Hub',
    };

    const nessusScanner = scanners.find(s => s.scanner_type === 'nessus');
    if (nessusScanner) ScannersPage._nessusScannerId = nessusScanner.id;
    const nucleiScanner = scanners.find(s => s.scanner_type === 'nuclei');
    if (nucleiScanner) ScannersPage._nucleiScannerId = nucleiScanner.id;
    const awsScanner = scanners.find(s => s.scanner_type === 'aws');
    if (awsScanner) ScannersPage._awsScannerId = awsScanner.id;

    const active = scanners.filter(s => s.configured);
    const activeJobs = active.map(s => {
      const idx = scanners.indexOf(s);
      return jobs[idx] || [];
    });

    const emptyState = active.length === 0 ? `
      <div style="text-align:center;padding:60px 20px;color:var(--text-muted)">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"
          style="margin-bottom:16px;opacity:0.3;display:block;margin-left:auto;margin-right:auto">
          <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
        </svg>
        <div style="font-size:14px;font-weight:500;margin-bottom:6px;color:var(--text-secondary)">No active integrations</div>
        <div style="font-size:12px;margin-bottom:20px">Connect a scanner to start importing vulnerability data.</div>
        <button class="btn btn-primary btn-sm" onclick="ScannersPage.openCatalog()">Browse Integrations</button>
      </div>
    ` : '';

    el.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
        <div>
          <div style="font-size:15px;font-weight:600;color:var(--text-primary)">Active Integrations</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:2px">${active.length} connected · <a href="#" onclick="ScannersPage.openCatalog();return false" style="color:var(--accent)">browse catalog</a></div>
        </div>
        <button class="btn btn-primary" onclick="ScannersPage.openCatalog()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          Add Integration
        </button>
      </div>

      ${emptyState}
      <div class="scanner-grid" id="scanner-grid">
        ${active.map((s, i) => ScannersPage._renderCard(s, activeJobs[i], typeLabels, icons)).join('')}
      </div>

      ${this._catalogModalHtml()}
      ${this._nessusModalHtml()}
      ${this._nucleiModalHtml()}
      ${this._awsModalHtml()}
      ${this._awsInfoModalHtml()}
    `;
  },

  // ── Scanner card ───────────────────────────────────────────────────────────

  _awsScannerId: null,

  _renderCard(s, jobList, typeLabels, icons) {
    const isNessus = s.scanner_type === 'nessus';
    const isNuclei = s.scanner_type === 'nuclei';
    const isAWS    = s.scanner_type === 'aws';
    const statusCls = s.configured
      ? (s.status === 'idle' ? 'status-remediated' : s.status === 'scanning' ? 'status-in_progress' : 'status-open')
      : 'status-accepted';

    const canDelete = isNessus || isAWS;
    return `
      <div class="scanner-card">
        <div class="scanner-card-header">
          <div class="scanner-icon ${s.scanner_type}">${icons[s.scanner_type] || '⚪'}</div>
          <div style="flex:1;min-width:0">
            <div class="scanner-card-name">${s.name}</div>
            <div class="scanner-card-type">${typeLabels[s.scanner_type] || s.scanner_type}</div>
          </div>
          ${canDelete ? `
            <button title="Delete this scanner" onclick="ScannersPage.deleteScanner(${s.id},'${s.name.replace(/'/g,"\\'")}')"
              style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:4px;border-radius:4px;line-height:1;opacity:0.6"
              onmouseover="this.style.opacity='1';this.style.color='#ef4444'" onmouseout="this.style.opacity='0.6';this.style.color='var(--text-muted)'">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/>
                <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
              </svg>
            </button>
          ` : ''}
        </div>

        <div class="scanner-status-row">
          <span>Status</span>
          <span class="status-badge ${statusCls}">${s.status}</span>
        </div>

        <div class="scanner-stat-row">
          <div class="scanner-stat">
            <span class="scanner-stat-label">Findings</span>
            <span class="scanner-stat-val">${s.total_findings.toLocaleString()}</span>
          </div>
          <div class="scanner-stat">
            <span class="scanner-stat-label">Last Sync</span>
            <span class="scanner-stat-val" style="font-size:12px;color:var(--text-secondary)">${s.last_sync ? fmtDateShort(s.last_sync) : '–'}</span>
          </div>
        </div>

        ${isAWS ? `
          <div style="display:flex;gap:6px;margin-bottom:6px">
            <button class="btn btn-primary btn-sm" style="flex:1" ${!s.configured ? 'disabled title="Configure first"' : ''}
              onclick="ScannersPage.runSync(${s.id})">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3"/>
              </svg>
              Sync Now
            </button>
            <button class="btn btn-secondary btn-sm" title="IAM policy &amp; setup info" onclick="ScannersPage.openAWSInfoModal()">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              Info
            </button>
            <button class="btn btn-secondary btn-sm" onclick="ScannersPage.openAWSModal(${s.id})">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="3"/>
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
              </svg>
              ${s.configured ? 'Configure' : 'Connect'}
            </button>
          </div>
          ${!s.configured ? `
            <div style="background:var(--accent-glow);border:1px solid var(--accent);border-radius:6px;padding:8px 10px;margin-bottom:10px">
              <div style="font-size:11px;color:var(--accent);font-weight:600;margin-bottom:2px">Not Connected</div>
              <div style="font-size:10px;color:var(--text-muted)">Click <strong>Connect</strong> to enter your AWS credentials</div>
            </div>
          ` : ''}
        ` : isNuclei ? `
          <div style="display:flex;gap:6px;margin-bottom:6px">
            <button class="btn btn-primary btn-sm" style="flex:1" onclick="ScannersPage.openNucleiModal()">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
              Upload Results
            </button>
            <button class="btn btn-secondary btn-sm" title="How to use Nuclei" onclick="ScannersPage.openNucleiInstructions()">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              Info
            </button>
          </div>
        ` : isNessus ? `
          <div style="display:flex;gap:6px;margin-bottom:6px">
            <button class="btn btn-primary btn-sm" style="flex:1" ${!s.configured ? 'disabled title="Configure first"' : ''}
              onclick="ScannersPage.runScan(${s.id}, '${s.name}')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              Run Scan
            </button>
            <button class="btn btn-secondary btn-sm" onclick="ScannersPage.openNessusModal(${s.id})">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="3"/>
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
              </svg>
              ${s.configured ? 'Configure' : 'Connect'}
            </button>
          </div>
          ${!s.configured ? `
            <div style="background:var(--accent-glow);border:1px solid var(--accent);border-radius:6px;padding:8px 10px;margin-bottom:10px">
              <div style="font-size:11px;color:var(--accent);font-weight:600;margin-bottom:2px">Not Connected</div>
              <div style="font-size:10px;color:var(--text-muted)">Click <strong>Connect</strong> to enter your Nessus URL and API keys</div>
            </div>
          ` : ''}
        ` : `
          ${!s.configured ? `
            <div style="background:var(--medium-bg,rgba(234,179,8,0.1));border:1px solid var(--medium-border,rgba(234,179,8,0.3));border-radius:6px;padding:8px 10px;margin-bottom:10px">
              <div style="font-size:11px;color:#eab308;font-weight:600;margin-bottom:3px">Not Configured</div>
              <div style="font-size:10px;color:var(--text-muted);font-family:monospace">Set credentials in .env and restart</div>
            </div>
          ` : ''}
          <button class="btn btn-primary btn-sm w-full" ${!s.configured ? 'disabled' : ''}
            onclick="ScannersPage.runScan(${s.id}, '${s.name}')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            Run Scan
          </button>
        `}

        ${jobList && jobList.length ? `
          <div style="margin-top:14px">
            <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px">Recent Jobs</div>
            ${jobList.slice(0, 4).map(j => `
              <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border);font-size:11px">
                <span style="color:var(--text-muted)">${fmtDateShort(j.started_at)}</span>
                <span class="status-badge ${j.status === 'completed' ? 'status-remediated' : j.status === 'failed' ? 'status-open' : 'status-in_progress'}" style="font-size:10px">${j.status}</span>
                <span style="color:var(--text-secondary)">${j.findings_count} findings</span>
              </div>
            `).join('')}
          </div>
        ` : ''}
      </div>
    `;
  },

  // ── Integration catalog modal ──────────────────────────────────────────────

  _catalogModalHtml() {
    const available = this._CATALOG.filter(c => !c.soon);
    const soon      = this._CATALOG.filter(c =>  c.soon);

    const card = (c) => {
      if (c.soon) {
        return `
          <div class="catalog-card" data-search="${(c.label + ' ' + c.vendor + ' ' + c.desc).toLowerCase()}"
            style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:14px;opacity:0.55">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:8px">
              <div>
                <div style="font-size:13px;font-weight:600;color:var(--text-primary)">${c.label}</div>
                <div style="font-size:10px;color:var(--text-muted);margin-top:2px">${c.vendor}</div>
              </div>
              <span style="flex-shrink:0;font-size:9px;background:#374151;color:#9ca3af;border-radius:4px;padding:2px 7px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;margin-top:2px">Soon</span>
            </div>
            <div style="font-size:11px;color:var(--text-muted);line-height:1.5">${c.desc}</div>
          </div>`;
      }

      let btn = '';
      if (c.action === 'nessus') {
        btn = `<button class="btn btn-primary btn-sm" style="width:100%" onclick="ScannersPage.closeCatalog();ScannersPage.openNessusModal(null)">+ Add Instance</button>`;
      } else if (c.action === 'nuclei') {
        btn = `<div style="display:flex;gap:6px">
                 <button class="btn btn-primary btn-sm" style="flex:1" onclick="ScannersPage.closeCatalog();ScannersPage.openNucleiModal()">Upload Results</button>
                 <button class="btn btn-secondary btn-sm" onclick="ScannersPage.closeCatalog();ScannersPage.openNucleiInstructions()">Info</button>
               </div>`;
      } else if (c.action === 'aws') {
        btn = `<button class="btn btn-primary btn-sm" style="width:100%" onclick="ScannersPage.closeCatalog();ScannersPage.openAWSModal(null)">+ Add Instance</button>`;
      } else {
        btn = `<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:5px;padding:6px 8px">
                 <div style="font-size:10px;color:var(--text-muted);margin-bottom:3px">Configure in .env</div>
                 <code style="font-size:10px;color:var(--accent)">${c.envVars || ''}</code>
               </div>`;
      }

      return `
        <div class="catalog-card" data-search="${(c.label + ' ' + c.vendor + ' ' + c.desc).toLowerCase()}"
          style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:14px;display:flex;flex-direction:column;gap:10px">
          <div>
            <div style="font-size:13px;font-weight:600;color:var(--text-primary)">${c.label}</div>
            <div style="font-size:10px;color:var(--text-muted);margin-top:2px">${c.vendor}</div>
          </div>
          <div style="font-size:11px;color:var(--text-secondary);line-height:1.5;flex:1">${c.desc}</div>
          ${btn}
        </div>`;
    };

    return `
      <div id="catalog-overlay" onclick="ScannersPage.closeCatalog()"
        style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:1000"></div>
      <div id="catalog-modal"
        style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
               z-index:1001;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;
               width:min(780px,calc(100vw - 32px));max-height:85vh;display:none;flex-direction:column;
               box-shadow:0 20px 60px rgba(0,0,0,0.5)">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--border);flex-shrink:0">
          <div style="font-size:15px;font-weight:600;color:var(--text-primary)">Integration Catalog</div>
          <button onclick="ScannersPage.closeCatalog()"
            style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;padding:4px;line-height:1">✕</button>
        </div>

        <div style="padding:16px 20px 12px;border-bottom:1px solid var(--border);flex-shrink:0">
          <div class="search-wrap" style="position:relative;max-width:100%">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
              style="position:absolute;left:10px;top:50%;transform:translateY(-50%);width:14px;height:14px;color:var(--text-muted);pointer-events:none">
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            <input class="input search-input" id="catalog-search" placeholder="Search integrations…"
              oninput="ScannersPage.filterCatalog(this.value)">
          </div>
        </div>

        <div style="overflow-y:auto;padding:20px;display:flex;flex-direction:column;gap:20px" id="catalog-body">
          <div>
            <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px" id="catalog-label-available">Available Now</div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px" id="catalog-grid-available">
              ${available.map(card).join('')}
            </div>
          </div>
          <div>
            <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px" id="catalog-label-soon">Coming Soon</div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px" id="catalog-grid-soon">
              ${soon.map(card).join('')}
            </div>
          </div>
          <div id="catalog-empty" style="display:none;padding:40px;text-align:center;color:var(--text-muted);font-size:13px">No integrations match your search</div>
        </div>
      </div>`;
  },

  openCatalog() {
    const modal = document.getElementById('catalog-modal');
    document.getElementById('catalog-overlay').style.display = 'block';
    modal.style.display = 'flex';
    const si = document.getElementById('catalog-search');
    if (si) { si.value = ''; this.filterCatalog(''); si.focus(); }
  },

  closeCatalog() {
    document.getElementById('catalog-overlay').style.display = 'none';
    document.getElementById('catalog-modal').style.display = 'none';
  },

  filterCatalog(q) {
    const term = q.trim().toLowerCase();
    const cards = document.querySelectorAll('.catalog-card');
    let visAvail = 0, visSoon = 0;
    cards.forEach(card => {
      const text = card.dataset.search || '';
      const show = !term || text.includes(term);
      card.style.display = show ? '' : 'none';
      const inSoon = card.closest('#catalog-grid-soon');
      if (show) { inSoon ? visSoon++ : visAvail++; }
    });
    document.getElementById('catalog-label-available').style.display = visAvail ? '' : 'none';
    document.getElementById('catalog-label-soon').style.display = visSoon ? '' : 'none';
    document.getElementById('catalog-empty').style.display = (!visAvail && !visSoon) ? 'block' : 'none';
  },

  // ── Nuclei instructions modal ──────────────────────────────────────────────

  openNucleiInstructions() {
    document.getElementById('nuclei-instr-overlay').style.display = 'block';
    document.getElementById('nuclei-instr-modal').style.display = 'block';
  },

  closeNucleiInstructions() {
    document.getElementById('nuclei-instr-overlay').style.display = 'none';
    document.getElementById('nuclei-instr-modal').style.display = 'none';
  },

  // ── Nuclei upload modal ────────────────────────────────────────────────────

  openNucleiModal() {
    this._nucleiFile = null;
    document.getElementById('nuclei-modal-overlay').style.display = 'block';
    document.getElementById('nuclei-modal').style.display = 'block';
    document.getElementById('nuclei-file-name').textContent = 'No file selected';
    document.getElementById('nuclei-upload-btn').disabled = true;
    document.getElementById('nuclei-upload-result').style.display = 'none';
    document.getElementById('nuclei-file-input').value = '';
  },

  closeNucleiModal() {
    document.getElementById('nuclei-modal-overlay').style.display = 'none';
    document.getElementById('nuclei-modal').style.display = 'none';
  },

  _handleNucleiFileSelect(files) {
    if (!files || !files[0]) return;
    this._nucleiFile = files[0];
    document.getElementById('nuclei-file-name').textContent = files[0].name + ' (' + (files[0].size / 1024).toFixed(1) + ' KB)';
    document.getElementById('nuclei-upload-btn').disabled = false;
  },

  _handleNucleiDrop(files) {
    this._handleNucleiFileSelect(files);
  },

  async uploadNucleiFile() {
    if (!this._nucleiFile) return;
    const btn = document.getElementById('nuclei-upload-btn');
    const res = document.getElementById('nuclei-upload-result');
    btn.disabled = true;
    btn.textContent = 'Importing…';
    res.style.display = 'block';
    res.style.background = 'var(--bg-secondary)';
    res.style.color = 'var(--text-muted)';
    res.textContent = 'Uploading and processing…';

    try {
      const form = new FormData();
      form.append('file', this._nucleiFile);
      const r = await fetch('/api/scanners/nuclei/ingest', { method: 'POST', body: form });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || 'Upload failed');
      res.style.background = 'rgba(34,197,94,0.1)';
      res.style.color = '#22c55e';
      res.textContent = '✓ ' + data.message;
      toast(`Nuclei: ${data.findings_imported} findings imported`, 'success');
      setTimeout(async () => {
        this.closeNucleiModal();
        await this.render(document.getElementById('page-content'));
      }, 1200);
    } catch (e) {
      res.style.background = 'rgba(239,68,68,0.1)';
      res.style.color = '#ef4444';
      res.textContent = '✗ ' + e.message;
      btn.disabled = false;
      btn.textContent = 'Import';
    }
  },

  _nucleiModalHtml() {
    const origin = window.location ? window.location.origin : 'http://PORTAL_IP:8000';
    const endpoint = `${origin}/api/scanners/nuclei/ingest`;

    return `
      <!-- Nuclei instructions modal -->
      <div id="nuclei-instr-overlay" onclick="ScannersPage.closeNucleiInstructions()"
        style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:1000"></div>
      <div id="nuclei-instr-modal"
        style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
               z-index:1001;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;
               width:min(640px,calc(100vw - 32px));max-height:88vh;overflow-y:auto;
               box-shadow:0 20px 60px rgba(0,0,0,0.5)">
        <div style="position:sticky;top:0;background:var(--bg-card);display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--border);z-index:1">
          <div>
            <div style="font-size:15px;font-weight:600;color:var(--text-primary)">☢️ Nuclei – Setup & Usage</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px">ProjectDiscovery open-source vulnerability scanner</div>
          </div>
          <button onclick="ScannersPage.closeNucleiInstructions()"
            style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;padding:4px;line-height:1">✕</button>
        </div>

        <div style="padding:20px;display:flex;flex-direction:column;gap:20px;font-size:13px;color:var(--text-secondary)">

          <!-- What is Nuclei -->
          <div>
            <div style="font-size:12px;font-weight:700;color:var(--text-primary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">What is Nuclei?</div>
            <p style="margin:0;line-height:1.7">
              Nuclei is a fast, template-based vulnerability scanner by ProjectDiscovery. It uses community-maintained YAML templates
              to detect CVEs, misconfigurations, exposed panels, default credentials, and more across HTTP, DNS, TCP, SSL and other protocols.
              It is <strong style="color:var(--text-primary)">completely free and open-source</strong>.
            </p>
          </div>

          <!-- Requirements -->
          <div>
            <div style="font-size:12px;font-weight:700;color:var(--text-primary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Requirements</div>
            <div style="display:flex;flex-direction:column;gap:6px">
              ${[
                ['Go 1.21+', 'Required to install Nuclei from source. Or use pre-built binary.'],
                ['nuclei binary', 'Install via go install or download from GitHub releases.'],
                ['nuclei-templates', 'Community templates (~7 000+). Auto-downloaded on first run.'],
                ['Network access', 'Nuclei host must reach the target systems.'],
                ['Portal reachable', 'Nuclei host must reach this portal to push results (or use file upload).'],
              ].map(([k, v]) => `
                <div style="display:flex;gap:10px;align-items:flex-start">
                  <span style="color:#22c55e;font-size:14px;line-height:1.4">✓</span>
                  <div><span style="font-weight:600;color:var(--text-primary)">${k}</span> – ${v}</div>
                </div>
              `).join('')}
            </div>
          </div>

          <!-- Installation -->
          <div>
            <div style="font-size:12px;font-weight:700;color:var(--text-primary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Installation</div>
            <div style="display:flex;flex-direction:column;gap:8px">
              <div>
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">Option A – Go install (recommended)</div>
                <pre style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin:0;font-size:11px;color:var(--accent);overflow-x:auto">go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest</pre>
              </div>
              <div>
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">Option B – Pre-built binary (Linux/macOS/Windows)</div>
                <pre style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin:0;font-size:11px;color:var(--accent);overflow-x:auto"># Download from: https://github.com/projectdiscovery/nuclei/releases
# Extract and place nuclei binary in /usr/local/bin/</pre>
              </div>
              <div>
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">Update templates (run once, then weekly)</div>
                <pre style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin:0;font-size:11px;color:var(--accent)">nuclei -update-templates</pre>
              </div>
            </div>
          </div>

          <!-- Recommended scan command -->
          <div>
            <div style="font-size:12px;font-weight:700;color:var(--text-primary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Recommended Scan Command</div>
            <pre style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:12px 14px;margin:0;font-size:11px;color:var(--accent);line-height:1.8;overflow-x:auto">nuclei \\
  -l targets.txt \\
  -t ~/nuclei-templates/ \\
  -severity info,low,medium,high,critical \\
  -jsonl \\
  -stats \\
  -o nuclei_scan_$(date +%Y%m%d-%H%M).jsonl</pre>
            <div style="margin-top:10px;display:flex;flex-direction:column;gap:5px;font-size:11px;color:var(--text-muted)">
              ${[
                ['-l targets.txt',  'Text file with one URL or IP per line (e.g. https://192.168.1.1)'],
                ['-t ~/nuclei-templates/', 'Path to downloaded templates directory'],
                ['-severity ...',    'Filter by severity levels – adjust as needed'],
                ['-jsonl',           'Output one JSON object per line (required for portal import)'],
                ['-stats',           'Show live progress during scan'],
                ['-o file.jsonl',    'Save results to file for later upload'],
              ].map(([flag, desc]) => `
                <div style="display:flex;gap:8px">
                  <code style="color:var(--accent);min-width:200px;flex-shrink:0">${flag}</code>
                  <span>${desc}</span>
                </div>
              `).join('')}
            </div>
          </div>

          <!-- Delivery options -->
          <div>
            <div style="font-size:12px;font-weight:700;color:var(--text-primary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:10px">Sending Results to Portal</div>

            <div style="display:flex;flex-direction:column;gap:12px">
              <!-- Method 1: pipe -->
              <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:14px">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                  <span style="background:#3b82f620;color:#3b82f6;border:1px solid #3b82f640;border-radius:4px;padding:2px 8px;font-size:10px;font-weight:700">METHOD 1</span>
                  <span style="font-size:12px;font-weight:600;color:var(--text-primary)">Pipe directly (live, recommended)</span>
                </div>
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px">Results stream into the portal in real-time as Nuclei finds them.</div>
                <pre style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin:0;font-size:11px;color:var(--accent);line-height:1.8;overflow-x:auto">nuclei -l targets.txt -t ~/nuclei-templates/ \\
  -severity info,low,medium,high,critical \\
  -jsonl -silent \\
  | curl -s -X POST \\
    -H "Content-Type: application/x-ndjson" \\
    --data-binary @- \\
    ${endpoint}</pre>
              </div>

              <!-- Method 2: file upload -->
              <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:14px">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                  <span style="background:#22c55e20;color:#22c55e;border:1px solid #22c55e40;border-radius:4px;padding:2px 8px;font-size:10px;font-weight:700">METHOD 2</span>
                  <span style="font-size:12px;font-weight:600;color:var(--text-primary)">Upload file via UI or curl</span>
                </div>
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px">Save output to file, then import it manually.</div>
                <pre style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin:0;font-size:11px;color:var(--accent);line-height:1.8;overflow-x:auto"># 1. Run scan and save to file
nuclei -l targets.txt -t ~/nuclei-templates/ \\
  -severity info,low,medium,high,critical -jsonl \\
  -o nuclei_scan_$(date +%Y%m%d-%H%M).jsonl

# 2a. Upload via curl
curl -s -X POST -F "file=@nuclei_scan_*.jsonl" \\
  ${endpoint}

# 2b. Or use the Upload Results button on the scanner card</pre>
              </div>
            </div>
          </div>

          <!-- What gets imported -->
          <div>
            <div style="font-size:12px;font-weight:700;color:var(--text-primary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">What Gets Imported</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:11px">
              ${[
                ['template-id', 'Plugin ID (deduplication key)'],
                ['info.name + matcher-name', 'Vulnerability title'],
                ['info.severity', 'Severity (critical→info)'],
                ['info.classification.cve-id', 'CVE identifiers'],
                ['info.classification.cvss-score', 'CVSS score'],
                ['info.description', 'Description'],
                ['info.remediation', 'Remediation advice'],
                ['host / ip field', 'Asset IP + hostname + port'],
                ['info.tags', 'Plugin family / tags'],
                ['matched-at', 'Evidence URL (in description)'],
              ].map(([k, v]) => `
                <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:5px;padding:6px 8px">
                  <code style="font-size:10px;color:var(--accent);display:block;margin-bottom:2px">${k}</code>
                  <span style="color:var(--text-muted)">${v}</span>
                </div>
              `).join('')}
            </div>
          </div>

          <!-- Auto-resolve note -->
          <div style="background:#22c55e10;border:1px solid #22c55e30;border-radius:8px;padding:12px 14px">
            <div style="font-size:11px;font-weight:600;color:#22c55e;margin-bottom:4px">Auto-Resolve</div>
            <div style="font-size:11px;color:var(--text-muted);line-height:1.6">
              When you run a new Nuclei scan against the same hosts, any vulnerability that was previously <em>open</em>
              but no longer appears in the new results will be automatically marked as <strong style="color:#22c55e">Remediated</strong>.
              Assets not included in the scan are left unchanged.
            </div>
          </div>

        </div>

        <div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end">
          <button class="btn btn-secondary btn-sm" onclick="ScannersPage.closeNucleiInstructions()">Close</button>
          <button class="btn btn-primary btn-sm" onclick="ScannersPage.closeNucleiInstructions();ScannersPage.openNucleiModal()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Upload Results
          </button>
        </div>
      </div>

      <!-- Nuclei upload modal -->
      <div id="nuclei-modal-overlay" onclick="ScannersPage.closeNucleiModal()"
        style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:1000"></div>
      <div id="nuclei-modal"
        style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
               z-index:1001;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;
               width:min(520px,calc(100vw - 32px));box-shadow:0 20px 60px rgba(0,0,0,0.5)">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--border)">
          <div>
            <div style="font-size:15px;font-weight:600;color:var(--text-primary)">☢️ Import Nuclei Results</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Upload .jsonl file from nuclei -jsonl output</div>
          </div>
          <button onclick="ScannersPage.closeNucleiModal()"
            style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;padding:4px;line-height:1">✕</button>
        </div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:16px">
          <div id="nuclei-drop-zone"
            style="border:2px dashed var(--border);border-radius:8px;padding:32px 20px;text-align:center;cursor:pointer;transition:border-color 0.2s"
            onclick="document.getElementById('nuclei-file-input').click()"
            ondragover="event.preventDefault();this.style.borderColor='var(--accent)'"
            ondragleave="this.style.borderColor='var(--border)'"
            ondrop="event.preventDefault();this.style.borderColor='var(--border)';ScannersPage._handleNucleiDrop(event.dataTransfer.files)">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom:8px">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            <div style="font-size:13px;color:var(--text-secondary);margin-bottom:4px">Drop .jsonl file here or click to browse</div>
            <div id="nuclei-file-name" style="font-size:11px;color:var(--text-muted)">No file selected</div>
          </div>
          <input id="nuclei-file-input" type="file" accept=".jsonl,.json,.txt" style="display:none"
            onchange="ScannersPage._handleNucleiFileSelect(this.files)">

          <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:10px 12px">
            <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">Or pipe via CLI</div>
            <pre style="font-size:10px;color:var(--accent);margin:0;white-space:pre-wrap;word-break:break-all;line-height:1.7">nuclei -l targets.txt -t ~/nuclei-templates/ -severity info,low,medium,high,critical -jsonl -silent | curl -s -X POST -H "Content-Type: application/x-ndjson" --data-binary @- ${endpoint}</pre>
          </div>

          <div id="nuclei-upload-result" style="display:none;padding:8px 12px;border-radius:6px;font-size:12px"></div>
        </div>
        <div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end">
          <button class="btn btn-secondary btn-sm" onclick="ScannersPage.closeNucleiModal()">Cancel</button>
          <button id="nuclei-upload-btn" class="btn btn-primary btn-sm" onclick="ScannersPage.uploadNucleiFile()" disabled>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Import
          </button>
        </div>
      </div>
    `;
  },

  // ── Nessus modal ───────────────────────────────────────────────────────────

  _nessusModalHtml() {
    return `
      <div id="nessus-modal-overlay" onclick="ScannersPage.closeNessusModal()"
        style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:1000;align-items:center;justify-content:center">
      </div>
      <div id="nessus-modal"
        style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
               z-index:1001;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;
               width:min(480px,calc(100vw - 32px));box-shadow:0 20px 60px rgba(0,0,0,0.5)">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--border)">
          <div>
            <div style="font-size:15px;font-weight:600;color:var(--text-primary)" id="nessus-modal-title">🔵 Connect Nessus</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Nessus / Tenable.sc API configuration</div>
          </div>
          <button onclick="ScannersPage.closeNessusModal()"
            style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;padding:4px;line-height:1">✕</button>
        </div>

        <div style="padding:20px;display:flex;flex-direction:column;gap:14px">
          <div id="n-name-wrap">
            <label style="display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">Instance Name</label>
            <input id="n-name" type="text" placeholder="e.g. Nessus Production"
              style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                     padding:8px 10px;color:var(--text-primary);font-size:13px;outline:none;box-sizing:border-box"
              onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
          </div>
          <div>
            <label style="display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">Nessus URL</label>
            <input id="n-url" type="text" placeholder="https://192.168.1.100:8834"
              style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                     padding:8px 10px;color:var(--text-primary);font-size:13px;outline:none;box-sizing:border-box"
              onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
            <div>
              <label style="display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">Access Key</label>
              <input id="n-access-key" type="password" placeholder="Leave blank to keep existing"
                style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                       padding:8px 10px;color:var(--text-primary);font-size:13px;outline:none;box-sizing:border-box"
                onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
            </div>
            <div>
              <label style="display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">Secret Key</label>
              <input id="n-secret-key" type="password" placeholder="Leave blank to keep existing"
                style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                       padding:8px 10px;color:var(--text-primary);font-size:13px;outline:none;box-sizing:border-box"
                onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
            </div>
          </div>

          <div>
            <label style="display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">
              Excluded Folder IDs <span style="font-weight:400;text-transform:none;color:var(--text-muted)">(optional)</span>
            </label>
            <input id="n-excluded" type="text" placeholder="1936,1264,1087  — comma-separated folder IDs to skip"
              style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                     padding:8px 10px;color:var(--text-primary);font-size:13px;outline:none;box-sizing:border-box"
              onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Folders listed here are skipped during sync (e.g. archive or policy folders)</div>
          </div>

          <div id="nessus-test-result" style="display:none;padding:8px 12px;border-radius:6px;font-size:12px"></div>
        </div>

        <div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end">
          <button class="btn btn-secondary btn-sm" onclick="ScannersPage.closeNessusModal()">Cancel</button>
          <button class="btn btn-secondary btn-sm" onclick="ScannersPage.testNessusConnection()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
            Test Connection
          </button>
          <button class="btn btn-primary btn-sm" onclick="ScannersPage.saveNessusConfig()">Save &amp; Connect</button>
        </div>
      </div>
    `;
  },

  async openNessusModal(scannerId) {
    this._configScannerId = scannerId || null;
    const isNew = !scannerId;
    document.getElementById('nessus-modal-overlay').style.display = 'block';
    document.getElementById('nessus-modal').style.display = 'block';
    document.getElementById('nessus-test-result').style.display = 'none';
    document.getElementById('n-name-wrap').style.display = isNew ? '' : 'none';
    document.getElementById('n-name').value = '';
    document.getElementById('nessus-modal-title').textContent = isNew ? '🔵 Add Nessus Instance' : '🔵 Configure Nessus';
    if (!isNew) {
      try {
        const cfg = await API.get(`/scanners/${scannerId}/configure`);
        if (cfg.configured) {
          document.getElementById('n-url').value = cfg.url || '';
          document.getElementById('n-excluded').value = cfg.excluded_folders || '';
        }
      } catch (_) {}
    } else {
      document.getElementById('n-url').value = '';
      document.getElementById('n-excluded').value = '';
    }
  },

  closeNessusModal() {
    document.getElementById('nessus-modal-overlay').style.display = 'none';
    document.getElementById('nessus-modal').style.display = 'none';
  },

  _readForm() {
    return {
      url: document.getElementById('n-url').value.trim(),
      access_key: document.getElementById('n-access-key').value.trim(),
      secret_key: document.getElementById('n-secret-key').value.trim(),
      excluded_folders: document.getElementById('n-excluded').value.trim() || null,
    };
  },

  async testNessusConnection() {
    const form = this._readForm();
    const res = document.getElementById('nessus-test-result');
    res.style.display = 'block';
    res.style.background = 'var(--bg-secondary)';
    res.style.color = 'var(--text-muted)';
    res.textContent = 'Testing connection…';
    try {
      const sid = this._configScannerId;
      const url = sid ? `/scanners/${sid}/test` : '/scanners/nessus/test';
      const r = await API.post(url, form);
      if (r.success) {
        res.style.background = 'rgba(34,197,94,0.1)'; res.style.color = '#22c55e';
        res.textContent = '✓ ' + r.message;
      } else {
        res.style.background = 'rgba(239,68,68,0.1)'; res.style.color = '#ef4444';
        res.textContent = '✗ ' + r.message;
      }
    } catch (e) {
      res.style.background = 'rgba(239,68,68,0.1)'; res.style.color = '#ef4444';
      res.textContent = '✗ ' + e.message;
    }
  },

  async saveNessusConfig() {
    const form = this._readForm();
    if (!form.url) { toast('URL is required', 'error'); return; }
    const res = document.getElementById('nessus-test-result');
    res.style.display = 'block'; res.style.background = 'var(--bg-secondary)'; res.style.color = 'var(--text-muted)';
    res.textContent = 'Saving…';
    try {
      let sid = this._configScannerId;
      if (!sid) {
        const name = document.getElementById('n-name').value.trim() || 'Nessus';
        const created = await API.post('/scanners/', { name, scanner_type: 'nessus' });
        sid = created.id;
      }
      await API.post(`/scanners/${sid}/configure`, form);
      res.style.background = 'rgba(34,197,94,0.1)'; res.style.color = '#22c55e';
      res.textContent = '✓ Nessus connected. Reloading…';
      setTimeout(async () => {
        ScannersPage.closeNessusModal();
        await ScannersPage.render(document.getElementById('page-content'));
        toast('Nessus connected – click Run Scan to import data', 'success');
      }, 800);
    } catch (e) {
      res.style.background = 'rgba(239,68,68,0.1)'; res.style.color = '#ef4444';
      res.textContent = '✗ ' + e.message;
    }
  },

  // ── AWS modal ──────────────────────────────────────────────────────────────

  _awsInfoModalHtml() {
    return `
      <div id="aws-info-modal-overlay" onclick="ScannersPage.closeAWSInfoModal()"
        style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:1000"></div>
      <div id="aws-info-modal"
        style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
               z-index:1001;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;
               width:min(560px,calc(100vw - 32px));max-height:85vh;overflow-y:auto;
               box-shadow:0 20px 60px rgba(0,0,0,0.5)">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg-card);z-index:1">
          <div>
            <div style="font-size:15px;font-weight:600;color:var(--text-primary)">🟧 AWS Connector — Setup Guide</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px">IAM policy · all regions · supported resources</div>
          </div>
          <button onclick="ScannersPage.closeAWSInfoModal()"
            style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;padding:4px;line-height:1">✕</button>
        </div>

        <div style="padding:20px;display:flex;flex-direction:column;gap:18px;font-size:13px;color:var(--text-secondary);line-height:1.6">

          <div>
            <div style="font-weight:600;color:var(--text-primary);margin-bottom:6px">How it works</div>
            The connector queries <strong>all enabled AWS regions</strong> automatically. It does not require AWS Config — it calls each service API directly. Findings come from AWS Inspector (CVEs) and Security Hub (CSPM).
          </div>

          <div>
            <div style="font-weight:600;color:var(--text-primary);margin-bottom:6px">Discovered resource types</div>
            <div style="display:flex;flex-wrap:wrap;gap:5px">
              ${['EC2 Instances','Lambda Functions','RDS Instances','S3 Buckets','ECS Clusters','EKS Clusters',
                 'ALB / NLB / CLB','DynamoDB Tables','API Gateway (REST/HTTP)','CloudFront Distributions',
                 'ElastiCache Clusters','SNS Topics','SQS Queues','Secrets Manager'].map(r =>
                `<span style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;padding:2px 8px;font-size:11px;color:var(--text-primary)">${r}</span>`
              ).join('')}
            </div>
          </div>

          <div>
            <div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">Step 1 — Create IAM user</div>
            <div style="color:var(--text-muted);font-size:12px">AWS Console → IAM → Users → Create user → attach the policy below</div>
          </div>

          <div>
            <div style="font-weight:600;color:var(--text-primary);margin-bottom:6px">Step 2 — Attach IAM policy (JSON)</div>
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px">IAM → Users → [user] → Add permissions → Create inline policy → JSON tab</div>
            <pre style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:12px;
                        font-size:11px;color:var(--text-primary);overflow-x:auto;white-space:pre;line-height:1.5;margin:0">{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "ec2:DescribeRegions",
      "ec2:DescribeInstances",
      "lambda:ListFunctions",
      "lambda:ListTags",
      "s3:ListAllMyBuckets",
      "s3:GetBucketTagging",
      "s3:GetBucketPublicAccessBlock",
      "rds:DescribeDBInstances",
      "rds:ListTagsForResource",
      "ecs:ListClusters",
      "ecs:DescribeClusters",
      "eks:ListClusters",
      "eks:DescribeCluster",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTags",
      "dynamodb:ListTables",
      "dynamodb:ListTagsOfResource",
      "apigateway:GET",
      "elasticache:DescribeCacheClusters",
      "elasticache:ListTagsForResource",
      "sns:ListTopics",
      "sns:ListTagsForResource",
      "sqs:ListQueues",
      "sqs:ListQueueTags",
      "secretsmanager:ListSecrets",
      "inspector2:ListFindings",
      "securityhub:GetFindings"
    ],
    "Resource": "*"
  }]
}</pre>
          </div>

          <div>
            <div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">Step 3 — Generate access keys</div>
            <div style="color:var(--text-muted);font-size:12px">IAM → Users → [user] → Security credentials → Create access key → Application running outside AWS</div>
          </div>

          <div>
            <div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">Step 4 — Connect</div>
            <div style="color:var(--text-muted);font-size:12px">Click <strong style="color:var(--text-primary)">Connect</strong> on the AWS Security card, enter the Access Key ID and Secret, set the home region (used as fallback), and click <strong style="color:var(--text-primary)">Save &amp; Connect</strong>. Then click <strong style="color:var(--text-primary)">Sync Now</strong>.</div>
          </div>

          <div style="background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.2);border-radius:6px;padding:10px 12px;font-size:11px;color:#fbbf24">
            The connector uses a <strong>5s connect / 10s read timeout</strong> per API call and automatically skips services you have not enabled in your account.
          </div>

        </div>

        <div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end">
          <button class="btn btn-primary btn-sm" onclick="ScannersPage.closeAWSInfoModal()">Close</button>
        </div>
      </div>`;
  },

  _awsModalHtml() {
    return `
      <div id="aws-modal-overlay" onclick="ScannersPage.closeAWSModal()"
        style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:1000"></div>
      <div id="aws-modal"
        style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
               z-index:1001;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;
               width:min(500px,calc(100vw - 32px));box-shadow:0 20px 60px rgba(0,0,0,0.5)">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--border)">
          <div>
            <div style="font-size:15px;font-weight:600;color:var(--text-primary)" id="aws-modal-title">🟧 Connect AWS Security</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Inspector · Config · Security Hub</div>
          </div>
          <button onclick="ScannersPage.closeAWSModal()"
            style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;padding:4px;line-height:1">✕</button>
        </div>

        <div style="padding:20px;display:flex;flex-direction:column;gap:14px">

          <div id="aws-name-wrap">
            <label style="display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">Instance Name</label>
            <input id="aws-name" type="text" placeholder="e.g. AWS Production (eu-central-1)"
              style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                     padding:8px 10px;color:var(--text-primary);font-size:13px;outline:none;box-sizing:border-box"
              onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
          </div>

          <details style="background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.25);border-radius:7px;font-size:11px;color:#fbbf24">
            <summary style="padding:10px 12px;cursor:pointer;font-weight:600;list-style:none;display:flex;align-items:center;justify-content:space-between;user-select:none">
              <span>Required IAM permissions</span>
              <span style="font-size:9px;opacity:0.7">click to expand</span>
            </summary>
            <div style="padding:0 12px 12px;border-top:1px solid rgba(251,191,36,0.2);margin-top:0">
              <div style="margin-top:10px;line-height:1.7;color:rgba(251,191,36,0.85)">
                Create an IAM user (or role) and attach this <strong>inline policy</strong>:<br>
                <em style="font-size:10px">AWS Console → IAM → Users → [user] → Add permissions → Create inline policy → JSON</em>
              </div>
              <pre style="margin:8px 0 0;background:rgba(0,0,0,0.3);border-radius:5px;padding:10px;font-size:9.5px;color:#fde68a;overflow-x:auto;white-space:pre;line-height:1.5">{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "ec2:DescribeRegions",
      "ec2:DescribeInstances",
      "lambda:ListFunctions",
      "lambda:ListTags",
      "s3:ListAllMyBuckets",
      "s3:GetBucketTagging",
      "s3:GetBucketPublicAccessBlock",
      "rds:DescribeDBInstances",
      "rds:ListTagsForResource",
      "ecs:ListClusters",
      "ecs:DescribeClusters",
      "eks:ListClusters",
      "eks:DescribeCluster",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTags",
      "dynamodb:ListTables",
      "dynamodb:ListTagsOfResource",
      "apigateway:GET",
      "elasticache:DescribeCacheClusters",
      "elasticache:ListTagsForResource",
      "sns:ListTopics",
      "sns:ListTagsForResource",
      "sqs:ListQueues",
      "sqs:ListQueueTags",
      "secretsmanager:ListSecrets",
      "inspector2:ListFindings",
      "securityhub:GetFindings"
    ],
    "Resource": "*"
  }]
}</pre>
              <div style="margin-top:8px;font-size:10px;color:rgba(251,191,36,0.65)">
                After saving the policy, run <strong>Sync</strong> — the connector queries all enabled AWS regions automatically.
              </div>
            </div>
          </details>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
            <div>
              <label style="display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">Access Key ID</label>
              <input id="aws-key-id" type="password" placeholder="AKIA…"
                style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                       padding:8px 10px;color:var(--text-primary);font-size:13px;outline:none;box-sizing:border-box"
                onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
            </div>
            <div>
              <label style="display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">Secret Access Key</label>
              <input id="aws-secret-key" type="password" placeholder="••••••••"
                style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                       padding:8px 10px;color:var(--text-primary);font-size:13px;outline:none;box-sizing:border-box"
                onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
            </div>
          </div>

          <div>
            <label style="display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px">Region</label>
            <input id="aws-region" type="text" value="eu-central-1"
              style="width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;
                     padding:8px 10px;color:var(--text-primary);font-size:13px;outline:none;box-sizing:border-box"
              onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
          </div>

          <div id="aws-test-result" style="display:none;padding:8px 12px;border-radius:6px;font-size:12px"></div>
        </div>

        <div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end">
          <button class="btn btn-secondary btn-sm" onclick="ScannersPage.closeAWSModal()">Cancel</button>
          <button class="btn btn-secondary btn-sm" onclick="ScannersPage.testAWSConnection()">Test Connection</button>
          <button class="btn btn-primary btn-sm" onclick="ScannersPage.saveAWSConfig()">Save &amp; Connect</button>
        </div>
      </div>`;
  },

  async openAWSModal(scannerId) {
    this._configScannerId = scannerId || null;
    const isNew = !scannerId;
    document.getElementById('aws-modal-overlay').style.display = 'block';
    document.getElementById('aws-modal').style.display = 'block';
    document.getElementById('aws-test-result').style.display = 'none';
    document.getElementById('aws-name-wrap').style.display = isNew ? '' : 'none';
    document.getElementById('aws-name').value = '';
    document.getElementById('aws-modal-title').textContent = isNew ? '🟧 Add AWS Instance' : '🟧 Configure AWS Security';
    document.getElementById('aws-key-id').value = '';
    document.getElementById('aws-secret-key').value = '';
    if (!isNew) {
      try {
        const cfg = await API.get(`/scanners/${scannerId}/configure`);
        if (cfg.configured) {
          document.getElementById('aws-region').value = cfg.region || 'eu-central-1';
        }
      } catch (_) {}
    } else {
      document.getElementById('aws-region').value = 'eu-central-1';
    }
  },

  closeAWSModal() {
    document.getElementById('aws-modal-overlay').style.display = 'none';
    document.getElementById('aws-modal').style.display = 'none';
  },

  openAWSInfoModal() {
    document.getElementById('aws-info-modal-overlay').style.display = 'block';
    document.getElementById('aws-info-modal').style.display = 'block';
  },

  closeAWSInfoModal() {
    document.getElementById('aws-info-modal-overlay').style.display = 'none';
    document.getElementById('aws-info-modal').style.display = 'none';
  },

  _readAWSForm() {
    return {
      access_key_id: document.getElementById('aws-key-id').value.trim(),
      secret_access_key: document.getElementById('aws-secret-key').value.trim(),
      region: document.getElementById('aws-region').value.trim() || 'eu-central-1',
    };
  },

  async testAWSConnection() {
    const form = this._readAWSForm();
    const res = document.getElementById('aws-test-result');
    res.style.display = 'block'; res.style.background = 'var(--bg-secondary)'; res.style.color = 'var(--text-muted)';
    res.textContent = 'Testing connection…';
    try {
      const sid = this._configScannerId;
      const url = sid ? `/scanners/${sid}/test` : '/scanners/aws/test';
      const r = await API.post(url, form);
      if (r.success) {
        res.style.background = 'rgba(34,197,94,0.1)'; res.style.color = '#22c55e';
        res.textContent = '✓ ' + r.message;
      } else {
        res.style.background = 'rgba(239,68,68,0.1)'; res.style.color = '#ef4444';
        res.textContent = '✗ ' + r.message;
      }
    } catch (e) {
      res.style.background = 'rgba(239,68,68,0.1)'; res.style.color = '#ef4444';
      res.textContent = '✗ ' + e.message;
    }
  },

  async saveAWSConfig() {
    const form = this._readAWSForm();
    if (!form.access_key_id || !form.secret_access_key) { toast('Access Key ID and Secret are required', 'error'); return; }
    const res = document.getElementById('aws-test-result');
    res.style.display = 'block'; res.style.background = 'var(--bg-secondary)'; res.style.color = 'var(--text-muted)';
    res.textContent = 'Saving…';
    try {
      let sid = this._configScannerId;
      if (!sid) {
        const name = document.getElementById('aws-name').value.trim() || 'AWS Security';
        const created = await API.post('/scanners/', { name, scanner_type: 'aws' });
        sid = created.id;
      }
      await API.post(`/scanners/${sid}/configure`, form);
      res.style.background = 'rgba(34,197,94,0.1)'; res.style.color = '#22c55e';
      res.textContent = '✓ AWS connected. Reloading…';
      setTimeout(async () => {
        ScannersPage.closeAWSModal();
        await ScannersPage.render(document.getElementById('page-content'));
        toast('AWS connected – click Sync Now to import data', 'success');
      }, 800);
    } catch (e) {
      res.style.background = 'rgba(239,68,68,0.1)'; res.style.color = '#ef4444';
      res.textContent = '✗ ' + e.message;
    }
  },

  async runSync(scannerId) {
    try {
      const result = await API.post(`/scanners/${scannerId}/sync`);
      toast(`Sync started (job #${result.job_id})`, 'success');
      setTimeout(() => this.render(document.getElementById('page-content')), 2000);
    } catch (e) {
      toast(e.message, 'error');
    }
  },

  async deleteScanner(scannerId, name) {
    if (!confirm(`Delete scanner "${name}"? This will remove its configuration and cannot be undone.`)) return;
    try {
      await API.delete(`/scanners/${scannerId}`);
      toast(`Scanner "${name}" deleted`, 'success');
      await this.render(document.getElementById('page-content'));
    } catch (e) {
      toast(e.message, 'error');
    }
  },

  // ── Run scan ───────────────────────────────────────────────────────────────

  async runScan(scannerId, scannerName) {
    try {
      const result = await API.post(`/scanners/${scannerId}/scan`);
      toast(`Scan started: ${scannerName} (job #${result.job_id})`, 'success');
      setTimeout(() => this.render(document.getElementById('page-content')), 2000);
    } catch (e) {
      toast(e.message, 'error');
    }
  },
};
