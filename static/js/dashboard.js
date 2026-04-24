/* Dashboard page */

const DashboardPage = {
  charts: {},

  async render(el) {
    el.innerHTML = `
      <div class="stat-grid" id="dash-stats">
        ${[...Array(10)].map(() => `<div class="stat-card" style="height:80px;background:var(--bg-card-hover)"></div>`).join('')}
      </div>
      <div class="grid-2-1" style="margin-bottom:16px">
        <div class="card">
          <div class="card-header"><span class="card-title">Vulnerability Trend (30 days)</span></div>
          <div class="chart-wrap"><canvas id="chart-trend" height="80"></canvas></div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Severity Distribution</span></div>
          <div class="chart-wrap" style="max-width:220px;margin:0 auto">
            <canvas id="chart-sev" height="180"></canvas>
          </div>
        </div>
      </div>
      <div class="grid-2" style="margin-bottom:16px">
        <div class="card">
          <div class="card-header"><span class="card-title">OS Distribution</span></div>
          <div class="chart-wrap"><canvas id="chart-os" height="100"></canvas></div>
        </div>
        <div class="card">
          <div class="card-header">
            <span class="card-title">Top Vulnerable Assets</span>
            <a class="btn btn-secondary btn-sm" data-page="assets" onclick="navigate(this.dataset.page)">View all</a>
          </div>
          <div id="dash-top-assets"></div>
        </div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><span class="card-title">Recent Scan Activity</span></div>
          <div id="dash-activity"></div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Exploit Intelligence</span></div>
          <div id="dash-exploit"></div>
        </div>
      </div>
      <div class="grid-2-1" style="margin-top:16px">
        <div class="card">
          <div class="card-header">
            <span class="card-title">Accepted Risk</span>
            <a class="btn btn-secondary btn-sm" onclick="VulnsPage.state.status='accepted';navigate('vulnerabilities')">View all</a>
          </div>
          <div id="dash-accepted"></div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Status Distribution</span></div>
          <div class="chart-wrap" style="max-width:220px;margin:0 auto"><canvas id="chart-status" height="180"></canvas></div>
        </div>
      </div>
      <div class="grid-2" style="margin-top:16px">
        <div class="card">
          <div class="card-header"><span class="card-title">Open Vuln Age</span></div>
          <div class="chart-wrap"><canvas id="chart-age" height="100"></canvas></div>
        </div>
      </div>
    `;

    this.loadStats();
    this.loadTrend();
    this.loadTopAssets();
    this.loadActivity();
    this.loadOsDistribution();
    this.loadExploitStats();
    this.updateScannerStatus();
    this.loadStatusDistribution();
    this.loadAcceptedRisks();
    this.loadRiskAge();
  },

  async loadStats() {
    const s = await API.get('/dashboard/stats');
    const d = await API.get('/dashboard/severity-distribution');

    const grid = document.getElementById('dash-stats');
    grid.innerHTML = `
      ${statCard('Total Vulns',      s.total_vulnerabilities, 'blue')}
      ${statCard('Critical',         s.critical,  'critical', 'critical')}
      ${statCard('High',             s.high,       'high',     'high')}
      ${statCard('Medium',           s.medium,     'medium',   'medium')}
      ${statCard('Low',              s.low,        'low',      'low')}
      ${statCard('Total Assets',     s.total_assets,     'cyan')}
      ${statCard('Assets at Risk',   s.assets_at_risk,   'high')}
      ${statCard('New (30d)',        s.new_30d,          'blue')}
      ${statCard('Remediated (30d)', s.remediated_30d,  'low')}
      ${statCard('Info',             s.info,       '',  '')}
    `;

    // Update nav badge
    const badge = document.getElementById('nav-badge-vulns');
    if (badge) badge.textContent = s.open_vulnerabilities;

    this.renderDonut(d);
  },

  async loadExploitStats() {
    let stats;
    try { stats = await API.get('/dashboard/enrichment-stats'); } catch { return; }
    const el = document.getElementById('dash-exploit');
    if (!el) return;
    el.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:8px 0">
        <div style="text-align:center;padding:16px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
          <div style="font-size:28px;font-weight:700;color:#f97316">${stats.exploit_available}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;text-transform:uppercase;letter-spacing:0.5px">Exploit Available</div>
        </div>
        <div style="text-align:center;padding:16px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
          <div style="font-size:28px;font-weight:700;color:#ef4444">${stats.cisa_kev}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;text-transform:uppercase;letter-spacing:0.5px">CISA KEV</div>
        </div>
      </div>
      ${stats.avg_vpr != null ? `
        <div style="padding:12px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border);margin-top:4px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="font-size:12px;color:var(--text-muted)">Avg VPR Score (open vulns)</span>
            <span style="font-size:20px;font-weight:700;color:#f97316">${stats.avg_vpr}</span>
          </div>
          <div style="margin-top:6px;background:var(--border);border-radius:4px;height:6px">
            <div style="background:#f97316;width:${Math.min(stats.avg_vpr*10,100)}%;height:100%;border-radius:4px"></div>
          </div>
        </div>
      ` : ''}
      <div style="margin-top:12px;font-size:11px;color:var(--text-muted);line-height:1.7">
        <div><strong style="color:var(--text-secondary)">Exploit Available</strong> – vulnerability has known public exploit code</div>
        <div><strong style="color:var(--text-secondary)">CISA KEV</strong> – actively exploited in the wild (CISA catalog)</div>
        <div><strong style="color:var(--text-secondary)">VPR</strong> – Tenable Vulnerability Priority Rating (0–10)</div>
      </div>
    `;
  },

  renderDonut(d) {
    const ctx = document.getElementById('chart-sev');
    if (!ctx) return;
    if (this.charts.sev) this.charts.sev.destroy();

    const getStyle = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
    this.charts.sev = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
          data: [d.critical, d.high, d.medium, d.low, d.info],
          backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e','#64748b'],
          borderWidth: 0,
          hoverOffset: 6,
        }],
      },
      options: {
        cutout: '68%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#8a9abf', font: { size: 11 }, boxWidth: 10, padding: 12 },
          },
          tooltip: {
            callbacks: {
              label: ctx => ` ${ctx.label}: ${ctx.parsed.toLocaleString()}`,
            },
          },
        },
      },
    });
  },

  async loadTrend() {
    const points = await API.get('/dashboard/trend');
    const ctx = document.getElementById('chart-trend');
    if (!ctx) return;
    if (this.charts.trend) this.charts.trend.destroy();

    const labels  = points.map(p => p.date.slice(5));
    const mkDs = (label, key, color) => ({
      label,
      data: points.map(p => p[key]),
      borderColor: color,
      backgroundColor: color + '18',
      borderWidth: 1.5,
      pointRadius: 0,
      fill: false,
      tension: 0.3,
    });

    this.charts.trend = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          mkDs('Critical', 'critical', '#ef4444'),
          mkDs('High',     'high',     '#f97316'),
          mkDs('Medium',   'medium',   '#eab308'),
          mkDs('Low',      'low',      '#22c55e'),
        ],
      },
      options: {
        responsive: true,
        interaction: { mode: 'index', intersect: false },
        scales: {
          x: { ticks: { color: '#4d5f80', font: { size: 10 }, maxTicksLimit: 10 }, grid: { color: '#1c2840' } },
          y: { ticks: { color: '#4d5f80', font: { size: 10 } }, grid: { color: '#1c2840' }, beginAtZero: true },
        },
        plugins: {
          legend: { labels: { color: '#8a9abf', font: { size: 11 }, boxWidth: 12, padding: 12 } },
        },
      },
    });
  },

  async loadTopAssets() {
    const items = await API.get('/dashboard/top-assets', { limit: 8 });
    const el = document.getElementById('dash-top-assets');
    if (!items.length) { el.innerHTML = emptyState('No assets found'); return; }

    el.innerHTML = `
      <table>
        <thead><tr>
          <th>Host</th><th>IP</th><th>Criticality</th><th>Vulns</th><th>Risk</th>
        </tr></thead>
        <tbody>
          ${items.map(a => `
            <tr style="cursor:pointer" onclick="loadAssetDetail(${a.id})">
              <td class="primary truncate" style="max-width:130px">${a.hostname || '–'}</td>
              <td style="font-family:monospace;font-size:12px">${a.ip_address || '–'}</td>
              <td>${critBadge(a.criticality)}</td>
              <td><span style="font-weight:600;color:${a.vuln_count > 10 ? 'var(--critical)' : 'var(--text-secondary)'}">${a.vuln_count}</span></td>
              <td style="min-width:100px">
                <div class="risk-bar-wrap">
                  <div class="risk-bar"><div class="risk-bar-fill ${a.risk_score > 60 ? 'critical' : a.risk_score > 30 ? 'high' : ''}" style="width:${Math.min(a.risk_score,100)}%"></div></div>
                  <span class="risk-score-num">${a.risk_score.toFixed(0)}</span>
                </div>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>`;
  },

  async loadOsDistribution() {
    let items;
    try { items = await API.get('/dashboard/os-distribution'); } catch { return; }
    const ctx = document.getElementById('chart-os');
    if (!ctx || !items.length) {
      if (ctx) ctx.parentElement.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px">No OS data yet – run a Nessus scan to populate</div>`;
      return;
    }
    if (this.charts.os) this.charts.os.destroy();

    const colors = ['#3b82f6','#8b5cf6','#06b6d4','#10b981','#f59e0b','#ef4444','#f97316','#ec4899','#6366f1','#14b8a6'];
    this.charts.os = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: items.map(i => i.os.length > 30 ? i.os.slice(0,28)+'…' : i.os),
        datasets: [{
          data: items.map(i => i.count),
          backgroundColor: items.map((_, i) => colors[i % colors.length] + 'cc'),
          borderColor: items.map((_, i) => colors[i % colors.length]),
          borderWidth: 1,
          borderRadius: 4,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: c => ` ${c.parsed.x} host${c.parsed.x !== 1 ? 's' : ''}` } },
        },
        scales: {
          x: { ticks: { color: '#4d5f80', font: { size: 10 } }, grid: { color: '#1c2840' }, beginAtZero: true },
          y: { ticks: { color: '#8a9abf', font: { size: 11 } }, grid: { display: false } },
        },
      },
    });
  },

  async loadActivity() {
    const items = await API.get('/dashboard/recent-activity', { limit: 8 });
    const el = document.getElementById('dash-activity');

    const scannerIcons = { nessus: '🔵', mde: '🔷', openvas: '🟢', nmap: '🟡', pac: '🟣' };

    el.innerHTML = items.length ? `
      <div style="display:flex;flex-direction:column;gap:8px">
        ${items.map(j => `
          <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
            <span style="font-size:16px">${scannerIcons[j.scanner_type] || '⚪'}</span>
            <div style="flex:1;min-width:0">
              <div style="font-size:12.5px;font-weight:500;color:var(--text-primary);margin-bottom:2px">${j.scanner}</div>
              <div style="font-size:11px;color:var(--text-muted)">${fmtDate(j.started_at)}</div>
            </div>
            <span class="status-badge status-${j.status === 'completed' ? 'remediated' : j.status === 'failed' ? 'open' : 'in_progress'}">${j.status}</span>
            <span style="font-size:11px;color:var(--text-muted);min-width:50px;text-align:right">${j.findings_count} findings</span>
          </div>
        `).join('')}
      </div>
    ` : emptyState('No scan jobs yet');
  },

  async loadStatusDistribution() {
    let d;
    try { d = await API.get('/dashboard/status-distribution'); } catch { return; }
    const ctx = document.getElementById('chart-status');
    if (!ctx) return;
    if (this.charts.status) this.charts.status.destroy();
    this.charts.status = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Open', 'In Progress', 'Accepted', 'Remediated'],
        datasets: [{
          data: [d.open, d.in_progress, d.accepted, d.remediated],
          backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
          borderWidth: 0,
          hoverOffset: 6,
        }],
      },
      options: {
        cutout: '68%',
        plugins: {
          legend: { position: 'bottom', labels: { color: '#8a9abf', font: { size: 11 }, boxWidth: 10, padding: 12 } },
          tooltip: { callbacks: { label: c => ` ${c.label}: ${c.parsed.toLocaleString()}` } },
        },
      },
    });
  },

  async loadAcceptedRisks() {
    let items;
    try { items = await API.get('/dashboard/accepted-risks', { limit: 15 }); } catch { return; }
    const el = document.getElementById('dash-accepted');
    if (!el) return;
    if (!items.length) { el.innerHTML = emptyState('No accepted risks'); return; }
    el.innerHTML = `
      <table>
        <thead><tr>
          <th style="width:40%">Title</th><th>Severity</th><th>CVSS</th><th>VPR</th><th>Asset</th><th>Flags</th>
        </tr></thead>
        <tbody>
          ${items.map(v => `
            <tr style="cursor:pointer" onclick="VulnsPage.openDetail(${v.id})">
              <td class="primary truncate" style="max-width:260px" title="${esc(v.title)}">${esc(v.title)}</td>
              <td>${sevBadge(v.severity)}</td>
              <td><span class="cvss-score cvss-${v.severity}">${v.cvss_score != null ? v.cvss_score.toFixed(1) : '–'}</span></td>
              <td><span style="font-size:12px;font-weight:600;color:${v.vpr_score >= 7 ? 'var(--critical)' : v.vpr_score >= 4 ? '#f97316' : 'var(--text-muted)'}">${v.vpr_score != null ? v.vpr_score.toFixed(1) : '–'}</span></td>
              <td style="font-size:12px">${v.asset_hostname || v.asset_ip || '–'}</td>
              <td style="white-space:nowrap">
                ${v.cisa_kev_date ? `<span style="font-size:10px;background:#ef444420;color:#ef4444;border:1px solid #ef444440;border-radius:3px;padding:1px 4px;margin-right:2px">KEV</span>` : ''}
                ${v.exploit_available ? `<span style="font-size:10px;background:#f9731620;color:#f97316;border:1px solid #f9731640;border-radius:3px;padding:1px 4px">EXP</span>` : ''}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>`;
  },

  async loadRiskAge() {
    let items;
    try { items = await API.get('/dashboard/risk-age'); } catch { return; }
    const ctx = document.getElementById('chart-age');
    if (!ctx || !items.length) return;
    if (this.charts.age) this.charts.age.destroy();
    const colors = ['#22c55e', '#eab308', '#f97316', '#ef4444'];
    this.charts.age = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: items.map(i => i.label),
        datasets: [{
          data: items.map(i => i.count),
          backgroundColor: colors.map(c => c + 'cc'),
          borderColor: colors,
          borderWidth: 1,
          borderRadius: 4,
        }],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: c => ` ${c.parsed.y} vulns` } },
        },
        scales: {
          x: { ticks: { color: '#8a9abf', font: { size: 11 } }, grid: { color: '#1c2840' } },
          y: { ticks: { color: '#4d5f80', font: { size: 10 } }, grid: { color: '#1c2840' }, beginAtZero: true },
        },
      },
    });
  },

  async updateScannerStatus() {
    const items = await API.get('/dashboard/scanner-status');
    const el = document.getElementById('sidebar-scanner-status');
    if (!el) return;
    el.innerHTML = items.map(s => `
      <div class="scanner-pill">
        <span class="dot dot-${s.status}"></span>
        <span class="truncate" style="max-width:130px">${s.name}</span>
      </div>
    `).join('');
  },
};

function statCard(label, value, type, valClass = '') {
  return `
    <div class="stat-card ${type}">
      <div class="stat-label">${label}</div>
      <div class="stat-value ${valClass}">${(value || 0).toLocaleString()}</div>
    </div>`;
}
