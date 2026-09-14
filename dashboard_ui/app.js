/**
 * Interactive Dashboard UI Logic for Cloud IAM Misconfiguration Detector.
 */

let state = {
  graph: null,
  findings: [],
  remediations: [],
  network: null,
  activeFindingId: null
};

document.addEventListener('DOMContentLoaded', () => {
  initDashboard();
  setupEventListeners();
});

/** Initialize dashboard by fetching graph, findings, and remediations datasets. */
async function initDashboard() {
  try {
    const data = await fetchDashboardData();
    state.graph = data.graph;
    state.findings = data.findings ? data.findings.findings || [] : [];
    state.remediations = data.remediations ? data.remediations.remediations || [] : [];

    updateMetrics();
    renderFindingsList();
    renderGraph();
  } catch (err) {
    console.error("Dashboard initialization error:", err);
  }
}

/** Fetch data from backend API endpoints or fallback to static root JSON files. */
async function fetchDashboardData() {
  try {
    const apiRes = await fetch('/api/data');
    if (apiRes.ok) {
      return await apiRes.json();
    }
  } catch (e) {
    console.log("API not available, falling back to static files...");
  }

  // Fallback to static JSON paths
  const [graphRes, findingsRes, remediationsRes] = await Promise.all([
    fetch('/graph_export.json').then(r => r.json()).catch(() => ({ nodes: [], edges: [] })),
    fetch('/findings.json').then(r => r.json()).catch(() => ({ findings: [] })),
    fetch('/remediations.json').then(r => r.json()).catch(() => ({ remediations: [] }))
  ]);

  return { graph: graphRes, findings: findingsRes, remediations: remediationsRes };
}

/** Update top scorecard metric counts. */
function updateMetrics() {
  const critical = state.findings.filter(f => f.risk_score >= 80).length;
  const high = state.findings.filter(f => f.risk_score >= 60 && f.risk_score < 80).length;
  const wildcards = state.findings.filter(f => f.type === 'wildcard_overpermission').length;
  
  document.getElementById('metric-critical').textContent = critical;
  document.getElementById('metric-high').textContent = high;
  document.getElementById('metric-wildcards').textContent = wildcards;
  
  const nodesCount = state.graph && state.graph.nodes ? state.graph.nodes.length : 0;
  const edgesCount = state.graph && state.graph.edges ? state.graph.edges.length : 0;
  
  document.getElementById('metric-nodes').textContent = nodesCount;
  document.getElementById('metric-edges-count').textContent = `${edgesCount} Graph Edges Evaluated`;
  document.getElementById('finding-count-label').textContent = `${state.findings.length} Findings`;
}

/** Render explainable risk scorecards list. */
function renderFindingsList() {
  const container = document.getElementById('findings-list');
  container.innerHTML = '';

  if (!state.findings.length) {
    container.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--text-muted);">No risk findings discovered.</div>`;
    return;
  }

  // Sort findings by risk_score descending
  const sorted = [...state.findings].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));

  sorted.forEach(finding => {
    const card = document.createElement('div');
    card.className = `finding-card ${state.activeFindingId === finding.finding_id ? 'active' : ''}`;
    card.dataset.id = finding.finding_id;

    const riskBadgeClass = getRiskBadgeClass(finding.risk_score);
    const breakdown = finding.risk_breakdown || { reachability: 0.5, blast_radius: 0.5, exploit_triviality: 0.5 };

    card.innerHTML = `
      <div class="finding-header">
        <div>
          <span class="finding-id">${finding.finding_id}</span>
          <div class="finding-name">${escapeHtml(finding.pattern_name || finding.type)}</div>
        </div>
        <span class="badge-risk ${riskBadgeClass}">${(finding.risk_score || 0).toFixed(1)}</span>
      </div>
      <p style="font-size: 0.775rem; color: var(--text-secondary); margin-top: 0.35rem; line-height: 1.4;">
        ${escapeHtml(finding.narrative || '')}
      </p>
      <div class="breakdown-grid">
        <div class="factor-item">
          <div class="factor-label">Reachability: ${(breakdown.reachability * 100).toFixed(0)}%</div>
          <div class="factor-bar-bg"><div class="factor-bar-fill" style="width: ${breakdown.reachability * 100}%;"></div></div>
        </div>
        <div class="factor-item">
          <div class="factor-label">Blast Radius: ${(breakdown.blast_radius * 100).toFixed(0)}%</div>
          <div class="factor-bar-bg"><div class="factor-bar-fill" style="width: ${breakdown.blast_radius * 100}%;"></div></div>
        </div>
        <div class="factor-item">
          <div class="factor-label">Exploit Triviality: ${(breakdown.exploit_triviality * 100).toFixed(0)}%</div>
          <div class="factor-bar-bg"><div class="factor-bar-fill" style="width: ${breakdown.exploit_triviality * 100}%;"></div></div>
        </div>
      </div>
    `;

    card.addEventListener('click', () => openFindingDetail(finding));
    container.appendChild(card);
  });
}

/** Get badge CSS class name based on numerical risk score. */
function getRiskBadgeClass(score) {
  if (score >= 80) return 'badge-critical';
  if (score >= 60) return 'badge-high';
  if (score >= 40) return 'badge-medium';
  return 'badge-low';
}

/** Render Vis.js privilege network graph visualization. */
function renderGraph() {
  const container = document.getElementById('vis-graph');
  if (!state.graph || !state.graph.nodes) return;

  // Transform nodes
  const visNodes = state.graph.nodes.map(node => {
    let color = '#38bdf8'; // user
    let shape = 'dot';
    
    if (node.is_admin_equivalent) {
      color = '#ef4444'; // admin red
    } else if (node.type === 'role') {
      color = '#a855f7'; // role purple
    } else if (node.type === 'policy') {
      color = '#10b981'; // policy green
    } else if (node.type === 'group') {
      color = '#6366f1';
    } else if (node.type === 'resource') {
      color = '#f59e0b';
    }

    return {
      id: node.id,
      label: node.name || node.id.split('/').pop(),
      title: `${node.type.toUpperCase()}: ${node.id}${node.is_admin_equivalent ? ' (ADMIN EQUIVALENT)' : ''}`,
      color: { background: color, border: '#ffffff', highlight: { background: '#00f2fe', border: '#ffffff' } },
      font: { color: '#ffffff', size: 12 },
      shape: shape,
      size: node.is_admin_equivalent ? 22 : 16
    };
  });

  // Transform edges
  const visEdges = (state.graph.edges || []).map((edge, index) => {
    return {
      id: `edge-${index}`,
      from: edge.source,
      to: edge.target,
      label: edge.permission || '',
      font: { color: '#94a3b8', size: 10, align: 'middle' },
      arrows: 'to',
      color: { color: edge.is_wildcard_resource ? '#ef4444' : 'rgba(148, 163, 184, 0.4)' },
      width: edge.is_wildcard_resource ? 2 : 1
    };
  });

  const data = { nodes: new vis.DataSet(visNodes), edges: new vis.DataSet(visEdges) };
  const options = {
    nodes: { borderWidth: 2, shadow: true },
    edges: { smooth: { type: 'continuous' } },
    physics: {
      solver: 'forceAtlas2Based',
      forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 100, springConstant: 0.08 }
    },
    interaction: { hover: true, tooltipDelay: 100 }
  };

  state.network = new vis.Network(container, data, options);

  state.network.on('click', (params) => {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0];
      const relatedFinding = state.findings.find(f => f.path && f.path.includes(nodeId));
      if (relatedFinding) {
        openFindingDetail(relatedFinding);
      }
    }
  });
}

/** Open finding detail drawer and highlight attack path on graph. */
function openFindingDetail(finding) {
  state.activeFindingId = finding.finding_id;

  // Highlight graph path
  if (state.network && finding.path && finding.path.length) {
    state.network.selectNodes(finding.path);
  }

  // Populate drawer
  document.getElementById('drawer-finding-id').textContent = finding.finding_id;
  document.getElementById('drawer-title').textContent = finding.pattern_name || finding.type;
  document.getElementById('drawer-narrative').textContent = finding.narrative || 'No narrative provided.';

  // Breakdown
  const b = finding.risk_breakdown || { reachability: 0.5, blast_radius: 0.5, exploit_triviality: 0.5 };
  document.getElementById('drawer-breakdown').innerHTML = `
    <div class="factor-item">
      <div class="factor-label">Reachability</div>
      <div style="font-size: 1.1rem; font-weight: 700; color: #fff;">${(b.reachability * 100).toFixed(0)}%</div>
    </div>
    <div class="factor-item">
      <div class="factor-label">Blast Radius</div>
      <div style="font-size: 1.1rem; font-weight: 700; color: #fff;">${(b.blast_radius * 100).toFixed(0)}%</div>
    </div>
    <div class="factor-item">
      <div class="factor-label">Exploit Triviality</div>
      <div style="font-size: 1.1rem; font-weight: 700; color: #fff;">${(b.exploit_triviality * 100).toFixed(0)}%</div>
    </div>
  `;

  // Find remediation matching finding_id
  const rem = state.remediations.find(r => r.finding_id === finding.finding_id) || {};
  
  const originalJson = rem.original_statement ? JSON.stringify(rem.original_statement, null, 2) : JSON.stringify(finding.offending_statement || {}, null, 2);
  const suggestedJson = rem.suggested_statement ? JSON.stringify(rem.suggested_statement, null, 2) : (rem.reason ? `// Non-remediable: ${rem.reason}` : '// No remediation generated');

  document.getElementById('drawer-original-json').textContent = originalJson;
  document.getElementById('drawer-suggested-json').textContent = suggestedJson;
  document.getElementById('drawer-justification').textContent = rem.justification || 'Restricts offending permissions to minimal required ARNs and actions.';

  // Setup download button
  const downloadBtn = document.getElementById('download-policy-btn');
  downloadBtn.onclick = () => downloadPolicyFile(finding.finding_id, rem.suggested_statement || rem);

  // Show drawer
  document.getElementById('drawer-overlay').classList.add('active');
  renderFindingsList();
}

/** Download single policy remediation statement as JSON file. */
function downloadPolicyFile(findingId, statement) {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(statement, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", `remediation_${findingId}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
}

/** Setup UI button event listeners. */
function setupEventListeners() {
  document.getElementById('close-drawer').addEventListener('click', () => {
    document.getElementById('drawer-overlay').classList.remove('active');
  });

  document.getElementById('drawer-overlay').addEventListener('click', (e) => {
    if (e.target.id === 'drawer-overlay') {
      document.getElementById('drawer-overlay').classList.remove('active');
    }
  });

  document.getElementById('refresh-btn').addEventListener('click', async () => {
    try {
      await fetch('/api/run-pipeline', { method: 'POST' });
    } catch (e) {}
    initDashboard();
  });

  document.getElementById('download-all-btn').addEventListener('click', () => {
    if (!state.remediations.length) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({ remediations: state.remediations }, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `all_remediations.json`);
    document.body.appendChild(dlAnchor);
    dlAnchor.click();
    dlAnchor.remove();
  });
}

/** Escape HTML characters in strings for rendering safety. */
function escapeHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
