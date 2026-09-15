/* ============================================================
   App Controller — file loading, orchestration, state management
   Person 4 Module — /dashboard_ui/js/app.js
   ============================================================ */

/**
 * Application controller — handles file loading (static-file mode),
 * wires up graph + scorecards + detail modal, and manages app state.
 * This is the main entry point that coordinates the three display modules.
 */
const App = (function () {
  'use strict';

  // Application state
  const state = {
    graphData: null,
    findingsData: null,
    remediationsData: null,
    filesLoaded: { graph: false, findings: false, remediations: false },
  };

  /** Reads a File object as JSON, returns a promise. */
  function readFileAsJson(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const json = JSON.parse(e.target.result);
          resolve(json);
        } catch (err) {
          reject(new Error(`Invalid JSON in ${file.name}: ${err.message}`));
        }
      };
      reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
      reader.readAsText(file);
    });
  }

  /** Validates graph_export.json has the expected shape. */
  function validateGraphData(data) {
    if (!data || !Array.isArray(data.nodes) || !Array.isArray(data.edges)) {
      throw new Error('graph_export.json must have "nodes" (array) and "edges" (array) fields.');
    }
    return true;
  }

  /** Validates findings.json has the expected shape. */
  function validateFindingsData(data) {
    if (!data || !Array.isArray(data.findings)) {
      throw new Error('findings.json must have a "findings" (array) field.');
    }
    return true;
  }

  /** Validates remediations.json has the expected shape. */
  function validateRemediationsData(data) {
    if (!data || !Array.isArray(data.remediations)) {
      throw new Error('remediations.json must have a "remediations" (array) field.');
    }
    return true;
  }

  /** Updates the file input row UI to show loaded state. */
  function markFileLoaded(inputId) {
    const row = document.querySelector(`#${inputId}`).closest('.file-input-row');
    const label = row.querySelector('.file-input-label');
    if (row) row.classList.add('loaded');
    if (label) {
      label.textContent = '✓ Loaded';
      label.classList.add('loaded');
    }
  }

  /** Checks if all three files are loaded and initializes the dashboard. */
  function checkAllLoaded() {
    if (state.filesLoaded.graph && state.filesLoaded.findings && state.filesLoaded.remediations) {
      initDashboard(state.graphData, state.findingsData, state.remediationsData);
    }
  }

  /** Builds the remediation lookup map (finding_id → remediation object). */
  function buildRemediationMap(remediationsData) {
    const map = {};
    if (!remediationsData || !remediationsData.remediations) return map;
    remediationsData.remediations.forEach((r) => {
      map[r.finding_id] = r;
    });
    return map;
  }

  /** Computes aggregate stats for the stats bar. */
  function computeStats(graphData, findingsData) {
    const stats = {
      totalNodes: graphData.nodes ? graphData.nodes.length : 0,
      totalEdges: graphData.edges ? graphData.edges.length : 0,
      totalFindings: findingsData.findings ? findingsData.findings.length : 0,
      criticalCount: 0,
      highCount: 0,
      adminCount: 0,
    };

    if (findingsData.findings) {
      findingsData.findings.forEach((f) => {
        if (f.risk_score >= 90) stats.criticalCount++;
        else if (f.risk_score >= 70) stats.highCount++;
      });
    }

    if (graphData.nodes) {
      graphData.nodes.forEach((n) => {
        if (n.is_admin_equivalent) stats.adminCount++;
      });
    }

    return stats;
  }

  /** Renders the stats bar with computed values. */
  function renderStatsBar(stats) {
    const statsEl = document.querySelector('.stats-bar');
    if (!statsEl) return;

    statsEl.innerHTML = `
      <div class="stat-item">
        <div>
          <div class="stat-value" style="color:var(--text-primary);">${stats.totalNodes}</div>
          <div class="stat-label">Principals</div>
        </div>
      </div>
      <div class="stat-divider"></div>
      <div class="stat-item">
        <div>
          <div class="stat-value" style="color:var(--text-primary);">${stats.totalEdges}</div>
          <div class="stat-label">Relationships</div>
        </div>
      </div>
      <div class="stat-divider"></div>
      <div class="stat-item">
        <div class="severity-dot critical"></div>
        <div>
          <div class="stat-value" style="color:var(--risk-critical);">${stats.criticalCount}</div>
          <div class="stat-label">Critical</div>
        </div>
      </div>
      <div class="stat-divider"></div>
      <div class="stat-item">
        <div class="severity-dot high"></div>
        <div>
          <div class="stat-value" style="color:var(--risk-high);">${stats.highCount}</div>
          <div class="stat-label">High</div>
        </div>
      </div>
      <div class="stat-divider"></div>
      <div class="stat-item">
        <div>
          <div class="stat-value" style="color:var(--risk-critical);">${stats.adminCount}</div>
          <div class="stat-label">Admin Equiv.</div>
        </div>
      </div>
      <div class="stat-divider"></div>
      <div class="stat-item">
        <div>
          <div class="stat-value" style="color:var(--text-accent);">${stats.totalFindings}</div>
          <div class="stat-label">Total Findings</div>
        </div>
      </div>
    `;
  }

  /** Renders account badges in the header. */
  function renderAccountBadges(graphData) {
    const container = document.querySelector('.account-badges');
    if (!container || !graphData.accounts) return;

    container.innerHTML = '';
    graphData.accounts.forEach((accountId) => {
      const badge = document.createElement('span');
      badge.className = 'account-badge';
      badge.textContent = accountId;
      container.appendChild(badge);
    });
  }

  /**
   * Main initialization — renders all dashboard components.
   * @param {Object} graphData - Parsed graph_export.json
   * @param {Object} findingsData - Parsed findings.json
   * @param {Object} remediationsData - Parsed remediations.json
   */
  function initDashboard(graphData, findingsData, remediationsData) {
    // Hide file loader overlay
    const loaderOverlay = document.querySelector('.file-loader-overlay');
    if (loaderOverlay) loaderOverlay.classList.add('hidden');

    // Build remediation lookup
    const remediationMap = buildRemediationMap(remediationsData);

    // Render account badges
    renderAccountBadges(graphData);

    // Render stats bar
    const stats = computeStats(graphData, findingsData);
    renderStatsBar(stats);

    // Initialize detail modal event listeners
    DetailModal.init();

    // Render graph
    GraphRenderer.renderGraph(graphData, findingsData, (nodeId, findingIds) => {
      // When a graph node is clicked, highlight matching finding cards
      ScoreCards.highlightCards(findingIds);
    });

    // Render scorecards
    ScoreCards.renderScoreCards(findingsData, (finding) => {
      // When a finding card is clicked:
      // 1. Highlight the attack path in the graph
      GraphRenderer.highlightPath(finding.path);

      // 2. Open the detail drawer with narrative + remediation
      const remediation = remediationMap[finding.finding_id] || null;
      DetailModal.showFindingDetail(finding, remediation);
    });

    // Wire up graph control buttons
    document.getElementById('btn-zoom-in')?.addEventListener('click', () => GraphRenderer.zoomIn());
    document.getElementById('btn-zoom-out')?.addEventListener('click', () => GraphRenderer.zoomOut());
    document.getElementById('btn-fit')?.addEventListener('click', () => GraphRenderer.fitGraph());
    document.getElementById('btn-reset')?.addEventListener('click', () => {
      GraphRenderer.clearHighlights();
      GraphRenderer.fitGraph();
      ScoreCards.clearActiveCards();
    });

    // Render graph legend
    renderGraphLegend();
  }

  /** Renders the graph legend overlay. */
  function renderGraphLegend() {
    const legend = document.querySelector('.graph-legend');
    if (!legend) return;

    legend.innerHTML = `
      <div class="legend-title">Node Types</div>
      <div class="legend-item"><div class="legend-shape circle" style="background:#64b5f6;"></div> User</div>
      <div class="legend-item"><div class="legend-shape diamond" style="background:#bb86fc;"></div> Role</div>
      <div class="legend-item"><div class="legend-shape" style="background:#4dd0e1;clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);"></div> Group</div>
      <div class="legend-item"><div class="legend-shape" style="background:#ffb74d;border-radius:4px;"></div> Policy</div>
      <div class="legend-item"><div class="legend-shape" style="background:#81c784;clip-path:polygon(50% 0%,100% 100%,0% 100%);"></div> Resource</div>
      <div class="legend-item"><div class="legend-shape circle" style="background:transparent;border:2px solid #ff3366;"></div> Admin Equiv.</div>
      <div class="legend-title" style="margin-top:var(--space-sm);">Edge Types</div>
      <div class="legend-item"><div style="width:20px;height:2px;background:#bb86fc;"></div> AssumeRole</div>
      <div class="legend-item"><div style="width:20px;height:2px;background:#ff6b35;border-top:2px dashed #ff6b35;height:0;"></div> PassRole</div>
      <div class="legend-item"><div style="width:20px;height:1px;background:rgba(99,130,190,0.5);"></div> Policy Attach</div>
      <div class="legend-item"><div style="width:20px;height:0;border-top:2px dotted rgba(77,208,225,0.5);"></div> Group Member</div>
      <div class="legend-item"><div style="width:20px;height:2px;background:#ff3366;"></div> Wildcard ⚠</div>
    `;
  }

  /** Initializes the application — sets up file loaders and event handlers. */
  function init() {
    // --- File input handlers ---
    const graphInput = document.getElementById('file-graph');
    const findingsInput = document.getElementById('file-findings');
    const remediationsInput = document.getElementById('file-remediations');

    if (graphInput) {
      graphInput.addEventListener('change', async (e) => {
        try {
          state.graphData = await readFileAsJson(e.target.files[0]);
          validateGraphData(state.graphData);
          state.filesLoaded.graph = true;
          markFileLoaded('file-graph');
          checkAllLoaded();
        } catch (err) {
          alert('Error loading graph file: ' + err.message);
        }
      });
    }

    if (findingsInput) {
      findingsInput.addEventListener('change', async (e) => {
        try {
          state.findingsData = await readFileAsJson(e.target.files[0]);
          validateFindingsData(state.findingsData);
          state.filesLoaded.findings = true;
          markFileLoaded('file-findings');
          checkAllLoaded();
        } catch (err) {
          alert('Error loading findings file: ' + err.message);
        }
      });
    }

    if (remediationsInput) {
      remediationsInput.addEventListener('change', async (e) => {
        try {
          state.remediationsData = await readFileAsJson(e.target.files[0]);
          validateRemediationsData(state.remediationsData);
          state.filesLoaded.remediations = true;
          markFileLoaded('file-remediations');
          checkAllLoaded();
        } catch (err) {
          alert('Error loading remediations file: ' + err.message);
        }
      });
    }

    // --- Load real scan data button ---
    const realBtn = document.getElementById('btn-load-real');
    if (realBtn) {
      realBtn.addEventListener('click', loadRealScanData);
    }

    // --- Load demo/stub data button ---
    const stubBtn = document.getElementById('btn-load-stubs');
    if (stubBtn) {
      stubBtn.addEventListener('click', loadStubData);
    }

    // --- Header reload / dataset switch button ---
    const reloadBtn = document.getElementById('btn-header-reload');
    if (reloadBtn) {
      reloadBtn.addEventListener('click', () => {
        const loaderOverlay = document.querySelector('.file-loader-overlay');
        if (loaderOverlay) {
          loaderOverlay.classList.remove('hidden');
        }
      });
    }

    // --- Close modal button ---
    const closeLoaderBtn = document.getElementById('btn-close-loader');
    if (closeLoaderBtn) {
      closeLoaderBtn.addEventListener('click', () => {
        const loaderOverlay = document.querySelector('.file-loader-overlay');
        if (loaderOverlay) {
          loaderOverlay.classList.add('hidden');
        }
      });
    }

    // Auto-load scan data on launch
    autoLoadScanData();
  }

  /** Automatically loads the pipeline scan data on startup. */
  async function autoLoadScanData() {
    try {
      const [graphResp, findingsResp, remediationsResp] = await Promise.all([
        fetch('data/graph_export.json'),
        fetch('data/findings.json'),
        fetch('data/remediations.json'),
      ]);

      if (graphResp.ok && findingsResp.ok && remediationsResp.ok) {
        state.graphData = await graphResp.json();
        state.findingsData = await findingsResp.json();
        state.remediationsData = await remediationsResp.json();

        validateGraphData(state.graphData);
        validateFindingsData(state.findingsData);
        validateRemediationsData(state.remediationsData);

        state.filesLoaded = { graph: true, findings: true, remediations: true };
        ['file-graph', 'file-findings', 'file-remediations'].forEach(markFileLoaded);

        initDashboard(state.graphData, state.findingsData, state.remediationsData);
        return;
      }
    } catch (err) {
      console.log('Auto-load waiting for manual import:', err.message);
      const loaderOverlay = document.querySelector('.file-loader-overlay');
      if (loaderOverlay) loaderOverlay.classList.remove('hidden');
    }
  }

  /** Loads real pipeline scan data files from the data/ directory. */
  async function loadRealScanData() {
    const btn = document.getElementById('btn-load-real');
    if (btn) {
      btn.textContent = 'Loading Scan…';
      btn.disabled = true;
    }

    try {
      const [graphResp, findingsResp, remediationsResp] = await Promise.all([
        fetch('data/graph_export.json'),
        fetch('data/findings.json'),
        fetch('data/remediations.json'),
      ]);

      if (!graphResp.ok) throw new Error('Failed to fetch graph_export.json — run main.py first to generate real scan data.');
      if (!findingsResp.ok) throw new Error('Failed to fetch findings.json — run main.py first.');
      if (!remediationsResp.ok) throw new Error('Failed to fetch remediations.json — run main.py first.');

      state.graphData = await graphResp.json();
      state.findingsData = await findingsResp.json();
      state.remediationsData = await remediationsResp.json();

      validateGraphData(state.graphData);
      validateFindingsData(state.findingsData);
      validateRemediationsData(state.remediationsData);

      state.filesLoaded = { graph: true, findings: true, remediations: true };

      // Mark all file inputs as loaded
      ['file-graph', 'file-findings', 'file-remediations'].forEach(markFileLoaded);

      initDashboard(state.graphData, state.findingsData, state.remediationsData);
    } catch (err) {
      alert('Error loading real scan data: ' + err.message + '\nFalling back to demo stubs.');
      if (btn) {
        btn.textContent = '⚡ Load Real IAM Scan Results (28 Nodes, Multi-Account)';
        btn.disabled = false;
      }
    }
  }

  /** Loads the built-in stub data files from the data/ directory. */
  async function loadStubData() {
    const btn = document.getElementById('btn-load-stubs');
    if (btn) {
      btn.textContent = 'Loading…';
      btn.disabled = true;
    }

    try {
      const [graphResp, findingsResp, remediationsResp] = await Promise.all([
        fetch('data/stub_graph_export.json'),
        fetch('data/stub_findings.json'),
        fetch('data/stub_remediations.json'),
      ]);

      if (!graphResp.ok) throw new Error('Failed to fetch stub_graph_export.json — make sure you are running from a local HTTP server.');
      if (!findingsResp.ok) throw new Error('Failed to fetch stub_findings.json');
      if (!remediationsResp.ok) throw new Error('Failed to fetch stub_remediations.json');

      state.graphData = await graphResp.json();
      state.findingsData = await findingsResp.json();
      state.remediationsData = await remediationsResp.json();

      validateGraphData(state.graphData);
      validateFindingsData(state.findingsData);
      validateRemediationsData(state.remediationsData);

      state.filesLoaded = { graph: true, findings: true, remediations: true };

      // Mark all file inputs as loaded
      ['file-graph', 'file-findings', 'file-remediations'].forEach(markFileLoaded);

      initDashboard(state.graphData, state.findingsData, state.remediationsData);
    } catch (err) {
      alert('Error loading stub data: ' + err.message);
      if (btn) {
        btn.textContent = 'Load Built-in Demo Data';
        btn.disabled = false;
      }
    }
  }

  // Initialize on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return {
    init,
    loadRealScanData,
    loadStubData,
    getState: () => state,
  };
})();
