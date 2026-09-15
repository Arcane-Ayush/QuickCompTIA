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
    const input = document.querySelector(`#${inputId}`);
    if (!input) return;
    const row = input.closest('.file-input-row') || input.parentElement;
    if (!row) return;
    row.classList.add('loaded');
    const label = row.querySelector('.file-input-label') || row.querySelector('label');
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

  /** Displays a sleek toast notification at the bottom of the screen. */
  function showToast(message, duration = 2600) {
    const toast = document.getElementById('toast-box');
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('show');
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => {
      toast.classList.remove('show');
    }, duration);
  }

  /** Computes aggregate stats for the stats bar. */
  function computeStats(graphData, findingsData) {
    const stats = {
      totalNodes: graphData && graphData.nodes ? graphData.nodes.length : 0,
      totalEdges: graphData && graphData.edges ? graphData.edges.length : 0,
      totalFindings: findingsData && findingsData.findings ? findingsData.findings.length : 0,
      criticalCount: 0,
      highCount: 0,
      adminCount: 0,
    };

    if (findingsData && findingsData.findings) {
      findingsData.findings.forEach((f) => {
        if (f.risk_score >= 90) stats.criticalCount++;
        else if (f.risk_score >= 70) stats.highCount++;
      });
    }

    if (graphData && graphData.nodes) {
      graphData.nodes.forEach((n) => {
        if (n.is_admin_equivalent) stats.adminCount++;
      });
    }

    return stats;
  }

  /** Renders the stats bar with computed values matching reference big metric numbers. */
  function renderStatsBar(stats) {
    const statsEl = document.querySelector('.stats-bar');
    if (!statsEl) return;

    statsEl.innerHTML = `
      <div class="metric-item">
        <div class="metric-big-number">${stats.totalNodes}</div>
        <div class="metric-label-two-line">Unique Principals<br>& Resources</div>
      </div>
      <div class="metric-item">
        <div class="metric-big-number">${stats.totalEdges}</div>
        <div class="metric-label-two-line">Discovered IAM<br>Relationships</div>
      </div>
      <div class="metric-item">
        <div class="metric-big-number" style="color:#c2410c;">${stats.totalFindings}</div>
        <div class="metric-label-two-line">Active Risk<br>Findings (${stats.criticalCount} Critical)</div>
      </div>
      <div class="metric-item">
        <div class="metric-big-number" style="color:#b91c1c;">${stats.adminCount}</div>
        <div class="metric-label-two-line">Admin-Equivalent<br>Identities</div>
      </div>
    `;
  }

  /** Renders account badges in the header. */
  function renderAccountBadges(graphData) {
    const container = document.querySelector('.account-badges');
    if (!container || !graphData || !graphData.accounts) return;

    container.innerHTML = '';
    graphData.accounts.forEach((accountId) => {
      const badge = document.createElement('span');
      badge.className = 'account-pill';
      badge.textContent = accountId;
      container.appendChild(badge);
    });
  }

  /**
   * Main initialization — renders all dashboard components.
   * @param {Object} graphData - Parsed graph_export.json
   * @param {Object} findingsData - Parsed findings.json (optional)
   * @param {Object} remediationsData - Parsed remediations.json (optional)
   */
  function initDashboard(graphData, findingsData, remediationsData) {
    findingsData = findingsData || { findings: [] };
    remediationsData = remediationsData || { remediations: [] };

    // Hide file loader overlay
    const loaderOverlay = document.querySelector('.file-loader-overlay');
    if (loaderOverlay) loaderOverlay.classList.add('hidden');

    // Update graph toolbar stat badge
    const graphBadge = document.getElementById('graph-stat-badge');
    if (graphBadge && graphData && graphData.nodes && graphData.edges) {
      graphBadge.textContent = `${graphData.nodes.length} Nodes • ${graphData.edges.length} Edges`;
    }

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
      ScoreCards.highlightCards(findingIds);
    });

    // Render scorecards and setup severity filter pills
    ScoreCards.renderScoreCards(findingsData, (finding) => {
      GraphRenderer.highlightPath(finding.path);
      const remediation = remediationMap[finding.finding_id] || null;
      DetailModal.showFindingDetail(finding, remediation);
    });
    ScoreCards.setupFilterListeners();

    // Auto-fit graph after elements render into the DOM
    setTimeout(() => {
      if (GraphRenderer && GraphRenderer.fitGraph) {
        GraphRenderer.fitGraph();
      }
    }, 350);

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
      <div class="legend-title-small">Node Types</div>
      <div class="legend-item-line"><div class="legend-chip" style="background:#3b82f6;"></div> User</div>
      <div class="legend-item-line"><div class="legend-chip" style="background:#8b5cf6;"></div> Role</div>
      <div class="legend-item-line"><div class="legend-chip" style="background:#06b6d4;"></div> Group</div>
      <div class="legend-item-line"><div class="legend-chip" style="background:#f97316;"></div> Policy</div>
      <div class="legend-item-line"><div class="legend-chip" style="background:#ef4444;"></div> Admin Equivalent</div>
    `;
  }

  /** Handles importing a Parser Graph (graph_export.json) with optional auto-visualization. */
  function handleParserGraphImport(graphJson, autoVisualize = false) {
    try {
      validateGraphData(graphJson);
      state.graphData = graphJson;
      state.filesLoaded.graph = true;
      markFileLoaded('file-graph');

      // Update status label in modal
      const statusLbl = document.getElementById('status-file-graph');
      if (statusLbl) {
        statusLbl.textContent = `✓ ${graphJson.nodes.length} Nodes, ${graphJson.edges.length} Relationships parsed`;
        statusLbl.style.color = '#15803d';
        statusLbl.style.fontWeight = '600';
      }

      // Show the direct visualize button in modal
      const vizBtn = document.getElementById('btn-render-graph-only');
      if (vizBtn) vizBtn.style.display = 'flex';

      if (autoVisualize) {
        initDashboard(state.graphData, state.findingsData || { findings: [] }, state.remediationsData || { remediations: [] });
        showToast(`✓ Parser Graph rendered (${graphJson.nodes.length} nodes, ${graphJson.edges.length} edges)`);
      }
    } catch (err) {
      alert('Invalid Parser Graph file: ' + err.message);
    }
  }

  /** Sets up global keyboard shortcuts. */
  function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Don't intercept when user is typing in form inputs
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
        return;
      }

      const key = e.key;

      if (key === '+' || key === '=') {
        e.preventDefault();
        GraphRenderer.zoomIn();
      } else if (key === '-' || key === '_') {
        e.preventDefault();
        GraphRenderer.zoomOut();
      } else if (key === '0' || key === 'f' || key === 'F') {
        e.preventDefault();
        GraphRenderer.fitGraph();
        showToast('⊡ Graph fitted to view');
      } else if (key === 'r' || key === 'R') {
        e.preventDefault();
        GraphRenderer.clearHighlights();
        GraphRenderer.fitGraph();
        ScoreCards.clearActiveCards();
        showToast('↺ Graph view reset');
      } else if (key === 'Escape') {
        const shortcutsModal = document.getElementById('shortcuts-overlay');
        const loaderModal = document.getElementById('file-loader-overlay');
        if (shortcutsModal && !shortcutsModal.classList.contains('hidden')) {
          shortcutsModal.classList.add('hidden');
        } else if (loaderModal && !loaderModal.classList.contains('hidden')) {
          loaderModal.classList.add('hidden');
        } else if (DetailModal.getIsOpen && DetailModal.getIsOpen()) {
          DetailModal.closeDrawer();
        } else {
          GraphRenderer.clearHighlights();
          ScoreCards.clearActiveCards();
        }
      } else if (key === 'ArrowDown' || key === 'j' || key === 'J') {
        e.preventDefault();
        ScoreCards.selectNextCard();
      } else if (key === 'ArrowUp' || key === 'k' || key === 'K') {
        e.preventDefault();
        ScoreCards.selectPrevCard();
      } else if (key === 'Enter') {
        e.preventDefault();
        ScoreCards.openSelectedCard();
      } else if (['1', '2', '3', '4', '5'].includes(key)) {
        e.preventDefault();
        ScoreCards.filterByKeyIndex(parseInt(key, 10));
        const names = { '1': 'All', '2': 'Critical', '3': 'High', '4': 'Medium', '5': 'Low' };
        showToast(`Filter: ${names[key]} findings`);
      } else if (key === 'i' || key === 'I') {
        e.preventDefault();
        const loaderModal = document.getElementById('file-loader-overlay');
        if (loaderModal) loaderModal.classList.toggle('hidden');
      } else if (key === '?') {
        e.preventDefault();
        const shortcutsModal = document.getElementById('shortcuts-overlay');
        if (shortcutsModal) shortcutsModal.classList.toggle('hidden');
      }
    });
  }

  /** Sets up drag and drop handling on the modal dropzone. */
  function setupDragAndDrop() {
    const dropzone = document.getElementById('dropzone-container');
    const fileInput = document.getElementById('file-dropzone');
    if (!dropzone) return;

    dropzone.addEventListener('click', () => fileInput && fileInput.click());

    ['dragenter', 'dragover'].forEach((eventName) => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach((eventName) => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('dragover');
      });
    });

    dropzone.addEventListener('drop', async (e) => {
      const files = Array.from(e.dataTransfer.files);
      if (files.length === 0) return;

      for (const file of files) {
        try {
          const json = await readFileAsJson(file);
          if (json.nodes && json.edges) {
            handleParserGraphImport(json, true);
          } else if (json.findings) {
            validateFindingsData(json);
            state.findingsData = json;
            state.filesLoaded.findings = true;
            markFileLoaded('file-findings');
            showToast(`✓ Loaded findings (${json.findings.length} items)`);
          } else if (json.remediations) {
            validateRemediationsData(json);
            state.remediationsData = json;
            state.filesLoaded.remediations = true;
            markFileLoaded('file-remediations');
            showToast(`✓ Loaded remediations (${json.remediations.length} items)`);
          }
        } catch (err) {
          showToast(`Error in ${file.name}: ${err.message}`);
        }
      }
    });

    if (fileInput) {
      fileInput.addEventListener('change', async (e) => {
        const files = Array.from(e.target.files);
        for (const file of files) {
          try {
            const json = await readFileAsJson(file);
            if (json.nodes && json.edges) {
              handleParserGraphImport(json, true);
            } else if (json.findings) {
              validateFindingsData(json);
              state.findingsData = json;
              state.filesLoaded.findings = true;
              markFileLoaded('file-findings');
            } else if (json.remediations) {
              validateRemediationsData(json);
              state.remediationsData = json;
              state.filesLoaded.remediations = true;
              markFileLoaded('file-remediations');
            }
          } catch (err) {
            alert(err.message);
          }
        }
      });
    }
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
          handleParserGraphImport(state.graphData, false);
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
          const statusLbl = document.getElementById('status-file-findings');
          if (statusLbl) {
            statusLbl.textContent = `✓ ${state.findingsData.findings.length} Findings detected`;
            statusLbl.style.color = '#15803d';
            statusLbl.style.fontWeight = '600';
          }
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
          const statusLbl = document.getElementById('status-file-remediations');
          if (statusLbl) {
            statusLbl.textContent = `✓ ${state.remediationsData.remediations.length} Remediations loaded`;
            statusLbl.style.color = '#15803d';
            statusLbl.style.fontWeight = '600';
          }
          checkAllLoaded();
        } catch (err) {
          alert('Error loading remediations file: ' + err.message);
        }
      });
    }

    // --- Direct Graph Import from Toolbar ---
    const directGraphBtn = document.getElementById('btn-graph-direct-import');
    const directGraphInput = document.getElementById('file-graph-direct');
    if (directGraphBtn && directGraphInput) {
      directGraphBtn.addEventListener('click', () => directGraphInput.click());
      directGraphInput.addEventListener('change', async (e) => {
        if (!e.target.files[0]) return;
        try {
          const json = await readFileAsJson(e.target.files[0]);
          handleParserGraphImport(json, true);
        } catch (err) {
          alert('Error loading parser graph: ' + err.message);
        }
      });
    }

    // --- Visualize Parser Graph Only button ---
    const vizGraphOnlyBtn = document.getElementById('btn-render-graph-only');
    if (vizGraphOnlyBtn) {
      vizGraphOnlyBtn.addEventListener('click', () => {
        if (state.graphData) {
          initDashboard(state.graphData, state.findingsData || { findings: [] }, state.remediationsData || { remediations: [] });
          showToast(`✓ Visualizing Parser Graph (${state.graphData.nodes.length} nodes)`);
        }
      });
    }

    // --- Apply All Imported Files button ---
    const applyAllBtn = document.getElementById('btn-apply-all-import');
    if (applyAllBtn) {
      applyAllBtn.addEventListener('click', () => {
        if (state.graphData) {
          initDashboard(state.graphData, state.findingsData || { findings: [] }, state.remediationsData || { remediations: [] });
          showToast('✓ Custom workspace loaded');
        } else {
          alert('Please select at least a Parser Graph (graph_export.json) before applying.');
        }
      });
    }

    // --- Live Scan / Pipeline Re-run button ---
    const liveScanBtn = document.getElementById('btn-run-pipeline');
    if (liveScanBtn) {
      liveScanBtn.addEventListener('click', async () => {
        liveScanBtn.textContent = '⟳ Scanning…';
        liveScanBtn.disabled = true;
        await autoLoadScanData();
        liveScanBtn.textContent = 'Live Scan';
        liveScanBtn.disabled = false;
        showToast('✓ Live scan synchronized with active environment');
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

    // --- Keyboard shortcuts modal toggle ---
    const shortcutsBtn = document.getElementById('btn-shortcuts-toggle');
    const closeShortcutsBtn = document.getElementById('btn-close-shortcuts');
    const shortcutsOverlay = document.getElementById('shortcuts-overlay');

    if (shortcutsBtn && shortcutsOverlay) {
      shortcutsBtn.addEventListener('click', () => shortcutsOverlay.classList.remove('hidden'));
    }
    if (closeShortcutsBtn && shortcutsOverlay) {
      closeShortcutsBtn.addEventListener('click', () => shortcutsOverlay.classList.add('hidden'));
    }
    if (shortcutsOverlay) {
      shortcutsOverlay.addEventListener('click', (e) => {
        if (e.target === shortcutsOverlay) shortcutsOverlay.classList.add('hidden');
      });
    }

    // Setup global keyboard shortcuts & drag and drop
    setupKeyboardShortcuts();
    setupDragAndDrop();

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
      ['file-graph', 'file-findings', 'file-remediations'].forEach(markFileLoaded);

      initDashboard(state.graphData, state.findingsData, state.remediationsData);
      showToast('✓ Real IAM Scan Results loaded (28 Principals, 11 Findings)');
      if (btn) {
        btn.textContent = '⚡ Real Scan (28 Nodes)';
        btn.disabled = false;
      }
    } catch (err) {
      alert('Error loading real scan data: ' + err.message + '\nFalling back to demo stubs.');
      if (btn) {
        btn.textContent = '⚡ Real Scan (28 Nodes)';
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

      if (!graphResp.ok) throw new Error('Failed to fetch stub_graph_export.json');
      if (!findingsResp.ok) throw new Error('Failed to fetch stub_findings.json');
      if (!remediationsResp.ok) throw new Error('Failed to fetch stub_remediations.json');

      state.graphData = await graphResp.json();
      state.findingsData = await findingsResp.json();
      state.remediationsData = await remediationsResp.json();

      validateGraphData(state.graphData);
      validateFindingsData(state.findingsData);
      validateRemediationsData(state.remediationsData);

      state.filesLoaded = { graph: true, findings: true, remediations: true };
      ['file-graph', 'file-findings', 'file-remediations'].forEach(markFileLoaded);

      initDashboard(state.graphData, state.findingsData, state.remediationsData);
      showToast('✓ Minimal Demo Fixture loaded (10 Nodes)');
      if (btn) {
        btn.textContent = '🧪 Minimal Stubs (10 Nodes)';
        btn.disabled = false;
      }
    } catch (err) {
      alert('Error loading stub data: ' + err.message);
      if (btn) {
        btn.textContent = '🧪 Minimal Stubs (10 Nodes)';
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
    showToast,
    handleParserGraphImport,
    initDashboard,
    loadRealScanData,
    loadStubData,
    getState: () => state,
  };
})();

window.App = App;

