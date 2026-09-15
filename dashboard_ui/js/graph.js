/* ============================================================
   Graph Renderer — Cytoscape.js graph visualization
   Person 4 Module — /dashboard_ui/js/graph.js
   ============================================================ */

/**
 * Graph module — renders IAM relationship graph using Cytoscape.js.
 * Consumes graph_export.json (Section 2.1 schema) and optionally
 * findings.json to color-code nodes by risk.
 */
const GraphRenderer = (function () {
  'use strict';

  let cyInstance = null;

  /** Maps node type to Cytoscape shape. */
  function getNodeShape(type) {
    const shapeMap = {
      user: 'ellipse',
      role: 'round-diamond',
      group: 'round-hexagon',
      policy: 'round-rectangle',
      resource: 'round-triangle',
    };
    return shapeMap[type] || 'ellipse';
  }

  /** Maps node type to base color. */
  function getNodeColor(type) {
    const colorMap = {
      user: '#2563eb',
      role: '#7c3aed',
      group: '#0891b2',
      policy: '#ea580c',
      resource: '#059669',
    };
    return colorMap[type] || '#64748b';
  }

  /** Maps edge permission to display style. */
  function getEdgeStyle(permission) {
    const styleMap = {
      'sts:AssumeRole': { color: '#7c3aed', style: 'solid', width: 2.5 },
      'iam:PassRole': { color: '#ea580c', style: 'dashed', width: 2.5 },
      'policy_attachment': { color: '#94a3b8', style: 'solid', width: 1.5 },
      'group_membership': { color: '#0891b2', style: 'dotted', width: 1.5 },
    };
    return styleMap[permission] || { color: '#cbd5e1', style: 'solid', width: 1 };
  }

  /** Returns short display name from ARN or full node id. */
  function getDisplayName(node) {
    return node.name || node.id.split('/').pop() || node.id;
  }

  /** Returns the severity class for a risk score. */
  function riskSeverity(score) {
    if (score >= 90) return 'critical';
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  /** Returns severity color for a risk score. */
  function riskColor(score) {
    if (score >= 90) return '#dc2626';
    if (score >= 70) return '#ea580c';
    if (score >= 40) return '#d97706';
    return '#16a34a';
  }

  /** Builds a nodeId → maxRiskScore lookup from findings. */
  function buildRiskMap(findingsData) {
    const riskMap = {};
    if (!findingsData || !findingsData.findings) return riskMap;
    findingsData.findings.forEach((f) => {
      (f.path || []).forEach((nodeId) => {
        if (!riskMap[nodeId] || f.risk_score > riskMap[nodeId]) {
          riskMap[nodeId] = f.risk_score;
        }
      });
    });
    return riskMap;
  }

  /** Builds a nodeId → [finding_ids] lookup from findings. */
  function buildNodeFindingsMap(findingsData) {
    const map = {};
    if (!findingsData || !findingsData.findings) return map;
    findingsData.findings.forEach((f) => {
      (f.path || []).forEach((nodeId) => {
        if (!map[nodeId]) map[nodeId] = [];
        map[nodeId].push(f.finding_id);
      });
    });
    return map;
  }

  /**
   * Renders the IAM graph into #cy-container.
   * @param {Object} graphData - Parsed graph_export.json
   * @param {Object} findingsData - Parsed findings.json (optional)
   * @param {Function} onNodeClick - Callback(nodeId, findingIds) when a node is clicked
   */
  function renderGraph(graphData, findingsData, onNodeClick) {
    const container = document.getElementById('cy-container');
    if (!container) {
      console.error('Graph container #cy-container not found');
      return;
    }

    const riskMap = buildRiskMap(findingsData);
    const nodeFindingsMap = buildNodeFindingsMap(findingsData);

    // Build Cytoscape elements
    const elements = [];

    // Nodes
    (graphData.nodes || []).forEach((node) => {
      const riskScore = riskMap[node.id] || 0;
      elements.push({
        group: 'nodes',
        data: {
          id: node.id,
          label: getDisplayName(node),
          nodeType: node.type,
          accountId: node.account_id,
          isAdmin: node.is_admin_equivalent,
          riskScore: riskScore,
          findingIds: nodeFindingsMap[node.id] || [],
        },
      });
    });

    // Edges
    (graphData.edges || []).forEach((edge, idx) => {
      elements.push({
        group: 'edges',
        data: {
          id: `e-${idx}`,
          source: edge.source,
          target: edge.target,
          permission: edge.permission,
          isWildcard: edge.is_wildcard_resource,
          condition: edge.condition,
        },
      });
    });

    // Cytoscape stylesheet tailored for clean white and orange theme
    const stylesheet = [
      // Default node
      {
        selector: 'node',
        style: {
          label: 'data(label)',
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': 6,
          'font-family': "'Inter', -apple-system, sans-serif",
          'font-size': '11px',
          'font-weight': 600,
          color: '#0f172a',
          'text-outline-width': 2.5,
          'text-outline-color': '#ffffff',
          'text-outline-opacity': 1.0,
          'background-opacity': 0.95,
          'border-width': 2,
          'border-color': '#e2e8f0',
          'border-opacity': 1,
          width: 38,
          height: 38,
          'overlay-padding': 6,
          'transition-property': 'background-color, border-color, border-width, width, height',
          'transition-duration': '200ms',
        },
      },
      // Node type: user
      {
        selector: 'node[nodeType="user"]',
        style: {
          shape: 'ellipse',
          'background-color': '#2563eb',
          'border-color': '#1d4ed8',
        },
      },
      // Node type: role
      {
        selector: 'node[nodeType="role"]',
        style: {
          shape: 'round-diamond',
          'background-color': '#7c3aed',
          'border-color': '#6d28d9',
          width: 42,
          height: 42,
        },
      },
      // Node type: group
      {
        selector: 'node[nodeType="group"]',
        style: {
          shape: 'round-hexagon',
          'background-color': '#0891b2',
          'border-color': '#0e7490',
        },
      },
      // Node type: policy
      {
        selector: 'node[nodeType="policy"]',
        style: {
          shape: 'round-rectangle',
          'background-color': '#ea580c',
          'border-color': '#c2410c',
          width: 36,
          height: 36,
        },
      },
      // Node type: resource
      {
        selector: 'node[nodeType="resource"]',
        style: {
          shape: 'round-triangle',
          'background-color': '#059669',
          'border-color': '#047857',
        },
      },
      // Admin-equivalent nodes
      {
        selector: 'node[?isAdmin]',
        style: {
          'border-color': '#dc2626',
          'border-width': 3.5,
          width: 48,
          height: 48,
          'shadow-blur': 12,
          'shadow-color': '#dc2626',
          'shadow-opacity': 0.35,
        },
      },
      // High-risk nodes glow
      {
        selector: 'node[riskScore >= 70]',
        style: {
          'border-color': '#ff6200',
          'shadow-blur': 14,
          'shadow-color': '#ff6200',
          'shadow-opacity': 0.45,
        },
      },
      // Critical-risk nodes glow
      {
        selector: 'node[riskScore >= 90]',
        style: {
          'border-color': '#dc2626',
          'shadow-blur': 18,
          'shadow-color': '#dc2626',
          'shadow-opacity': 0.5,
        },
      },
      // Default edge
      {
        selector: 'edge',
        style: {
          width: 1.5,
          'line-color': '#cbd5e1',
          'target-arrow-color': '#94a3b8',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'arrow-scale': 0.8,
          opacity: 0.85,
          'transition-property': 'line-color, target-arrow-color, width, opacity',
          'transition-duration': '200ms',
        },
      },
      // Edge: sts:AssumeRole
      {
        selector: 'edge[permission="sts:AssumeRole"]',
        style: {
          'line-color': '#7c3aed',
          'target-arrow-color': '#7c3aed',
          width: 2.5,
          opacity: 0.9,
        },
      },
      // Edge: iam:PassRole
      {
        selector: 'edge[permission="iam:PassRole"]',
        style: {
          'line-color': '#ea580c',
          'target-arrow-color': '#ea580c',
          'line-style': 'dashed',
          width: 2.5,
          opacity: 0.95,
        },
      },
      // Edge: policy_attachment
      {
        selector: 'edge[permission="policy_attachment"]',
        style: {
          'line-color': '#94a3b8',
          'target-arrow-color': '#94a3b8',
          width: 1.5,
          opacity: 0.65,
        },
      },
      // Edge: group_membership
      {
        selector: 'edge[permission="group_membership"]',
        style: {
          'line-color': '#0891b2',
          'target-arrow-color': '#0891b2',
          'line-style': 'dotted',
          width: 1.5,
          opacity: 0.65,
        },
      },
      // Wildcard edges get danger color
      {
        selector: 'edge[?isWildcard]',
        style: {
          'line-color': '#dc2626',
          'target-arrow-color': '#dc2626',
          width: 3,
          opacity: 1,
        },
      },
      // Highlighted state (used on click & attack path highlight)
      {
        selector: 'node.highlighted',
        style: {
          'border-color': '#ff6200',
          'border-width': 4,
          'shadow-blur': 20,
          'shadow-color': '#ff6200',
          'shadow-opacity': 0.7,
          opacity: 1,
          'z-index': 99,
        },
      },
      {
        selector: 'edge.highlighted',
        style: {
          'line-color': '#ff6200',
          'target-arrow-color': '#ff6200',
          width: 4,
          opacity: 1,
          'z-index': 99,
        },
      },
      {
        selector: '.dimmed',
        style: {
          opacity: 0.18,
        },
      },
      // Selected node
      {
        selector: 'node:selected',
        style: {
          'border-color': '#ff6200',
          'border-width': 4,
          'shadow-blur': 22,
          'shadow-color': '#ff6200',
          'shadow-opacity': 0.6,
        },
      },
    ];

    // Determine best available layout (cose-bilkent preferred, built-in cose as fallback)
    let layoutConfig;
    try {
      // Check if cose-bilkent extension is registered
      if (typeof cytoscapeCoseBilkent !== 'undefined') {
        cytoscape.use(cytoscapeCoseBilkent);
      }
      layoutConfig = {
        name: 'cose-bilkent',
        animate: true,
        animationDuration: 800,
        nodeDimensionsIncludeLabels: true,
        idealEdgeLength: 120,
        nodeRepulsion: 6500,
        edgeElasticity: 0.45,
        gravity: 0.25,
        gravityRange: 3.8,
        numIter: 2500,
        tile: true,
        tilingPaddingVertical: 20,
        tilingPaddingHorizontal: 20,
        randomize: false,
      };
    } catch (e) {
      console.warn('cose-bilkent layout not available, falling back to built-in cose:', e.message);
      layoutConfig = {
        name: 'cose',
        animate: true,
        animationDuration: 800,
        nodeDimensionsIncludeLabels: true,
        idealEdgeLength: 120,
        nodeRepulsion: function(node) { return 6500; },
        gravity: 0.25,
        randomize: false,
      };
    }

    // Initialize Cytoscape
    cyInstance = cytoscape({
      container: container,
      elements: elements,
      style: stylesheet,
      layout: layoutConfig,
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.3,
    });

    // Node click handler — highlights related findings
    cyInstance.on('tap', 'node', function (evt) {
      const node = evt.target;
      const nodeId = node.id();
      const findingIds = node.data('findingIds') || [];

      // Reset all
      cyInstance.elements().removeClass('highlighted dimmed');

      if (findingIds.length > 0 && onNodeClick) {
        // Highlight this node and connected edges
        node.addClass('highlighted');
        node.connectedEdges().addClass('highlighted');
        node.neighborhood().addClass('highlighted');
        cyInstance.elements().not(node.neighborhood().union(node)).addClass('dimmed');

        onNodeClick(nodeId, findingIds);
      }
    });

    // Background click — reset highlights
    cyInstance.on('tap', function (evt) {
      if (evt.target === cyInstance) {
        cyInstance.elements().removeClass('highlighted dimmed');
      }
    });

    return cyInstance;
  }

  /**
   * Highlights a specific attack path in the graph.
   * @param {string[]} pathArns - Array of ARN strings forming the attack path
   */
  function highlightPath(pathArns) {
    if (!cyInstance) return;
    cyInstance.elements().removeClass('highlighted dimmed');

    if (!pathArns || pathArns.length === 0) return;

    // Collect path nodes and edges between them
    const pathNodes = cyInstance.collection();
    const pathEdges = cyInstance.collection();

    pathArns.forEach((arn) => {
      const node = cyInstance.getElementById(arn);
      if (node.length) pathNodes.merge(node);
    });

    // Find edges connecting consecutive path nodes
    for (let i = 0; i < pathArns.length - 1; i++) {
      const src = cyInstance.getElementById(pathArns[i]);
      const tgt = cyInstance.getElementById(pathArns[i + 1]);
      if (src.length && tgt.length) {
        const connecting = src.edgesTo(tgt);
        pathEdges.merge(connecting);
      }
    }

    const pathElements = pathNodes.union(pathEdges);
    pathElements.addClass('highlighted');
    cyInstance.elements().not(pathElements).addClass('dimmed');

    // Fit view to path with padding
    if (pathNodes.length > 0) {
      cyInstance.animate({
        fit: { eles: pathNodes, padding: 60 },
        duration: 500,
        easing: 'ease-out-cubic',
      });
    }
  }

  /** Resets all graph highlights. */
  function clearHighlights() {
    if (!cyInstance) return;
    cyInstance.elements().removeClass('highlighted dimmed');
  }

  /** Fits the graph to the viewport. */
  function fitGraph() {
    if (!cyInstance) return;
    cyInstance.animate({
      fit: { padding: 40 },
      duration: 400,
      easing: 'ease-out-cubic',
    });
  }

  /** Zooms in. */
  function zoomIn() {
    if (!cyInstance) return;
    cyInstance.animate({
      zoom: { level: cyInstance.zoom() * 1.3, renderedPosition: { x: cyInstance.width() / 2, y: cyInstance.height() / 2 } },
      duration: 200,
    });
  }

  /** Zooms out. */
  function zoomOut() {
    if (!cyInstance) return;
    cyInstance.animate({
      zoom: { level: cyInstance.zoom() / 1.3, renderedPosition: { x: cyInstance.width() / 2, y: cyInstance.height() / 2 } },
      duration: 200,
    });
  }

  /** Returns the Cytoscape instance for external use. */
  function getInstance() {
    return cyInstance;
  }

  return {
    renderGraph,
    highlightPath,
    clearHighlights,
    fitGraph,
    zoomIn,
    zoomOut,
    getInstance,
  };
})();
