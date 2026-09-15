/* ============================================================
   Detail Modal — Click-to-expand finding + remediation drawer
   Person 4 Module — /dashboard_ui/js/detail-modal.js
   ============================================================ */

/**
 * Detail modal module — renders the slide-in drawer showing a finding's
 * narrative, attack path, offending statement, and remediation.
 * Pure display — never modifies or recomputes any scores or statements.
 */
const DetailModal = (function () {
  'use strict';

  let isOpen = false;

  /** Simple HTML escaper. */
  function esc(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  /** Pretty-prints a JSON value for display in code blocks. */
  function prettyJson(obj) {
    if (!obj) return '—';
    return JSON.stringify(obj, null, 2);
  }

  /** Returns severity class for a risk score. */
  function getSeverity(score) {
    if (score >= 90) return 'critical';
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  /** Extracts a short display name from an ARN. */
  function arnShortName(arn) {
    if (!arn) return '';
    const parts = arn.split(':');
    const last = parts[parts.length - 1];
    return last.includes('/') ? last.split('/').pop() : last;
  }

  /** Extracts the resource type from an ARN (e.g., "user", "role"). */
  function arnType(arn) {
    if (!arn) return '';
    const parts = arn.split(':');
    const last = parts[parts.length - 1];
    return last.includes('/') ? last.split('/')[0] : '';
  }

  /**
   * Opens the detail drawer for a specific finding.
   * @param {Object} finding - A single finding object from findings.json
   * @param {Object|null} remediation - Matching remediation from remediations.json, or null
   */
  function showFindingDetail(finding, remediation) {
    const overlay = document.querySelector('.detail-overlay');
    const drawer = document.querySelector('.detail-drawer');
    const body = document.querySelector('.detail-drawer-body');

    if (!overlay || !drawer || !body) {
      console.error('Detail modal DOM elements not found');
      return;
    }

    const severity = getSeverity(finding.risk_score);
    const rb = finding.risk_breakdown || {};

    // Build the drawer content
    let html = '';

    // --- Risk score header ---
    html += `
      <div class="detail-section">
        <div style="display:flex;align-items:center;gap:var(--space-md);flex-wrap:wrap;">
          <span class="risk-score-number ${severity}" style="font-size:2.2rem;">${finding.risk_score.toFixed(1)}</span>
          <span class="type-badge ${esc(finding.type)}" style="font-size:0.72rem;">${esc(formatType(finding.type))}</span>
          <span style="color:var(--text-tertiary);font-family:var(--font-mono);font-size:0.72rem;">${esc(finding.finding_id)}</span>
        </div>
        <div class="risk-breakdown" style="max-width:360px;">
          <div class="breakdown-item">
            <span class="breakdown-label">Reachability</span>
            <div class="breakdown-bar-track">
              <div class="breakdown-bar-fill" style="width:${(rb.reachability || 0) * 100}%;"></div>
            </div>
            <span class="breakdown-value">${((rb.reachability || 0) * 100).toFixed(0)}%</span>
          </div>
          <div class="breakdown-item">
            <span class="breakdown-label">Blast Radius</span>
            <div class="breakdown-bar-track">
              <div class="breakdown-bar-fill" style="width:${(rb.blast_radius || 0) * 100}%;"></div>
            </div>
            <span class="breakdown-value">${((rb.blast_radius || 0) * 100).toFixed(0)}%</span>
          </div>
          <div class="breakdown-item">
            <span class="breakdown-label">Exploit Triviality</span>
            <div class="breakdown-bar-track">
              <div class="breakdown-bar-fill" style="width:${(rb.exploit_triviality || 0) * 100}%;"></div>
            </div>
            <span class="breakdown-value">${((rb.exploit_triviality || 0) * 100).toFixed(0)}%</span>
          </div>
        </div>
      </div>
    `;

    // --- Narrative ---
    html += `
      <div class="detail-section">
        <span class="detail-section-label">Attack Narrative</span>
        <div class="detail-narrative">${esc(finding.narrative)}</div>
      </div>
    `;

    // --- Attack Path ---
    if (finding.path && finding.path.length > 0) {
      html += `
        <div class="detail-section">
          <span class="detail-section-label">Escalation Path (${finding.path.length} hops)</span>
          <div class="attack-path">
      `;
      finding.path.forEach((arn, idx) => {
        html += `
          <div class="attack-path-step">
            <div class="path-step-dot"></div>
            <div>
              <span class="path-step-arn">${esc(arn)}</span>
            </div>
          </div>
        `;
        if (idx < finding.path.length - 1) {
          html += `<div class="path-step-arrow">↓</div>`;
        }
      });
      html += `</div></div>`;
    }

    // --- Offending Statement ---
    if (finding.offending_statement) {
      const os = finding.offending_statement;
      html += `
        <div class="detail-section">
          <span class="detail-section-label">Offending Policy Statement</span>
          <div class="offending-block">
            <div><span class="key">Policy:</span> <span class="value">${esc(os.policy_arn)}</span></div>
            <div><span class="key">Action:</span> <span class="value">${esc(os.action)}</span></div>
            <div><span class="key">Resource:</span> <span class="value">${esc(os.resource)}</span></div>
          </div>
        </div>
      `;
    }

    // --- Remediation ---
    html += `<div class="detail-section">`;
    html += `<span class="detail-section-label">Remediation</span>`;

    if (remediation && remediation.remediable === false) {
      // Not remediable
      html += `
        <div class="not-remediable-banner">
          <span>⚠</span>
          <div>
            <strong>Not auto-remediable</strong><br>
            ${esc(remediation.justification)}
          </div>
        </div>
      `;
    } else if (remediation && remediation.suggested_statement) {
      // Has a fix
      html += `
        <div class="remediation-container">
          <div class="remediation-comparison">
            <div class="remediation-side">
              <span class="remediation-side-label original">✗ Current (Overpermissioned)</span>
              <div class="remediation-code original">${esc(prettyJson(remediation.original_statement))}</div>
            </div>
            <div class="remediation-side">
              <span class="remediation-side-label suggested">✓ Suggested (Least Privilege)</span>
              <div class="remediation-code suggested">${esc(prettyJson(remediation.suggested_statement))}</div>
            </div>
          </div>
          <div class="remediation-justification">${esc(remediation.justification)}</div>
          <button class="download-btn" id="download-fix-btn" data-finding-id="${esc(finding.finding_id)}">
            ⬇ Download Fixed Policy
          </button>
        </div>
      `;
    } else {
      html += `
        <div class="not-remediable-banner">
          <span>ℹ</span>
          <div>No remediation available for this finding.</div>
        </div>
      `;
    }

    html += `</div>`;

    // Set content
    body.innerHTML = html;

    // Update drawer title
    const titleEl = document.querySelector('.detail-drawer-title');
    if (titleEl) titleEl.textContent = finding.pattern_name || finding.finding_id;

    // Open drawer
    overlay.classList.add('open');
    drawer.classList.add('open');
    isOpen = true;

    // Wire up download button
    const dlBtn = document.getElementById('download-fix-btn');
    if (dlBtn && remediation && remediation.suggested_statement) {
      dlBtn.addEventListener('click', () => {
        downloadFixedPolicy(finding, remediation);
      });
    }
  }

  /** Closes the detail drawer. */
  function closeDrawer() {
    const overlay = document.querySelector('.detail-overlay');
    const drawer = document.querySelector('.detail-drawer');
    if (overlay) overlay.classList.remove('open');
    if (drawer) drawer.classList.remove('open');
    isOpen = false;

    // Clear active finding card
    ScoreCards.clearActiveCards();
    GraphRenderer.clearHighlights();
  }

  /**
   * Downloads the suggested policy statement as a JSON file.
   * @param {Object} finding - The finding object
   * @param {Object} remediation - The remediation object
   */
  function downloadFixedPolicy(finding, remediation) {
    const policyDoc = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: remediation.suggested_statement.action,
          Resource: remediation.suggested_statement.resource,
        },
      ],
    };

    // Include condition if present
    if (remediation.suggested_statement.condition) {
      policyDoc.Statement[0].Condition = remediation.suggested_statement.condition;
    }

    const blob = new Blob([JSON.stringify(policyDoc, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `fixed-policy-${finding.finding_id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /** Formats finding type for display. */
  function formatType(type) {
    const labels = {
      known_pattern: 'Known Pattern',
      novel_path: 'Novel Path',
      wildcard_overpermission: 'Wildcard',
    };
    return labels[type] || type;
  }

  /** Returns whether the drawer is currently open. */
  function getIsOpen() {
    return isOpen;
  }

  /** Initializes event listeners for closing the drawer. */
  function init() {
    // Close on overlay click
    const overlay = document.querySelector('.detail-overlay');
    if (overlay) {
      overlay.addEventListener('click', closeDrawer);
    }

    // Close on close button
    const closeBtn = document.querySelector('.detail-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', closeDrawer);
    }

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && isOpen) {
        closeDrawer();
      }
    });
  }

  return {
    showFindingDetail,
    closeDrawer,
    init,
    getIsOpen,
  };
})();
