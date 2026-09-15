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

    if (!drawer || !body) {
      console.error('Detail modal DOM elements not found');
      return;
    }

    const severity = getSeverity(finding.risk_score);
    const rb = finding.risk_breakdown || {};

    // Build the drawer content
    let html = '';

    // --- Risk score header ---
    html += `
      <div style="display:flex;flex-direction:column;gap:8px;">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <span style="font-family:var(--font-mono);font-size:0.75rem;font-weight:700;color:var(--text-muted);">${esc(finding.finding_id)}</span>
          <span class="type-pill ${esc(finding.type)}">${esc(formatType(finding.type))}</span>
        </div>
        <h2 style="font-size:1.35rem;font-weight:800;letter-spacing:-0.02em;color:var(--text-display);line-height:1.25;">
          ${esc(finding.pattern_name)}
        </h2>
        <div style="display:flex;align-items:baseline;gap:6px;margin-top:4px;">
          <span class="score-big ${severity}" style="font-size:2.4rem;">${finding.risk_score.toFixed(1)}</span>
          <span style="color:var(--text-muted);font-weight:600;font-size:0.85rem;">/ 100 Risk Score</span>
        </div>
      </div>
    `;

    // --- 3-Factor Breakdown Row ---
    html += `
      <div class="breakdown-3col" style="padding:14px;background:#f8fafc;border-radius:var(--radius-inner);border:1px solid #e2e8f0;">
        <div class="breakdown-unit">
          <span class="breakdown-header-lbl">Reachability</span>
          <div class="breakdown-track">
            <div class="breakdown-bar" style="width:${(rb.reachability || 0) * 100}%;"></div>
          </div>
          <span class="breakdown-num">${((rb.reachability || 0) * 100).toFixed(0)}%</span>
        </div>
        <div class="breakdown-unit">
          <span class="breakdown-header-lbl">Blast Radius</span>
          <div class="breakdown-track">
            <div class="breakdown-bar" style="width:${(rb.blast_radius || 0) * 100}%;"></div>
          </div>
          <span class="breakdown-num">${((rb.blast_radius || 0) * 100).toFixed(0)}%</span>
        </div>
        <div class="breakdown-unit">
          <span class="breakdown-header-lbl">Exploit Triviality</span>
          <div class="breakdown-track">
            <div class="breakdown-bar" style="width:${(rb.exploit_triviality || 0) * 100}%;"></div>
          </div>
          <span class="breakdown-num">${((rb.exploit_triviality || 0) * 100).toFixed(0)}%</span>
        </div>
      </div>
    `;

    // --- Narrative in Pastel Callout Box ---
    html += `
      <div>
        <div style="font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:8px;">Attack Narrative</div>
        <div class="narrative-pastel-callout">${esc(finding.narrative)}</div>
      </div>
    `;

    // --- Escalation Path ---
    if (finding.path && finding.path.length > 0) {
      html += `
        <div>
          <div style="font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:8px;">
            Escalation Path (${finding.path.length} hops)
          </div>
          <div style="display:flex;flex-direction:column;gap:6px;padding:12px 16px;background:#f8fafc;border-radius:var(--radius-inner);border:1px solid #e2e8f0;font-family:var(--font-mono);font-size:0.72rem;">
      `;
      finding.path.forEach((arn, idx) => {
        html += `
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="width:8px;height:8px;border-radius:50%;background:var(--btn-charcoal);flex-shrink:0;"></span>
            <span style="word-break:break-all;color:var(--text-display);font-weight:600;">${esc(arn)}</span>
          </div>
        `;
        if (idx < finding.path.length - 1) {
          html += `<div style="padding-left:14px;color:var(--text-muted);font-size:10px;">↓</div>`;
        }
      });
      html += `</div></div>`;
    }

    // --- Remediation Section ---
    html += `<div>`;
    html += `<div style="font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:8px;">Remediation Policy</div>`;

    if (remediation && remediation.remediable === false) {
      html += `
        <div class="justification-pastel-box" style="background:#fef2f2;border-color:#fecaca;color:#991b1b;">
          <strong>⚠ Architectural Review Required</strong><br>
          ${esc(remediation.justification)}
        </div>
      `;
    } else if (remediation && remediation.suggested_statement) {
      const fixedDoc = {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: remediation.suggested_statement.action,
            Resource: remediation.suggested_statement.resource,
            ...(remediation.suggested_statement.condition ? { Condition: remediation.suggested_statement.condition } : {})
          }
        ]
      };
      const jsonStr = JSON.stringify(fixedDoc, null, 2);
      const cliCmd = `aws iam create-policy-version --policy-arn ${esc(finding.offending_policy_arn || 'arn:aws:iam::111111111111:policy/RemediatedPolicy')} --policy-document '${JSON.stringify(fixedDoc)}' --set-as-default`;

      html += `
        <div style="display:flex;flex-direction:column;gap:12px;">
          <div class="code-preview-card">
            <div class="code-preview-header">✓ Suggested Least-Privilege Statement</div>
            <pre>${esc(prettyJson(remediation.suggested_statement))}</pre>
          </div>
          <div class="justification-pastel-box">
            ${esc(remediation.justification)}
          </div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <button class="pill-btn pill-btn-dark" id="download-fix-btn" style="width:100%;justify-content:center;padding:10px 20px;">
              ⬇ Download Fixed Policy JSON
            </button>
            <div style="display:flex;gap:8px;">
              <button class="pill-btn pill-btn-outline" id="copy-fix-btn" style="flex:1;justify-content:center;font-size:0.75rem;padding:8px 12px;">
                📋 Copy Policy JSON
              </button>
              <button class="pill-btn pill-btn-outline" id="copy-cli-btn" style="flex:1;justify-content:center;font-size:0.75rem;padding:8px 12px;">
                ⚡ Copy AWS CLI Fix
              </button>
            </div>
          </div>
        </div>
      `;
    } else {
      html += `<div class="justification-pastel-box">No remediation needed for this finding.</div>`;
    }

    html += `</div>`;

    // Set content
    body.innerHTML = html;

    // Open drawer
    if (overlay) overlay.classList.add('open');
    drawer.classList.add('open');
    isOpen = true;

    // Wire up download button
    const dlBtn = document.getElementById('download-fix-btn');
    if (dlBtn && remediation && remediation.suggested_statement) {
      dlBtn.addEventListener('click', () => {
        downloadFixedPolicy(finding, remediation);
      });
    }

    // Wire up copy JSON button
    const copyJsonBtn = document.getElementById('copy-fix-btn');
    if (copyJsonBtn && remediation && remediation.suggested_statement) {
      copyJsonBtn.addEventListener('click', () => {
        const fixedDoc = {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: remediation.suggested_statement.action,
              Resource: remediation.suggested_statement.resource,
              ...(remediation.suggested_statement.condition ? { Condition: remediation.suggested_statement.condition } : {})
            }
          ]
        };
        navigator.clipboard.writeText(JSON.stringify(fixedDoc, null, 2)).then(() => {
          copyJsonBtn.textContent = '✓ Copied JSON!';
          if (window.App && window.App.showToast) {
            window.App.showToast('✓ Policy JSON copied to clipboard');
          }
          setTimeout(() => { copyJsonBtn.textContent = '📋 Copy Policy JSON'; }, 2000);
        });
      });
    }

    // Wire up copy CLI button
    const copyCliBtn = document.getElementById('copy-cli-btn');
    if (copyCliBtn && remediation && remediation.suggested_statement) {
      copyCliBtn.addEventListener('click', () => {
        const fixedDoc = {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: remediation.suggested_statement.action,
              Resource: remediation.suggested_statement.resource,
              ...(remediation.suggested_statement.condition ? { Condition: remediation.suggested_statement.condition } : {})
            }
          ]
        };
        const cliCmd = `aws iam create-policy-version --policy-arn ${finding.offending_policy_arn || 'arn:aws:iam::111111111111:policy/RemediatedPolicy'} --policy-document '${JSON.stringify(fixedDoc)}' --set-as-default`;
        navigator.clipboard.writeText(cliCmd).then(() => {
          copyCliBtn.textContent = '✓ Copied CLI!';
          if (window.App && window.App.showToast) {
            window.App.showToast('✓ AWS CLI command copied to clipboard');
          }
          setTimeout(() => { copyCliBtn.textContent = '⚡ Copy AWS CLI Fix'; }, 2000);
        });
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
    const closeBtn = document.querySelector('.detail-close-btn') || 
                     document.querySelector('#btn-close-drawer') || 
                     document.querySelector('.drawer-close-circle');
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
