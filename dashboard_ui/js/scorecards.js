/* ============================================================
   Scorecards — Risk findings ranked list with 3-factor breakdown
   Person 4 Module — /dashboard_ui/js/scorecards.js
   ============================================================ */

/**
 * Scorecards module — renders the ranked findings list in the right panel.
 * Displays risk_score, pattern_name, type badge, and the 3-factor
 * risk_breakdown (reachability, blast_radius, exploit_triviality).
 * Pure display — reads findings.json, never computes scores.
 */
const ScoreCards = (function () {
  'use strict';

  /** Returns severity class string for a risk score (0–100). */
  function getSeverity(score) {
    if (score >= 90) return 'critical';
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  /** Returns human-readable severity label. */
  function getSeverityLabel(score) {
    if (score >= 90) return 'Critical';
    if (score >= 70) return 'High';
    if (score >= 40) return 'Medium';
    return 'Low';
  }

  /** Formats a finding type enum to a display label. */
  function formatType(type) {
    const labels = {
      known_pattern: 'Known Pattern',
      novel_path: 'Novel Path',
      wildcard_overpermission: 'Wildcard',
    };
    return labels[type] || type;
  }

  /** Truncates a string with ellipsis. */
  function truncate(str, maxLen) {
    if (!str) return '';
    return str.length > maxLen ? str.substring(0, maxLen) + '…' : str;
  }

  /**
   * Renders all finding scorecards into the .findings-list container.
   * @param {Object} findingsData - Parsed findings.json
   * @param {Function} onCardClick - Callback(finding) when a card is clicked
   */
  function renderScoreCards(findingsData, onCardClick) {
    const listEl = document.querySelector('.findings-list');
    if (!listEl) {
      console.error('Findings list container .findings-list not found');
      return;
    }

    listEl.innerHTML = '';

    if (!findingsData || !findingsData.findings || findingsData.findings.length === 0) {
      listEl.innerHTML = '<div style="text-align:center;color:var(--text-tertiary);padding:var(--space-xl);">No findings to display.</div>';
      return;
    }

    // Sort by risk_score descending
    const sorted = [...findingsData.findings].sort((a, b) => b.risk_score - a.risk_score);

    // Update count badge
    const countEl = document.querySelector('.findings-count');
    if (countEl) countEl.textContent = sorted.length;

    sorted.forEach((finding, index) => {
      const severity = getSeverity(finding.risk_score);
      const card = document.createElement('div');
      card.className = `finding-card ${severity} animate-in`;
      card.dataset.findingId = finding.finding_id;
      card.style.animationDelay = `${index * 70}ms`;

      const rb = finding.risk_breakdown || {};

      card.innerHTML = `
        <div class="card-top-meta">
          <span class="finding-id-pill">${escapeHtml(finding.finding_id)}</span>
          <span class="type-pill ${escapeHtml(finding.type)}">${formatType(finding.type)}</span>
        </div>
        <div class="finding-pattern-title">${escapeHtml(finding.pattern_name)}</div>
        <div class="score-line">
          <span class="score-big ${severity}">${finding.risk_score.toFixed(1)}</span>
          <span class="score-out-of">/ 100 Risk</span>
        </div>
        <div class="breakdown-3col">
          <div class="breakdown-unit">
            <span class="breakdown-header-lbl">Reach</span>
            <div class="breakdown-track">
              <div class="breakdown-bar" style="width:${(rb.reachability || 0) * 100}%;"></div>
            </div>
            <span class="breakdown-num">${((rb.reachability || 0) * 100).toFixed(0)}%</span>
          </div>
          <div class="breakdown-unit">
            <span class="breakdown-header-lbl">Blast</span>
            <div class="breakdown-track">
              <div class="breakdown-bar" style="width:${(rb.blast_radius || 0) * 100}%;"></div>
            </div>
            <span class="breakdown-num">${((rb.blast_radius || 0) * 100).toFixed(0)}%</span>
          </div>
          <div class="breakdown-unit">
            <span class="breakdown-header-lbl">Exploit</span>
            <div class="breakdown-track">
              <div class="breakdown-bar" style="width:${(rb.exploit_triviality || 0) * 100}%;"></div>
            </div>
            <span class="breakdown-num">${((rb.exploit_triviality || 0) * 100).toFixed(0)}%</span>
          </div>
        </div>
      `;

      // Click handler → delegate to app controller
      card.addEventListener('click', () => {
        // Remove active from all cards
        document.querySelectorAll('.finding-card').forEach((c) => c.classList.remove('active'));
        card.classList.add('active');
        if (onCardClick) onCardClick(finding);
      });

      listEl.appendChild(card);
    });

    // Animate risk bars after a brief delay (so the animation is visible)
    requestAnimationFrame(() => {
      setTimeout(() => {
        document.querySelectorAll('.risk-bar-fill[data-width]').forEach((bar) => {
          bar.style.width = bar.dataset.width + '%';
        });
        document.querySelectorAll('.breakdown-bar-fill[data-width]').forEach((bar) => {
          bar.style.width = bar.dataset.width + '%';
        });
      }, 100);
    });
  }

  /**
   * Highlights finding cards whose finding_id is in the given list.
   * @param {string[]} findingIds - Array of finding_id strings
   */
  function highlightCards(findingIds) {
    document.querySelectorAll('.finding-card').forEach((card) => {
      if (findingIds.includes(card.dataset.findingId)) {
        card.classList.add('active');
        card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      } else {
        card.classList.remove('active');
      }
    });
  }

  /** Clears all active states from finding cards. */
  function clearActiveCards() {
    document.querySelectorAll('.finding-card').forEach((c) => c.classList.remove('active'));
  }

  /** Simple HTML escaper to prevent XSS in rendered content. */
  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  let currentFindingsData = null;
  let currentOnCardClick = null;
  let currentFilter = 'all';

  /**
   * Filters findings by severity ('all', 'critical', 'high', 'medium', 'low').
   */
  function filterBySeverity(filter) {
    currentFilter = filter;
    const cards = document.querySelectorAll('.finding-card');
    let visibleCount = 0;

    cards.forEach((card) => {
      if (filter === 'all' || card.classList.contains(filter)) {
        card.style.display = '';
        visibleCount++;
      } else {
        card.style.display = 'none';
      }
    });

    const countEl = document.querySelector('.findings-count');
    if (countEl) countEl.textContent = visibleCount;
  }

  /**
   * Sets up filter pill button click listeners.
   */
  function setupFilterListeners() {
    const filterPills = document.querySelectorAll('.filter-pill');
    filterPills.forEach((pill) => {
      pill.addEventListener('click', () => {
        filterPills.forEach((p) => p.classList.remove('active'));
        pill.classList.add('active');
        const filter = pill.dataset.filter || 'all';
        filterBySeverity(filter);
      });
    });
  }

  return {
    renderScoreCards,
    highlightCards,
    clearActiveCards,
    filterBySeverity,
    setupFilterListeners,
    getSeverity,
    getSeverityLabel,
    escapeHtml,
  };
})();
