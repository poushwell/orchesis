/**
 * Orchesis Context Engine Plugin
 * Real-time context quality monitoring for AI agents
 *
 * Usage:
 *   const { OrchesisContext } = require('orchesis-context');
 *   const ctx = new OrchesisContext({ proxyUrl: 'http://localhost:8090' });
 *   await ctx.checkQuality(messages);
 */

class OrchesisContext {
  constructor(config = {}) {
    this.proxyUrl = config.proxyUrl || 'http://localhost:8090';
    this.token = config.token || null;
    this.enabled = config.enabled !== false;
  }

  async checkQuality(messages) {
    if (!this.enabled) return { quality: 1.0, phase: 'LIQUID' };
    try {
      const resp = await fetch(`${this.proxyUrl}/api/v1/nlce/metrics`, {
        headers: this.token ? { Authorization: `Bearer ${this.token}` } : {}
      });
      const data = await resp.json();
      return {
        quality: data.pipeline_state?.crystallinity_psi ?? 0.5,
        phase: data.pipeline_state?.current_phase ?? 'LIQUID',
        token_yield: data.token_yield?.avg ?? null,
        warning: data.pipeline_state?.slope_alert ?? false,
      };
    } catch {
      return { quality: null, phase: 'unknown', error: 'proxy_unreachable' };
    }
  }

  async getMetrics() {
    try {
      const resp = await fetch(`${this.proxyUrl}/api/v1/nlce/metrics`);
      return await resp.json();
    } catch {
      return { error: 'proxy_unreachable' };
    }
  }

  async reportCost(sessionId, tokens, costUsd) {
    try {
      await fetch(`${this.proxyUrl}/api/v1/cost/track`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId, tokens, cost_usd: costUsd })
      });
      return true;
    } catch {
      return false;
    }
  }
}

class OrchesisMiddleware {
  /**
   * Express/Node middleware — adds Orchesis context headers to responses
   */
  static create(config = {}) {
    const ctx = new OrchesisContext(config);
    return async (req, res, next) => {
      try {
        const quality = await ctx.checkQuality([]);
        res.setHeader('X-Orchesis-Phase', quality.phase);
        res.setHeader('X-Orchesis-Quality', quality.quality ?? 'unknown');
        if (quality.warning) {
          res.setHeader('X-Orchesis-Warning', 'context_degraded');
        }
      } catch {}
      next();
    };
  }
}

module.exports = { OrchesisContext, OrchesisMiddleware };
