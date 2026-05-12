/**
 * Agent Pipeline Component
 * Visual representation of AI agent workflow
 */

class AgentPipeline {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.agents = [
      { id: 'analyzer', name: 'Analyzer', icon: '🔍', status: 'pending', time: null },
      { id: 'strategy', name: 'Strategy', icon: '🎯', status: 'pending', time: null },
      { id: 'generator', name: 'Generator', icon: '⚙️', status: 'pending', time: null },
      { id: 'validator', name: 'Validator', icon: '✅', status: 'pending', time: null },
      { id: 'optimizer', name: 'Optimizer', icon: '🚀', status: 'pending', time: null }
    ];
    this.render();
  }

  /**
   * Update agent status
   */
  updateAgent(agentId, status, time = null) {
    const agent = this.agents.find(a => a.id === agentId);
    if (agent) {
      agent.status = status; // pending, active, completed, failed
      if (time !== null) {
        agent.time = time;
      }
      this.render();
    }
  }

  /**
   * Render the pipeline
   */
  render() {
    if (!this.container) return;

    this.container.innerHTML = this.agents.map(agent => `
      <div class="pipeline-agent">
        <div class="agent-icon ${agent.status}">
          ${agent.icon}
        </div>
        <div class="agent-name">${agent.name}</div>
        <div class="agent-status">
          ${this.getStatusText(agent.status)}
        </div>
        ${agent.time ? `<div class="agent-time">${agent.time}s</div>` : ''}
      </div>
    `).join('');
  }

  /**
   * Get status display text
   */
  getStatusText(status) {
    const statusMap = {
      pending: '⏳ Pending',
      active: '🔄 Working',
      completed: '✓ Done',
      failed: '✗ Failed'
    };
    return statusMap[status] || status;
  }

  /**
   * Reset all agents to pending
   */
  reset() {
    this.agents.forEach(agent => {
      agent.status = 'pending';
      agent.time = null;
    });
    this.render();
  }

  /**
   * Get current progress percentage
   */
  getProgress() {
    const completed = this.agents.filter(a => a.status === 'completed').length;
    return Math.round((completed / this.agents.length) * 100);
  }
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AgentPipeline;
}
