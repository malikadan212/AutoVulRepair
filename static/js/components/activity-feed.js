/**
 * Activity Feed Component
 * Real-time logging of AI agent activities
 */

class ActivityFeed {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.entries = [];
    this.autoScroll = true;
  }

  /**
   * Add a log entry to the feed
   */
  addEntry(entry) {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = {
      timestamp,
      agent: entry.agent || 'system',
      icon: entry.icon || '📝',
      message: entry.message,
      type: entry.type || 'info', // info, success, error, warning
      ...entry
    };

    this.entries.push(logEntry);
    this.render(logEntry);
  }

  /**
   * Render a single log entry
   */
  render(entry) {
    if (!this.container) return;

    const entryDiv = document.createElement('div');
    entryDiv.className = `activity-log-entry ${entry.agent} log-${entry.type}`;
    
    entryDiv.innerHTML = `
      <span class="log-timestamp">[${entry.timestamp}]</span>
      <span class="log-icon">${entry.icon}</span>
      <span class="log-message">${Utils.escapeHtml(entry.message)}</span>
    `;

    this.container.appendChild(entryDiv);

    // Auto-scroll to bottom if enabled
    if (this.autoScroll) {
      this.container.scrollTop = this.container.scrollHeight;
    }

    // Add animation
    entryDiv.style.animation = 'fadeInLeft 0.3s ease';
  }

  /**
   * Clear all entries
   */
  clear() {
    this.entries = [];
    if (this.container) {
      this.container.innerHTML = '';
    }
  }

  /**
   * Add analyzer agent log
   */
  logAnalyzer(message, type = 'info') {
    this.addEntry({
      agent: 'analyzer',
      icon: '🔍',
      message,
      type
    });
  }

  /**
   * Add strategy agent log
   */
  logStrategy(message, type = 'info') {
    this.addEntry({
      agent: 'strategy',
      icon: '🎯',
      message,
      type
    });
  }

  /**
   * Add generator agent log
   */
  logGenerator(message, type = 'info') {
    this.addEntry({
      agent: 'generator',
      icon: '⚙️',
      message,
      type
    });
  }

  /**
   * Add validator agent log
   */
  logValidator(message, type = 'info') {
    this.addEntry({
      agent: 'validator',
      icon: '✅',
      message,
      type
    });
  }

  /**
   * Add optimizer agent log
   */
  logOptimizer(message, type = 'info') {
    this.addEntry({
      agent: 'optimizer',
      icon: '🚀',
      message,
      type
    });
  }

  /**
   * Export logs as text
   */
  exportLogs() {
    const logText = this.entries.map(entry => 
      `[${entry.timestamp}] ${entry.icon} ${entry.message}`
    ).join('\n');
    
    return logText;
  }

  /**
   * Toggle auto-scroll
   */
  toggleAutoScroll() {
    this.autoScroll = !this.autoScroll;
  }
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ActivityFeed;
}
