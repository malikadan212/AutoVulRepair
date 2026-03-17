/**
 * AutoVulRepair - Common Utility Functions
 */

const Utils = {
  /**
   * Show a notification toast
   */
  notify(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `notification-toast ${type}`;
    toast.innerHTML = `
      <i class="fas fa-${this.getIconForType(type)}"></i>
      <span>${message}</span>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
      toast.style.animation = 'slideOutRight 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  },

  getIconForType(type) {
    const icons = {
      success: 'check-circle',
      error: 'exclamation-circle',
      warning: 'exclamation-triangle',
      info: 'info-circle'
    };
    return icons[type] || 'info-circle';
  },

  /**
   * Format timestamp to readable string
   */
  formatTime(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleString();
  },

  /**
   * Format duration in seconds to readable string
   */
  formatDuration(seconds) {
    if (!seconds) return '0s';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    } else {
      return `${secs}s`;
    }
  },

  /**
   * Update progress bar
   */
  updateProgressBar(elementId, percentage, text = null) {
    const progressBar = document.getElementById(elementId);
    if (!progressBar) return;
    
    progressBar.style.width = percentage + '%';
    progressBar.setAttribute('aria-valuenow', percentage);
    
    if (text) {
      progressBar.textContent = text;
    } else {
      progressBar.textContent = percentage + '%';
    }
  },

  /**
   * Show/hide loading spinner on button
   */
  setButtonLoading(button, loading, originalText = null) {
    if (loading) {
      button.dataset.originalText = button.innerHTML;
      button.innerHTML = '<span class="loading-spinner"></span> Loading...';
      button.disabled = true;
    } else {
      button.innerHTML = originalText || button.dataset.originalText || 'Submit';
      button.disabled = false;
    }
  },

  /**
   * Debounce function calls
   */
  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  },

  /**
   * Get severity badge class
   */
  getSeverityClass(severity) {
    const classes = {
      critical: 'danger',
      high: 'danger',
      medium: 'warning',
      low: 'info'
    };
    return classes[severity?.toLowerCase()] || 'secondary';
  },

  /**
   * Get status badge class
   */
  getStatusClass(status) {
    const classes = {
      completed: 'success',
      success: 'success',
      running: 'primary',
      pending: 'warning',
      queued: 'secondary',
      failed: 'danger',
      error: 'danger'
    };
    return classes[status?.toLowerCase()] || 'secondary';
  },

  /**
   * Escape HTML to prevent XSS
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  /**
   * Copy text to clipboard
   */
  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      this.notify('Copied to clipboard!', 'success');
    } catch (err) {
      console.error('Failed to copy:', err);
      this.notify('Failed to copy to clipboard', 'error');
    }
  },

  /**
   * Download data as file
   */
  downloadFile(data, filename, type = 'text/plain') {
    const blob = new Blob([data], { type });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  }
};

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Utils;
}
