/**
 * Status Poller Component
 * Reusable polling mechanism for checking scan/repair/build status
 */

class StatusPoller {
  constructor(config) {
    this.scanId = config.scanId;
    this.apiEndpoint = config.apiEndpoint;
    this.interval = config.interval || 2000; // Default 2 seconds
    this.onUpdate = config.onUpdate || (() => {});
    this.onComplete = config.onComplete || (() => {});
    this.onError = config.onError || (() => {});
    
    this.pollInterval = null;
    this.isPolling = false;
  }

  /**
   * Start polling
   */
  start() {
    if (this.isPolling) return;
    
    this.isPolling = true;
    this.poll(); // Poll immediately
    this.pollInterval = setInterval(() => this.poll(), this.interval);
  }

  /**
   * Stop polling
   */
  stop() {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    this.isPolling = false;
  }

  /**
   * Perform a single poll
   */
  async poll() {
    try {
      const response = await fetch(this.apiEndpoint);
      const data = await response.json();
      
      // Call update callback
      this.onUpdate(data);
      
      // Check if completed
      if (this.isComplete(data)) {
        this.stop();
        this.onComplete(data);
      }
    } catch (error) {
      console.error('Polling error:', error);
      this.onError(error);
    }
  }

  /**
   * Check if status indicates completion
   */
  isComplete(data) {
    const completedStatuses = ['completed', 'success', 'failed', 'error'];
    return completedStatuses.includes(data.status?.toLowerCase());
  }

  /**
   * Restart polling
   */
  restart() {
    this.stop();
    this.start();
  }
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = StatusPoller;
}
