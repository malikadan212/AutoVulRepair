/**
 * AutoVulRepair - Centralized API Layer
 * All API calls go through this module for consistency
 */

const API = {
  /**
   * Base fetch wrapper with error handling
   */
  async request(url, options = {}) {
    try {
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        ...options
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  },

  /**
   * Scan API endpoints
   */
  scan: {
    status(scanId) {
      return API.request(`/api/scan-status/${scanId}`);
    },
    
    start(data) {
      return API.request('/api/scan/start', {
        method: 'POST',
        body: JSON.stringify(data)
      });
    },
    
    results(scanId) {
      return API.request(`/api/scan/${scanId}/results`);
    }
  },

  /**
   * Fuzzing API endpoints
   */
  fuzz: {
    start(scanId, options = {}) {
      return API.request(`/api/fuzz/start/${scanId}`, {
        method: 'POST',
        body: JSON.stringify(options)
      });
    },
    
    results(scanId) {
      return API.request(`/api/fuzz/results/${scanId}`);
    },
    
    status(scanId) {
      return API.request(`/api/fuzz/status/${scanId}`);
    }
  },

  /**
   * Repair/Patch API endpoints
   */
  repair: {
    start(scanId) {
      return API.request(`/api/repair/start/${scanId}`, {
        method: 'POST'
      });
    },
    
    status(scanId) {
      return API.request(`/api/repair/status/${scanId}`);
    },
    
    patch(scanId, crashId) {
      return API.request(`/api/repair/patch/${scanId}/${crashId}`);
    },
    
    apply(scanId, crashId) {
      return API.request(`/api/repair/apply/${scanId}/${crashId}`, {
        method: 'POST'
      });
    },
    
    download(scanId, crashId) {
      window.location.href = `/api/repair/download/${scanId}/${crashId}`;
    },
    
    health() {
      return API.request('/api/repair/health');
    }
  },

  /**
   * Triage API endpoints
   */
  triage: {
    start(scanId) {
      return API.request(`/api/triage/start/${scanId}`, {
        method: 'POST'
      });
    },
    
    results(scanId) {
      return API.request(`/api/triage/results/${scanId}`);
    }
  },

  /**
   * Build API endpoints
   */
  build: {
    start(scanId) {
      return API.request(`/api/build/start/${scanId}`, {
        method: 'POST'
      });
    },
    
    status(scanId) {
      return API.request(`/api/build/status/${scanId}`);
    }
  }
};

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = API;
}
