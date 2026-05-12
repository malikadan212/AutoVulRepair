/**
 * Monitoring Dashboard Module
 * Handles monitoring dashboard interactions and chart rendering
 */

function refreshMetrics() {
  // Simulate metrics refresh
  const button = event.target;
  const originalText = button.innerHTML;
  button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
  button.disabled = true;
  
  setTimeout(() => {
    button.innerHTML = originalText;
    button.disabled = false;
    // In real app, this would update all metrics
    location.reload();
  }, 2000);
}

function exportReport() {
  alert('Generating comprehensive system report...\nThis would export metrics to PDF/CSV format.');
}

function viewAlert(alertId) {
  const alertMessages = {
    'memory-high': 'Memory usage is at 87%. Consider scaling up the cluster or optimizing memory-intensive processes.',
    'queue-backlog': 'Analysis queue has 45 pending jobs. Current processing rate: 12 jobs/hour. Estimated completion: 3.7 hours.',
    'slow-response': 'CodeQL analysis is taking 23% longer than baseline. This may be due to increased complexity in recent scans.'
  };
  
  alert(`Alert Details:\n\n${alertMessages[alertId] || 'Alert details not available.'}`);
}

// Initialize charts
document.addEventListener('DOMContentLoaded', function() {
  // Scan Volume Chart
  const scanVolumeChart = document.getElementById('scanVolumeChart');
  if (scanVolumeChart) {
    const scanCtx = scanVolumeChart.getContext('2d');
    scanCtx.fillStyle = '#e9ecef';
    scanCtx.fillRect(0, 0, scanCtx.canvas.width, scanCtx.canvas.height);
    scanCtx.fillStyle = '#495057';
    scanCtx.font = '12px Arial';
    scanCtx.textAlign = 'center';
    scanCtx.fillText('Scan Volume Trends', scanCtx.canvas.width/2, scanCtx.canvas.height/2 - 10);
    scanCtx.fillText('(Last 24 hours)', scanCtx.canvas.width/2, scanCtx.canvas.height/2 + 10);
  }
  
  // Response Time Chart
  const responseTimeChart = document.getElementById('responseTimeChart');
  if (responseTimeChart) {
    const responseCtx = responseTimeChart.getContext('2d');
    responseCtx.fillStyle = '#e9ecef';
    responseCtx.fillRect(0, 0, responseCtx.canvas.width, responseCtx.canvas.height);
    responseCtx.fillStyle = '#495057';
    responseCtx.font = '12px Arial';
    responseCtx.textAlign = 'center';
    responseCtx.fillText('Response Time Trends', responseCtx.canvas.width/2, responseCtx.canvas.height/2 - 10);
    responseCtx.fillText('(Average per hour)', responseCtx.canvas.width/2, responseCtx.canvas.height/2 + 10);
  }
  
  // Auto-refresh every 30 seconds (in real app)
  // setInterval(refreshMetrics, 30000);
});
