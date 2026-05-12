/**
 * Scan Progress Module
 * Handles real-time scan progress tracking and status updates
 */

const scanId = document.getElementById('scan-context')?.dataset.scanId;

let currentStage = 0;
let isCompleted = false;

const stages = [
  { id: 'stage-init', name: 'Initializing Environment', progress: 10 },
  { id: 'stage-source', name: 'Processing Source Code', progress: 30 },
  { id: 'stage-analysis', name: 'Running Static Analysis', progress: 60 },
  { id: 'stage-patches', name: 'Generating Patches', progress: 85 },
  { id: 'stage-complete', name: 'Finalizing Results', progress: 100 }
];

function updateStage(stageIndex, status = 'active') {
  if (stageIndex >= stages.length) return;
  
  const stage = stages[stageIndex];
  const element = document.getElementById(stage.id);
  if (!element) return;
  
  const icon = element.querySelector('i');
  const badge = element.querySelector('.badge');
  
  // Update previous stages to completed
  for (let i = 0; i < stageIndex; i++) {
    const prevElement = document.getElementById(stages[i].id);
    if (!prevElement) continue;
    
    const prevIcon = prevElement.querySelector('i');
    const prevBadge = prevElement.querySelector('.badge');
    
    if (prevIcon) prevIcon.className = 'fas fa-check-circle text-success';
    if (prevBadge) {
      prevBadge.className = 'badge bg-success';
      prevBadge.textContent = 'Completed';
    }
  }
  
  // Update current stage
  if (status === 'active') {
    if (icon) icon.className = 'fas fa-spinner fa-spin text-primary';
    if (badge) {
      badge.className = 'badge bg-primary';
      badge.textContent = 'Running';
    }
    Utils.updateProgressBar('progress-bar', stage.progress);
    updateProgressText(stage.name);
  } else if (status === 'completed') {
    if (icon) icon.className = 'fas fa-check-circle text-success';
    if (badge) {
      badge.className = 'badge bg-success';
      badge.textContent = 'Completed';
    }
  }
}

function updateProgressText(text) {
  const progressText = document.getElementById('progress-text');
  if (progressText) {
    progressText.textContent = text;
  }
}

function addLogEntry(message) {
  const logsElement = document.getElementById('live-logs');
  if (!logsElement) return;
  
  const timestamp = new Date().toLocaleTimeString();
  logsElement.textContent += `\n[${timestamp}] ${message}`;
  logsElement.scrollTop = logsElement.scrollHeight;
}

function completeScan() {
  isCompleted = true;
  
  const statusBadge = document.getElementById('scan-status');
  if (statusBadge) {
    statusBadge.textContent = 'Completed';
    statusBadge.className = 'badge bg-success';
  }
  
  const cancelBtn = document.getElementById('cancel-btn');
  if (cancelBtn) cancelBtn.style.display = 'none';
  
  const viewBtn = document.getElementById('view-results-btn');
  if (viewBtn) {
    viewBtn.classList.remove('d-none');
    viewBtn.href = `/public-results/${scanId}`;
  }
  
  addLogEntry('Static analysis complete');
  addLogEntry('Triggering automated fuzzing pipeline...');
  addLogEntry('Preparing AI patch generation...');
  addLogEntry('Results ready for automated workflow');
  
  // Show automated next steps
  setTimeout(() => {
    const workflowAlert = document.createElement('div');
    workflowAlert.className = 'alert alert-info mt-3';
    workflowAlert.innerHTML = `
      <h6><i class="fas fa-cogs"></i> Automated Workflow Triggered</h6>
      <p class="mb-2">The system is now automatically:</p>
      <ul class="mb-2">
        <li>Generating fuzz targets for discovered vulnerabilities</li>
        <li>Preparing AI patch generation using Vul-RAG</li>
        <li>Setting up monitoring for the deployment pipeline</li>
      </ul>
      <div class="btn-group">
        <a href="/detailed-findings/${scanId}" class="btn btn-primary btn-sm">
          <i class="fas fa-list"></i> View Findings & Continue Workflow
        </a>
      </div>
    `;
    const cardBody = document.querySelector('.card-body');
    if (cardBody) cardBody.appendChild(workflowAlert);
  }, 2000);
}

function toggleLogs() {
  const container = document.getElementById('log-container');
  const icon = document.getElementById('log-toggle-icon');
  
  if (!container || !icon) return;
  
  if (container.style.display === 'none') {
    container.style.display = 'block';
    icon.className = 'fas fa-eye-slash';
  } else {
    container.style.display = 'none';
    icon.className = 'fas fa-eye';
  }
}

function cancelScan() {
  if (confirm('Are you sure you want to cancel this scan?')) {
    // Stop polling
    if (window.scanPoller) {
      window.scanPoller.stop();
    }
    window.location.href = '/';
  }
}

function handleScanStatusUpdate(data) {
  console.log('Scan status:', data);
  
  // Update status badge
  const statusBadge = document.getElementById('scan-status');
  if (statusBadge) {
    statusBadge.textContent = data.status.charAt(0).toUpperCase() + data.status.slice(1);
  }
  
  if (data.status === 'queued') {
    if (statusBadge) statusBadge.className = 'badge bg-secondary';
    Utils.updateProgressBar('progress-bar', 5);
    updateProgressText('Scan queued, starting analysis...');
    updateStage(0, 'active');
    addLogEntry('Scan submitted and queued for processing');
    addLogEntry('Initializing analysis environment...');
  } else if (data.status === 'running') {
    if (statusBadge) statusBadge.className = 'badge bg-primary';
    const elapsed = data.elapsed_time || 0;
    const elapsedText = elapsed > 0 ? ` (${Math.floor(elapsed)}s)` : '';
    Utils.updateProgressBar('progress-bar', 40);
    updateProgressText(`Analysis in progress${elapsedText}...`);
    updateStage(1, 'completed');
    updateStage(2, 'active');
    
    // Show more detailed status based on time
    if (elapsed < 10) {
      addLogEntry('Setting up source code...');
    } else if (elapsed < 30) {
      addLogEntry('Running static analysis tool...');
    } else {
      addLogEntry('Processing analysis results...');
    }
  } else if (data.status === 'completed') {
    if (statusBadge) statusBadge.className = 'badge bg-success';
    Utils.updateProgressBar('progress-bar', 100);
    updateProgressText('Scan completed successfully');
    updateStage(4, 'completed');
    
    const vulnCount = data.vulnerabilities_count || 0;
    const patchCount = data.patches_count || 0;
    
    addLogEntry(`Analysis complete: Found ${vulnCount} vulnerabilities and ${patchCount} patches`);
    
    // Show results button
    const viewBtn = document.getElementById('view-results-btn');
    if (viewBtn) {
      viewBtn.href = `/detailed-findings/${scanId}`;
      viewBtn.classList.remove('d-none');
    }
    
    // Auto-redirect to detailed findings after 3 seconds
    setTimeout(() => {
      window.location.href = `/detailed-findings/${scanId}`;
    }, 3000);
  } else if (data.status === 'failed') {
    if (statusBadge) statusBadge.className = 'badge bg-danger';
    Utils.updateProgressBar('progress-bar', 0);
    const errorMsg = data.error || 'Unknown error occurred';
    const progressText = document.getElementById('progress-text');
    if (progressText) {
      progressText.innerHTML = `<span class="text-danger">Error: ${Utils.escapeHtml(errorMsg)}</span>`;
    }
    addLogEntry(`Scan failed: ${errorMsg}`);
  }
}

// Initialize polling when page loads
document.addEventListener('DOMContentLoaded', function() {
  if (!scanId) {
    console.error('No scan ID found');
    return;
  }
  
  // Create status poller using the reusable component
  window.scanPoller = new StatusPoller({
    scanId: scanId,
    apiEndpoint: `/api/scan-status/${scanId}`,
    interval: 2000,
    onUpdate: handleScanStatusUpdate,
    onComplete: (data) => {
      console.log('Scan polling complete:', data);
    },
    onError: (error) => {
      console.error('Polling error:', error);
      updateProgressText('Error checking status');
      addLogEntry('Error checking scan status');
    }
  });
  
  // Start polling
  window.scanPoller.start();
});
