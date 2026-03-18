/**
 * Fuzzing Dashboard Module
 * Handles fuzzing campaign management and results display
 */

// Get scanId from page context
const scanId = document.getElementById('scan-context')?.dataset.scanId || 
               new URLSearchParams(window.location.search).get('scan_id');

function startFuzzing() {
  const runtime = document.getElementById('runtimeMinutes').value;
  const btn = document.getElementById('startFuzzingBtn');
  const status = document.getElementById('campaignStatus');
  const statusText = document.getElementById('statusText');
  
  Utils.setButtonLoading(btn, true);
  status.style.display = 'block';
  statusText.textContent = 'Starting fuzzing campaign...';
  
  API.fuzz.start(scanId, { runtime_minutes: parseInt(runtime) })
    .then(data => {
      if (data.error) {
        Utils.notify('Error: ' + data.error, 'error');
        status.style.display = 'none';
      } else {
        statusText.textContent = 'Campaign completed!';
        setTimeout(() => {
          status.style.display = 'none';
          displayResults(data);
        }, 1000);
      }
      Utils.setButtonLoading(btn, false, '<i class="fas fa-play"></i> Start Fuzzing Campaign');
    })
    .catch(err => {
      Utils.notify('Error starting fuzzing: ' + err.message, 'error');
      status.style.display = 'none';
      Utils.setButtonLoading(btn, false, '<i class="fas fa-play"></i> Start Fuzzing Campaign');
    });
}

function loadResults() {
  API.fuzz.results(scanId)
    .then(data => {
      if (data.error) {
        console.log('No results found yet');
      } else {
        displayResults(data);
      }
    })
    .catch(err => {
      console.error('Error loading results:', err);
    });
}

function displayResults(data) {
  document.getElementById('resultsContainer').style.display = 'block';
  document.getElementById('totalTargets').textContent = data.total_targets || 0;
  
  const totalCrashes = data.results.reduce((sum, r) => sum + (r.crashes_found || 0), 0);
  document.getElementById('totalCrashes').textContent = totalCrashes;
  document.getElementById('totalTime').textContent = data.total_time || 0;
  
  const ts = Utils.formatTime(data.timestamp);
  document.getElementById('timestamp').textContent = ts;
  
  // Display target results
  let html = '<table class="table table-sm"><thead><tr><th>Target</th><th>Status</th><th>Runtime</th><th>Crashes</th><th>Coverage</th></tr></thead><tbody>';
  
  data.results.forEach(r => {
    const statusClass = Utils.getStatusClass(r.status);
    const statusBadge = `<span class="badge bg-${statusClass}">${r.status}</span>`;
    
    const crashBadge = r.crashes_found > 0 ?
      `<span class="badge bg-danger">${r.crashes_found}</span>` :
      '<span class="badge bg-secondary">0</span>';
    
    html += `<tr>
      <td><code>${Utils.escapeHtml(r.target)}</code></td>
      <td>${statusBadge}</td>
      <td>${r.runtime}s</td>
      <td>${crashBadge}</td>
      <td>${r.stats?.coverage || 'N/A'}</td>
    </tr>`;
  });
  
  html += '</tbody></table>';
  document.getElementById('targetResults').innerHTML = html;
}

// Load existing results on page load
window.addEventListener('load', () => {
  if (scanId) {
    loadResults();
  }
});
