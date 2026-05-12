/**
 * Patch Batch Management
 * Handles batch status polling and application
 */

class PatchBatchManager {
    constructor(scanId) {
        this.scanId = scanId;
        this.batchId = null;
        this.pollInterval = null;
        this.pollFrequency = 3000; // 3 seconds
    }
    
    /**
     * Start polling for batch status
     */
    startPolling() {
        console.log(`Starting batch status polling for scan ${this.scanId}`);
        
        // Poll immediately
        this.pollBatchStatus();
        
        // Then poll every 3 seconds
        this.pollInterval = setInterval(() => {
            this.pollBatchStatus();
        }, this.pollFrequency);
    }
    
    /**
     * Stop polling
     */
    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
            console.log('Stopped batch status polling');
        }
    }
    
    /**
     * Poll batch status from API
     */
    async pollBatchStatus() {
        try {
            const response = await fetch(`/api/scans/${this.scanId}/patch-batch/status`);
            
            if (!response.ok) {
                if (response.status === 404) {
                    console.log('No batch found yet');
                    return;
                }
                throw new Error(`HTTP ${response.status}`);
            }
            
            const status = await response.json();
            this.batchId = status.batch_id;
            
            // Update UI
            this.updateBatchStatusUI(status);
            
            // Stop polling if all ready
            if (status.all_ready) {
                this.stopPolling();
                this.showApplyAllButton();
            }
            
        } catch (error) {
            console.error('Error polling batch status:', error);
        }
    }
    
    /**
     * Update batch status UI
     */
    updateBatchStatusUI(status) {
        const statusContainer = document.getElementById('batch-status-container');
        if (!statusContainer) return;
        
        const stage1Icon = status.stage1.complete ? '✅' : '⏳';
        const stage2Icon = status.stage2.complete ? '✅' : '⏳';
        
        const stage1Text = status.stage1.complete 
            ? `${status.stage1.patches_count} patches ready`
            : 'Generating patches...';
        
        const stage2Text = status.stage2.complete
            ? `${status.stage2.patches_count} patches ready`
            : status.stage2.vulnerabilities_count > 0 
                ? 'Generating patches (AI)...'
                : 'No AI patches needed';
        
        const progressPercent = status.progress_percent || 0;
        
        const html = `
            <div class="batch-status-card">
                <h3>Patch Generation Status</h3>
                
                <div class="stage-status">
                    <div class="stage-row">
                        <span class="stage-icon">${stage1Icon}</span>
                        <span class="stage-label">Stage 1 (Deterministic):</span>
                        <span class="stage-info">${stage1Text}</span>
                    </div>
                    <div class="stage-row">
                        <span class="stage-icon">${stage2Icon}</span>
                        <span class="stage-label">Stage 2 (AI-Assisted):</span>
                        <span class="stage-info">${stage2Text}</span>
                    </div>
                </div>
                
                <div class="progress-bar-container">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${progressPercent}%"></div>
                    </div>
                    <div class="progress-text">
                        Total Progress: ${status.total_patches_count} patches ready (${progressPercent}%)
                    </div>
                </div>
                
                ${!status.all_ready ? `
                    <div class="warning-message">
                        <span class="warning-icon">⚠️</span>
                        <span>Waiting for all patches before applying</span>
                    </div>
                ` : `
                    <div class="success-message">
                        <span class="success-icon">✅</span>
                        <span>All patches ready to apply!</span>
                    </div>
                `}
            </div>
        `;
        
        statusContainer.innerHTML = html;
        
        // Update patch counts in other parts of UI
        this.updatePatchCounts(status);
    }
    
    /**
     * Update patch counts in UI
     */
    updatePatchCounts(status) {
        // Update Stage 1 count
        const stage1CountEl = document.getElementById('stage1-patches-count');
        if (stage1CountEl) {
            stage1CountEl.textContent = status.stage1.patches_count;
        }
        
        // Update Stage 2 count
        const stage2CountEl = document.getElementById('stage2-patches-count');
        if (stage2CountEl) {
            stage2CountEl.textContent = status.stage2.patches_count;
        }
        
        // Update total count
        const totalCountEl = document.getElementById('total-patches-count');
        if (totalCountEl) {
            totalCountEl.textContent = status.total_patches_count;
        }
    }
    
    /**
     * Show "Apply All" button when ready
     */
    showApplyAllButton() {
        const applyButton = document.getElementById('apply-all-patches-btn');
        if (!applyButton) return;
        
        applyButton.disabled = false;
        applyButton.classList.remove('disabled');
        applyButton.classList.add('ready');
        applyButton.textContent = `Apply All Patches`;
        
        // Show success notification
        this.showNotification('✅ All patches ready to apply!', 'success');
    }
    
    /**
     * Apply all patches in batch
     */
    async applyAllPatches(selectedPatchIds = null) {
        if (!this.batchId) {
            this.showNotification('❌ No batch found', 'error');
            return;
        }
        
        const applyButton = document.getElementById('apply-all-patches-btn');
        if (applyButton) {
            applyButton.disabled = true;
            applyButton.textContent = 'Applying patches...';
        }
        
        try {
            const response = await fetch(`/api/patch-batches/${this.batchId}/apply`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    selected_patch_ids: selectedPatchIds,
                    create_pr: true
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showNotification(
                    `✅ ${result.patches_applied} patches applied successfully!`,
                    'success'
                );
                
                if (applyButton) {
                    applyButton.textContent = '✅ Patches Applied';
                    applyButton.classList.add('success');
                }
                
                // Show PR link if available
                if (result.pr_url) {
                    this.showPRLink(result.pr_url);
                }
                
                // Show commit info
                if (result.commit_sha) {
                    this.showCommitInfo(result.commit_sha, result.modified_files);
                }
                
            } else {
                throw new Error(result.error || 'Unknown error');
            }
            
        } catch (error) {
            console.error('Error applying patches:', error);
            this.showNotification(`❌ Error applying patches: ${error.message}`, 'error');
            
            if (applyButton) {
                applyButton.disabled = false;
                applyButton.textContent = 'Apply All Patches';
            }
        }
    }
    
    /**
     * Show notification
     */
    showNotification(message, type = 'info') {
        // Check if using flash messages
        const flashContainer = document.getElementById('flash-messages');
        if (flashContainer) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type}`;
            alertDiv.textContent = message;
            flashContainer.appendChild(alertDiv);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                alertDiv.remove();
            }, 5000);
        } else {
            // Fallback to console
            console.log(`[${type.toUpperCase()}] ${message}`);
        }
    }
    
    /**
     * Show PR link
     */
    showPRLink(prUrl) {
        const prContainer = document.getElementById('pr-link-container');
        if (!prContainer) return;
        
        prContainer.innerHTML = `
            <div class="pr-link-card">
                <h4>Pull Request Created</h4>
                <a href="${prUrl}" target="_blank" class="btn btn-primary">
                    View Pull Request →
                </a>
            </div>
        `;
        prContainer.style.display = 'block';
    }
    
    /**
     * Show commit info
     */
    showCommitInfo(commitSha, modifiedFiles) {
        const commitContainer = document.getElementById('commit-info-container');
        if (!commitContainer) return;
        
        const filesHtml = modifiedFiles.map(f => `<li>${f}</li>`).join('');
        
        commitContainer.innerHTML = `
            <div class="commit-info-card">
                <h4>Commit Created</h4>
                <p><strong>SHA:</strong> <code>${commitSha.substring(0, 8)}</code></p>
                <p><strong>Files Modified:</strong></p>
                <ul>${filesHtml}</ul>
            </div>
        `;
        commitContainer.style.display = 'block';
    }
    
    /**
     * Load and display patches
     */
    async loadPatches(stage = null) {
        if (!this.batchId) return;
        
        try {
            const url = stage 
                ? `/api/patch-batches/${this.batchId}/patches?stage=${stage}`
                : `/api/patch-batches/${this.batchId}/patches`;
            
            const response = await fetch(url);
            const data = await response.json();
            
            this.displayPatches(data.patches);
            
        } catch (error) {
            console.error('Error loading patches:', error);
        }
    }
    
    /**
     * Display patches in UI
     */
    displayPatches(patches) {
        const patchesContainer = document.getElementById('patches-list');
        if (!patchesContainer) return;
        
        if (patches.length === 0) {
            patchesContainer.innerHTML = '<p>No patches available yet.</p>';
            return;
        }
        
        const html = patches.map(patch => `
            <div class="patch-card" data-patch-id="${patch.id}">
                <div class="patch-header">
                    <input type="checkbox" 
                           class="patch-checkbox" 
                           data-patch-id="${patch.id}"
                           ${patch.selected_for_application ? 'checked' : ''}>
                    <span class="patch-file">${patch.file}:${patch.line}</span>
                    <span class="patch-stage badge">Stage ${patch.stage}</span>
                    <span class="patch-confidence">${Math.round(patch.confidence * 100)}% confidence</span>
                </div>
                <div class="patch-description">${patch.description}</div>
                <div class="patch-category">${patch.category}</div>
                <details class="patch-details">
                    <summary>View Patch</summary>
                    <pre class="patch-diff">${patch.diff || 'No diff available'}</pre>
                </details>
            </div>
        `).join('');
        
        patchesContainer.innerHTML = html;
        
        // Add checkbox event listeners
        this.attachCheckboxListeners();
    }
    
    /**
     * Attach checkbox event listeners
     */
    attachCheckboxListeners() {
        const checkboxes = document.querySelectorAll('.patch-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', async (e) => {
                const patchId = e.target.dataset.patchId;
                const selected = e.target.checked;
                
                try {
                    await fetch(`/api/patches/${patchId}/select`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({selected})
                    });
                } catch (error) {
                    console.error('Error updating patch selection:', error);
                }
            });
        });
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    const scanId = document.getElementById('scan-id')?.value;
    if (!scanId) return;
    
    const batchManager = new PatchBatchManager(scanId);
    
    // Start polling
    batchManager.startPolling();
    
    // Attach apply button
    const applyButton = document.getElementById('apply-all-patches-btn');
    if (applyButton) {
        applyButton.addEventListener('click', () => {
            batchManager.applyAllPatches();
        });
    }
    
    // Make globally accessible
    window.patchBatchManager = batchManager;
});
