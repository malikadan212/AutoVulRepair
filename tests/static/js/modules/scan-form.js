/**
 * Scan Form Module
 * Handles scan form interactions, tab switching, and validation
 */

// Auto-clear other inputs when switching tabs and manage required attributes
document.addEventListener('DOMContentLoaded', function() {
  // Initialize: Set required on active tab only (GitHub is default)
  function updateRequiredAttributes(activeTarget) {
    // Remove required from ALL inputs first
    const repoInput = document.getElementById('repo_url');
    const zipInput = document.getElementById('zip_file');
    const snippetInput = document.getElementById('code_snippet');
    
    if (repoInput) repoInput.removeAttribute('required');
    if (zipInput) zipInput.removeAttribute('required');
    if (snippetInput) snippetInput.removeAttribute('required');
    
    // Set required only on active tab's input
    if (activeTarget === '#github' && repoInput) {
      repoInput.setAttribute('required', 'required');
    } else if (activeTarget === '#upload' && zipInput) {
      zipInput.setAttribute('required', 'required');
    } else if (activeTarget === '#snippet' && snippetInput) {
      snippetInput.setAttribute('required', 'required');
    }
  }
  
  // Set initial required attribute (GitHub tab is active by default)
  updateRequiredAttributes('#github');
  
  const tabs = document.querySelectorAll('#scanTabs button[data-bs-toggle="tab"]');
  tabs.forEach(tab => {
    tab.addEventListener('shown.bs.tab', function(e) {
      // Clear other inputs when switching tabs
      const target = e.target.getAttribute('data-bs-target');
      
      if (target !== '#github') {
        const repoInput = document.getElementById('repo_url');
        if (repoInput) repoInput.value = '';
      }
      if (target !== '#upload') {
        const zipInput = document.getElementById('zip_file');
        if (zipInput) zipInput.value = '';
      }
      if (target !== '#snippet') {
        const snippetInput = document.getElementById('code_snippet');
        if (snippetInput) snippetInput.value = '';
      }
      
      // Update required attributes based on active tab
      updateRequiredAttributes(target);
    });
  });
  
  // Form validation before submission
  const form = document.querySelector('form[action*="scan-public"]');
  if (form) {
    form.addEventListener('submit', function(e) {
      const activeTab = document.querySelector('#scanTabs .nav-link.active');
      const activeTarget = activeTab?.getAttribute('data-bs-target');
      
      let hasInput = false;
      let errorMsg = '';
      
      if (activeTarget === '#github') {
        const repoInput = document.getElementById('repo_url');
        hasInput = repoInput && repoInput.value.trim() !== '';
        if (!hasInput) errorMsg = 'Please enter a GitHub repository URL.';
      } else if (activeTarget === '#upload') {
        const zipInput = document.getElementById('zip_file');
        hasInput = zipInput && zipInput.files.length > 0;
        if (!hasInput) errorMsg = 'Please select a ZIP file to upload.';
      } else if (activeTarget === '#snippet') {
        const snippetInput = document.getElementById('code_snippet');
        hasInput = snippetInput && snippetInput.value.trim() !== '';
        if (!hasInput) errorMsg = 'Please paste your code snippet.';
      }
      
      if (!hasInput) {
        e.preventDefault();
        Utils.notify(errorMsg || 'Please provide input before submitting.', 'warning');
        return false;
      }
      
      // Ensure only active tab's input is required before submission
      updateRequiredAttributes(activeTarget);
      
      // Show loading state
      const submitBtn = form.querySelector('button[type="submit"]');
      if (submitBtn) {
        Utils.setButtonLoading(submitBtn, true, '<i class="fas fa-spinner fa-spin"></i> Starting Scan...');
      }
      
      // Allow form to submit normally
      return true;
    });
  }
  
  // Check tool status on page load
  checkToolStatus();
});

function checkToolStatus() {
  fetch('/api/tool-status')
    .then(response => {
      if (!response.ok) {
        // API endpoint doesn't exist, assume tools are available
        console.log('Tool status API not available, assuming tools are installed');
        return null;
      }
      return response.json();
    })
    .then(data => {
      if (!data) return; // API not available, keep default status
      
      updateToolStatus('cppcheck', data.cppcheck);
      updateToolStatus('codeql', data.codeql);
      
      // Show installation help if any tools are missing
      const helpElement = document.getElementById('tool-installation-help');
      if (helpElement) {
        const anyMissing = !data.cppcheck.available || !data.codeql.available;
        helpElement.style.display = anyMissing ? 'block' : 'none';
      }
    })
    .catch(error => {
      // Silently fail - assume tools are available
      console.log('Could not check tool status:', error);
    });
}

function updateToolStatus(toolName, status) {
  const statusElement = document.getElementById(toolName + '-status');
  if (!statusElement) return;
  
  if (status.available) {
    statusElement.textContent = 'Available';
    statusElement.className = 'badge bg-success ms-2';
    statusElement.title = `Version: ${status.version}`;
  } else {
    statusElement.textContent = 'Not Installed';
    statusElement.className = 'badge bg-warning ms-2';
    statusElement.title = 'Tool not found in PATH';
  }
}

function showInstallationInstructions() {
  const instructions = `
Installation Instructions:

1. For Windows (PowerShell as Administrator):
   Run: .\\install_tools.ps1

2. Manual Installation:
   - Cppcheck: Download from https://cppcheck.sourceforge.io/
   - CodeQL: Download from https://github.com/github/codeql-cli-binaries/releases

3. Alternative (Chocolatey):
   choco install cppcheck
   
Note: Tools will fall back to simulation mode if not installed.
  `;
  alert(instructions);
}

function loadSampleCode() {
  const sampleCode = `// Sample vulnerable C code for AutoVulRepair
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Vulnerability 1: Buffer overflow in strcpy
int process_user_input(const char* input) {
    char buffer[256];
    
    if (!input) {
        return -1;
    }
    
    // VULNERABLE: No bounds checking
    strcpy(buffer, input);  // Buffer overflow risk
    
    printf("Processed: %s\\n", buffer);
    return 0;
}

// Vulnerability 2: Use after free
char* get_user_data() {
    char* data = malloc(100);
    strcpy(data, "user data");
    
    free(data);  // Memory freed
    
    // VULNERABLE: Use after free
    return data;  // Returning freed pointer
}

// Vulnerability 3: Null pointer dereference
void process_config(char* config) {
    // VULNERABLE: No null check
    int len = strlen(config);  // Potential null pointer dereference
    
    if (len > 0) {
        printf("Config length: %d\\n", len);
    }
}

int main() {
    char user_input[1000];
    
    printf("Enter data: ");
    // VULNERABLE: No bounds checking on input
    gets(user_input);  // Deprecated and unsafe function
    
    process_user_input(user_input);
    
    char* data = get_user_data();
    printf("Data: %s\\n", data);  // Using freed memory
    
    process_config(NULL);  // Passing null pointer
    
    return 0;
}`;
  
  const snippetInput = document.getElementById('code_snippet');
  if (snippetInput) {
    snippetInput.value = sampleCode;
  }
  
  // Switch to snippet tab if not already active
  const snippetTab = document.getElementById('snippet-tab');
  if (snippetTab && !snippetTab.classList.contains('active')) {
    snippetTab.click();
  }
  
  Utils.notify('Sample vulnerable code loaded!', 'success');
}
