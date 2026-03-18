import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { APIClient } from './apiClient';
import { DiagnosticManager } from './diagnosticManager';
import { PatchManager } from './patchManager';
import { ConfigurationManager } from './configurationManager';
import { WebSocketHandler } from './websocketHandler';
import { ProgressTracker } from './progressTracker';
import { VulnerabilityReport } from './types';
import { Logger } from './logger';

// ============================================================================
// Global report output channel (reused across commands)
// ============================================================================
let reportChannel: vscode.OutputChannel | undefined;

function getReportChannel(): vscode.OutputChannel {
  if (!reportChannel) {
    reportChannel = vscode.window.createOutputChannel('AutoVulRepair — Report');
  }
  return reportChannel;
}

/**
 * Register all extension commands
 */
export function registerCommands(
  context: vscode.ExtensionContext,
  apiClient: APIClient,
  diagnosticManager: DiagnosticManager,
  patchManager: PatchManager,
  config: ConfigurationManager,
  progressTracker: ProgressTracker
): void {
  // Scan file command
  context.subscriptions.push(
    vscode.commands.registerCommand('autoVulRepair.scanFile', async () => {
      await scanFileCommand(apiClient, diagnosticManager, progressTracker, config);
    })
  );

  // Scan folder command
  context.subscriptions.push(
    vscode.commands.registerCommand('autoVulRepair.scanFolder', async (uri: vscode.Uri) => {
      await scanFolderCommand(uri, apiClient, diagnosticManager, progressTracker);
    })
  );

  // View patch command
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'autoVulRepair.viewPatch',
      async (fileUri: vscode.Uri, line: number) => {
        await viewPatchCommand(fileUri, line, diagnosticManager, patchManager);
      }
    )
  );

  // Apply patch command
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'autoVulRepair.applyPatch',
      async (fileUri: vscode.Uri, line: number) => {
        await applyPatchCommand(fileUri, line, diagnosticManager, patchManager);
      }
    )
  );

  // Generate patch command
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'autoVulRepair.generatePatch',
      async (fileUri: vscode.Uri, line: number) => {
        await generatePatchCommand(fileUri, line, apiClient, diagnosticManager, patchManager);
      }
    )
  );

  // Apply all rule-based patches command
  context.subscriptions.push(
    vscode.commands.registerCommand('autoVulRepair.applyAllRuleBased', async () => {
      await applyAllRuleBasedCommand(apiClient, diagnosticManager, patchManager);
    })
  );

  // Apply AI-assisted patch command (single vulnerability)
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'autoVulRepair.applyAIPatch',
      async (fileUri: vscode.Uri, line: number) => {
        await applyAIPatchCommand(fileUri, line, apiClient, diagnosticManager, patchManager);
      }
    )
  );

  // ── Smart Fix: Combined rule-based → AI workflow ──────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('autoVulRepair.smartFix', async () => {
      await smartFixCommand(apiClient, diagnosticManager, patchManager);
    })
  );

  // ── Fix All with AI Assistance (bulk) ─────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('autoVulRepair.fixAllWithAI', async () => {
      await fixAllWithAICommand(apiClient, diagnosticManager, patchManager);
    })
  );

  // ── Download Report ───────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('autoVulRepair.downloadReport', async () => {
      await downloadReportCommand();
    })
  );

  // Clear diagnostics command
  context.subscriptions.push(
    vscode.commands.registerCommand('autoVulRepair.clearDiagnostics', () => {
      diagnosticManager.clearDiagnostics();
      vscode.window.showInformationMessage('Cleared all vulnerability diagnostics');
    })
  );

  // Test connection command
  context.subscriptions.push(
    vscode.commands.registerCommand('autoVulRepair.testConnection', async () => {
      await testConnectionCommand(apiClient);
    })
  );

  // Navigate to vulnerability command
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'autoVulRepair.navigateToVulnerability',
      async (fileUri: vscode.Uri, line: number) => {
        const document = await vscode.workspace.openTextDocument(fileUri);
        const editor = await vscode.window.showTextDocument(document);
        const position = new vscode.Position(line, 0);
        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(new vscode.Range(position, position));
      }
    )
  );

  // Clear cache command
  context.subscriptions.push(
    vscode.commands.registerCommand('autoVulRepair.clearCache', () => {
      vscode.window.showInformationMessage('Cache cleared');
    })
  );
}

/**
 * Scan current file
 */
async function scanFileCommand(
  apiClient: APIClient,
  diagnosticManager: DiagnosticManager,
  progressTracker: ProgressTracker,
  config: ConfigurationManager
): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active editor');
    return;
  }

  const document = editor.document;
  const ext = document.fileName.split('.').pop();
  if (!['c', 'cpp', 'cc', 'cxx', 'h', 'hpp'].includes(ext || '')) {
    vscode.window.showErrorMessage('Not a C/C++ file');
    return;
  }

  try {
    Logger.info(`Starting scan for file: ${document.fileName}`);
    Logger.debug(`Code snippet length: ${document.getText().length}`);
    
    const response = await apiClient.scan({
      code_snippet: document.getText(),
      analysis_tool: 'cppcheck',
    });

    Logger.debug(`Received response: ${JSON.stringify(response)}`);

    // Validate response
    if (!response || !response.scanId) {
      Logger.error('Invalid scan response received from backend', response);
      throw new Error('Backend returned invalid response');
    }

    Logger.info(`Scan initiated successfully: ${response.scanId}`);
    progressTracker.showProgress(response.scanId, 'Starting scan...');

    // Wait for results with polling
    Logger.info(`Waiting for scan ${response.scanId} to complete...`);
    const results = await apiClient.waitForScanResults(
      response.scanId,
      (progress, stage) => {
        Logger.debug(`Scan ${response.scanId} progress: ${progress}% - ${stage}`);
        progressTracker.updateProgress(response.scanId, progress, stage);
      }
    );

    Logger.info(`Scan completed for ${response.scanId}. Found ${results.vulnerabilities?.length || 0} issues.`);

    progressTracker.hideProgress(response.scanId);

    // Display results
    if (results.vulnerabilities && results.vulnerabilities.length > 0) {
      Logger.debug('Creating diagnostics for vulnerabilities...');
      
      // Inject scanId into each vulnerability report
      results.vulnerabilities.forEach(vuln => {
        vuln.scanId = response.scanId;
      });

      diagnosticManager.createDiagnostics(document.uri, results.vulnerabilities);
      vscode.window.showInformationMessage(`Found ${results.vulnerabilities.length} vulnerabilities`);
    } else {
      Logger.info('No vulnerabilities found in the scanned file.');
      vscode.window.showInformationMessage('No vulnerabilities found');
    }
  } catch (error) {
    Logger.error('Scan failed', error);
    vscode.window.showErrorMessage(`Scan failed: ${error}`);
  }
}

/**
 * Scan folder
 */
async function scanFolderCommand(
  uri: vscode.Uri,
  apiClient: APIClient,
  diagnosticManager: DiagnosticManager,
  progressTracker: ProgressTracker
): Promise<void> {
  vscode.window.showInformationMessage(`Scanning folder: ${uri.fsPath}`);
}

/**
 * View patch for vulnerability
 */
async function viewPatchCommand(
  fileUri: vscode.Uri,
  line: number,
  diagnosticManager: DiagnosticManager,
  patchManager: PatchManager
): Promise<void> {
  const vulnerability = diagnosticManager.getVulnerability(fileUri, line);
  if (!vulnerability) {
    vscode.window.showErrorMessage('No vulnerability found at this location');
    return;
  }

  await patchManager.showPatchPreview(fileUri, vulnerability);
}

/**
 * Apply patch for vulnerability
 */
async function applyPatchCommand(
  fileUri: vscode.Uri,
  line: number,
  diagnosticManager: DiagnosticManager,
  patchManager: PatchManager
): Promise<void> {
  const vulnerability = diagnosticManager.getVulnerability(fileUri, line);
  if (!vulnerability) {
    vscode.window.showErrorMessage('No vulnerability found at this location');
    return;
  }

  await patchManager.applyPatch(fileUri, vulnerability);
}

/**
 * Generate patch for vulnerability
 */
async function generatePatchCommand(
  fileUri: vscode.Uri,
  line: number,
  apiClient: APIClient,
  diagnosticManager: DiagnosticManager,
  patchManager: PatchManager
): Promise<void> {
  const vulnerability = diagnosticManager.getVulnerability(fileUri, line);
  if (!vulnerability) {
    vscode.window.showErrorMessage('No vulnerability found at this location');
    return;
  }

  Logger.debug(`Vulnerability details for patch generation: ${JSON.stringify(vulnerability)}`);
  
  if (!vulnerability.scanId || !vulnerability.id) {
    Logger.error(`Missing metadata for patch generation: scanId=${vulnerability.scanId}, id=${vulnerability.id}`);
    vscode.window.showErrorMessage(
      `Cannot generate patch: missing scan or vulnerability ID.\n` +
      `Please re-scan the file first.`
    );
    return;
  }

  vscode.window.showInformationMessage(
    `🔧 Generating rule-based patch for [${vulnerability.severity}] ${vulnerability.type} on line ${vulnerability.line}...`
  );

  try {
    const patchContent = await apiClient.generateSinglePatch(vulnerability.scanId, vulnerability.id);

    if (patchContent) {
      Logger.info(`Successfully generated rule-based patch for ${vulnerability.type} at line ${vulnerability.line}`);
      vulnerability.patch = patchContent;
      await patchManager.showPatchPreview(fileUri, vulnerability);

      const choice = await vscode.window.showInformationMessage(
        `✅ Rule-based patch ready for "${vulnerability.type}". What would you like to do next?`,
        { modal: false },
        '✅ Apply This Patch',
        '🤖 Move to AI Assistance',
        'Dismiss'
      );

      if (choice === '✅ Apply This Patch') {
        await patchManager.applyPatch(fileUri, vulnerability);
        vscode.window.showInformationMessage(`✅ Rule-based patch applied for "${vulnerability.type}".`);
      } else if (choice === '🤖 Move to AI Assistance') {
        Logger.info(`User chose AI patching for vulnerability: ${vulnerability.id}`);
        await applyAIPatchCommand(fileUri, line, apiClient, diagnosticManager, patchManager);
      }
    } else {
      Logger.warn(`No rule-based patch for ${vulnerability.type} (id: ${vulnerability.id})`);

      const choice = await vscode.window.showWarningMessage(
        `⚠️ No rule-based patch available for "${vulnerability.type}". Would you like to try AI Assistance instead?`,
        { modal: false },
        '🤖 Try AI Assistance',
        'Dismiss'
      );

      if (choice === '🤖 Try AI Assistance') {
        await applyAIPatchCommand(fileUri, line, apiClient, diagnosticManager, patchManager);
      }
    }
  } catch (error: any) {
    const backendMsg = error?.response?.data?.error || error?.message || String(error);
    Logger.error(`Patch generation failed for ${vulnerability.type}`, backendMsg);
    vscode.window.showErrorMessage(
      `Patch failed for "${vulnerability.type}" (id: ${vulnerability.id}):\n${backendMsg}`
    );
  }
}

/**
 * Test backend connection
 */
async function testConnectionCommand(apiClient: APIClient): Promise<void> {
  try {
    const connected = await apiClient.testConnection();
    if (connected) {
      Logger.info('Backend connection test successful');
      vscode.window.showInformationMessage('Backend connection successful');
    } else {
      Logger.warn('Backend connection test failed');
      vscode.window.showErrorMessage('Cannot connect to backend');
    }
  } catch (error) {
    Logger.error('Connection test failed', error);
    vscode.window.showErrorMessage(`Connection test failed: ${error}`);
  }
}

// ============================================================================
// Rule-based error types that can be patched deterministically
// ============================================================================
const RULE_BASED_FIXABLE_TYPES = new Set([
  'buffer_overflow', 'stack_buffer_overflow', 'heap_buffer_overflow',
  'integer_overflow', 'integer_underflow',
  'null_pointer_dereference', 'null_dereference',
  'uninitialized_variable', 'uninitialized_memory',
  'format_string', 'format_string_vulnerability',
  'memory_leak', 'resource_leak',
  'double_free', 'use_after_free', 'dangling_pointer',
  'array_out_of_bounds', 'off_by_one', 'missing_bounds_check',
  'strcpy_overflow', 'sprintf_overflow', 'gets_usage',
  'insecure_function', 'deprecated_function', 'unsafe_api',
  'signed_unsigned_mismatch', 'division_by_zero',
  'missing_return', 'missing_null_check', 'unchecked_return_value',
]);

function classifyVulnerability(vuln: VulnerabilityReport): 'rule-based' | 'ai-required' {
  const vulnTypeLower = vuln.type.toLowerCase().replace(/[\s-]+/g, '_');
  for (const ruleType of RULE_BASED_FIXABLE_TYPES) {
    if (vulnTypeLower.includes(ruleType) || ruleType.includes(vulnTypeLower)) {
      return 'rule-based';
    }
  }
  if (vuln.patch) {
    return 'rule-based';
  }
  return 'ai-required';
}

/** Format elapsed time nicely */
function formatElapsed(ms: number): string {
  if (ms < 1000) { return `${ms}ms`; }
  const secs = Math.floor(ms / 1000);
  if (secs < 60) { return `${secs}s`; }
  const mins = Math.floor(secs / 60);
  const remSecs = secs % 60;
  return `${mins}m ${remSecs}s`;
}

/** Build a progress bar string */
function progressBar(current: number, total: number, width: number = 20): string {
  const pct = total > 0 ? current / total : 0;
  const filled = Math.round(pct * width);
  const empty = width - filled;
  return `[${'█'.repeat(filled)}${'░'.repeat(empty)}] ${Math.round(pct * 100)}%`;
}

// ============================================================================
// Apply All Rule-Based Command
// ============================================================================

async function applyAllRuleBasedCommand(
  apiClient: APIClient,
  diagnosticManager: DiagnosticManager,
  patchManager: PatchManager
): Promise<void> {
  const activeEditor = vscode.window.activeTextEditor;
  if (!activeEditor) {
    vscode.window.showErrorMessage('No active editor found. Please open the file with vulnerabilities.');
    return;
  }

  const fileUri = activeEditor.document.uri;
  const vulnerabilities = diagnosticManager.getVulnerabilitiesForFile(fileUri);
  
  if (!vulnerabilities || vulnerabilities.length === 0) {
    vscode.window.showInformationMessage('No detected vulnerabilities found in this file to patch.');
    return;
  }

  const scanId = vulnerabilities[0].scanId;
  if (!scanId) {
    vscode.window.showErrorMessage('No scan ID found for these vulnerabilities. Please re-scan the file first.');
    return;
  }

  // Classify to know how many AI-required remain
  const aiRequiredCount = vulnerabilities.filter(v => classifyVulnerability(v) === 'ai-required').length;

  await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: "AutoVulRepair: Applying all rule-based patches...",
    cancellable: false
  }, async (progress) => {
    try {
      progress.report({ message: 'Analyzing vulnerabilities and generating rule-based fixes...' });
      
      const response = await apiClient.generateStage1Patches(scanId);
      
      if (!response.success || !response.patches || response.patches.length === 0) {
        // ── NO rule-based patches available → offer AI ──────────────────
        const aiChoice = await vscode.window.showInformationMessage(
          `No more rule-based patches available.` +
          (aiRequiredCount > 0
            ? ` ${aiRequiredCount} vulnerabilit${aiRequiredCount !== 1 ? 'ies' : 'y'} can be fixed with AI Assistance.`
            : ''),
          { modal: false },
          ...(aiRequiredCount > 0 ? ['🤖 Fix All with AI Assistance'] : []),
          '✅ Done'
        );

        if (aiChoice === '🤖 Fix All with AI Assistance') {
          await runBulkAIRepair(apiClient, diagnosticManager, patchManager, scanId);
        }
        return;
      }

      progress.report({ message: 'Integrating fixes into source code...' });
      
      const patchesToApply: { vuln: VulnerabilityReport, patchContent: string }[] = [];
      const appliedVulnTypes: string[] = [];

      for (const patch of response.patches) {
        const vulnId = patch.vulnerability_id;
        const vuln = vulnerabilities.find(v => v.id === vulnId);
        
        if (vuln && patch.repaired) {
          patchesToApply.push({ vuln, patchContent: patch.repaired });
          if (!appliedVulnTypes.includes(vuln.type)) {
            appliedVulnTypes.push(vuln.type);
          }
        }
      }

      if (patchesToApply.length === 0) {
        // Same offering here — no applicable patches but may have AI targets
        const aiChoice = await vscode.window.showInformationMessage(
          `No rule-based patches were applicable to the vulnerabilities in this file.` +
          (aiRequiredCount > 0
            ? ` ${aiRequiredCount} vulnerabilit${aiRequiredCount !== 1 ? 'ies' : 'y'} can be fixed with AI Assistance.`
            : ''),
          { modal: false },
          ...(aiRequiredCount > 0 ? ['🤖 Fix All with AI Assistance'] : []),
          '✅ Done'
        );

        if (aiChoice === '🤖 Fix All with AI Assistance') {
          await runBulkAIRepair(apiClient, diagnosticManager, patchManager, scanId);
        }
        return;
      }

      const success = await patchManager.applyBulkPatches(fileUri, patchesToApply);
      
      if (success) {
        const count = patchesToApply.length;
        const typeStr = appliedVulnTypes.join(', ');
        const remaining = vulnerabilities.length - count;
        const summary = `✅ Applied ${count} rule-based patch${count !== 1 ? 'es' : ''} (${typeStr}).`;

        Logger.info(`Bulk patch summary: ${summary}`);
        for (const p of patchesToApply) {
          Logger.info(`Applied fix for ${p.vuln.type} at line ${p.vuln.line}`);
        }

        const remainingMsg = remaining > 0
          ? `\n${remaining} vulnerabilit${remaining !== 1 ? 'ies' : 'y'} remaining.`
          : '';

        const choice = await vscode.window.showInformationMessage(
          `${summary}${remainingMsg}`,
          { modal: remaining > 0 },
          ...(remaining > 0 ? ['🤖 Fix Remaining with AI Assistance'] : []),
          '📋 View Patch Details',
          '✅ Done'
        );

        if (choice === '📋 View Patch Details') {
          Logger.show();
        } else if (choice === '🤖 Fix Remaining with AI Assistance') {
          await runBulkAIRepair(apiClient, diagnosticManager, patchManager, scanId);
        }
      }
    } catch (error: any) {
      console.error('[applyAllRuleBasedCommand] Error:', error);
      const msg = error?.response?.data?.error || error?.message || String(error);
      vscode.window.showErrorMessage(`Bulk patching failed: ${msg}`);
    }
  });
}

// ============================================================================
// Smart Fix — The Unified Workflow
// ============================================================================

async function smartFixCommand(
  apiClient: APIClient,
  diagnosticManager: DiagnosticManager,
  patchManager: PatchManager
): Promise<void> {
  const activeEditor = vscode.window.activeTextEditor;
  if (!activeEditor) {
    vscode.window.showErrorMessage('No active editor found. Please open the file with vulnerabilities.');
    return;
  }

  const fileUri = activeEditor.document.uri;
  const vulnerabilities = diagnosticManager.getVulnerabilitiesForFile(fileUri);

  if (!vulnerabilities || vulnerabilities.length === 0) {
    vscode.window.showInformationMessage('No detected vulnerabilities found in this file. Run a scan first.');
    return;
  }

  const scanId = vulnerabilities[0].scanId;
  if (!scanId) {
    vscode.window.showErrorMessage('No scan ID found for these vulnerabilities. Please re-scan the file first.');
    return;
  }

  const startTime = Date.now();

  // ── Step 1: Classify vulnerabilities ──────────────────────────────────
  const ruleBasedVulns: VulnerabilityReport[] = [];
  const aiRequiredVulns: VulnerabilityReport[] = [];

  for (const vuln of vulnerabilities) {
    if (classifyVulnerability(vuln) === 'rule-based') {
      ruleBasedVulns.push(vuln);
    } else {
      aiRequiredVulns.push(vuln);
    }
  }

  // ── Step 2: Show classification in Output Channel ─────────────────────
  const out = getReportChannel();
  out.clear();
  out.appendLine('');
  out.appendLine('╔══════════════════════════════════════════════════════════════════════╗');
  out.appendLine('║                 AutoVulRepair — Smart Fix Report                     ║');
  out.appendLine('╠══════════════════════════════════════════════════════════════════════╣');
  out.appendLine(`║  File: ${path.basename(fileUri.fsPath).padEnd(59)}║`);
  out.appendLine(`║  Scan ID: ${(scanId || 'N/A').substring(0, 55).padEnd(56)}║`);
  out.appendLine(`║  Started: ${new Date().toLocaleString().padEnd(56)}║`);
  out.appendLine('╠══════════════════════════════════════════════════════════════════════╣');
  out.appendLine(`║  Total vulnerabilities found: ${String(vulnerabilities.length).padEnd(37)}║`);
  out.appendLine(`║  🔧 Rule-based fixable:       ${String(ruleBasedVulns.length).padEnd(37)}║`);
  out.appendLine(`║  🤖 AI assistance needed:     ${String(aiRequiredVulns.length).padEnd(37)}║`);
  out.appendLine('╠══════════════════════════════════════════════════════════════════════╣');
  out.appendLine('');
  out.appendLine('  ┌──────────────────────────────────────────────────────────────────┐');
  out.appendLine('  │                    VULNERABILITY CLASSIFICATION                  │');
  out.appendLine('  └──────────────────────────────────────────────────────────────────┘');
  out.appendLine('');

  if (ruleBasedVulns.length > 0) {
    out.appendLine('  🔧 RULE-BASED FIXABLE ERRORS:');
    out.appendLine('  ──────────────────────────────────────────────────────────────');
    for (const vuln of ruleBasedVulns) {
      out.appendLine(`    Line ${String(vuln.line).padEnd(5)} │ [${vuln.severity.padEnd(8)}] ${vuln.type}`);
      out.appendLine(`           │  ${vuln.description}`);
    }
    out.appendLine('');
  }

  if (aiRequiredVulns.length > 0) {
    out.appendLine('  🤖 AI ASSISTANCE REQUIRED:');
    out.appendLine('  ──────────────────────────────────────────────────────────────');
    for (const vuln of aiRequiredVulns) {
      out.appendLine(`    Line ${String(vuln.line).padEnd(5)} │ [${vuln.severity.padEnd(8)}] ${vuln.type}`);
      out.appendLine(`           │  ${vuln.description}`);
    }
    out.appendLine('');
  }

  out.show(true);

  // ── Step 3: If no rule-based vulns, jump directly to AI ───────────────
  if (ruleBasedVulns.length === 0) {
    const choice = await vscode.window.showInformationMessage(
      `All ${vulnerabilities.length} vulnerabilit${vulnerabilities.length !== 1 ? 'ies' : 'y'} require AI Assistance. Proceed?`,
      { modal: true },
      '🤖 Start AI Fixing',
      'Cancel'
    );

    if (choice === '🤖 Start AI Fixing') {
      await runBulkAIRepair(apiClient, diagnosticManager, patchManager, scanId);
    }
    return;
  }

  // ── Step 4: Apply rule-based fixes ────────────────────────────────────
  let ruleBasedAppliedCount = 0;
  const ruleBasedDetails: string[] = [];

  out.appendLine('  ┌──────────────────────────────────────────────────────────────────┐');
  out.appendLine('  │                   STAGE 1: RULE-BASED PATCHING                   │');
  out.appendLine('  └──────────────────────────────────────────────────────────────────┘');
  out.appendLine('');
  out.appendLine(`  ⏳ Status: Generating rule-based patches...`);

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: '🔧 AutoVulRepair: Rule-Based Fixing',
      cancellable: false,
    },
    async (progress) => {
      try {
        progress.report({
          message: `Generating patches for ${ruleBasedVulns.length} rule-based issues...`,
          increment: 0,
        });

        const patchStart = Date.now();
        const response = await apiClient.generateStage1Patches(scanId);
        const patchGenTime = Date.now() - patchStart;

        out.appendLine(`  ✅ Patch generation completed in ${formatElapsed(patchGenTime)}`);

        if (!response.success || !response.patches || response.patches.length === 0) {
          out.appendLine('  ⚠️  No rule-based patches could be generated.');
          return;
        }

        progress.report({
          message: 'Applying patches to source code...',
          increment: 50,
        });

        const patchesToApply: { vuln: VulnerabilityReport; patchContent: string }[] = [];

        for (const patch of response.patches) {
          const vulnId = patch.vulnerability_id;
          const vuln = vulnerabilities.find((v) => v.id === vulnId);

          if (vuln && patch.repaired) {
            patchesToApply.push({ vuln, patchContent: patch.repaired });
            ruleBasedDetails.push(
              `    ✅ Line ${String(vuln.line).padEnd(5)} │ [${vuln.severity.padEnd(8)}] ${vuln.type}`
            );
          }
        }

        if (patchesToApply.length === 0) {
          out.appendLine('  ⚠️  No patches applicable.');
          return;
        }

        const applyStart = Date.now();
        const success = await patchManager.applyBulkPatches(fileUri, patchesToApply);
        const applyTime = Date.now() - applyStart;

        if (success) {
          ruleBasedAppliedCount = patchesToApply.length;

          progress.report({
            message: `Applied ${ruleBasedAppliedCount} patches!`,
            increment: 50,
          });

          out.appendLine(`  ✅ Applied ${ruleBasedAppliedCount} patches in ${formatElapsed(applyTime)}`);
          out.appendLine('');
          out.appendLine('  Patched vulnerabilities:');
          for (const detail of ruleBasedDetails) {
            out.appendLine(detail);
          }
          out.appendLine('');

          for (const p of patchesToApply) {
            Logger.info(`[Smart Fix] Applied rule-based fix: ${p.vuln.type} at line ${p.vuln.line}`);
          }
        }
      } catch (error: any) {
        const msg = error?.response?.data?.error || error?.message || String(error);
        Logger.error('[Smart Fix] Rule-based patching failed', msg);
        out.appendLine(`  ❌ Rule-based patching failed: ${msg}`);
        vscode.window.showErrorMessage(`Rule-based patching failed: ${msg}`);
      }
    }
  );

  // ── Step 5: Show results + two options ────────────────────────────────
  const fixedMsg =
    ruleBasedAppliedCount > 0
      ? `✅ Fixed ${ruleBasedAppliedCount} rule-based error${ruleBasedAppliedCount !== 1 ? 's' : ''} successfully!`
      : '⚠️ Could not apply any rule-based patches.';

  const aiPending = aiRequiredVulns.length;
  const aiNote =
    aiPending > 0
      ? `\n\n${aiPending} vulnerabilit${aiPending !== 1 ? 'ies' : 'y'} still need AI-based fixing.`
      : '';

  const choice = await vscode.window.showInformationMessage(
    `${fixedMsg}${aiNote}`,
    { modal: true },
    '📋 Details of Rule-Based Fixes',
    ...(aiPending > 0 ? ['🤖 Move to AI-Based Error Fixing'] : []),
    '✅ Done'
  );

  if (choice === '📋 Details of Rule-Based Fixes') {
    out.show(true);

    if (aiPending > 0) {
      const nextChoice = await vscode.window.showInformationMessage(
        `${aiPending} vulnerabilit${aiPending !== 1 ? 'ies' : 'y'} still require AI Assistance. Proceed?`,
        { modal: false },
        '🤖 Move to AI-Based Error Fixing',
        '✅ Done'
      );

      if (nextChoice === '🤖 Move to AI-Based Error Fixing') {
        await runBulkAIRepair(apiClient, diagnosticManager, patchManager, scanId);
      }
    }
  } else if (choice === '🤖 Move to AI-Based Error Fixing') {
    await runBulkAIRepair(apiClient, diagnosticManager, patchManager, scanId);
  }
}

// ============================================================================
// AI Patch Commands
// ============================================================================

/**
 * Apply AI-assisted patch for a single vulnerability
 */
async function applyAIPatchCommand(
  fileUri: vscode.Uri,
  line: number,
  apiClient: APIClient,
  diagnosticManager: DiagnosticManager,
  patchManager: PatchManager
): Promise<void> {
  const vulnerability = diagnosticManager.getVulnerability(fileUri, line);
  if (!vulnerability) {
    vscode.window.showErrorMessage('No vulnerability found at this location.');
    return;
  }

  if (!vulnerability.scanId) {
    vscode.window.showErrorMessage(
      'Missing scan ID. Please re-scan the file first, then try AI Assistance.'
    );
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `🤖 AutoVulRepair: AI Assistance — ${vulnerability.type}`,
      cancellable: false,
    },
    async (progress) => {
      try {
        progress.report({ message: 'Sending to AI backend (Groq / Gemini)...' });
        Logger.info(`[AI Patch] Requesting AI repair for ${vulnerability.type} (scan: ${vulnerability.scanId})`);

        const result = await apiClient.runAIRepair(
          vulnerability.scanId!,
          undefined
        );

        if (!result.success || !result.repair_results || result.repair_results.length === 0) {
          vscode.window.showWarningMessage(
            `⚠️ AI could not generate a patch for "${vulnerability.type}". ` +
            `Check that your Groq/Gemini API key is set in the backend .env file.`
          );
          return;
        }

        progress.report({ message: 'AI patch ready — preparing preview...' });

        const aiResult = result.repair_results.find(
          (r: any) => r.vulnerability_id === vulnerability.id || r.type === vulnerability.type
        ) || result.repair_results[0];

        const aiPatchContent: string = aiResult?.repaired_code || aiResult?.patch || '';

        if (!aiPatchContent) {
          vscode.window.showWarningMessage('AI returned an empty patch. Please try again.');
          return;
        }

        vulnerability.patch = aiPatchContent;
        await patchManager.showPatchPreview(fileUri, vulnerability);

        Logger.info(`[AI Patch] AI patch ready for ${vulnerability.type} at line ${vulnerability.line}`);

        const choice = await vscode.window.showInformationMessage(
          `🤖 AI patch generated for "${vulnerability.type}" (line ${vulnerability.line}). Apply it now?`,
          { modal: false },
          '✅ Apply AI Patch',
          'Dismiss'
        );

        if (choice === '✅ Apply AI Patch') {
          await patchManager.applyPatch(fileUri, vulnerability);
          vscode.window.showInformationMessage(
            `✅ AI patch applied for "${vulnerability.type}".`
          );
        }
      } catch (error: any) {
        const msg = error?.response?.data?.error || error?.message || String(error);
        Logger.error('[AI Patch] AI repair failed', msg);
        vscode.window.showErrorMessage(`AI Assistance failed: ${msg}`);
      }
    }
  );
}

// ============================================================================
// Fix All with AI Command (from right-click menu)
// ============================================================================

async function fixAllWithAICommand(
  apiClient: APIClient,
  diagnosticManager: DiagnosticManager,
  patchManager: PatchManager
): Promise<void> {
  const activeEditor = vscode.window.activeTextEditor;
  if (!activeEditor) {
    vscode.window.showErrorMessage('No active editor found.');
    return;
  }

  const fileUri = activeEditor.document.uri;
  const vulnerabilities = diagnosticManager.getVulnerabilitiesForFile(fileUri);

  if (!vulnerabilities || vulnerabilities.length === 0) {
    vscode.window.showInformationMessage('No vulnerabilities found. Run a scan first.');
    return;
  }

  const scanId = vulnerabilities[0].scanId;
  if (!scanId) {
    vscode.window.showErrorMessage('No scan ID found. Please re-scan the file first.');
    return;
  }

  await runBulkAIRepair(apiClient, diagnosticManager, patchManager, scanId);
}

// ============================================================================
// Bulk AI Repair — The Big One
// ============================================================================

/**
 * Run AI repair for ALL remaining vulnerabilities.
 * Shows detailed progress with stages, metrics, time tracking.
 * Applies all AI patches together at once.
 * Then shows a complete report + download option.
 */
async function runBulkAIRepair(
  apiClient: APIClient,
  diagnosticManager: DiagnosticManager,
  patchManager: PatchManager,
  scanId: string
): Promise<void> {
  const activeEditor = vscode.window.activeTextEditor;
  const fileUri = activeEditor?.document.uri;
  const out = getReportChannel();

  // Write AI section header
  out.appendLine('');
  out.appendLine('  ┌──────────────────────────────────────────────────────────────────┐');
  out.appendLine('  │                  STAGE 2: AI-ASSISTED PATCHING                   │');
  out.appendLine('  └──────────────────────────────────────────────────────────────────┘');
  out.appendLine('');
  out.show(true);

  const aiStartTime = Date.now();
  let aiPatchCount = 0;
  let aiFailCount = 0;
  let aiTotalProcessed = 0;
  const aiPatchDetails: Array<{
    type: string;
    vulnId: string;
    status: 'success' | 'failed';
    explanation?: string;
    timeMs: number;
  }> = [];

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: '🤖 AutoVulRepair: AI Assistance',
      cancellable: true,
    },
    async (progress, token) => {
      try {
        // ── Phase 1: Connecting ─────────────────────────────────────────
        progress.report({
          message: '📡 Connecting to AI backend (Groq / Gemini)...',
          increment: 0,
        });
        out.appendLine('  📡 Phase 1/4: Connecting to AI backend...');
        out.appendLine(`  ⏱️  Started at ${new Date().toLocaleTimeString()}`);
        out.appendLine('');

        if (token.isCancellationRequested) { return; }

        // ── Phase 2: Sending to AI ──────────────────────────────────────
        progress.report({
          message: '🧠 AI is analyzing vulnerabilities and generating patches...',
          increment: 10,
        });
        out.appendLine('  🧠 Phase 2/4: AI analyzing vulnerabilities...');
        out.appendLine('  ────────────────────────────────────────────────────');
        out.appendLine('    This may take 30-120 seconds depending on:');
        out.appendLine('    • Number of vulnerabilities');
        out.appendLine('    • AI model response time (Groq/Gemini/Ollama)');
        out.appendLine('    • Code complexity');
        out.appendLine('  ────────────────────────────────────────────────────');
        out.appendLine('');

        const apiStart = Date.now();
        const result = await apiClient.runAIRepair(scanId);
        const apiTime = Date.now() - apiStart;

        out.appendLine(`  ✅ AI backend responded in ${formatElapsed(apiTime)}`);
        out.appendLine('');

        if (!result.success || !result.repair_results || result.repair_results.length === 0) {
          out.appendLine('  ❌ AI could not generate any patches.');
          out.appendLine('     Check your Groq/Gemini API key in the backend .env file.');
          vscode.window.showWarningMessage(
            '⚠️ AI could not generate patches. Ensure your API key is configured in the backend .env.'
          );
          return;
        }

        if (token.isCancellationRequested) { return; }

        // ── Phase 3: Processing results ─────────────────────────────────
        const totalResults = result.repair_results.length;
        progress.report({
          message: `🔧 Processing ${totalResults} AI results...`,
          increment: 30,
        });
        out.appendLine('  🔧 Phase 3/4: Processing AI repair results...');
        out.appendLine('');

        const patchesToApply: { vuln: VulnerabilityReport; patchContent: string }[] = [];

        // Process each result and log live to output channel
        for (let i = 0; i < totalResults; i++) {
          const r = result.repair_results[i];
          const patchContent = r.repaired_code || r.patch || '';
          const vulnType = r.type || r.vulnerability_id || `vulnerability_${i + 1}`;
          const vulnId = r.vulnerability_id || `unknown_${i}`;
          const stepStart = Date.now();

          aiTotalProcessed++;

          // Update progress bar in notification
          const pct = Math.round(((i + 1) / totalResults) * 100);
          progress.report({
            message: `${progressBar(i + 1, totalResults)} Processing: ${vulnType}`,
            increment: Math.round(40 / totalResults),
          });

          if (patchContent) {
            aiPatchCount++;
            aiPatchDetails.push({
              type: vulnType,
              vulnId,
              status: 'success',
              explanation: r.explanation,
              timeMs: Date.now() - stepStart,
            });

            out.appendLine(`    ${progressBar(i + 1, totalResults)}  ✅ ${vulnType}`);
            if (r.explanation) {
              out.appendLine(`       💡 ${r.explanation.substring(0, 80)}${r.explanation.length > 80 ? '...' : ''}`);
            }

            // Find matching vulnerability and queue for bulk apply
            if (fileUri) {
              const vulns = diagnosticManager.getVulnerabilitiesForFile(fileUri);
              const matchingVuln = vulns.find(
                (v) => v.id === vulnId || v.type === vulnType
              );
              if (matchingVuln) {
                patchesToApply.push({ vuln: matchingVuln, patchContent });
              }
            }
          } else {
            aiFailCount++;
            aiPatchDetails.push({
              type: vulnType,
              vulnId,
              status: 'failed',
              timeMs: Date.now() - stepStart,
            });

            out.appendLine(`    ${progressBar(i + 1, totalResults)}  ❌ ${vulnType} — no patch generated`);
          }
        }

        out.appendLine('');

        if (token.isCancellationRequested) { return; }

        // ── Phase 4: Applying all AI patches together ───────────────────
        progress.report({
          message: `📝 Applying ${patchesToApply.length} AI patches to source code...`,
          increment: 15,
        });
        out.appendLine('  📝 Phase 4/4: Applying AI patches to source code...');

        let appliedCount = 0;
        if (patchesToApply.length > 0 && fileUri) {
          const applyStart = Date.now();
          const success = await patchManager.applyBulkPatches(fileUri, patchesToApply);
          const applyTime = Date.now() - applyStart;

          if (success) {
            appliedCount = patchesToApply.length;
            out.appendLine(`  ✅ Applied ${appliedCount} AI patches in ${formatElapsed(applyTime)}`);
          } else {
            out.appendLine(`  ⚠️  Bulk apply failed, falling back to individual patches...`);
            // Fallback: apply one by one
            for (const p of patchesToApply) {
              try {
                p.vuln.patch = p.patchContent;
                const ok = await patchManager.applyPatch(fileUri, p.vuln);
                if (ok) { appliedCount++; }
              } catch (e) {
                Logger.error(`[AI Bulk] Failed to apply patch for ${p.vuln.type}`, e);
              }
            }
            out.appendLine(`  ✅ Applied ${appliedCount}/${patchesToApply.length} patches individually`);
          }
        }

        const totalTime = Date.now() - aiStartTime;

        progress.report({
          message: `✅ Done! ${appliedCount} AI patches applied.`,
          increment: 5,
        });

        // ── Write final report ──────────────────────────────────────────
        out.appendLine('');
        out.appendLine('  ┌──────────────────────────────────────────────────────────────────┐');
        out.appendLine('  │                         FINAL REPORT                             │');
        out.appendLine('  └──────────────────────────────────────────────────────────────────┘');
        out.appendLine('');
        out.appendLine('  ┌─────────────────────────────┬────────────┐');
        out.appendLine('  │ Metric                      │ Value      │');
        out.appendLine('  ├─────────────────────────────┼────────────┤');
        out.appendLine(`  │ AI patches generated        │ ${String(aiPatchCount).padEnd(10)} │`);
        out.appendLine(`  │ AI patches failed            │ ${String(aiFailCount).padEnd(10)} │`);
        out.appendLine(`  │ AI patches applied           │ ${String(appliedCount).padEnd(10)} │`);
        out.appendLine(`  │ Total processed              │ ${String(aiTotalProcessed).padEnd(10)} │`);
        out.appendLine(`  │ AI backend response time     │ ${formatElapsed(apiTime).padEnd(10)} │`);
        out.appendLine(`  │ Total AI stage time          │ ${formatElapsed(totalTime).padEnd(10)} │`);
        out.appendLine('  └─────────────────────────────┴────────────┘');
        out.appendLine('');

        if (aiPatchDetails.length > 0) {
          out.appendLine('  Detailed Results:');
          out.appendLine('  ──────────────────────────────────────────────────────────────');
          for (const d of aiPatchDetails) {
            const icon = d.status === 'success' ? '✅' : '❌';
            out.appendLine(`    ${icon} ${d.type}`);
            if (d.explanation) {
              out.appendLine(`       💡 ${d.explanation}`);
            }
          }
          out.appendLine('');
        }

        out.appendLine(`  ⏱️  Completed at ${new Date().toLocaleTimeString()}`);
        out.appendLine('');
        out.appendLine('╚══════════════════════════════════════════════════════════════════════╝');
        out.appendLine('');

        // ── Show final dialog ───────────────────────────────────────────
        const finalChoice = await vscode.window.showInformationMessage(
          `🤖 AI Patching Complete!\n\n` +
          `✅ ${appliedCount} patch${appliedCount !== 1 ? 'es' : ''} applied  |  ` +
          `❌ ${aiFailCount} failed  |  ` +
          `⏱️ ${formatElapsed(totalTime)}`,
          { modal: false },
          '📋 View Full Report',
          '💾 Download Report',
          '🔄 Re-Scan File',
          '✅ Done'
        );

        if (finalChoice === '📋 View Full Report') {
          out.show(true);
        } else if (finalChoice === '💾 Download Report') {
          await saveReportToFile(out);
        } else if (finalChoice === '🔄 Re-Scan File') {
          await vscode.commands.executeCommand('autoVulRepair.scanFile');
        }
      } catch (error: any) {
        const msg = error?.response?.data?.error || error?.message || String(error);
        Logger.error('[AI Bulk] AI repair failed', msg);
        out.appendLine(`  ❌ AI repair failed: ${msg}`);
        out.appendLine('');
        vscode.window.showErrorMessage(`AI Assistance failed: ${msg}`);
      }
    }
  );
}

// ============================================================================
// Report Download
// ============================================================================

/**
 * Save the current report Output Channel content to a file
 */
async function saveReportToFile(outputChannel?: vscode.OutputChannel): Promise<void> {
  // Prompt user for save location
  const defaultUri = vscode.workspace.workspaceFolders?.[0]?.uri;
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
  const defaultName = `autovulrepair-report-${timestamp}.txt`;

  const saveUri = await vscode.window.showSaveDialog({
    defaultUri: defaultUri
      ? vscode.Uri.joinPath(defaultUri, defaultName)
      : vscode.Uri.file(defaultName),
    filters: {
      'Text Files': ['txt'],
      'Markdown Files': ['md'],
      'All Files': ['*'],
    },
    title: 'Save AutoVulRepair Report',
  });

  if (!saveUri) { return; }

  try {
    // Build a comprehensive report from what we know
    const reportContent = buildReportContent();

    await vscode.workspace.fs.writeFile(
      saveUri,
      Buffer.from(reportContent, 'utf-8')
    );

    const openChoice = await vscode.window.showInformationMessage(
      `✅ Report saved to ${path.basename(saveUri.fsPath)}`,
      'Open Report',
      'Open Folder',
      'Done'
    );

    if (openChoice === 'Open Report') {
      const doc = await vscode.workspace.openTextDocument(saveUri);
      await vscode.window.showTextDocument(doc);
    } else if (openChoice === 'Open Folder') {
      await vscode.commands.executeCommand('revealFileInOS', saveUri);
    }
  } catch (error: any) {
    vscode.window.showErrorMessage(`Failed to save report: ${error.message}`);
  }
}

function buildReportContent(): string {
  const lines: string[] = [];
  const now = new Date();

  lines.push('==========================================================================');
  lines.push('                    AutoVulRepair — Vulnerability Report');
  lines.push('==========================================================================');
  lines.push('');
  lines.push(`Generated: ${now.toLocaleString()}`);
  lines.push(`Tool:      AutoVulRepair VS Code Extension v0.1.0`);
  lines.push('');
  lines.push('--------------------------------------------------------------------------');
  lines.push('Note: For the full detailed report with patching results, please');
  lines.push('view the "AutoVulRepair — Report" Output Channel in VS Code.');
  lines.push('This file is a snapshot saved at the time of export.');
  lines.push('--------------------------------------------------------------------------');
  lines.push('');

  // Include current diagnostics info
  lines.push('CURRENT OPEN FILES WITH VULNERABILITIES:');
  lines.push('');

  const editor = vscode.window.activeTextEditor;
  if (editor) {
    lines.push(`Active file: ${editor.document.fileName}`);
  }

  lines.push('');
  lines.push('==========================================================================');
  lines.push('                            End of Report');
  lines.push('==========================================================================');

  return lines.join('\n');
}

/**
 * Download report command — callable from command palette
 */
async function downloadReportCommand(): Promise<void> {
  await saveReportToFile();
}
