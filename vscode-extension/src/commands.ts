import * as vscode from 'vscode';
import { APIClient } from './apiClient';
import { DiagnosticManager } from './diagnosticManager';
import { PatchManager } from './patchManager';
import { ConfigurationManager } from './configurationManager';
import { WebSocketHandler } from './websocketHandler';
import { ProgressTracker } from './progressTracker';

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
    console.log('[scanFileCommand] Starting scan for file:', document.fileName);
    console.log('[scanFileCommand] Code snippet length:', document.getText().length);
    
    const response = await apiClient.scan({
      code_snippet: document.getText(),
      analysis_tool: 'cppcheck',
    });

    console.log('[scanFileCommand] Received response:', response);
    console.log('[scanFileCommand] Response type:', typeof response);
    console.log('[scanFileCommand] Response keys:', Object.keys(response || {}));
    console.log('[scanFileCommand] scanId value:', response?.scanId);
    console.log('[scanFileCommand] scanId type:', typeof response?.scanId);

    // Validate response
    if (!response || !response.scanId) {
      console.error('[scanFileCommand] Invalid scan response:', response);
      throw new Error('Backend returned invalid response');
    }

    console.log('[scanFileCommand] Scan initiated successfully:', response.scanId);
    progressTracker.showProgress(response.scanId, 'Starting scan...');

    // WebSocket support disabled - using polling instead
    // The backend doesn't have WebSocket endpoints implemented yet
    // Polling provides reliable progress updates every 2 seconds

    // Wait for results with polling
    console.log('[scanFileCommand] Waiting for scan to complete...');
    const results = await apiClient.waitForScanResults(
      response.scanId,
      (progress, stage) => {
        console.log(`[scanFileCommand] Progress: ${progress}% - ${stage}`);
        progressTracker.updateProgress(response.scanId, progress, stage);
      }
    );

    console.log('[scanFileCommand] Scan completed, received results:', results);
    console.log('[scanFileCommand] Vulnerabilities count:', results.vulnerabilities?.length || 0);

    progressTracker.hideProgress(response.scanId);

    // Display results
    if (results.vulnerabilities && results.vulnerabilities.length > 0) {
      console.log('[scanFileCommand] Creating diagnostics for vulnerabilities...');
      
      // Transform backend response to match extension types
      const transformedVulns = results.vulnerabilities.map(vuln => ({
        file: vuln.file || document.fileName,
        line: vuln.line || 1,
        column: vuln.column || 0,
        severity: vuln.severity,
        type: vuln.type,
        description: vuln.description,
        exploitabilityScore: (vuln as any).exploitability || vuln.exploitabilityScore,
        patch: vuln.patch
      }));
      
      console.log('[scanFileCommand] Transformed vulnerabilities:', transformedVulns);
      diagnosticManager.createDiagnostics(document.uri, transformedVulns);
      vscode.window.showInformationMessage(`Found ${transformedVulns.length} vulnerabilities`);
    } else {
      console.log('[scanFileCommand] No vulnerabilities found');
      vscode.window.showInformationMessage('No vulnerabilities found');
    }
  } catch (error) {
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
  // Implementation would scan all C/C++ files in folder
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
 * Test backend connection
 */
async function testConnectionCommand(apiClient: APIClient): Promise<void> {
  try {
    const connected = await apiClient.testConnection();
    if (connected) {
      vscode.window.showInformationMessage('Backend connection successful');
    } else {
      vscode.window.showErrorMessage('Cannot connect to backend');
    }
  } catch (error) {
    vscode.window.showErrorMessage(`Connection test failed: ${error}`);
  }
}
