import * as vscode from 'vscode';
import { ConfigurationManager } from './configurationManager';
import { APIClient } from './apiClient';
import { DiagnosticManager } from './diagnosticManager';
import { PatchManager } from './patchManager';
import { CacheManager } from './cacheManager';
import { BackgroundScanner } from './backgroundScanner';
import { VulnerabilitySidebarProvider } from './sidebarProvider';
import { ProgressTracker } from './progressTracker';
import { CodeActionsProvider } from './codeActionsProvider';
import { registerCommands } from './commands';

// Global instances for cleanup
let diagnosticManager: DiagnosticManager;
let backgroundScanner: BackgroundScanner;
let progressTracker: ProgressTracker;

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext): void {
  console.log('AutoVulRepair extension is now active');

  // Initialize configuration
  const config = new ConfigurationManager(context);

  // Initialize API client
  const apiClient = new APIClient(config);

  // Initialize managers
  diagnosticManager = new DiagnosticManager();
  const patchManager = new PatchManager(diagnosticManager);
  const cacheManager = new CacheManager(context);

  // Initialize background scanner
  backgroundScanner = new BackgroundScanner(apiClient, diagnosticManager, config, cacheManager);

  // Initialize UI components
  const sidebarProvider = new VulnerabilitySidebarProvider(diagnosticManager);
  progressTracker = new ProgressTracker();

  // Register commands
  registerCommands(context, apiClient, diagnosticManager, patchManager, config, progressTracker);

  // Register sidebar tree view
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('autoVulRepairSidebar', sidebarProvider)
  );

  // Listen for diagnostic changes and refresh sidebar
  context.subscriptions.push(
    diagnosticManager.onDidChangeDiagnostics(() => {
      sidebarProvider.refresh();
    })
  );

  // Register code actions provider
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      ['c', 'cpp'],
      new CodeActionsProvider(diagnosticManager),
      {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
      }
    )
  );

  // Register event listeners
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      backgroundScanner.onFileSave(document);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      // Invalidate cache when file is modified
      cacheManager.invalidate(event.document.uri.fsPath);
    })
  );

  // Listen for configuration changes
  context.subscriptions.push(
    config.onDidChange(() => {
      apiClient.updateBaseURL();
      sidebarProvider.refresh();
    })
  );

  vscode.window.showInformationMessage('AutoVulRepair extension activated');
}

/**
 * Extension deactivation
 */
export function deactivate(): void {
  console.log('AutoVulRepair extension is now deactivated');

  // Cleanup resources
  if (diagnosticManager) {
    diagnosticManager.dispose();
  }

  if (backgroundScanner) {
    backgroundScanner.dispose();
  }

  if (progressTracker) {
    progressTracker.dispose();
  }
}
