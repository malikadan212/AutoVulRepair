import * as vscode from 'vscode';
import { DiagnosticManager } from './diagnosticManager';

/**
 * Provides code actions (quick fixes) for vulnerabilities
 */
export class CodeActionsProvider implements vscode.CodeActionProvider {
  constructor(private diagnosticManager: DiagnosticManager) {}

  /**
   * Provide code actions for diagnostics
   */
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.CodeAction[] | undefined {
    const actions: vscode.CodeAction[] = [];

    // Check if there are AutoVulRepair diagnostics in this range
    const diagnostics = context.diagnostics.filter((d) => d.source === 'AutoVulRepair');

    if (diagnostics.length === 0) {
      return undefined;
    }

    // Get vulnerability for this location
    const vulnerability = this.diagnosticManager.getVulnerability(document.uri, range.start.line);

    if (!vulnerability) {
      return undefined;
    }

    // Add "View Patch" action if patch is available
    if (vulnerability.patch) {
      const viewPatchAction = new vscode.CodeAction('View Patch', vscode.CodeActionKind.QuickFix);
      viewPatchAction.command = {
        command: 'autoVulRepair.viewPatch',
        title: 'View Patch',
        arguments: [document.uri, range.start.line],
      };
      viewPatchAction.diagnostics = diagnostics;
      actions.push(viewPatchAction);

      // Add "Apply Patch" action
      const applyPatchAction = new vscode.CodeAction('Apply Patch', vscode.CodeActionKind.QuickFix);
      applyPatchAction.command = {
        command: 'autoVulRepair.applyPatch',
        title: 'Apply Patch',
        arguments: [document.uri, range.start.line],
      };
      applyPatchAction.diagnostics = diagnostics;
      applyPatchAction.isPreferred = true;
      actions.push(applyPatchAction);
    }

    return actions;
  }
}
