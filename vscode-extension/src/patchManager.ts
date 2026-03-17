import * as vscode from 'vscode';
import { VulnerabilityReport, PatchApplication } from './types';
import { DiagnosticManager } from './diagnosticManager';

/**
 * Manages patch preview and application
 * Handles patch validation, application, and history tracking
 */
export class PatchManager {
  private patchHistory: PatchApplication[] = [];

  constructor(private diagnosticManager: DiagnosticManager) {}

  /**
   * Show patch preview in diff view
   * @param fileUri File URI
   * @param vulnerability Vulnerability with patch
   */
  async showPatchPreview(fileUri: vscode.Uri, vulnerability: VulnerabilityReport): Promise<void> {
    if (!vulnerability.patch) {
      vscode.window.showErrorMessage('No patch available for this vulnerability');
      return;
    }

    const document = await vscode.workspace.openTextDocument(fileUri);
    const originalContent = document.getText();

    // For now, show the patch as-is (in real implementation, would apply patch)
    const patchedContent = this.applyPatchToContent(originalContent, vulnerability);

    // Create virtual document for diff
    const originalUri = fileUri.with({ scheme: 'file' });
    const patchedUri = fileUri.with({
      scheme: 'autovulrepair-patch',
      query: patchedContent,
    });

    await vscode.commands.executeCommand(
      'vscode.diff',
      originalUri,
      patchedUri,
      `Patch Preview: ${vulnerability.type}`
    );
  }

  /**
   * Apply patch to file
   * @param fileUri File URI
   * @param vulnerability Vulnerability with patch
   * @returns True if patch applied successfully
   */
  async applyPatch(fileUri: vscode.Uri, vulnerability: VulnerabilityReport): Promise<boolean> {
    if (!vulnerability.patch) {
      return false;
    }

    try {
      const document = await vscode.workspace.openTextDocument(fileUri);

      // Validate patch applicability
      if (!this.validatePatchApplicability(document, vulnerability)) {
        const rescan = await vscode.window.showWarningMessage(
          'File has been modified since scan. Rescan before applying patch?',
          'Rescan',
          'Cancel'
        );

        if (rescan !== 'Rescan') {
          return false;
        }
        // Would trigger rescan here
        return false;
      }

      // Create workspace edit
      const edit = new vscode.WorkspaceEdit();
      const range = this.getPatchRange(document, vulnerability);
      edit.replace(fileUri, range, vulnerability.patch);

      // Apply edit
      const success = await vscode.workspace.applyEdit(edit);

      if (success) {
        // Clear diagnostic for this vulnerability
        this.diagnosticManager.clearDiagnostics(fileUri);

        // Log patch application
        this.logPatchApplication(fileUri, vulnerability, true);

        vscode.window.showInformationMessage(
          `Patch applied successfully for ${vulnerability.type}`
        );
      }

      return success;
    } catch (error) {
      this.logPatchApplication(fileUri, vulnerability, false);
      vscode.window.showErrorMessage(`Failed to apply patch: ${error}`);
      return false;
    }
  }

  /**
   * Validate that patch can be applied to current file state
   */
  private validatePatchApplicability(
    document: vscode.TextDocument,
    vulnerability: VulnerabilityReport
  ): boolean {
    // Simple validation - check if line exists
    if (vulnerability.line > document.lineCount) {
      return false;
    }
    return true;
  }

  /**
   * Get range for patch application
   */
  private getPatchRange(
    document: vscode.TextDocument,
    vulnerability: VulnerabilityReport
  ): vscode.Range {
    const line = vulnerability.line - 1; // Convert to 0-indexed
    const lineText = document.lineAt(line).text;

    return new vscode.Range(line, 0, line, lineText.length);
  }

  /**
   * Apply patch to content string (for preview)
   */
  private applyPatchToContent(content: string, vulnerability: VulnerabilityReport): string {
    if (!vulnerability.patch) {
      return content;
    }

    const lines = content.split('\n');
    const lineIndex = vulnerability.line - 1;

    if (lineIndex >= 0 && lineIndex < lines.length) {
      lines[lineIndex] = vulnerability.patch;
    }

    return lines.join('\n');
  }

  /**
   * Log patch application for audit trail
   */
  private logPatchApplication(
    fileUri: vscode.Uri,
    vulnerability: VulnerabilityReport,
    success: boolean
  ): void {
    this.patchHistory.push({
      fileUri: fileUri.fsPath,
      vulnerability,
      timestamp: new Date(),
      success,
    });
  }

  /**
   * Get patch application history
   */
  getPatchHistory(): PatchApplication[] {
    return [...this.patchHistory];
  }

  /**
   * Clear patch history
   */
  clearHistory(): void {
    this.patchHistory = [];
  }
}
