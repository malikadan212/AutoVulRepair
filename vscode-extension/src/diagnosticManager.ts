import * as vscode from 'vscode';
import { VulnerabilityReport } from './types';

/**
 * Manages VS Code diagnostics for displaying vulnerabilities
 * Creates inline squiggly lines and provides vulnerability information
 */
export class DiagnosticManager {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private vulnerabilityMap: Map<string, VulnerabilityReport[]>;
  private _onDidChangeDiagnostics = new vscode.EventEmitter<void>();
  readonly onDidChangeDiagnostics = this._onDidChangeDiagnostics.event;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('autoVulRepair');
    this.vulnerabilityMap = new Map();
  }

  /**
   * Create diagnostics for a file
   * @param fileUri File URI
   * @param vulnerabilities Array of vulnerability reports
   */
  createDiagnostics(fileUri: vscode.Uri, vulnerabilities: VulnerabilityReport[]): void {
    // Normalize severity to capitalize first letter (backend returns lowercase)
    const normalizedVulns = vulnerabilities.map(vuln => ({
      ...vuln,
      severity: this.normalizeSeverity(vuln.severity)
    }));
    
    this.vulnerabilityMap.set(fileUri.fsPath, normalizedVulns);

    const diagnostics = normalizedVulns.map((vuln) => this.createDiagnostic(vuln));

    this.diagnosticCollection.set(fileUri, diagnostics);
    
    // Notify listeners that diagnostics have changed
    this._onDidChangeDiagnostics.fire();
  }

  /**
   * Normalize severity string to match SeverityLevel type
   * @param severity Severity string from backend (may be lowercase)
   * @returns Normalized severity level
   */
  private normalizeSeverity(severity: string): VulnerabilityReport['severity'] {
    const normalized = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
    // Ensure it's a valid severity level
    if (['Critical', 'High', 'Medium', 'Low', 'Info'].includes(normalized)) {
      return normalized as VulnerabilityReport['severity'];
    }
    // Default to Medium if unknown
    return 'Medium';
  }

  /**
   * Create a single diagnostic from a vulnerability report
   * @param vuln Vulnerability report
   * @returns VS Code diagnostic
   */
  private createDiagnostic(vuln: VulnerabilityReport): vscode.Diagnostic {
    // Convert 1-indexed line to 0-indexed
    const line = vuln.line - 1;
    const column = vuln.column;

    // Create range (single character for now)
    const range = new vscode.Range(line, column, line, column + 1);

    // Create diagnostic with formatted message
    const diagnostic = new vscode.Diagnostic(
      range,
      this.formatMessage(vuln),
      this.mapSeverity(vuln.severity)
    );

    diagnostic.source = 'AutoVulRepair';
    diagnostic.code = vuln.type;

    return diagnostic;
  }

  /**
   * Map vulnerability severity to VS Code diagnostic severity
   * @param severity Vulnerability severity level
   * @returns VS Code diagnostic severity
   */
  private mapSeverity(severity: VulnerabilityReport['severity']): vscode.DiagnosticSeverity {
    switch (severity) {
      case 'Critical':
      case 'High':
        return vscode.DiagnosticSeverity.Error;
      case 'Medium':
        return vscode.DiagnosticSeverity.Warning;
      case 'Low':
      case 'Info':
        return vscode.DiagnosticSeverity.Information;
    }
  }

  /**
   * Format diagnostic message with severity and exploitability
   * @param vuln Vulnerability report
   * @returns Formatted message string
   */
  private formatMessage(vuln: VulnerabilityReport): string {
    let message = `[${vuln.severity}] ${vuln.type}: ${vuln.description}`;

    if (vuln.exploitabilityScore !== undefined) {
      message += ` (Exploitability: ${vuln.exploitabilityScore}/10)`;
    }

    return message;
  }

  /**
   * Get vulnerability at a specific location
   * @param fileUri File URI
   * @param line Line number (0-indexed)
   * @returns Vulnerability report or undefined
   */
  getVulnerability(fileUri: vscode.Uri, line: number): VulnerabilityReport | undefined {
    const vulnerabilities = this.vulnerabilityMap.get(fileUri.fsPath);
    if (!vulnerabilities) {
      return undefined;
    }

    // Convert 0-indexed line to 1-indexed for comparison
    return vulnerabilities.find((v) => v.line === line + 1);
  }

  /**
   * Get all vulnerabilities for a file
   * @param fileUri File URI
   * @returns Array of vulnerability reports
   */
  getVulnerabilitiesForFile(fileUri: vscode.Uri): VulnerabilityReport[] {
    return this.vulnerabilityMap.get(fileUri.fsPath) || [];
  }

  /**
   * Clear diagnostics for a specific file or all files
   * @param fileUri Optional file URI (clears all if not provided)
   */
  clearDiagnostics(fileUri?: vscode.Uri): void {
    if (fileUri) {
      this.diagnosticCollection.delete(fileUri);
      this.vulnerabilityMap.delete(fileUri.fsPath);
    } else {
      this.diagnosticCollection.clear();
      this.vulnerabilityMap.clear();
    }
    
    // Notify listeners that diagnostics have changed
    this._onDidChangeDiagnostics.fire();
  }

  /**
   * Get all vulnerabilities across all files
   * @returns Map of file paths to vulnerability arrays
   */
  getAllVulnerabilities(): Map<string, VulnerabilityReport[]> {
    return new Map(this.vulnerabilityMap);
  }

  /**
   * Get total vulnerability count
   * @returns Total number of vulnerabilities
   */
  getTotalCount(): number {
    let count = 0;
    for (const vulnerabilities of this.vulnerabilityMap.values()) {
      count += vulnerabilities.length;
    }
    return count;
  }

  /**
   * Get vulnerability count by severity
   * @returns Object with counts per severity level
   */
  getCountBySeverity(): Record<string, number> {
    const counts: Record<string, number> = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Info: 0,
    };

    for (const vulnerabilities of this.vulnerabilityMap.values()) {
      for (const vuln of vulnerabilities) {
        counts[vuln.severity]++;
      }
    }

    return counts;
  }

  /**
   * Check if a file has vulnerabilities
   * @param fileUri File URI
   * @returns True if file has vulnerabilities
   */
  hasVulnerabilities(fileUri: vscode.Uri): boolean {
    const vulnerabilities = this.vulnerabilityMap.get(fileUri.fsPath);
    return vulnerabilities !== undefined && vulnerabilities.length > 0;
  }

  /**
   * Dispose of the diagnostic collection
   */
  dispose(): void {
    this.diagnosticCollection.dispose();
    this.vulnerabilityMap.clear();
    this._onDidChangeDiagnostics.dispose();
  }
}
