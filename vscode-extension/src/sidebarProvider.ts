import * as vscode from 'vscode';
import { VulnerabilityReport, SeverityLevel } from './types';
import { DiagnosticManager } from './diagnosticManager';

/**
 * Tree item for vulnerability sidebar
 */
export class VulnerabilityTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly type: 'file' | 'vulnerability',
    public readonly vulnerability?: VulnerabilityReport,
    public readonly fileUri?: vscode.Uri
  ) {
    super(label, collapsibleState);

    if (type === 'vulnerability' && vulnerability) {
      this.command = {
        command: 'autoVulRepair.navigateToVulnerability',
        title: 'Navigate to Vulnerability',
        arguments: [fileUri, vulnerability.line - 1],
      };

      this.iconPath = this.getIconForSeverity(vulnerability.severity);
      this.tooltip = vulnerability.description;
    }
  }

  private getIconForSeverity(severity: SeverityLevel): vscode.ThemeIcon {
    switch (severity) {
      case 'Critical':
      case 'High':
        return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
      case 'Medium':
        return new vscode.ThemeIcon('warning', new vscode.ThemeColor('warningForeground'));
      case 'Low':
      case 'Info':
        return new vscode.ThemeIcon('info', new vscode.ThemeColor('infoForeground'));
    }
  }
}

/**
 * Provides tree view for vulnerability sidebar
 */
export class VulnerabilitySidebarProvider
  implements vscode.TreeDataProvider<VulnerabilityTreeItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    VulnerabilityTreeItem | undefined | null | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private filterSeverities: Set<SeverityLevel> = new Set([
    'Critical',
    'High',
    'Medium',
    'Low',
    'Info',
  ]);
  private searchQuery = '';

  constructor(private diagnosticManager: DiagnosticManager) {}

  /**
   * Refresh tree view
   */
  refresh(): void {
    console.log('[Sidebar] Refresh called');
    this._onDidChangeTreeData.fire();
  }

  /**
   * Get tree item
   */
  getTreeItem(element: VulnerabilityTreeItem): vscode.TreeItem {
    return element;
  }

  /**
   * Get children for tree item
   */
  getChildren(element?: VulnerabilityTreeItem): Thenable<VulnerabilityTreeItem[]> {
    console.log('[Sidebar] getChildren called, element:', element?.label);
    
    if (!element) {
      // Root level - return file nodes
      const fileNodes = this.getFileNodes();
      console.log('[Sidebar] Returning', fileNodes.length, 'file nodes');
      return Promise.resolve(fileNodes);
    } else if (element.type === 'file' && element.fileUri) {
      // File level - return vulnerability nodes
      const vulnNodes = this.getVulnerabilityNodes(element.fileUri);
      console.log('[Sidebar] Returning', vulnNodes.length, 'vulnerability nodes for', element.label);
      return Promise.resolve(vulnNodes);
    }

    return Promise.resolve([]);
  }

  /**
   * Get file-level nodes
   */
  private getFileNodes(): VulnerabilityTreeItem[] {
    const allVulnerabilities = this.diagnosticManager.getAllVulnerabilities();
    console.log('[Sidebar] getAllVulnerabilities returned', allVulnerabilities.size, 'files');
    
    const fileNodes: VulnerabilityTreeItem[] = [];

    for (const [filePath, vulnerabilities] of allVulnerabilities) {
      console.log('[Sidebar] Processing file:', filePath, 'with', vulnerabilities.length, 'vulnerabilities');
      const filtered = this.filterVulnerabilities(vulnerabilities);
      if (filtered.length === 0) {
        console.log('[Sidebar] Skipping file (no vulnerabilities after filtering)');
        continue;
      }

      const uri = vscode.Uri.file(filePath);
      const fileName = filePath.split(/[/\\]/).pop() || filePath;
      const label = `${fileName} (${filtered.length})`;

      fileNodes.push(
        new VulnerabilityTreeItem(
          label,
          vscode.TreeItemCollapsibleState.Expanded,
          'file',
          undefined,
          uri
        )
      );
    }

    console.log('[Sidebar] Returning', fileNodes.length, 'file nodes');
    return fileNodes;
  }

  /**
   * Get vulnerability nodes for a file
   */
  private getVulnerabilityNodes(fileUri: vscode.Uri): VulnerabilityTreeItem[] {
    const vulnerabilities = this.diagnosticManager.getVulnerabilitiesForFile(fileUri);
    const filtered = this.filterVulnerabilities(vulnerabilities);

    return filtered.map((vuln) => {
      const label = `[${vuln.severity}] ${vuln.type} (Line ${vuln.line})`;
      return new VulnerabilityTreeItem(
        label,
        vscode.TreeItemCollapsibleState.None,
        'vulnerability',
        vuln,
        fileUri
      );
    });
  }

  /**
   * Filter vulnerabilities by severity and search query
   */
  private filterVulnerabilities(vulnerabilities: VulnerabilityReport[]): VulnerabilityReport[] {
    return vulnerabilities.filter((vuln) => {
      // Filter by severity
      if (!this.filterSeverities.has(vuln.severity)) {
        return false;
      }

      // Filter by search query
      if (this.searchQuery) {
        const query = this.searchQuery.toLowerCase();
        return (
          vuln.type.toLowerCase().includes(query) || vuln.description.toLowerCase().includes(query)
        );
      }

      return true;
    });
  }

  /**
   * Set severity filter
   */
  setFilter(severity: SeverityLevel, enabled: boolean): void {
    if (enabled) {
      this.filterSeverities.add(severity);
    } else {
      this.filterSeverities.delete(severity);
    }
    this.refresh();
  }

  /**
   * Set search query
   */
  setSearchQuery(query: string): void {
    this.searchQuery = query;
    this.refresh();
  }

  /**
   * Clear all filters
   */
  clearFilters(): void {
    this.filterSeverities = new Set(['Critical', 'High', 'Medium', 'Low', 'Info']);
    this.searchQuery = '';
    this.refresh();
  }
}
