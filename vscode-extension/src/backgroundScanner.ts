import * as vscode from 'vscode';
import * as path from 'path';
import { minimatch } from 'minimatch';
import { APIClient } from './apiClient';
import { DiagnosticManager } from './diagnosticManager';
import { ConfigurationManager } from './configurationManager';
import { CacheManager } from './cacheManager';

/**
 * Manages background scanning on file save
 * Implements debouncing and concurrent scan limits
 */
export class BackgroundScanner {
  private scanQueue: Map<string, NodeJS.Timeout> = new Map();
  private activeScanSessions: Set<string> = new Set();
  private maxConcurrentScans: number;

  constructor(
    private apiClient: APIClient,
    private diagnosticManager: DiagnosticManager,
    private config: ConfigurationManager,
    private cacheManager: CacheManager
  ) {
    this.maxConcurrentScans = config.get('maxConcurrentScans', 3);
  }

  /**
   * Handle file save event
   * @param document Saved document
   */
  onFileSave(document: vscode.TextDocument): void {
    if (!this.shouldScan(document)) {
      return;
    }

    const filePath = document.uri.fsPath;

    // Clear existing debounce timer
    const existingTimer = this.scanQueue.get(filePath);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Set new debounce timer
    const delay = this.config.get('backgroundScanDelay', 2000);
    const timer = setTimeout(() => {
      this.scanQueue.delete(filePath);
      this.enqueueScan(document);
    }, delay);

    this.scanQueue.set(filePath, timer);
  }

  /**
   * Check if document should be scanned
   */
  private shouldScan(document: vscode.TextDocument): boolean {
    // Check if background scanning is enabled
    if (!this.config.get('backgroundScanEnabled', false)) {
      return false;
    }

    // Check file extension
    const ext = path.extname(document.fileName);
    if (!['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'].includes(ext)) {
      return false;
    }

    // Check file size limit
    const maxSize = this.config.get('maxFileSizeKB', 1024) * 1024;
    if (document.getText().length > maxSize) {
      return false;
    }

    // Check exclusion patterns
    const exclusions = this.config.get<string[]>('excludePatterns', []);
    const relativePath = vscode.workspace.asRelativePath(document.uri);
    if (exclusions.some((pattern) => minimatch(relativePath, pattern))) {
      return false;
    }

    return true;
  }

  /**
   * Enqueue scan for execution
   */
  private async enqueueScan(document: vscode.TextDocument): Promise<void> {
    const filePath = document.uri.fsPath;

    // Check if already scanning
    if (this.activeScanSessions.has(filePath)) {
      return;
    }

    // Check concurrent scan limit
    if (this.activeScanSessions.size >= this.maxConcurrentScans) {
      // Queue for later
      setTimeout(() => this.enqueueScan(document), 5000);
      return;
    }

    await this.performScan(document);
  }

  /**
   * Perform actual scan
   */
  private async performScan(document: vscode.TextDocument): Promise<void> {
    const filePath = document.uri.fsPath;
    this.activeScanSessions.add(filePath);

    try {
      const response = await this.apiClient.scan({
        code_snippet: document.getText(),
        analysis_tool: 'cppcheck',
      });

      // Poll for results (WebSocket disabled for background scans)
      const results = await this.pollForResults(response.scanId);

      // Update diagnostics
      this.diagnosticManager.createDiagnostics(document.uri, results.vulnerabilities);

      // Update cache
      this.cacheManager.set(filePath, results.vulnerabilities);
    } catch (error) {
      // Silent failure for background scans
      console.error(`Background scan failed for ${filePath}:`, error);
    } finally {
      this.activeScanSessions.delete(filePath);
    }
  }

  /**
   * Poll for scan results
   */
  private async pollForResults(sessionId: string): Promise<any> {
    const maxAttempts = 60; // 5 minutes with 5s intervals
    let attempts = 0;

    while (attempts < maxAttempts) {
      const status = await this.apiClient.getScanStatus(sessionId);

      if (status.status === 'completed') {
        return await this.apiClient.getScanResults(sessionId);
      }

      if (status.status === 'failed') {
        throw new Error('Scan failed');
      }

      await new Promise((resolve) => setTimeout(resolve, 5000));
      attempts++;
    }

    throw new Error('Scan timeout');
  }

  /**
   * Get active scan count
   */
  getActiveScanCount(): number {
    return this.activeScanSessions.size;
  }

  /**
   * Get queued scan count
   */
  getQueuedScanCount(): number {
    return this.scanQueue.size;
  }

  /**
   * Dispose and cleanup
   */
  dispose(): void {
    // Clear all pending timers
    for (const timer of this.scanQueue.values()) {
      clearTimeout(timer);
    }
    this.scanQueue.clear();
  }
}
