import * as vscode from 'vscode';

/**
 * Tracks and displays scan progress
 * Manages status bar and modal progress indicators
 */
export class ProgressTracker {
  private statusBarItem: vscode.StatusBarItem;
  private activeProgress: Map<string, { message: string; progress: number }> = new Map();

  constructor() {
    this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  }

  /**
   * Show progress for a scan session
   * @param sessionId Scan session ID
   * @param message Progress message
   */
  showProgress(sessionId: string, message: string): void {
    this.activeProgress.set(sessionId, { message, progress: 0 });
    this.updateStatusBar();
  }

  /**
   * Update progress for a scan session
   * @param sessionId Scan session ID
   * @param progress Progress percentage (0-100)
   * @param stage Current stage name
   */
  updateProgress(sessionId: string, progress: number, stage: string): void {
    const existing = this.activeProgress.get(sessionId);
    if (existing) {
      existing.progress = progress;
      existing.message = `${stage} (${Math.round(progress)}%)`;
      this.updateStatusBar();
    }
  }

  /**
   * Hide progress for a scan session
   * @param sessionId Scan session ID
   */
  hideProgress(sessionId: string): void {
    this.activeProgress.delete(sessionId);
    this.updateStatusBar();
  }

  /**
   * Update status bar display
   */
  private updateStatusBar(): void {
    if (this.activeProgress.size === 0) {
      this.statusBarItem.hide();
      return;
    }

    // Show first active progress
    const first = this.activeProgress.values().next().value;
    if (first) {
      this.statusBarItem.text = `$(sync~spin) AutoVulRepair: ${first.message}`;
      this.statusBarItem.show();
    }
  }

  /**
   * Show modal progress with cancellation support
   * @param title Progress title
   * @param task Task to execute
   * @returns Task result
   */
  async withProgress<T>(
    title: string,
    task: (
      progress: vscode.Progress<{ message?: string; increment?: number }>,
      token: vscode.CancellationToken
    ) => Promise<T>
  ): Promise<T> {
    return vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title,
        cancellable: true,
      },
      task
    );
  }

  /**
   * Get active progress count
   */
  getActiveCount(): number {
    return this.activeProgress.size;
  }

  /**
   * Dispose of resources
   */
  dispose(): void {
    this.statusBarItem.dispose();
    this.activeProgress.clear();
  }
}
