import * as vscode from 'vscode';

/**
 * Manages an Output Channel for user-facing logs and debug info
 */
export class Logger {
  private static channel: vscode.OutputChannel;

  /**
   * Initialize the output channel
   */
  public static init(): void {
    if (!this.channel) {
      this.channel = vscode.window.createOutputChannel('AutoVulRepair');
    }
  }

  /**
   * Log info message
   */
  public static info(message: string): void {
    this.appendLine(`[INFO] ${message}`);
  }

  /**
   * Log warning message
   */
  public static warn(message: string): void {
    this.appendLine(`[WARN] ${message}`);
  }

  /**
   * Log error message
   */
  public static error(message: string, error?: any): void {
    let fullMessage = `[ERROR] ${message}`;
    if (error) {
      fullMessage += `: ${error?.message || String(error)}`;
    }
    this.appendLine(fullMessage);
    if (error?.stack) {
      this.appendLine(error.stack);
    }
  }

  /**
   * Log debug message
   */
  public static debug(message: string): void {
    this.appendLine(`[DEBUG] ${message}`);
  }

  /**
   * Show the output channel
   */
  public static show(): void {
    if (this.channel) {
      this.channel.show(true);
    }
  }

  /**
   * Clear the output channel
   */
  public static clear(): void {
    if (this.channel) {
      this.channel.clear();
    }
  }

  /**
   * Internal helper to append line with timestamp
   */
  private static appendLine(message: string): void {
    if (!this.channel) {
      this.init();
    }
    const timestamp = new Date().toLocaleTimeString();
    this.channel.appendLine(`[${timestamp}] ${message}`);
  }
}
