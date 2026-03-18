import * as vscode from 'vscode';
import { ExtensionConfiguration } from './types';

/**
 * Manages extension configuration and settings
 * Handles VS Code workspace settings, secure storage, and validation
 */
export class ConfigurationManager {
  private static readonly CONFIG_PREFIX = 'autoVulRepair';

  constructor(private context: vscode.ExtensionContext) {}

  /**
   * Get a configuration value with type safety
   * @param key Configuration key (without prefix)
   * @param defaultValue Default value if not set
   * @returns Configuration value
   */
  get<T>(key: string, defaultValue: T): T {
    const config = vscode.workspace.getConfiguration(ConfigurationManager.CONFIG_PREFIX);
    return config.get<T>(key, defaultValue);
  }

  /**
   * Set a configuration value
   * @param key Configuration key (without prefix)
   * @param value Value to set
   * @param global Whether to set globally or workspace-level
   */
  async set(key: string, value: unknown, global = false): Promise<void> {
    const config = vscode.workspace.getConfiguration(ConfigurationManager.CONFIG_PREFIX);
    const target = global
      ? vscode.ConfigurationTarget.Global
      : vscode.ConfigurationTarget.Workspace;
    await config.update(key, value, target);
  }

  /**
   * Get a secure value from VS Code's secret storage
   * @param key Secret key (will be prefixed)
   * @returns Secret value or undefined
   */
  async getSecure(key: string): Promise<string | undefined> {
    return await this.context.secrets.get(`${ConfigurationManager.CONFIG_PREFIX}.${key}`);
  }

  /**
   * Store a secure value in VS Code's secret storage
   * @param key Secret key (will be prefixed)
   * @param value Secret value
   */
  async setSecure(key: string, value: string): Promise<void> {
    await this.context.secrets.store(`${ConfigurationManager.CONFIG_PREFIX}.${key}`, value);
  }

  /**
   * Register a callback for configuration changes
   * @param callback Function to call when configuration changes
   * @returns Disposable to unregister the callback
   */
  onDidChange(callback: (e: vscode.ConfigurationChangeEvent) => void): vscode.Disposable {
    return vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration(ConfigurationManager.CONFIG_PREFIX)) {
        callback(e);
      }
    });
  }

  /**
   * Get all configuration as a typed object
   * @returns Complete configuration object
   */
  getAll(): ExtensionConfiguration {
    return {
      backendURL: this.get('backendURL', 'http://localhost:5000'),
      backgroundScanEnabled: this.get('backgroundScanEnabled', false),
      backgroundScanDelay: this.get('backgroundScanDelay', 2000),
      excludePatterns: this.get('excludePatterns', [
        '**/node_modules/**',
        '**/build/**',
        '**/dist/**',
      ]),
      maxFileSizeKB: this.get('maxFileSizeKB', 1024),
      maxConcurrentScans: this.get('maxConcurrentScans', 3),
      defaultSeverityFilter: this.get('defaultSeverityFilter', 'All'),
      enableWebSocketProgress: this.get('enableWebSocketProgress', true),
      allowSelfSignedCertificates: this.get('allowSelfSignedCertificates', false),
    };
  }

  /**
   * Validate all configuration values
   * @returns Validation result with errors if any
   */
  validate(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate backend URL
    const backendURL = this.get('backendURL', 'http://localhost:5000');
    try {
      const url = new URL(backendURL);
      // Check if URL uses localhost or is explicitly allowed
      if (
        !url.hostname.includes('localhost') &&
        url.hostname !== '127.0.0.1' &&
        !url.protocol.startsWith('https')
      ) {
        errors.push('Backend URL must use localhost, 127.0.0.1, or HTTPS for security reasons');
      }
    } catch {
      errors.push('Invalid backend URL format');
    }

    // Validate scan delay
    const delay = this.get('backgroundScanDelay', 2000);
    if (delay < 100 || delay > 10000) {
      errors.push('Background scan delay must be between 100 and 10000ms');
    }

    // Validate max file size
    const maxSize = this.get('maxFileSizeKB', 1024);
    if (maxSize < 1 || maxSize > 10240) {
      errors.push('Max file size must be between 1 and 10240 KB');
    }

    // Validate concurrent scans
    const maxConcurrent = this.get('maxConcurrentScans', 3);
    if (maxConcurrent < 1 || maxConcurrent > 10) {
      errors.push('Max concurrent scans must be between 1 and 10');
    }

    // Validate exclude patterns
    const excludePatterns = this.get<string[]>('excludePatterns', []);
    if (!Array.isArray(excludePatterns)) {
      errors.push('Exclude patterns must be an array of strings');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Reset all configuration to defaults
   */
  async resetToDefaults(): Promise<void> {
    const config = vscode.workspace.getConfiguration(ConfigurationManager.CONFIG_PREFIX);
    const keys = [
      'backendURL',
      'backgroundScanEnabled',
      'backgroundScanDelay',
      'excludePatterns',
      'maxFileSizeKB',
      'maxConcurrentScans',
      'defaultSeverityFilter',
      'enableWebSocketProgress',
      'allowSelfSignedCertificates',
    ];

    for (const key of keys) {
      await config.update(key, undefined, vscode.ConfigurationTarget.Workspace);
    }
  }
}
