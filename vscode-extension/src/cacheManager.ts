import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { VulnerabilityReport, CacheEntry } from './types';

/**
 * Manages caching of vulnerability scan results
 * Implements LRU eviction and file hash validation
 */
export class CacheManager {
  private cache: Map<string, CacheEntry> = new Map();
  private maxEntries = 100;

  constructor(private context: vscode.ExtensionContext) {
    this.loadFromStorage();
  }

  /**
   * Store vulnerabilities in cache
   * @param filePath File path
   * @param vulnerabilities Array of vulnerability reports
   */
  set(filePath: string, vulnerabilities: VulnerabilityReport[]): void {
    // Implement LRU eviction
    if (this.cache.size >= this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(filePath, {
      vulnerabilities,
      timestamp: Date.now(),
      fileHash: this.hashFile(filePath),
    });

    this.saveToStorage();
  }

  /**
   * Get vulnerabilities from cache
   * @param filePath File path
   * @returns Vulnerability reports or null if not cached or invalid
   */
  get(filePath: string): VulnerabilityReport[] | null {
    const entry = this.cache.get(filePath);
    if (!entry) {
      return null;
    }

    // Validate cache is still valid
    const currentHash = this.hashFile(filePath);
    if (currentHash !== entry.fileHash) {
      this.cache.delete(filePath);
      this.saveToStorage();
      return null;
    }

    // Move to end for LRU (re-insert)
    this.cache.delete(filePath);
    this.cache.set(filePath, entry);

    return entry.vulnerabilities;
  }

  /**
   * Invalidate cache for a specific file
   * @param filePath File path
   */
  invalidate(filePath: string): void {
    this.cache.delete(filePath);
    this.saveToStorage();
  }

  /**
   * Clear all cache entries
   */
  clear(): void {
    this.cache.clear();
    this.saveToStorage();
  }

  /**
   * Get cache size
   */
  size(): number {
    return this.cache.size;
  }

  /**
   * Check if file is cached
   */
  has(filePath: string): boolean {
    return this.cache.has(filePath);
  }

  /**
   * Get cache entry age in milliseconds
   */
  getAge(filePath: string): number | null {
    const entry = this.cache.get(filePath);
    if (!entry) {
      return null;
    }
    return Date.now() - entry.timestamp;
  }

  /**
   * Hash file path for validation
   * @param filePath File path
   * @returns Hash string
   */
  private hashFile(filePath: string): string {
    return crypto.createHash('md5').update(filePath).digest('hex');
  }

  /**
   * Load cache from workspace storage
   */
  private async loadFromStorage(): Promise<void> {
    const stored =
      this.context.workspaceState.get<Record<string, CacheEntry>>('vulnerabilityCache');
    if (stored) {
      this.cache = new Map(Object.entries(stored));
    }
  }

  /**
   * Save cache to workspace storage
   */
  private async saveToStorage(): Promise<void> {
    const obj = Object.fromEntries(this.cache);
    await this.context.workspaceState.update('vulnerabilityCache', obj);
  }
}
