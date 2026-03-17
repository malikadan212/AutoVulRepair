import * as vscode from 'vscode';
import { BackgroundScanner } from '../../src/backgroundScanner';
import { APIClient } from '../../src/apiClient';
import { DiagnosticManager } from '../../src/diagnosticManager';
import { ConfigurationManager } from '../../src/configurationManager';
import { CacheManager } from '../../src/cacheManager';

describe('BackgroundScanner', () => {
  let scanner: BackgroundScanner;
  let mockApiClient: jest.Mocked<APIClient>;
  let mockDiagnosticManager: jest.Mocked<DiagnosticManager>;
  let mockConfig: jest.Mocked<ConfigurationManager>;
  let mockCacheManager: jest.Mocked<CacheManager>;

  beforeEach(() => {
    mockApiClient = {} as any;
    mockDiagnosticManager = {} as any;
    mockConfig = {
      get: jest.fn((key: string, defaultValue: any) => {
        if (key === 'backgroundScanEnabled') return false;
        if (key === 'backgroundScanDelay') return 2000;
        if (key === 'maxConcurrentScans') return 3;
        if (key === 'maxFileSizeKB') return 1024;
        if (key === 'excludePatterns') return [];
        return defaultValue;
      }),
    } as any;
    mockCacheManager = {} as any;

    scanner = new BackgroundScanner(
      mockApiClient,
      mockDiagnosticManager,
      mockConfig,
      mockCacheManager
    );
  });

  describe('initialization', () => {
    it('should initialize with config values', () => {
      expect(scanner.getActiveScanCount()).toBe(0);
      expect(scanner.getQueuedScanCount()).toBe(0);
    });
  });

  describe('dispose', () => {
    it('should clear all pending timers', () => {
      scanner.dispose();
      expect(scanner.getQueuedScanCount()).toBe(0);
    });
  });
});
