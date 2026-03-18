import { CacheManager } from '../../src/cacheManager';
import { VulnerabilityReport } from '../../src/types';
import * as vscode from 'vscode';

describe('CacheManager', () => {
  let cacheManager: CacheManager;
  let mockContext: any;

  beforeEach(() => {
    mockContext = {
      workspaceState: {
        get: jest.fn().mockReturnValue(undefined),
        update: jest.fn().mockResolvedValue(undefined),
      },
    };

    cacheManager = new CacheManager(mockContext);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('set and get', () => {
    it('should store and retrieve vulnerabilities', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'test.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Buffer Overflow',
          description: 'Test',
        },
      ];

      cacheManager.set('/path/to/test.c', vulnerabilities);
      const result = cacheManager.get('/path/to/test.c');

      expect(result).toEqual(vulnerabilities);
    });

    it('should return null for non-existent entry', () => {
      const result = cacheManager.get('/nonexistent.c');
      expect(result).toBeNull();
    });

    it('should implement LRU eviction', () => {
      // Fill cache to max (100 entries)
      for (let i = 0; i < 100; i++) {
        cacheManager.set(`/file${i}.c`, []);
      }

      expect(cacheManager.size()).toBe(100);

      // Add one more - should evict oldest
      cacheManager.set('/file100.c', []);

      expect(cacheManager.size()).toBe(100);
      expect(cacheManager.has('/file0.c')).toBe(false);
      expect(cacheManager.has('/file100.c')).toBe(true);
    });
  });

  describe('invalidate', () => {
    it('should remove entry from cache', () => {
      cacheManager.set('/test.c', []);
      expect(cacheManager.has('/test.c')).toBe(true);

      cacheManager.invalidate('/test.c');
      expect(cacheManager.has('/test.c')).toBe(false);
    });
  });

  describe('clear', () => {
    it('should remove all entries', () => {
      cacheManager.set('/file1.c', []);
      cacheManager.set('/file2.c', []);
      expect(cacheManager.size()).toBe(2);

      cacheManager.clear();
      expect(cacheManager.size()).toBe(0);
    });
  });

  describe('getAge', () => {
    it('should return age of cache entry', () => {
      cacheManager.set('/test.c', []);
      const age = cacheManager.getAge('/test.c');

      expect(age).toBeGreaterThanOrEqual(0);
      expect(age).toBeLessThan(1000);
    });

    it('should return null for non-existent entry', () => {
      const age = cacheManager.getAge('/nonexistent.c');
      expect(age).toBeNull();
    });
  });

  describe('persistence', () => {
    it('should save to workspace state on set', () => {
      cacheManager.set('/test.c', []);

      expect(mockContext.workspaceState.update).toHaveBeenCalledWith(
        'vulnerabilityCache',
        expect.any(Object)
      );
    });

    it('should save to workspace state on clear', () => {
      cacheManager.clear();

      expect(mockContext.workspaceState.update).toHaveBeenCalledWith(
        'vulnerabilityCache',
        {}
      );
    });
  });
});
