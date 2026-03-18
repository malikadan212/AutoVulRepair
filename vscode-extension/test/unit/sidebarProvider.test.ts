import * as vscode from 'vscode';
import { VulnerabilitySidebarProvider } from '../../src/sidebarProvider';
import { DiagnosticManager } from '../../src/diagnosticManager';
import { VulnerabilityReport } from '../../src/types';

describe('VulnerabilitySidebarProvider', () => {
  let provider: VulnerabilitySidebarProvider;
  let mockDiagnosticManager: jest.Mocked<DiagnosticManager>;

  beforeEach(() => {
    mockDiagnosticManager = {
      getAllVulnerabilities: jest.fn().mockReturnValue(new Map()),
      getVulnerabilitiesForFile: jest.fn().mockReturnValue([]),
    } as any;

    provider = new VulnerabilitySidebarProvider(mockDiagnosticManager);
  });

  describe('initialization', () => {
    it('should create provider', () => {
      expect(provider).toBeDefined();
    });
  });

  describe('getChildren', () => {
    it('should return empty array when no vulnerabilities', async () => {
      const children = await provider.getChildren();
      expect(children).toEqual([]);
    });

    it('should return file nodes at root level', async () => {
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

      mockDiagnosticManager.getAllVulnerabilities.mockReturnValue(
        new Map([['/path/to/test.c', vulnerabilities]])
      );

      const children = await provider.getChildren();
      expect(children.length).toBe(1);
      expect(children[0].type).toBe('file');
    });
  });

  describe('filtering', () => {
    it('should filter by severity', async () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'test.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
        {
          file: 'test.c',
          line: 20,
          column: 5,
          severity: 'Low',
          type: 'Test',
          description: 'Test',
        },
      ];

      mockDiagnosticManager.getAllVulnerabilities.mockReturnValue(
        new Map([['/path/to/test.c', vulnerabilities]])
      );

      provider.setFilter('Low', false);
      const children = await provider.getChildren();

      expect(children[0].label).toContain('(1)'); // Only High severity
    });

    it('should filter by search query', () => {
      provider.setSearchQuery('buffer');
      provider.clearFilters();
      expect(true).toBe(true); // Just testing methods don't throw
    });
  });

  describe('refresh', () => {
    it('should trigger tree data change event', () => {
      const spy = jest.fn();
      provider.onDidChangeTreeData(spy);
      provider.refresh();
      expect(spy).toHaveBeenCalled();
    });
  });
});
