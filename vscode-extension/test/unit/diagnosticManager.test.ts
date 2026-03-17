import * as vscode from 'vscode';
import { DiagnosticManager } from '../../src/diagnosticManager';
import { VulnerabilityReport } from '../../src/types';

describe('DiagnosticManager', () => {
  let diagnosticManager: DiagnosticManager;
  let mockDiagnosticCollection: any;
  let testUri: vscode.Uri;

  beforeEach(() => {
    mockDiagnosticCollection = {
      set: jest.fn(),
      delete: jest.fn(),
      clear: jest.fn(),
      dispose: jest.fn(),
    };

    (vscode.languages.createDiagnosticCollection as jest.Mock).mockReturnValue(
      mockDiagnosticCollection
    );

    diagnosticManager = new DiagnosticManager();
    testUri = vscode.Uri.file('/test/file.c');
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('initialization', () => {
    it('should create diagnostic collection', () => {
      expect(vscode.languages.createDiagnosticCollection).toHaveBeenCalledWith(
        'autoVulRepair'
      );
    });
  });

  describe('createDiagnostics', () => {
    it('should create diagnostics for vulnerabilities', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Buffer Overflow',
          description: 'Potential buffer overflow',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      expect(mockDiagnosticCollection.set).toHaveBeenCalledWith(
        testUri,
        expect.arrayContaining([
          expect.objectContaining({
            source: 'AutoVulRepair',
            code: 'Buffer Overflow',
          }),
        ])
      );
    });

    it('should convert 1-indexed line to 0-indexed range', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Buffer Overflow',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics[0].range.start.line).toBe(9); // 10 - 1
      expect(diagnostics[0].range.start.character).toBe(5);
    });

    it('should store vulnerabilities in map', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Buffer Overflow',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      expect(diagnosticManager.getVulnerabilitiesForFile(testUri)).toEqual(vulnerabilities);
    });

    it('should handle multiple vulnerabilities', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Buffer Overflow',
          description: 'Test 1',
        },
        {
          file: 'file.c',
          line: 20,
          column: 10,
          severity: 'Medium',
          type: 'Use After Free',
          description: 'Test 2',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics).toHaveLength(2);
    });
  });

  describe('severity mapping', () => {
    it('should map Critical to Error', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'Critical',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics[0].severity).toBe(vscode.DiagnosticSeverity.Error);
    });

    it('should map High to Error', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics[0].severity).toBe(vscode.DiagnosticSeverity.Error);
    });

    it('should map Medium to Warning', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'Medium',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics[0].severity).toBe(vscode.DiagnosticSeverity.Warning);
    });

    it('should map Low to Information', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'Low',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics[0].severity).toBe(vscode.DiagnosticSeverity.Information);
    });

    it('should map Info to Information', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'Info',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics[0].severity).toBe(vscode.DiagnosticSeverity.Information);
    });
  });

  describe('message formatting', () => {
    it('should format message with severity and type', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Buffer Overflow',
          description: 'Potential buffer overflow detected',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics[0].message).toContain('[High]');
      expect(diagnostics[0].message).toContain('Buffer Overflow');
      expect(diagnostics[0].message).toContain('Potential buffer overflow detected');
    });

    it('should include exploitability score when present', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'Critical',
          type: 'Buffer Overflow',
          description: 'Test',
          exploitabilityScore: 8,
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics[0].message).toContain('(Exploitability: 8/10)');
    });

    it('should not include exploitability when not present', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const diagnostics = mockDiagnosticCollection.set.mock.calls[0][1];
      expect(diagnostics[0].message).not.toContain('Exploitability');
    });
  });

  describe('getVulnerability', () => {
    it('should get vulnerability at specific line', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Buffer Overflow',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const vuln = diagnosticManager.getVulnerability(testUri, 9); // 0-indexed
      expect(vuln).toEqual(vulnerabilities[0]);
    });

    it('should return undefined for non-existent line', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const vuln = diagnosticManager.getVulnerability(testUri, 20);
      expect(vuln).toBeUndefined();
    });

    it('should return undefined for non-existent file', () => {
      const otherUri = vscode.Uri.file('/other/file.c');
      const vuln = diagnosticManager.getVulnerability(otherUri, 10);
      expect(vuln).toBeUndefined();
    });
  });

  describe('clearDiagnostics', () => {
    it('should clear diagnostics for specific file', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);
      diagnosticManager.clearDiagnostics(testUri);

      expect(mockDiagnosticCollection.delete).toHaveBeenCalledWith(testUri);
      expect(diagnosticManager.getVulnerabilitiesForFile(testUri)).toEqual([]);
    });

    it('should clear all diagnostics when no URI provided', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);
      diagnosticManager.clearDiagnostics();

      expect(mockDiagnosticCollection.clear).toHaveBeenCalled();
      expect(diagnosticManager.getTotalCount()).toBe(0);
    });
  });

  describe('getAllVulnerabilities', () => {
    it('should return all vulnerabilities across files', () => {
      const uri1 = vscode.Uri.file('/test/file1.c');
      const uri2 = vscode.Uri.file('/test/file2.c');

      const vulns1: VulnerabilityReport[] = [
        {
          file: 'file1.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
      ];

      const vulns2: VulnerabilityReport[] = [
        {
          file: 'file2.c',
          line: 20,
          column: 10,
          severity: 'Medium',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(uri1, vulns1);
      diagnosticManager.createDiagnostics(uri2, vulns2);

      const allVulns = diagnosticManager.getAllVulnerabilities();
      expect(allVulns.size).toBe(2);
      expect(allVulns.get(uri1.fsPath)).toEqual(vulns1);
      expect(allVulns.get(uri2.fsPath)).toEqual(vulns2);
    });
  });

  describe('getTotalCount', () => {
    it('should return total vulnerability count', () => {
      const uri1 = vscode.Uri.file('/test/file1.c');
      const uri2 = vscode.Uri.file('/test/file2.c');

      diagnosticManager.createDiagnostics(uri1, [
        {
          file: 'file1.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
        {
          file: 'file1.c',
          line: 20,
          column: 5,
          severity: 'Medium',
          type: 'Test',
          description: 'Test',
        },
      ]);

      diagnosticManager.createDiagnostics(uri2, [
        {
          file: 'file2.c',
          line: 30,
          column: 5,
          severity: 'Low',
          type: 'Test',
          description: 'Test',
        },
      ]);

      expect(diagnosticManager.getTotalCount()).toBe(3);
    });
  });

  describe('getCountBySeverity', () => {
    it('should return counts by severity level', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'Critical',
          type: 'Test',
          description: 'Test',
        },
        {
          file: 'file.c',
          line: 20,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
        {
          file: 'file.c',
          line: 30,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
        {
          file: 'file.c',
          line: 40,
          column: 5,
          severity: 'Medium',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      const counts = diagnosticManager.getCountBySeverity();
      expect(counts.Critical).toBe(1);
      expect(counts.High).toBe(2);
      expect(counts.Medium).toBe(1);
      expect(counts.Low).toBe(0);
      expect(counts.Info).toBe(0);
    });
  });

  describe('hasVulnerabilities', () => {
    it('should return true when file has vulnerabilities', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);

      expect(diagnosticManager.hasVulnerabilities(testUri)).toBe(true);
    });

    it('should return false when file has no vulnerabilities', () => {
      const otherUri = vscode.Uri.file('/other/file.c');
      expect(diagnosticManager.hasVulnerabilities(otherUri)).toBe(false);
    });
  });

  describe('dispose', () => {
    it('should dispose diagnostic collection', () => {
      diagnosticManager.dispose();

      expect(mockDiagnosticCollection.dispose).toHaveBeenCalled();
    });

    it('should clear vulnerability map', () => {
      const vulnerabilities: VulnerabilityReport[] = [
        {
          file: 'file.c',
          line: 10,
          column: 5,
          severity: 'High',
          type: 'Test',
          description: 'Test',
        },
      ];

      diagnosticManager.createDiagnostics(testUri, vulnerabilities);
      diagnosticManager.dispose();

      expect(diagnosticManager.getTotalCount()).toBe(0);
    });
  });
});
