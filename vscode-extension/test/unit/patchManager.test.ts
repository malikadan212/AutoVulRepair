import * as vscode from 'vscode';
import { PatchManager } from '../../src/patchManager';
import { DiagnosticManager } from '../../src/diagnosticManager';
import { VulnerabilityReport } from '../../src/types';

describe('PatchManager', () => {
  let patchManager: PatchManager;
  let mockDiagnosticManager: jest.Mocked<DiagnosticManager>;

  beforeEach(() => {
    mockDiagnosticManager = {
      clearDiagnostics: jest.fn(),
    } as any;

    patchManager = new PatchManager(mockDiagnosticManager);
  });

  describe('showPatchPreview', () => {
    it('should show error when no patch available', async () => {
      const vulnerability: VulnerabilityReport = {
        file: 'test.c',
        line: 10,
        column: 5,
        severity: 'High',
        type: 'Buffer Overflow',
        description: 'Test',
      };

      const uri = vscode.Uri.file('/test.c');
      await patchManager.showPatchPreview(uri, vulnerability);

      expect(vscode.window.showErrorMessage).toHaveBeenCalledWith(
        'No patch available for this vulnerability'
      );
    });
  });

  describe('applyPatch', () => {
    it('should return false when no patch available', async () => {
      const vulnerability: VulnerabilityReport = {
        file: 'test.c',
        line: 10,
        column: 5,
        severity: 'High',
        type: 'Buffer Overflow',
        description: 'Test',
      };

      const uri = vscode.Uri.file('/test.c');
      const result = await patchManager.applyPatch(uri, vulnerability);

      expect(result).toBe(false);
    });
  });

  describe('patch history', () => {
    it('should track patch history', () => {
      expect(patchManager.getPatchHistory()).toEqual([]);
    });

    it('should clear patch history', () => {
      patchManager.clearHistory();
      expect(patchManager.getPatchHistory()).toEqual([]);
    });
  });
});
