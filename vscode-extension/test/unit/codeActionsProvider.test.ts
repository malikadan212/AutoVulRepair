import * as vscode from 'vscode';
import { CodeActionsProvider } from '../../src/codeActionsProvider';
import { DiagnosticManager } from '../../src/diagnosticManager';
import { VulnerabilityReport } from '../../src/types';

describe('CodeActionsProvider', () => {
  let provider: CodeActionsProvider;
  let mockDiagnosticManager: jest.Mocked<DiagnosticManager>;

  beforeEach(() => {
    mockDiagnosticManager = {
      getVulnerability: jest.fn(),
    } as any;

    provider = new CodeActionsProvider(mockDiagnosticManager);
  });

  describe('provideCodeActions', () => {
    it('should return undefined when no AutoVulRepair diagnostics', () => {
      const document = {} as vscode.TextDocument;
      const range = new vscode.Range(0, 0, 0, 10);
      const context = {
        diagnostics: [],
        triggerKind: 1,
        only: undefined,
      } as unknown as vscode.CodeActionContext;

      const actions = provider.provideCodeActions(document, range, context, {} as any);

      expect(actions).toBeUndefined();
    });

    it('should return undefined when no vulnerability found', () => {
      const document = { uri: vscode.Uri.file('/test.c') } as vscode.TextDocument;
      const range = new vscode.Range(0, 0, 0, 10);
      const context = {
        diagnostics: [
          {
            source: 'AutoVulRepair',
            message: 'Test',
            range,
            severity: vscode.DiagnosticSeverity.Error,
          },
        ],
        triggerKind: 1,
        only: undefined,
      } as unknown as vscode.CodeActionContext;

      mockDiagnosticManager.getVulnerability.mockReturnValue(undefined);

      const actions = provider.provideCodeActions(document, range, context, {} as any);

      expect(actions).toBeUndefined();
    });

    it('should return code actions when patch is available', () => {
      const document = { uri: vscode.Uri.file('/test.c') } as vscode.TextDocument;
      const range = new vscode.Range(0, 0, 0, 10);
      const context = {
        diagnostics: [
          {
            source: 'AutoVulRepair',
            message: 'Test',
            range,
            severity: vscode.DiagnosticSeverity.Error,
          },
        ],
        triggerKind: 1,
        only: undefined,
      } as unknown as vscode.CodeActionContext;

      const vulnerability: VulnerabilityReport = {
        file: 'test.c',
        line: 1,
        column: 0,
        severity: 'High',
        type: 'Buffer Overflow',
        description: 'Test',
        patch: 'fixed code',
      };

      mockDiagnosticManager.getVulnerability.mockReturnValue(vulnerability);

      const actions = provider.provideCodeActions(document, range, context, {} as any);

      expect(actions).toHaveLength(2);
      expect(actions![0].title).toBe('View Patch');
      expect(actions![1].title).toBe('Apply Patch');
      expect(actions![1].isPreferred).toBe(true);
    });

    it('should not return actions when no patch available', () => {
      const document = { uri: vscode.Uri.file('/test.c') } as vscode.TextDocument;
      const range = new vscode.Range(0, 0, 0, 10);
      const context = {
        diagnostics: [
          {
            source: 'AutoVulRepair',
            message: 'Test',
            range,
            severity: vscode.DiagnosticSeverity.Error,
          },
        ],
        triggerKind: 1,
        only: undefined,
      } as unknown as vscode.CodeActionContext;

      const vulnerability: VulnerabilityReport = {
        file: 'test.c',
        line: 1,
        column: 0,
        severity: 'High',
        type: 'Buffer Overflow',
        description: 'Test',
      };

      mockDiagnosticManager.getVulnerability.mockReturnValue(vulnerability);

      const actions = provider.provideCodeActions(document, range, context, {} as any);

      expect(actions).toHaveLength(0);
    });
  });
});
