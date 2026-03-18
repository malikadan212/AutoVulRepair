// Mock VS Code API for testing
export const workspace = {
  getConfiguration: jest.fn(),
  onDidChangeConfiguration: jest.fn(),
};

export const ConfigurationTarget = {
  Global: 1,
  Workspace: 2,
  WorkspaceFolder: 3,
};

export const window = {
  showInformationMessage: jest.fn(),
  showWarningMessage: jest.fn(),
  showErrorMessage: jest.fn(),
  createOutputChannel: jest.fn(),
  createStatusBarItem: jest.fn(),
  withProgress: jest.fn(),
  registerTreeDataProvider: jest.fn(),
};

export const commands = {
  registerCommand: jest.fn(),
  executeCommand: jest.fn(),
};

export const languages = {
  createDiagnosticCollection: jest.fn(),
  registerCodeActionsProvider: jest.fn(),
};

export const Uri = {
  file: jest.fn((path: string) => ({ fsPath: path, scheme: 'file', path })),
  parse: jest.fn((uri: string) => ({ fsPath: uri, scheme: 'file', path: uri })),
};

export const Range = jest.fn((startLine: number, startChar: number, endLine: number, endChar: number) => ({
  start: { line: startLine, character: startChar },
  end: { line: endLine, character: endChar },
}));

export const Position = jest.fn((line: number, character: number) => ({
  line,
  character,
}));

export const Diagnostic = jest.fn((range: any, message: string, severity: number) => ({
  range,
  message,
  severity,
  source: undefined,
  code: undefined,
}));

export const DiagnosticSeverity = {
  Error: 0,
  Warning: 1,
  Information: 2,
  Hint: 3,
};

export const TreeItem = jest.fn();

export const TreeItemCollapsibleState = {
  None: 0,
  Collapsed: 1,
  Expanded: 2,
};

export const EventEmitter = jest.fn(() => {
  const listeners: any[] = [];
  return {
    event: (listener: any) => {
      listeners.push(listener);
      return { dispose: () => {} };
    },
    fire: (data: any) => {
      listeners.forEach((l) => l(data));
    },
  };
});

export const WorkspaceEdit = jest.fn();

export const StatusBarAlignment = {
  Left: 1,
  Right: 2,
};

export const ThemeIcon = jest.fn((id: string, color?: any) => ({ id, color }));

export const ThemeColor = jest.fn((id: string) => ({ id }));

export const ProgressLocation = {
  SourceControl: 1,
  Window: 10,
  Notification: 15,
};

export const CodeAction = jest.fn((title: string, kind: any) => ({
  title,
  kind,
  command: undefined,
  diagnostics: undefined,
  isPreferred: false,
}));

export const CodeActionKind = {
  QuickFix: { value: 'quickfix' },
  Refactor: { value: 'refactor' },
  RefactorExtract: { value: 'refactor.extract' },
  RefactorInline: { value: 'refactor.inline' },
  RefactorRewrite: { value: 'refactor.rewrite' },
  Source: { value: 'source' },
  SourceOrganizeImports: { value: 'source.organizeImports' },
};
