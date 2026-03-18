import * as vscode from 'vscode';
import { ConfigurationManager } from '../../src/configurationManager';

describe('ConfigurationManager', () => {
  let configManager: ConfigurationManager;
  let mockContext: vscode.ExtensionContext;
  let mockConfig: any;
  let mockSecrets: any;

  beforeEach(() => {
    // Setup mock configuration
    mockConfig = {
      get: jest.fn((key: string, defaultValue: any) => defaultValue),
      update: jest.fn(),
    };

    // Setup mock secrets
    mockSecrets = {
      get: jest.fn(),
      store: jest.fn(),
    };

    // Setup mock context
    mockContext = {
      secrets: mockSecrets,
    } as any;

    (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue(mockConfig);

    configManager = new ConfigurationManager(mockContext);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('get', () => {
    it('should get configuration value with default', () => {
      mockConfig.get.mockReturnValue('http://localhost:5000');

      const result = configManager.get('backendURL', 'http://default:5000');

      expect(vscode.workspace.getConfiguration).toHaveBeenCalledWith('autoVulRepair');
      expect(mockConfig.get).toHaveBeenCalledWith('backendURL', 'http://default:5000');
      expect(result).toBe('http://localhost:5000');
    });

    it('should return default value when config not set', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => defaultValue);

      const result = configManager.get('nonexistent', 'default');

      expect(result).toBe('default');
    });

    it('should handle boolean values', () => {
      mockConfig.get.mockReturnValue(true);

      const result = configManager.get('backgroundScanEnabled', false);

      expect(result).toBe(true);
    });

    it('should handle number values', () => {
      mockConfig.get.mockReturnValue(5000);

      const result = configManager.get('backgroundScanDelay', 2000);

      expect(result).toBe(5000);
    });

    it('should handle array values', () => {
      const patterns = ['**/test/**', '**/node_modules/**'];
      mockConfig.get.mockReturnValue(patterns);

      const result = configManager.get('excludePatterns', []);

      expect(result).toEqual(patterns);
    });
  });

  describe('set', () => {
    it('should set workspace-level configuration', async () => {
      await configManager.set('backendURL', 'http://localhost:8080', false);

      expect(mockConfig.update).toHaveBeenCalledWith(
        'backendURL',
        'http://localhost:8080',
        vscode.ConfigurationTarget.Workspace
      );
    });

    it('should set global configuration', async () => {
      await configManager.set('backendURL', 'http://localhost:8080', true);

      expect(mockConfig.update).toHaveBeenCalledWith(
        'backendURL',
        'http://localhost:8080',
        vscode.ConfigurationTarget.Global
      );
    });

    it('should handle boolean values', async () => {
      await configManager.set('backgroundScanEnabled', true);

      expect(mockConfig.update).toHaveBeenCalledWith(
        'backgroundScanEnabled',
        true,
        vscode.ConfigurationTarget.Workspace
      );
    });
  });

  describe('getSecure', () => {
    it('should get secure value from secrets', async () => {
      mockSecrets.get.mockResolvedValue('secret-token');

      const result = await configManager.getSecure('authToken');

      expect(mockSecrets.get).toHaveBeenCalledWith('autoVulRepair.authToken');
      expect(result).toBe('secret-token');
    });

    it('should return undefined when secret not found', async () => {
      mockSecrets.get.mockResolvedValue(undefined);

      const result = await configManager.getSecure('nonexistent');

      expect(result).toBeUndefined();
    });
  });

  describe('setSecure', () => {
    it('should store secure value in secrets', async () => {
      await configManager.setSecure('authToken', 'my-secret-token');

      expect(mockSecrets.store).toHaveBeenCalledWith(
        'autoVulRepair.authToken',
        'my-secret-token'
      );
    });
  });

  describe('onDidChange', () => {
    it('should register configuration change callback', () => {
      const callback = jest.fn();
      const mockDisposable = { dispose: jest.fn() };
      (vscode.workspace.onDidChangeConfiguration as jest.Mock).mockReturnValue(
        mockDisposable
      );

      const disposable = configManager.onDidChange(callback);

      expect(vscode.workspace.onDidChangeConfiguration).toHaveBeenCalled();
      expect(disposable).toBe(mockDisposable);
    });

    it('should only trigger callback for autoVulRepair configuration changes', () => {
      const callback = jest.fn();
      let registeredCallback: any;

      (vscode.workspace.onDidChangeConfiguration as jest.Mock).mockImplementation((cb) => {
        registeredCallback = cb;
        return { dispose: jest.fn() };
      });

      configManager.onDidChange(callback);

      // Simulate configuration change for autoVulRepair
      const mockEvent = {
        affectsConfiguration: jest.fn((section: string) => section === 'autoVulRepair'),
      };
      registeredCallback(mockEvent);

      expect(callback).toHaveBeenCalledWith(mockEvent);
    });

    it('should not trigger callback for other configuration changes', () => {
      const callback = jest.fn();
      let registeredCallback: any;

      (vscode.workspace.onDidChangeConfiguration as jest.Mock).mockImplementation((cb) => {
        registeredCallback = cb;
        return { dispose: jest.fn() };
      });

      configManager.onDidChange(callback);

      // Simulate configuration change for different extension
      const mockEvent = {
        affectsConfiguration: jest.fn((section: string) => section === 'otherExtension'),
      };
      registeredCallback(mockEvent);

      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe('getAll', () => {
    it('should return complete configuration object', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        const values: any = {
          backendURL: 'http://localhost:5000',
          backgroundScanEnabled: true,
          backgroundScanDelay: 3000,
          excludePatterns: ['**/test/**'],
          maxFileSizeKB: 2048,
          maxConcurrentScans: 5,
          defaultSeverityFilter: 'High',
          enableWebSocketProgress: false,
          allowSelfSignedCertificates: true,
        };
        return values[key] ?? defaultValue;
      });

      const config = configManager.getAll();

      expect(config).toEqual({
        backendURL: 'http://localhost:5000',
        backgroundScanEnabled: true,
        backgroundScanDelay: 3000,
        excludePatterns: ['**/test/**'],
        maxFileSizeKB: 2048,
        maxConcurrentScans: 5,
        defaultSeverityFilter: 'High',
        enableWebSocketProgress: false,
        allowSelfSignedCertificates: true,
      });
    });
  });

  describe('validate', () => {
    it('should validate valid configuration', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => defaultValue);

      const result = configManager.validate();

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject invalid backend URL format', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'backendURL') return 'not-a-url';
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid backend URL format');
    });

    it('should reject non-localhost HTTP URLs', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'backendURL') return 'http://example.com:5000';
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Backend URL must use localhost, 127.0.0.1, or HTTPS for security reasons'
      );
    });

    it('should accept localhost URLs', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'backendURL') return 'http://localhost:5000';
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(true);
    });

    it('should accept 127.0.0.1 URLs', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'backendURL') return 'http://127.0.0.1:5000';
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(true);
    });

    it('should accept HTTPS URLs', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'backendURL') return 'https://api.example.com';
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(true);
    });

    it('should reject scan delay below minimum', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'backgroundScanDelay') return 50;
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Background scan delay must be between 100 and 10000ms');
    });

    it('should reject scan delay above maximum', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'backgroundScanDelay') return 15000;
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Background scan delay must be between 100 and 10000ms');
    });

    it('should reject file size below minimum', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'maxFileSizeKB') return 0;
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Max file size must be between 1 and 10240 KB');
    });

    it('should reject file size above maximum', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'maxFileSizeKB') return 20000;
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Max file size must be between 1 and 10240 KB');
    });

    it('should reject concurrent scans below minimum', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'maxConcurrentScans') return 0;
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Max concurrent scans must be between 1 and 10');
    });

    it('should reject concurrent scans above maximum', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'maxConcurrentScans') return 15;
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Max concurrent scans must be between 1 and 10');
    });

    it('should reject non-array exclude patterns', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'excludePatterns') return 'not-an-array';
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Exclude patterns must be an array of strings');
    });

    it('should accumulate multiple validation errors', () => {
      mockConfig.get.mockImplementation((key: string, defaultValue: any) => {
        if (key === 'backendURL') return 'invalid';
        if (key === 'backgroundScanDelay') return 50;
        if (key === 'maxFileSizeKB') return 0;
        return defaultValue;
      });

      const result = configManager.validate();

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(1);
    });
  });

  describe('resetToDefaults', () => {
    it('should reset all configuration keys to undefined', async () => {
      await configManager.resetToDefaults();

      const expectedKeys = [
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

      expect(mockConfig.update).toHaveBeenCalledTimes(expectedKeys.length);

      expectedKeys.forEach((key) => {
        expect(mockConfig.update).toHaveBeenCalledWith(
          key,
          undefined,
          vscode.ConfigurationTarget.Workspace
        );
      });
    });
  });
});
