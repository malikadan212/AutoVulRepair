import axios from 'axios';
import { APIClient } from '../../src/apiClient';
import { ConfigurationManager } from '../../src/configurationManager';
import { ScanRequest, FuzzRequest } from '../../src/types';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock axios.isAxiosError
(axios.isAxiosError as unknown as jest.Mock) = jest.fn();

describe('APIClient', () => {
  let apiClient: APIClient;
  let mockConfig: jest.Mocked<ConfigurationManager>;

  beforeEach(() => {
    mockConfig = {
      get: jest.fn((key: string, defaultValue: any) => {
        if (key === 'backendURL') return 'http://localhost:5000';
        return defaultValue;
      }),
    } as any;

    apiClient = new APIClient(mockConfig);
    jest.clearAllMocks();
  });

  describe('scan', () => {
    it('should send scan request and return response', async () => {
      const request: ScanRequest = {
        files: [{ path: 'test.c', content: 'int main() {}' }],
        options: { staticAnalysis: true, fuzzing: false },
      };

      const response = {
        sessionId: 'test-session-123',
        status: 'pending',
        estimatedDuration: 60,
      };

      mockedAxios.post.mockResolvedValue({ data: response });

      const result = await apiClient.scan(request);

      expect(result).toEqual(response);
      expect(mockedAxios.post).toHaveBeenCalledWith(
        'http://localhost:5000/api/scan',
        request,
        expect.objectContaining({
          timeout: 30000,
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'User-Agent': expect.stringContaining('AutoVulRepair-VSCode'),
          }),
        })
      );
    });

    it('should include auth token in headers when set', async () => {
      const request: ScanRequest = {
        files: [{ path: 'test.c', content: 'int main() {}' }],
        options: { staticAnalysis: true, fuzzing: false },
      };

      apiClient.setAuthToken('test-token-123');
      mockedAxios.post.mockResolvedValue({ data: { sessionId: 'test' } });

      await apiClient.scan(request);

      expect(mockedAxios.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(Object),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer test-token-123',
          }),
        })
      );
    });

    it('should retry on timeout errors', async () => {
      const request: ScanRequest = {
        files: [{ path: 'test.c', content: 'int main() {}' }],
        options: { staticAnalysis: true, fuzzing: false },
      };

      mockedAxios.post
        .mockRejectedValueOnce({ code: 'ETIMEDOUT' })
        .mockResolvedValue({ data: { sessionId: 'test' } });

      const result = await apiClient.scan(request);

      expect(result.sessionId).toBe('test');
      expect(mockedAxios.post).toHaveBeenCalledTimes(2);
    });

    it('should not retry on 4xx errors', async () => {
      const request: ScanRequest = {
        files: [{ path: 'test.c', content: 'int main() {}' }],
        options: { staticAnalysis: true, fuzzing: false },
      };

      mockedAxios.post.mockRejectedValue({
        isAxiosError: true,
        response: { status: 400, data: { message: 'Bad request' } },
      });
      (axios.isAxiosError as unknown as jest.Mock).mockReturnValue(true);

      await expect(apiClient.scan(request)).rejects.toThrow();
      expect(mockedAxios.post).toHaveBeenCalledTimes(1);
    });
  });

  describe('getScanStatus', () => {
    it('should get scan status', async () => {
      const response = {
        status: 'running',
        progress: 50,
        stage: 'Static Analysis',
      };

      mockedAxios.get.mockResolvedValue({ data: response });

      const result = await apiClient.getScanStatus('test-session');

      expect(result).toEqual(response);
      expect(mockedAxios.get).toHaveBeenCalledWith(
        'http://localhost:5000/api/scan/test-session/status',
        expect.any(Object)
      );
    });
  });

  describe('getScanResults', () => {
    it('should get scan results', async () => {
      const response = {
        vulnerabilities: [
          {
            file: 'test.c',
            line: 10,
            column: 5,
            severity: 'High',
            type: 'Buffer Overflow',
            description: 'Potential buffer overflow',
          },
        ],
      };

      mockedAxios.get.mockResolvedValue({ data: response });

      const result = await apiClient.getScanResults('test-session');

      expect(result).toEqual(response);
      expect(mockedAxios.get).toHaveBeenCalledWith(
        'http://localhost:5000/api/scan/test-session/results',
        expect.objectContaining({
          timeout: 300000,
        })
      );
    });
  });

  describe('cancelScan', () => {
    it('should cancel scan', async () => {
      mockedAxios.delete.mockResolvedValue({});

      await apiClient.cancelScan('test-session');

      expect(mockedAxios.delete).toHaveBeenCalledWith(
        'http://localhost:5000/api/scan/test-session',
        expect.any(Object)
      );
    });
  });

  describe('fuzz', () => {
    it('should start fuzzing campaign', async () => {
      const request: FuzzRequest = {
        file: { path: 'test.c', content: 'int main() {}' },
        duration: 60,
      };

      const response = {
        sessionId: 'fuzz-session-123',
        status: 'pending',
      };

      mockedAxios.post.mockResolvedValue({ data: response });

      const result = await apiClient.fuzz(request);

      expect(result).toEqual(response);
      expect(mockedAxios.post).toHaveBeenCalledWith(
        'http://localhost:5000/api/fuzz',
        request,
        expect.any(Object)
      );
    });
  });

  describe('testConnection', () => {
    it('should return true when backend is reachable', async () => {
      mockedAxios.get.mockResolvedValue({});

      const result = await apiClient.testConnection();

      expect(result).toBe(true);
      expect(mockedAxios.get).toHaveBeenCalledWith(
        'http://localhost:5000/api/health',
        expect.objectContaining({ timeout: 5000 })
      );
    });

    it('should return false when backend is unreachable', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Connection refused'));

      const result = await apiClient.testConnection();

      expect(result).toBe(false);
    });
  });

  describe('authentication', () => {
    it('should set auth token', () => {
      apiClient.setAuthToken('my-token');
      // Token will be used in next request
    });

    it('should clear auth token', () => {
      apiClient.setAuthToken('my-token');
      apiClient.clearAuthToken();
      // Token will not be used in next request
    });
  });

  describe('configuration', () => {
    it('should update base URL from config', () => {
      mockConfig.get.mockReturnValue('http://newhost:8080');
      apiClient.updateBaseURL();
      // Next request will use new URL
    });
  });

  describe('circuit breaker', () => {
    it('should expose circuit breaker state', () => {
      const state = apiClient.getCircuitBreakerState();
      expect(['CLOSED', 'OPEN', 'HALF_OPEN']).toContain(state);
    });

    it('should allow manual circuit breaker reset', () => {
      apiClient.resetCircuitBreaker();
      expect(apiClient.getCircuitBreakerState()).toBe('CLOSED');
    });
  });
});
