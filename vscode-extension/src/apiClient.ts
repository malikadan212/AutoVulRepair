import axios, { AxiosResponse, AxiosError } from 'axios';
import { ConfigurationManager } from './configurationManager';
import { CircuitBreaker } from './circuitBreaker';
import {
  ScanRequest,
  ScanResponse,
  ScanStatusResponse,
  ScanResultsResponse,
  FuzzRequest,
  FuzzResponse,
} from './types';

/**
 * API Client for communicating with the AutoVulRepair backend service
 * Handles REST API requests with retry logic, circuit breaker, and timeout management
 */
export class APIClient {
  private baseURL: string;
  private timeout: { initiation: number; results: number };
  private maxRetries: number;
  private circuitBreaker: CircuitBreaker;
  private authToken?: string;

  constructor(private config: ConfigurationManager) {
    this.baseURL = config.get('backendURL', 'http://localhost:5001');
    this.timeout = { initiation: 60000, results: 300000 };
    this.maxRetries = 3;
    this.circuitBreaker = new CircuitBreaker(5, 60000); // 5 failures, 60s timeout
  }

  /**
   * Initiate a vulnerability scan
   * @param request Scan request with files and options
   * @returns Scan session information
   */
  async scan(request: ScanRequest): Promise<ScanResponse> {
    return this.circuitBreaker.execute(() =>
      this.retryRequest(async () => {
        console.log('[APIClient] Sending scan request:', request);
        const response = await axios.post<ScanResponse>(`${this.baseURL}/api/scan`, request, {
          timeout: this.timeout.initiation,
          headers: this.getHeaders(),
        });
        
        console.log('[APIClient] Received scan response:', response.data);
        console.log('[APIClient] Response status:', response.status);
        console.log('[APIClient] Response headers:', response.headers);
        
        // Validate response has required fields
        if (!response.data || !response.data.scanId) {
          console.error('[APIClient] Invalid scan response - missing scanId:', response.data);
          console.error('[APIClient] Full response object:', JSON.stringify(response, null, 2));
          throw new Error('Backend returned invalid response: missing scanId');
        }
        
        console.log('[APIClient] Scan initiated successfully with ID:', response.data.scanId);
        return response.data;
      })
    );
  }

  /**
   * Get scan status
   * @param sessionId Scan session ID
   * @returns Current scan status and progress
   */
  async getScanStatus(sessionId: string): Promise<ScanStatusResponse> {
    return this.retryRequest(async () => {
      const response = await axios.get<ScanStatusResponse>(
        `${this.baseURL}/api/scan/${sessionId}/status`,
        {
          timeout: this.timeout.initiation,
          headers: this.getHeaders(),
        }
      );
      return response.data;
    });
  }

  /**
   * Get scan results
   * @param sessionId Scan session ID
   * @returns Vulnerability reports
   */
  async getScanResults(sessionId: string): Promise<ScanResultsResponse> {
    return this.retryRequest(async () => {
      const response = await axios.get<ScanResultsResponse>(
        `${this.baseURL}/api/scan/${sessionId}/results`,
        {
          timeout: this.timeout.results,
          headers: this.getHeaders(),
        }
      );
      return response.data;
    });
  }

  /**
   * Wait for scan to complete and get results
   * Polls the backend until scan is completed or failed
   * @param sessionId Scan session ID
   * @param onProgress Optional callback for progress updates
   * @returns Vulnerability reports
   */
  async waitForScanResults(
    sessionId: string,
    onProgress?: (progress: number, stage: string) => void
  ): Promise<ScanResultsResponse> {
    const maxWaitTime = 300000; // 5 minutes
    const pollInterval = 2000; // 2 seconds
    const startTime = Date.now();

    console.log(`[APIClient] Waiting for scan ${sessionId} to complete...`);

    while (Date.now() - startTime < maxWaitTime) {
      try {
        // Get current results (includes status and progress)
        const results = await this.getScanResults(sessionId);
        
        console.log(`[APIClient] Scan ${sessionId} status: ${results.status}, progress: ${results.progress}%`);
        
        // Update progress if callback provided
        if (onProgress && results.progress !== undefined && results.stage) {
          onProgress(results.progress, results.stage);
        }

        // Check if scan is complete
        if (results.status === 'completed') {
          console.log(`[APIClient] Scan ${sessionId} completed with ${results.vulnerabilities?.length || 0} vulnerabilities`);
          return results;
        }

        // Check if scan failed
        if (results.status === 'failed') {
          throw new Error('Scan failed on backend');
        }

        // Check if scan was cancelled
        if (results.status === 'cancelled') {
          throw new Error('Scan was cancelled');
        }

        // Wait before next poll
        await this.sleep(pollInterval);
      } catch (error) {
        // If it's a 404, the scan might not be ready yet, continue polling
        if (axios.isAxiosError(error) && error.response?.status === 404) {
          console.log(`[APIClient] Scan ${sessionId} not found yet, continuing to poll...`);
          await this.sleep(pollInterval);
          continue;
        }
        throw error;
      }
    }

    throw new Error('Scan timeout: exceeded maximum wait time');
  }

  /**
   * Cancel a running scan
   * @param sessionId Scan session ID
   */
  async cancelScan(sessionId: string): Promise<void> {
    await axios.delete(`${this.baseURL}/api/scan/${sessionId}`, {
      headers: this.getHeaders(),
    });
  }

  /**
   * Request a single rule-based patch from the backend
   */
  async generateSinglePatch(scanId: string, vulnId: string): Promise<string | undefined> {
    return this.circuitBreaker.execute(() =>
      this.retryRequest(async () => {
        console.log(`[APIClient] Requesting single patch for scan: ${scanId}, vuln: ${vulnId}`);
        const response = await axios.post<{ success: boolean; patch?: { repaired: string } }>(
          `${this.baseURL}/api/generate-single-patch/${scanId}/${vulnId}`,
          {},
          {
            timeout: this.timeout.initiation,
            headers: this.getHeaders(),
          }
        );

        if (response.data.success && response.data.patch && response.data.patch.repaired) {
          return response.data.patch.repaired;
        }
        return undefined;
      })
    );
  }

  /**
   * Request batch Stage 1 patches for all vulnerabilities in a scan
   */
  async generateStage1Patches(scanId: string): Promise<{ success: boolean; patches: any[]; stats: any }> {
    return this.circuitBreaker.execute(() =>
      this.retryRequest(async () => {
        console.log(`[APIClient] Requesting batch Stage 1 patches for scan: ${scanId}`);
        const response = await axios.post<{ success: boolean; patches: any[]; stats: any }>(
          `${this.baseURL}/api/generate-stage1-patches/${scanId}`,
          {},
          {
            timeout: this.timeout.results,
            headers: this.getHeaders(),
          }
        );
        return response.data;
      })
    );
  }

  /**
   * Start a fuzzing campaign
   * @param request Fuzzing request with file and duration
   * @returns Fuzzing session information
   */
  async fuzz(request: FuzzRequest): Promise<FuzzResponse> {
    return this.circuitBreaker.execute(() =>
      this.retryRequest(async () => {
        const response = await axios.post<FuzzResponse>(`${this.baseURL}/api/fuzz`, request, {
          timeout: this.timeout.initiation,
          headers: this.getHeaders(),
        });
        return response.data;
      })
    );
  }

  /**
   * Test connection to backend service
   * @returns True if backend is reachable
   */
  async testConnection(): Promise<boolean> {
    try {
      await axios.get(`${this.baseURL}/api/health`, {
        timeout: 5000,
        headers: this.getHeaders(),
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Set authentication token
   * @param token Bearer token for API authentication
   */
  setAuthToken(token: string): void {
    this.authToken = token;
  }

  /**
   * Clear authentication token
   */
  clearAuthToken(): void {
    this.authToken = undefined;
  }

  /**
   * Update base URL from configuration
   */
  updateBaseURL(): void {
    this.baseURL = this.config.get('backendURL', 'http://localhost:5000');
  }

  /**
   * Retry a request with exponential backoff
   * @param fn Function to execute
   * @returns Result of the function
   */
  private async retryRequest<T>(fn: () => Promise<T>): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error as Error;

        // Don't retry on 4xx errors (client errors)
        if (axios.isAxiosError(error)) {
          const axiosError = error as AxiosError;
          if (
            axiosError.response &&
            axiosError.response.status >= 400 &&
            axiosError.response.status < 500
          ) {
            throw this.formatError(axiosError);
          }
        }

        // Don't retry on last attempt
        if (attempt === this.maxRetries) {
          break;
        }

        // Exponential backoff: 1s, 2s, 4s
        const delay = Math.pow(2, attempt) * 1000;
        await this.sleep(delay);
      }
    }

    throw this.formatError(lastError!);
  }

  /**
   * Get request headers
   * @returns Headers object
   */
  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': `AutoVulRepair-VSCode/${this.getExtensionVersion()}`,
    };

    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    return headers;
  }

  /**
   * Get extension version from package.json
   * @returns Extension version string
   */
  private getExtensionVersion(): string {
    // In production, this would read from package.json
    return '0.1.0';
  }

  /**
   * Format error for user-friendly display
   * @param error Error object
   * @returns Formatted error
   */
  private formatError(error: Error): Error {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError;

      if (axiosError.code === 'ECONNREFUSED') {
        return new Error(
          'Cannot connect to AutoVulRepair backend. Please ensure the service is running at ' +
            this.baseURL
        );
      }

      if (axiosError.code === 'ETIMEDOUT' || axiosError.code === 'ECONNABORTED') {
        return new Error('Request timed out. The backend service may be overloaded.');
      }

      if (axiosError.response) {
        const status = axiosError.response.status;
        const data = axiosError.response.data as any;

        if (status === 400) {
          return new Error(`Invalid request: ${data?.message || 'Bad request'}`);
        }

        if (status === 401) {
          return new Error('Authentication failed. Please check your API token.');
        }

        if (status === 404) {
          return new Error('API endpoint not found. Please check backend version.');
        }

        if (status === 500) {
          return new Error(`Backend error: ${data?.message || 'Internal server error'}`);
        }

        return new Error(`HTTP ${status}: ${data?.message || axiosError.message}`);
      }
    }

    return error;
  }

  /**
   * Sleep for specified milliseconds
   * @param ms Milliseconds to sleep
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Request advanced AI-assisted patching for remaining vulnerabilities
   */
  async runAIRepair(scanId: string, vulnIndex?: number): Promise<{ success: boolean; repair_results: any[] }> {
    return this.circuitBreaker.execute(() =>
      this.retryRequest(async () => {
        console.log(`[APIClient] Requesting AI-assisted repair for scan: ${scanId}, index: ${vulnIndex}`);
        const response = await axios.post<{ success: boolean; repair_results: any[] }>(
          `${this.baseURL}/api/repair/${scanId}`,
          { vuln_index: vulnIndex },
          {
            timeout: this.timeout.results * 2, // AI patching takes longer
            headers: this.getHeaders(),
          }
        );
        return response.data;
      })
    );
  }

  /**
   * Get circuit breaker state for monitoring
   */
  getCircuitBreakerState(): 'CLOSED' | 'OPEN' | 'HALF_OPEN' {
    return this.circuitBreaker.getState();
  }

  /**
   * Reset circuit breaker manually
   */
  resetCircuitBreaker(): void {
    this.circuitBreaker.reset();
  }
}
