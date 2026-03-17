import WebSocket from 'ws';
import { ProgressMessage } from './types';

/**
 * WebSocket Handler for real-time progress updates
 * Manages WebSocket connections with reconnection and fallback to polling
 */
export class WebSocketHandler {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 3;
  private fallbackToPolling = false;
  private isClosed = false;

  constructor(
    private sessionId: string,
    private baseURL: string,
    private onProgress: (message: ProgressMessage) => void,
    private onComplete: () => void,
    private onError: (error: Error) => void
  ) {}

  /**
   * Establish WebSocket connection
   */
  connect(): void {
    if (this.isClosed) {
      return;
    }

    try {
      // Convert HTTP URL to WebSocket URL
      const wsURL = this.baseURL.replace(/^http/, 'ws');
      const url = `${wsURL}/api/scan/${this.sessionId}/progress`;

      this.ws = new WebSocket(url);

      this.ws.on('open', () => {
        this.reconnectAttempts = 0;
      });

      this.ws.on('message', (data: WebSocket.Data) => {
        this.handleMessage(data);
      });

      this.ws.on('error', (error: Error) => {
        this.handleError(error);
      });

      this.ws.on('close', () => {
        this.handleClose();
      });
    } catch (error) {
      this.onError(error as Error);
      this.fallbackToPolling = true;
    }
  }

  /**
   * Handle incoming WebSocket message
   */
  private handleMessage(data: WebSocket.Data): void {
    try {
      const message: ProgressMessage = JSON.parse(data.toString());

      // Validate message structure
      if (typeof message.progress !== 'number' || typeof message.stage !== 'string') {
        throw new Error('Invalid progress message format');
      }

      this.onProgress(message);

      // Check if scan is complete
      if (message.progress >= 100) {
        this.onComplete();
        this.close();
      }
    } catch (error) {
      this.onError(new Error('Failed to parse progress message'));
    }
  }

  /**
   * Handle WebSocket error
   */
  private handleError(error: Error): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts && !this.isClosed) {
      this.reconnect();
    } else {
      this.fallbackToPolling = true;
      this.onError(error);
    }
  }

  /**
   * Handle WebSocket close
   */
  private handleClose(): void {
    if (
      !this.fallbackToPolling &&
      this.reconnectAttempts < this.maxReconnectAttempts &&
      !this.isClosed
    ) {
      this.reconnect();
    }
  }

  /**
   * Attempt to reconnect with exponential backoff
   */
  private reconnect(): void {
    this.reconnectAttempts++;
    const delay = Math.pow(2, this.reconnectAttempts - 1) * 1000; // 1s, 2s, 4s

    setTimeout(() => {
      if (!this.isClosed) {
        this.connect();
      }
    }, delay);
  }

  /**
   * Close WebSocket connection
   */
  close(): void {
    this.isClosed = true;

    if (this.ws) {
      this.ws.removeAllListeners();
      if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.close();
      }
      this.ws = null;
    }
  }

  /**
   * Check if should fallback to polling
   */
  shouldFallbackToPolling(): boolean {
    return this.fallbackToPolling;
  }

  /**
   * Get current connection state
   */
  getState(): 'CONNECTING' | 'OPEN' | 'CLOSING' | 'CLOSED' | 'NOT_CONNECTED' {
    if (!this.ws) {
      return 'NOT_CONNECTED';
    }

    switch (this.ws.readyState) {
      case WebSocket.CONNECTING:
        return 'CONNECTING';
      case WebSocket.OPEN:
        return 'OPEN';
      case WebSocket.CLOSING:
        return 'CLOSING';
      case WebSocket.CLOSED:
        return 'CLOSED';
      default:
        return 'NOT_CONNECTED';
    }
  }

  /**
   * Get number of reconnection attempts
   */
  getReconnectAttempts(): number {
    return this.reconnectAttempts;
  }
}
