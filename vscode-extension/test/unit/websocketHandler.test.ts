import WebSocket from 'ws';
import { WebSocketHandler } from '../../src/websocketHandler';
import { ProgressMessage } from '../../src/types';

// Mock WebSocket
jest.mock('ws');

describe('WebSocketHandler', () => {
  let handler: WebSocketHandler;
  let mockOnProgress: jest.Mock;
  let mockOnComplete: jest.Mock;
  let mockOnError: jest.Mock;
  let mockWs: any;

  beforeEach(() => {
    mockOnProgress = jest.fn();
    mockOnComplete = jest.fn();
    mockOnError = jest.fn();

    // Create mock WebSocket instance
    mockWs = {
      on: jest.fn(),
      close: jest.fn(),
      removeAllListeners: jest.fn(),
      readyState: WebSocket.OPEN,
    };

    (WebSocket as unknown as jest.Mock).mockImplementation(() => mockWs);

    handler = new WebSocketHandler(
      'test-session-123',
      'http://localhost:5000',
      mockOnProgress,
      mockOnComplete,
      mockOnError
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('connect', () => {
    it('should create WebSocket connection with correct URL', () => {
      handler.connect();

      expect(WebSocket).toHaveBeenCalledWith(
        'ws://localhost:5000/api/scan/test-session-123/progress'
      );
    });

    it('should convert https to wss', () => {
      const httpsHandler = new WebSocketHandler(
        'test-session',
        'https://example.com',
        mockOnProgress,
        mockOnComplete,
        mockOnError
      );

      httpsHandler.connect();

      expect(WebSocket).toHaveBeenCalledWith(
        'wss://example.com/api/scan/test-session/progress'
      );
    });

    it('should register event listeners', () => {
      handler.connect();

      expect(mockWs.on).toHaveBeenCalledWith('open', expect.any(Function));
      expect(mockWs.on).toHaveBeenCalledWith('message', expect.any(Function));
      expect(mockWs.on).toHaveBeenCalledWith('error', expect.any(Function));
      expect(mockWs.on).toHaveBeenCalledWith('close', expect.any(Function));
    });
  });

  describe('message handling', () => {
    let messageHandler: (data: any) => void;

    beforeEach(() => {
      handler.connect();
      messageHandler = mockWs.on.mock.calls.find(
        (call: any) => call[0] === 'message'
      )[1];
    });

    it('should parse and forward progress messages', () => {
      const message: ProgressMessage = {
        progress: 50,
        stage: 'Static Analysis',
        details: 'Analyzing file.c',
      };

      messageHandler(JSON.stringify(message));

      expect(mockOnProgress).toHaveBeenCalledWith(message);
    });

    it('should call onComplete when progress reaches 100', () => {
      const message: ProgressMessage = {
        progress: 100,
        stage: 'Patch Generation',
        details: 'Complete',
      };

      messageHandler(JSON.stringify(message));

      expect(mockOnProgress).toHaveBeenCalledWith(message);
      expect(mockOnComplete).toHaveBeenCalled();
    });

    it('should handle malformed JSON', () => {
      messageHandler('invalid json');

      expect(mockOnError).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Failed to parse progress message',
        })
      );
    });

    it('should validate message structure', () => {
      const invalidMessage = {
        progress: 'not a number',
        stage: 'Static Analysis',
      };

      messageHandler(JSON.stringify(invalidMessage));

      expect(mockOnError).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Failed to parse progress message',
        })
      );
    });
  });

  describe('error handling', () => {
    let errorHandler: (error: Error) => void;

    beforeEach(() => {
      handler.connect();
      errorHandler = mockWs.on.mock.calls.find(
        (call: any) => call[0] === 'error'
      )[1];
    });

    it('should attempt reconnection on error', () => {
      jest.useFakeTimers();

      errorHandler(new Error('Connection failed'));

      // Should not call onError immediately (will retry)
      expect(mockOnError).not.toHaveBeenCalled();

      // Fast-forward time for reconnection
      jest.advanceTimersByTime(1000);

      // Should attempt to reconnect
      expect(WebSocket).toHaveBeenCalledTimes(2);

      jest.useRealTimers();
    });

    it('should fallback to polling after max reconnection attempts', () => {
      jest.useFakeTimers();

      // Trigger 4 errors (exceeds max of 3 attempts)
      for (let i = 0; i < 4; i++) {
        errorHandler(new Error('Connection failed'));
        jest.advanceTimersByTime(5000);
      }

      expect(handler.shouldFallbackToPolling()).toBe(true);
      expect(mockOnError).toHaveBeenCalled();

      jest.useRealTimers();
    });
  });

  describe('close handling', () => {
    let closeHandler: () => void;

    beforeEach(() => {
      handler.connect();
      closeHandler = mockWs.on.mock.calls.find(
        (call: any) => call[0] === 'close'
      )[1];
    });

    it('should attempt reconnection on unexpected close', () => {
      jest.useFakeTimers();

      closeHandler();

      jest.advanceTimersByTime(1000);

      expect(WebSocket).toHaveBeenCalledTimes(2);

      jest.useRealTimers();
    });

    it('should not reconnect if already closed manually', () => {
      jest.useFakeTimers();

      handler.close();
      closeHandler();

      jest.advanceTimersByTime(5000);

      // Should only be called once (initial connection)
      expect(WebSocket).toHaveBeenCalledTimes(1);

      jest.useRealTimers();
    });
  });

  describe('reconnection', () => {
    it('should use exponential backoff for reconnection', () => {
      jest.useFakeTimers();

      handler.connect();
      const errorHandler = mockWs.on.mock.calls.find(
        (call: any) => call[0] === 'error'
      )[1];

      // First reconnection: 1 second
      errorHandler(new Error('fail'));
      jest.advanceTimersByTime(999);
      expect(WebSocket).toHaveBeenCalledTimes(1);
      jest.advanceTimersByTime(1);
      expect(WebSocket).toHaveBeenCalledTimes(2);

      // Second reconnection: 2 seconds
      errorHandler(new Error('fail'));
      jest.advanceTimersByTime(1999);
      expect(WebSocket).toHaveBeenCalledTimes(2);
      jest.advanceTimersByTime(1);
      expect(WebSocket).toHaveBeenCalledTimes(3);

      jest.useRealTimers();
    });

    it('should reset reconnection attempts on successful connection', () => {
      jest.useFakeTimers();

      handler.connect();
      const errorHandler = mockWs.on.mock.calls.find(
        (call: any) => call[0] === 'error'
      )[1];
      const openHandler = mockWs.on.mock.calls.find(
        (call: any) => call[0] === 'open'
      )[1];

      // Fail once
      errorHandler(new Error('fail'));
      jest.advanceTimersByTime(1000);

      // Succeed
      openHandler();

      expect(handler.getReconnectAttempts()).toBe(0);

      jest.useRealTimers();
    });
  });

  describe('close', () => {
    it('should close WebSocket connection', () => {
      handler.connect();
      handler.close();

      expect(mockWs.removeAllListeners).toHaveBeenCalled();
      expect(mockWs.close).toHaveBeenCalled();
    });

    it('should not close if WebSocket is not open', () => {
      mockWs.readyState = WebSocket.CLOSED;
      handler.connect();
      handler.close();

      expect(mockWs.close).not.toHaveBeenCalled();
    });

    it('should prevent reconnection after close', () => {
      jest.useFakeTimers();

      handler.connect();
      handler.close();

      const errorHandler = mockWs.on.mock.calls.find(
        (call: any) => call[0] === 'error'
      )[1];
      errorHandler(new Error('fail'));

      jest.advanceTimersByTime(5000);

      // Should not attempt reconnection
      expect(WebSocket).toHaveBeenCalledTimes(1);

      jest.useRealTimers();
    });
  });

  describe('state management', () => {
    it('should return correct connection state', () => {
      handler.connect();

      mockWs.readyState = WebSocket.CONNECTING;
      expect(handler.getState()).toBe('CONNECTING');

      mockWs.readyState = WebSocket.OPEN;
      expect(handler.getState()).toBe('OPEN');

      mockWs.readyState = WebSocket.CLOSING;
      expect(handler.getState()).toBe('CLOSING');

      mockWs.readyState = WebSocket.CLOSED;
      expect(handler.getState()).toBe('CLOSED');
    });

    it('should return NOT_CONNECTED when no WebSocket', () => {
      expect(handler.getState()).toBe('NOT_CONNECTED');
    });
  });

  describe('fallback to polling', () => {
    it('should indicate fallback after max reconnection attempts', () => {
      jest.useFakeTimers();

      handler.connect();
      const errorHandler = mockWs.on.mock.calls.find(
        (call: any) => call[0] === 'error'
      )[1];

      expect(handler.shouldFallbackToPolling()).toBe(false);

      // Trigger 4 errors (exceeds max of 3 attempts)
      for (let i = 0; i < 4; i++) {
        errorHandler(new Error('fail'));
        jest.advanceTimersByTime(5000);
      }

      expect(handler.shouldFallbackToPolling()).toBe(true);

      jest.useRealTimers();
    });
  });
});
