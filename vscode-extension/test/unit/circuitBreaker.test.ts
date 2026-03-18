import { CircuitBreaker } from '../../src/circuitBreaker';

describe('CircuitBreaker', () => {
  let circuitBreaker: CircuitBreaker;

  beforeEach(() => {
    circuitBreaker = new CircuitBreaker(3, 1000); // 3 failures, 1 second timeout
  });

  describe('initial state', () => {
    it('should start in CLOSED state', () => {
      expect(circuitBreaker.getState()).toBe('CLOSED');
    });

    it('should have zero failure count', () => {
      expect(circuitBreaker.getFailureCount()).toBe(0);
    });
  });

  describe('successful execution', () => {
    it('should execute function and return result', async () => {
      const mockFn = jest.fn().mockResolvedValue('success');

      const result = await circuitBreaker.execute(mockFn);

      expect(result).toBe('success');
      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(circuitBreaker.getState()).toBe('CLOSED');
    });

    it('should keep failure count at zero', async () => {
      const mockFn = jest.fn().mockResolvedValue('success');

      await circuitBreaker.execute(mockFn);

      expect(circuitBreaker.getFailureCount()).toBe(0);
    });

    it('should reset failure count after success', async () => {
      const mockFn = jest.fn()
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValue('success');

      try {
        await circuitBreaker.execute(mockFn);
      } catch {
        // Expected failure
      }

      expect(circuitBreaker.getFailureCount()).toBe(1);

      await circuitBreaker.execute(mockFn);

      expect(circuitBreaker.getFailureCount()).toBe(0);
      expect(circuitBreaker.getState()).toBe('CLOSED');
    });
  });

  describe('failure handling', () => {
    it('should increment failure count on error', async () => {
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));

      try {
        await circuitBreaker.execute(mockFn);
      } catch {
        // Expected
      }

      expect(circuitBreaker.getFailureCount()).toBe(1);
      expect(circuitBreaker.getState()).toBe('CLOSED');
    });

    it('should stay CLOSED below threshold', async () => {
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));

      // Fail twice (below threshold of 3)
      for (let i = 0; i < 2; i++) {
        try {
          await circuitBreaker.execute(mockFn);
        } catch {
          // Expected
        }
      }

      expect(circuitBreaker.getFailureCount()).toBe(2);
      expect(circuitBreaker.getState()).toBe('CLOSED');
    });

    it('should open circuit after threshold failures', async () => {
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));

      // Fail 3 times (threshold)
      for (let i = 0; i < 3; i++) {
        try {
          await circuitBreaker.execute(mockFn);
        } catch {
          // Expected
        }
      }

      expect(circuitBreaker.getFailureCount()).toBe(3);
      expect(circuitBreaker.getState()).toBe('OPEN');
    });

    it('should propagate error to caller', async () => {
      const error = new Error('test error');
      const mockFn = jest.fn().mockRejectedValue(error);

      await expect(circuitBreaker.execute(mockFn)).rejects.toThrow('test error');
    });
  });

  describe('OPEN state behavior', () => {
    beforeEach(async () => {
      // Open the circuit by failing 3 times
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));
      for (let i = 0; i < 3; i++) {
        try {
          await circuitBreaker.execute(mockFn);
        } catch {
          // Expected
        }
      }
    });

    it('should block execution when OPEN', async () => {
      const mockFn = jest.fn().mockResolvedValue('success');

      await expect(circuitBreaker.execute(mockFn)).rejects.toThrow(
        'Circuit breaker is OPEN - too many failures'
      );

      expect(mockFn).not.toHaveBeenCalled();
    });

    it('should transition to HALF_OPEN after timeout', async () => {
      // Wait for timeout
      await new Promise((resolve) => setTimeout(resolve, 1100));

      const mockFn = jest.fn().mockResolvedValue('success');
      await circuitBreaker.execute(mockFn);

      expect(mockFn).toHaveBeenCalled();
      expect(circuitBreaker.getState()).toBe('CLOSED');
    });

    it('should not transition to HALF_OPEN before timeout', async () => {
      // Wait less than timeout
      await new Promise((resolve) => setTimeout(resolve, 500));

      const mockFn = jest.fn().mockResolvedValue('success');

      await expect(circuitBreaker.execute(mockFn)).rejects.toThrow(
        'Circuit breaker is OPEN'
      );

      expect(mockFn).not.toHaveBeenCalled();
    });
  });

  describe('HALF_OPEN state behavior', () => {
    beforeEach(async () => {
      // Open the circuit
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));
      for (let i = 0; i < 3; i++) {
        try {
          await circuitBreaker.execute(mockFn);
        } catch {
          // Expected
        }
      }
      // Wait for timeout to enter HALF_OPEN
      await new Promise((resolve) => setTimeout(resolve, 1100));
    });

    it('should close circuit on successful execution', async () => {
      const mockFn = jest.fn().mockResolvedValue('success');

      const result = await circuitBreaker.execute(mockFn);

      expect(result).toBe('success');
      expect(circuitBreaker.getState()).toBe('CLOSED');
      expect(circuitBreaker.getFailureCount()).toBe(0);
    });

    it('should reopen circuit on failed execution', async () => {
      const mockFn = jest.fn().mockRejectedValue(new Error('fail again'));

      try {
        await circuitBreaker.execute(mockFn);
      } catch {
        // Expected
      }

      expect(circuitBreaker.getState()).toBe('OPEN');
    });
  });

  describe('reset', () => {
    it('should reset failure count', async () => {
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));

      try {
        await circuitBreaker.execute(mockFn);
      } catch {
        // Expected
      }

      expect(circuitBreaker.getFailureCount()).toBe(1);

      circuitBreaker.reset();

      expect(circuitBreaker.getFailureCount()).toBe(0);
    });

    it('should reset state to CLOSED', async () => {
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));

      // Open the circuit
      for (let i = 0; i < 3; i++) {
        try {
          await circuitBreaker.execute(mockFn);
        } catch {
          // Expected
        }
      }

      expect(circuitBreaker.getState()).toBe('OPEN');

      circuitBreaker.reset();

      expect(circuitBreaker.getState()).toBe('CLOSED');
    });

    it('should allow execution after reset', async () => {
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));

      // Open the circuit
      for (let i = 0; i < 3; i++) {
        try {
          await circuitBreaker.execute(mockFn);
        } catch {
          // Expected
        }
      }

      circuitBreaker.reset();

      mockFn.mockResolvedValue('success');
      const result = await circuitBreaker.execute(mockFn);

      expect(result).toBe('success');
    });
  });

  describe('different thresholds', () => {
    it('should respect custom threshold', async () => {
      const cb = new CircuitBreaker(5, 1000); // 5 failures threshold
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));

      // Fail 4 times (below threshold)
      for (let i = 0; i < 4; i++) {
        try {
          await cb.execute(mockFn);
        } catch {
          // Expected
        }
      }

      expect(cb.getState()).toBe('CLOSED');

      // 5th failure should open circuit
      try {
        await cb.execute(mockFn);
      } catch {
        // Expected
      }

      expect(cb.getState()).toBe('OPEN');
    });
  });

  describe('different timeouts', () => {
    it('should respect custom timeout', async () => {
      const cb = new CircuitBreaker(2, 2000); // 2 second timeout
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));

      // Open the circuit
      for (let i = 0; i < 2; i++) {
        try {
          await cb.execute(mockFn);
        } catch {
          // Expected
        }
      }

      expect(cb.getState()).toBe('OPEN');

      // Wait 1 second (less than timeout)
      await new Promise((resolve) => setTimeout(resolve, 1000));

      await expect(cb.execute(mockFn)).rejects.toThrow('Circuit breaker is OPEN');

      // Wait another 1.1 seconds (total > timeout)
      await new Promise((resolve) => setTimeout(resolve, 1100));

      mockFn.mockResolvedValue('success');
      await cb.execute(mockFn);

      expect(cb.getState()).toBe('CLOSED');
    });
  });

  describe('concurrent executions', () => {
    it('should handle multiple concurrent successful executions', async () => {
      const mockFn = jest.fn().mockResolvedValue('success');

      const promises = Array(5)
        .fill(null)
        .map(() => circuitBreaker.execute(mockFn));

      const results = await Promise.all(promises);

      expect(results).toEqual(['success', 'success', 'success', 'success', 'success']);
      expect(circuitBreaker.getState()).toBe('CLOSED');
      expect(circuitBreaker.getFailureCount()).toBe(0);
    });

    it('should handle multiple concurrent failures', async () => {
      const mockFn = jest.fn().mockRejectedValue(new Error('fail'));

      const promises = Array(5)
        .fill(null)
        .map(() => circuitBreaker.execute(mockFn).catch(() => 'caught'));

      await Promise.all(promises);

      expect(circuitBreaker.getState()).toBe('OPEN');
      expect(circuitBreaker.getFailureCount()).toBeGreaterThanOrEqual(3);
    });
  });
});
