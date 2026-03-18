import * as vscode from 'vscode';
import { ProgressTracker } from '../../src/progressTracker';

describe('ProgressTracker', () => {
  let tracker: ProgressTracker;
  let mockStatusBarItem: any;

  beforeEach(() => {
    mockStatusBarItem = {
      text: '',
      show: jest.fn(),
      hide: jest.fn(),
      dispose: jest.fn(),
    };

    (vscode.window.createStatusBarItem as jest.Mock).mockReturnValue(mockStatusBarItem);

    tracker = new ProgressTracker();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('showProgress', () => {
    it('should show progress in status bar', () => {
      tracker.showProgress('session-1', 'Scanning...');

      expect(mockStatusBarItem.show).toHaveBeenCalled();
      expect(mockStatusBarItem.text).toContain('AutoVulRepair');
    });
  });

  describe('updateProgress', () => {
    it('should update progress message', () => {
      tracker.showProgress('session-1', 'Scanning...');
      tracker.updateProgress('session-1', 50, 'Static Analysis');

      expect(mockStatusBarItem.text).toContain('Static Analysis');
      expect(mockStatusBarItem.text).toContain('50%');
    });
  });

  describe('hideProgress', () => {
    it('should hide status bar when no active progress', () => {
      tracker.showProgress('session-1', 'Scanning...');
      tracker.hideProgress('session-1');

      expect(mockStatusBarItem.hide).toHaveBeenCalled();
    });
  });

  describe('getActiveCount', () => {
    it('should return number of active progress items', () => {
      expect(tracker.getActiveCount()).toBe(0);

      tracker.showProgress('session-1', 'Scanning...');
      expect(tracker.getActiveCount()).toBe(1);

      tracker.showProgress('session-2', 'Scanning...');
      expect(tracker.getActiveCount()).toBe(2);

      tracker.hideProgress('session-1');
      expect(tracker.getActiveCount()).toBe(1);
    });
  });

  describe('dispose', () => {
    it('should dispose status bar item', () => {
      tracker.dispose();
      expect(mockStatusBarItem.dispose).toHaveBeenCalled();
    });

    it('should clear active progress', () => {
      tracker.showProgress('session-1', 'Scanning...');
      tracker.dispose();
      expect(tracker.getActiveCount()).toBe(0);
    });
  });
});
