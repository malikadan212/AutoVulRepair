// Core type definitions for AutoVulRepair VS Code Extension

export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanStage = 'Static Analysis' | 'Fuzzing' | 'Crash Triage' | 'Patch Generation';

export interface VulnerabilityReport {
  file: string;
  line: number;
  column: number;
  severity: SeverityLevel;
  type: string;
  description: string;
  exploitabilityScore?: number;
  patch?: string;
}

export interface ScanRequest {
  code_snippet: string;
  analysis_tool: 'cppcheck' | 'codeql';
}

export interface ScanResponse {
  scanId: string;
  status: string;
  message: string;
}

export interface ScanStatusResponse {
  status: ScanStatus;
  progress: number;
  stage: ScanStage;
}

export interface ScanResultsResponse {
  scanId?: string;
  status?: string;
  progress?: number;
  stage?: string;
  vulnerabilities: VulnerabilityReport[];
  summary?: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface FuzzRequest {
  file: {
    path: string;
    content: string;
  };
  duration: number;
}

export interface FuzzResponse {
  sessionId: string;
  status: ScanStatus;
}

export interface ProgressMessage {
  progress: number;
  stage: ScanStage;
  details: string;
}

export interface ExtensionConfiguration {
  backendURL: string;
  backgroundScanEnabled: boolean;
  backgroundScanDelay: number;
  excludePatterns: string[];
  maxFileSizeKB: number;
  maxConcurrentScans: number;
  defaultSeverityFilter: string;
  enableWebSocketProgress: boolean;
  allowSelfSignedCertificates: boolean;
}

export interface ScanSession {
  sessionId: string;
  fileUri: string;
  startTime: Date;
  status: ScanStatus;
}

export interface PatchApplication {
  fileUri: string;
  vulnerability: VulnerabilityReport;
  timestamp: Date;
  success: boolean;
}

export interface CacheEntry {
  vulnerabilities: VulnerabilityReport[];
  timestamp: number;
  fileHash: string;
}
