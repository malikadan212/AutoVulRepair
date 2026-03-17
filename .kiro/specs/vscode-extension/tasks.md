# Implementation Plan: VS Code AutoVulRepair Extension

## Overview

This implementation plan breaks down the VS Code AutoVulRepair Extension into discrete, actionable tasks. The extension integrates automated vulnerability detection and repair capabilities directly into the developer's IDE, communicating with an existing Flask backend service at localhost:5000.

The implementation follows a phased approach: project setup, core communication layer, business logic components, UI components, integration and testing. Each task builds incrementally on previous work, with checkpoints to ensure quality and completeness.

## Prerequisites

- **Backend Dependencies**: The Flask backend must implement the following before extension development:
  - REST API endpoints: POST /api/scan, GET /api/scan/{sessionId}/status, GET /api/scan/{sessionId}/results, DELETE /api/scan/{sessionId}, POST /api/fuzz
  - WebSocket endpoint: ws://localhost:5000/api/scan/{sessionId}/progress
  - Response formats matching the API contract in design document

## Tasks

- [ ] 1. Project setup and scaffolding
  - Initialize VS Code extension project with TypeScript
  - Configure package.json with extension metadata, activation events, and contribution points
  - Set up TypeScript compiler with strict mode enabled
  - Configure ESLint and Prettier for code quality
  - Install dependencies: vscode, axios, ws, glob, diff, fast-check, jest
  - Create directory structure: src/, test/unit/, test/property/, test/integration/
  - Set up VS Code extension development environment and launch configuration
  - _Requirements: 15.1, 15.2_


- [ ] 2. Implement core type definitions and interfaces
  - Create src/types.ts with all TypeScript interfaces from design document
  - Define VulnerabilityReport, ScanRequest, ScanResponse, ScanStatusResponse, ScanResultsResponse interfaces
  - Define ScanSession, ExtensionConfiguration, ProgressMessage, WebSocketMessage types
  - Define SeverityLevel, ScanStatus, ScanStage type unions
  - Export all types for use across the extension
  - _Requirements: 13.1-13.11_

- [ ] 3. Implement Configuration Manager
  - [ ] 3.1 Create src/configurationManager.ts with ConfigurationManager class
    - Implement get<T>(key: string, defaultValue: T): T method
    - Implement async set(key: string, value: any, global: boolean): Promise<void> method
    - Implement async getSecure(key: string): Promise<string | undefined> for token storage
    - Implement async setSecure(key: string, value: string): Promise<void> for token storage
    - Implement onDidChange(callback) method for reactive configuration updates
    - _Requirements: 8.1-8.13, 12.6_
  
  - [ ] 3.2 Implement configuration validation
    - Create validate() method that checks all configuration values
    - Validate backend URL format and protocol
    - Validate numeric ranges (scan delay 100-10000ms, file size 1-10240KB, concurrent scans 1-10)
    - Return validation errors with descriptive messages
    - _Requirements: 8.12_
  
  - [ ]* 3.3 Write unit tests for Configuration Manager
    - Test get/set for all configuration types (string, number, boolean, array)
    - Test secure storage for authentication tokens
    - Test validation logic for all constraints
    - Test onDidChange callback triggering
    - _Requirements: 8.11_
  
  - [ ]* 3.4 Write property test for Configuration Manager
    - **Property 3: Configuration Round-Trip**
    - **Validates: Requirements 8.11, 8.12**
    - Generate random configuration values and verify write/read preserves exact values

- [ ] 4. Implement Circuit Breaker
  - [ ] 4.1 Create src/circuitBreaker.ts with CircuitBreaker class
    - Implement state machine with CLOSED, OPEN, HALF_OPEN states
    - Implement execute<T>(fn: () => Promise<T>): Promise<T> method
    - Track failure count and last failure time
    - Implement threshold-based state transitions (5 failures → OPEN)
    - Implement timeout-based recovery (60 seconds → HALF_OPEN)
    - _Requirements: 11.10_
  
  - [ ]* 4.2 Write unit tests for Circuit Breaker
    - Test state transitions on consecutive failures
    - Test timeout-based recovery to HALF_OPEN
    - Test successful execution resets failure count
    - Test OPEN state blocks execution


- [ ] 5. Implement API Client
  - [ ] 5.1 Create src/apiClient.ts with APIClient class
    - Implement constructor that accepts ConfigurationManager
    - Initialize axios client with configurable base URL
    - Implement getHeaders() method with User-Agent and optional Authorization
    - Set up timeout configuration (30s for initiation, 300s for results)
    - Integrate CircuitBreaker for fault tolerance
    - _Requirements: 6.1, 6.5, 6.9_
  
  - [ ] 5.2 Implement scan endpoints
    - Implement async scan(request: ScanRequest): Promise<ScanResponse>
    - Implement async getScanStatus(sessionId: string): Promise<ScanStatusResponse>
    - Implement async getScanResults(sessionId: string): Promise<ScanResultsResponse>
    - Implement async cancelScan(sessionId: string): Promise<void>
    - All methods should use circuit breaker and retry logic
    - _Requirements: 6.2, 6.3, 6.4, 13.1-13.4, 13.8_
  
  - [ ] 5.3 Implement retry logic with exponential backoff
    - Create retryRequest<T>(fn: () => Promise<T>): Promise<T> method
    - Implement exponential backoff: 1s, 2s, 4s delays
    - Retry up to 3 times on timeout and 5xx errors
    - Do not retry on 4xx errors (validation failures)
    - _Requirements: 6.7, 6.8_
  
  - [ ] 5.4 Implement fuzzing endpoint
    - Implement async fuzz(request: FuzzRequest): Promise<FuzzResponse>
    - Send POST request to /api/fuzz with file content and duration
    - _Requirements: 9.2, 9.3, 13.5, 13.6_
  
  - [ ]* 5.5 Write unit tests for API Client
    - Test request header construction (User-Agent, Authorization)
    - Test timeout configuration
    - Test retry logic with mock failures
    - Test circuit breaker integration
    - Test all endpoint methods with mock responses
    - _Requirements: 6.6, 6.7_
  
  - [ ]* 5.6 Write property tests for API Client
    - **Property 4: API Response Round-Trip**
    - **Validates: Requirements 13.11**
    - Generate random API responses and verify JSON parse/serialize preserves structure
    - **Property 13: Scan Request Format Consistency**
    - **Validates: Requirements 6.2**
    - Verify all scan requests have correct structure with required fields
    - **Property 14: Authentication Token Inclusion**
    - **Validates: Requirements 6.5**
    - Verify Authorization header present when token configured, absent otherwise
    - **Property 15: Retry Exponential Backoff**
    - **Validates: Requirements 6.7**
    - Verify retry delays follow exponential pattern (1s, 2s, 4s)


- [ ] 6. Implement WebSocket Handler
  - [ ] 6.1 Create src/websocketHandler.ts with WebSocketHandler class
    - Implement constructor with sessionId, baseURL, and callback functions
    - Implement connect() method to establish WebSocket connection
    - Convert HTTP URL to WebSocket URL (http → ws, https → wss)
    - Set up event handlers: open, message, error, close
    - _Requirements: 7.1, 7.2_
  
  - [ ] 6.2 Implement progress message handling
    - Parse incoming WebSocket messages as ProgressMessage objects
    - Invoke onProgress callback with parsed message
    - Detect completion (progress >= 100) and invoke onComplete callback
    - Handle malformed messages gracefully with error callback
    - _Requirements: 7.3, 13.7_
  
  - [ ] 6.3 Implement reconnection and fallback logic
    - Attempt reconnection up to 3 times with increasing delays
    - Set fallbackToPolling flag after max reconnection attempts
    - Implement shouldFallbackToPolling() method
    - Implement close() method to cleanup WebSocket connection
    - _Requirements: 7.6_
  
  - [ ]* 6.4 Write unit tests for WebSocket Handler
    - Test connection establishment with mock WebSocket
    - Test progress message parsing and callback invocation
    - Test reconnection logic on connection failures
    - Test fallback flag after max reconnection attempts
    - Test cleanup on close
  
  - [ ]* 6.5 Write property test for WebSocket Handler
    - **Property 7: WebSocket Fallback Equivalence**
    - **Validates: Requirements 7.6**
    - Verify results obtained via WebSocket match results from polling
    - **Property 16: Progress Update Monotonicity**
    - **Validates: Requirements 7.3, 7.4**
    - Verify progress values are monotonically increasing and reach exactly 100

- [ ] 7. Checkpoint - Core communication layer complete
  - Ensure all tests pass for Configuration Manager, Circuit Breaker, API Client, and WebSocket Handler
  - Verify API Client can connect to mock backend
  - Verify WebSocket Handler can receive mock progress updates
  - Ask the user if questions arise


- [ ] 8. Implement Diagnostic Manager
  - [ ] 8.1 Create src/diagnosticManager.ts with DiagnosticManager class
    - Create diagnostic collection using vscode.languages.createDiagnosticCollection
    - Initialize vulnerability map to store VulnerabilityReport objects by file path
    - Implement constructor and dispose() method
    - _Requirements: 2.1_
  
  - [ ] 8.2 Implement diagnostic creation
    - Implement createDiagnostics(fileUri: Uri, vulnerabilities: VulnerabilityReport[]): void
    - Store vulnerabilities in internal map keyed by file path
    - Convert each VulnerabilityReport to VS Code Diagnostic object
    - Create Range from line/column (convert 1-indexed to 0-indexed)
    - Set diagnostic collection for the file URI
    - _Requirements: 2.1, 2.8_
  
  - [ ] 8.3 Implement severity mapping
    - Create mapSeverity(severity: SeverityLevel): vscode.DiagnosticSeverity method
    - Map Critical/High → Error, Medium → Warning, Low/Info → Information
    - Apply severity to each diagnostic object
    - _Requirements: 2.2, 2.4_
  
  - [ ] 8.4 Implement diagnostic message formatting
    - Create formatMessage(vuln: VulnerabilityReport): string method
    - Format: "[{severity}] {type}: {description}"
    - Append exploitability score if present: "(Exploitability: {score}/10)"
    - Set diagnostic source to "AutoVulRepair"
    - Set diagnostic code to vulnerability type
    - _Requirements: 2.3_
  
  - [ ] 8.5 Implement diagnostic retrieval and clearing
    - Implement getVulnerability(fileUri: Uri, line: number): VulnerabilityReport | undefined
    - Implement clearDiagnostics(fileUri?: Uri): void to clear specific file or all files
    - Implement getAllVulnerabilities(): Map<string, VulnerabilityReport[]>
    - _Requirements: 3.7_
  
  - [ ]* 8.6 Write unit tests for Diagnostic Manager
    - Test diagnostic creation with various vulnerability counts
    - Test severity mapping for all severity levels
    - Test message formatting with and without exploitability score
    - Test diagnostic retrieval by file and line
    - Test clearing diagnostics for specific file and all files
    - _Requirements: 2.1-2.8_
  
  - [ ]* 8.7 Write property tests for Diagnostic Manager
    - **Property 1: Diagnostic Creation Completeness**
    - **Validates: Requirements 1.5, 2.1, 2.8**
    - Verify diagnostic count equals vulnerability count and positions match exactly
    - **Property 2: Severity Mapping Correctness**
    - **Validates: Requirements 2.2, 2.4**
    - Verify all severity levels map correctly to VS Code diagnostic severity
    - **Property 21: Diagnostic Tooltip Completeness**
    - **Validates: Requirements 2.3**
    - Verify tooltip contains description, severity, and exploitability score


- [ ] 9. Implement Cache Manager
  - [ ] 9.1 Create src/cacheManager.ts with CacheManager class
    - Implement constructor that accepts ExtensionContext
    - Initialize in-memory cache as Map<string, CacheEntry>
    - Set maxEntries to 100 for LRU eviction
    - Load cached data from workspace state on initialization
    - _Requirements: 10.4_
  
  - [ ] 9.2 Implement cache operations
    - Implement set(filePath: string, vulnerabilities: VulnerabilityReport[]): void
    - Implement LRU eviction when cache size exceeds maxEntries
    - Store timestamp and file hash with each cache entry
    - Persist cache to workspace state after modifications
    - _Requirements: 10.4_
  
  - [ ] 9.3 Implement cache retrieval with validation
    - Implement get(filePath: string): VulnerabilityReport[] | null
    - Validate cached entry by comparing file hash
    - Return null and invalidate entry if file hash doesn't match
    - _Requirements: 10.5_
  
  - [ ] 9.4 Implement cache invalidation
    - Implement invalidate(filePath: string): void to remove specific entry
    - Implement clear(): void to remove all entries
    - Persist changes to workspace state
    - _Requirements: 10.5_
  
  - [ ]* 9.5 Write unit tests for Cache Manager
    - Test set/get operations
    - Test LRU eviction when exceeding maxEntries
    - Test cache invalidation on file hash mismatch
    - Test clear operation
    - Test persistence to workspace state
  
  - [ ]* 9.6 Write property test for Cache Manager
    - **Property 10: Cache Invalidation on Modification**
    - **Validates: Requirements 10.4, 10.5**
    - Verify file modification invalidates cache and subsequent scans fetch fresh results

- [ ] 10. Implement Patch Manager
  - [ ] 10.1 Create src/patchManager.ts with PatchManager class
    - Implement constructor that accepts DiagnosticManager
    - Initialize patch history array to track applied patches
    - _Requirements: 5.11_
  
  - [ ] 10.2 Implement patch preview
    - Implement async showPatchPreview(fileUri: Uri, vulnerability: VulnerabilityReport): Promise<void>
    - Check if vulnerability has patch, show error if not
    - Open document and get original content
    - Apply patch to content to generate patched version
    - Create temporary URI with patched content
    - Execute vscode.diff command to show side-by-side comparison
    - _Requirements: 5.2, 5.3_
  
  - [ ] 10.3 Implement patch application
    - Implement async applyPatch(fileUri: Uri, vulnerability: VulnerabilityReport): Promise<boolean>
    - Validate patch applicability by checking file hasn't changed since scan
    - Show warning and offer rescan if file modified
    - Create WorkspaceEdit with patch replacement
    - Apply edit using vscode.workspace.applyEdit
    - Clear diagnostic for patched vulnerability on success
    - Log patch application with timestamp
    - _Requirements: 5.4, 5.5, 5.6, 5.8, 5.9, 5.11_
  
  - [ ] 10.4 Implement patch validation and utilities
    - Implement validatePatchApplicability(document, vulnerability): boolean
    - Implement getPatchRange(document, vulnerability): Range to determine affected lines
    - Implement applyPatchToContent(content, vulnerability): string for preview
    - Implement logPatchApplication(fileUri, vulnerability, success): void
    - _Requirements: 5.8_
  
  - [ ]* 10.5 Write unit tests for Patch Manager
    - Test patch preview with valid and missing patches
    - Test patch application success flow
    - Test patch application rejection when file modified
    - Test diagnostic clearing after successful patch
    - Test patch history logging
    - _Requirements: 5.1-5.11_
  
  - [ ]* 10.6 Write property tests for Patch Manager
    - **Property 6: Patch Application Undo Round-Trip**
    - **Validates: Requirements 5.6, 5.10**
    - Verify undo restores exact original code and redo reapplies exact patch
    - **Property 23: Patch Applicability Validation**
    - **Validates: Requirements 5.8**
    - Verify patch validation rejects application when file modified since scan


- [ ] 11. Implement Background Scanner
  - [ ] 11.1 Create src/backgroundScanner.ts with BackgroundScanner class
    - Implement constructor accepting APIClient, DiagnosticManager, ConfigurationManager, CacheManager
    - Initialize scan queue as Map<string, NodeJS.Timeout> for debouncing
    - Initialize active scan sessions as Set<string> to track concurrent scans
    - Read maxConcurrentScans from configuration
    - _Requirements: 4.1, 10.6_
  
  - [ ] 11.2 Implement file save handler with debouncing
    - Implement onFileSave(document: TextDocument): void
    - Check if file should be scanned using shouldScan() method
    - Clear existing debounce timer for the file if present
    - Set new debounce timer with configured delay (default 2000ms)
    - Enqueue scan when timer expires
    - _Requirements: 4.2, 4.4, 4.5_
  
  - [ ] 11.3 Implement scan eligibility checks
    - Implement shouldScan(document: TextDocument): boolean
    - Check if background scanning is enabled in configuration
    - Check file extension is C/C++ (.c, .cpp, .cc, .cxx, .h, .hpp)
    - Check file size is under configured limit
    - Check file doesn't match exclusion glob patterns
    - _Requirements: 4.3, 4.6, 4.9_
  
  - [ ] 11.4 Implement scan queueing and execution
    - Implement enqueueScan(document: TextDocument): Promise<void>
    - Check if file is already being scanned
    - Check if concurrent scan limit reached, queue for later if so
    - Call performScan() when ready
    - _Requirements: 10.6, 10.7_
  
  - [ ] 11.5 Implement scan execution
    - Implement performScan(document: TextDocument): Promise<void>
    - Add file to active scan sessions
    - Send scan request to API client
    - Poll for results (WebSocket disabled for background scans)
    - Update diagnostics with results
    - Update cache with results
    - Handle errors silently (log but don't show notifications)
    - Remove file from active scan sessions in finally block
    - _Requirements: 4.2, 4.7, 4.8_
  
  - [ ] 11.6 Implement polling for background scans
    - Implement pollForResults(sessionId: string): Promise<ScanResultsResponse>
    - Poll status endpoint every 5 seconds
    - Maximum 60 attempts (5 minutes timeout)
    - Return results when status is 'completed'
    - Throw error if status is 'failed' or timeout reached
    - _Requirements: 7.6_
  
  - [ ]* 11.7 Write unit tests for Background Scanner
    - Test debouncing with multiple rapid saves
    - Test file eligibility checks (extension, size, exclusion patterns)
    - Test concurrent scan limit enforcement
    - Test scan queueing when limit reached
    - Test silent error handling
    - _Requirements: 4.1-4.9_
  
  - [ ]* 11.8 Write property tests for Background Scanner
    - **Property 11: Background Scan Debouncing**
    - **Validates: Requirements 4.5**
    - Verify multiple saves within delay period result in exactly one scan
    - **Property 18: File Size Exclusion**
    - **Validates: Requirements 4.9**
    - Verify files exceeding size limit are not scanned
    - **Property 19: Glob Pattern Exclusion**
    - **Validates: Requirements 4.6**
    - Verify files matching exclusion patterns are not scanned
    - **Property 20: Concurrent Scan Queueing**
    - **Validates: Requirements 10.6, 10.7**
    - Verify concurrent scan limit is maintained and excess requests are queued


- [ ] 12. Checkpoint - Business logic components complete
  - Ensure all tests pass for Diagnostic Manager, Cache Manager, Patch Manager, and Background Scanner
  - Verify diagnostic creation and clearing works correctly
  - Verify cache invalidation on file modification
  - Verify patch preview and application flow
  - Verify background scanning with debouncing
  - Ask the user if questions arise

- [ ] 13. Implement Sidebar Provider
  - [ ] 13.1 Create src/sidebarProvider.ts with VulnerabilitySidebarProvider class
    - Implement TreeDataProvider<VulnerabilityTreeItem> interface
    - Create EventEmitter for tree data changes
    - Initialize filter severity set with all severity levels
    - Initialize search query string
    - Accept DiagnosticManager in constructor
    - _Requirements: 3.1, 3.2_
  
  - [ ] 13.2 Implement tree structure methods
    - Implement getTreeItem(element: VulnerabilityTreeItem): TreeItem
    - Implement getChildren(element?: VulnerabilityTreeItem): Thenable<VulnerabilityTreeItem[]>
    - Return file nodes at root level
    - Return vulnerability nodes for file children
    - _Requirements: 3.2, 3.3_
  
  - [ ] 13.3 Implement file and vulnerability node creation
    - Implement getFileNodes(): VulnerabilityTreeItem[] to create file-level nodes
    - Group vulnerabilities by file path
    - Show vulnerability count badge for each file
    - Implement getVulnerabilityNodes(filePath: string): VulnerabilityTreeItem[] for vulnerability items
    - Format vulnerability label: "[{severity}] {type} (Line {line})"
    - _Requirements: 3.2, 3.6_
  
  - [ ] 13.4 Implement filtering and search
    - Implement filterVulnerabilities(vulnerabilities: VulnerabilityReport[]): VulnerabilityReport[]
    - Filter by active severity levels
    - Filter by search query (match type or description)
    - Implement setFilter(severity: string, enabled: boolean): void
    - Implement setSearchQuery(query: string): void
    - Call refresh() after filter changes
    - _Requirements: 3.4, 3.5_
  
  - [ ] 13.5 Create VulnerabilityTreeItem class
    - Extend vscode.TreeItem
    - Support 'file' and 'vulnerability' types
    - Set appropriate icons based on type and severity
    - Add command for navigation when clicking vulnerability items
    - Show count description for file items
    - _Requirements: 3.3, 3.6_
  
  - [ ]* 13.6 Write unit tests for Sidebar Provider
    - Test tree structure with mock vulnerabilities
    - Test file node creation and grouping
    - Test vulnerability node creation and formatting
    - Test severity filtering
    - Test search query filtering
    - Test refresh triggering
    - _Requirements: 3.1-3.10_
  
  - [ ]* 13.7 Write property test for Sidebar Provider
    - **Property 8: Sidebar Filter Correctness**
    - **Validates: Requirements 3.4, 3.5, 3.6**
    - Verify displayed vulnerabilities match all active filter criteria exactly


- [ ] 14. Implement Progress Tracker
  - [ ] 14.1 Create src/progressTracker.ts with ProgressTracker class
    - Create status bar item for background scan progress
    - Track active scan sessions with progress information
    - Implement showProgress(sessionId: string, message: string): void
    - Implement updateProgress(sessionId: string, progress: number, stage: string): void
    - Implement hideProgress(sessionId: string): void
    - _Requirements: 1.4, 4.7, 7.3_
  
  - [ ] 14.2 Implement modal progress for user-initiated scans
    - Use vscode.window.withProgress for modal progress indicator
    - Display current stage and percentage
    - Provide cancellation support
    - _Requirements: 7.4, 7.7, 7.8_
  
  - [ ]* 14.3 Write unit tests for Progress Tracker
    - Test status bar item creation and updates
    - Test progress message formatting
    - Test hiding progress on completion
    - Test cancellation handling

- [ ] 15. Implement Command Handlers
  - [ ] 15.1 Create src/commands.ts with command registration function
    - Implement registerCommands(context, apiClient, diagnosticManager, patchManager, config)
    - Register all extension commands with VS Code
    - _Requirements: 1.1, 1.2_
  
  - [ ] 15.2 Implement scan file command
    - Register autoVulRepair.scanFile command
    - Get active text editor and document
    - Validate file is C/C++ source
    - Show progress indicator
    - Establish WebSocket connection for progress updates
    - Send scan request via API client
    - Update progress as messages arrive
    - Retrieve and display results
    - Create diagnostics from results
    - Handle errors with user-friendly messages
    - _Requirements: 1.1, 1.3, 1.4, 1.5, 1.6, 7.1-7.5_
  
  - [ ] 15.3 Implement scan folder command
    - Register autoVulRepair.scanFolder command
    - Get selected folder from explorer context
    - Find all C/C++ files in folder recursively
    - Scan multiple files simultaneously
    - Aggregate results in sidebar panel
    - _Requirements: 1.2, 1.7, 1.8_
  
  - [ ] 15.4 Implement view patch command
    - Register autoVulRepair.viewPatch command
    - Get vulnerability from diagnostic position
    - Call PatchManager.showPatchPreview()
    - _Requirements: 2.7, 5.1, 5.2_
  
  - [ ] 15.5 Implement apply patch command
    - Register autoVulRepair.applyPatch command
    - Get vulnerability from diagnostic position
    - Call PatchManager.applyPatch()
    - Show success or error message
    - _Requirements: 5.4, 5.5_
  
  - [ ] 15.6 Implement utility commands
    - Register autoVulRepair.clearDiagnostics command to clear all diagnostics
    - Register autoVulRepair.rescanAll command to rescan all previously scanned files
    - Register autoVulRepair.testConnection command to verify backend availability
    - Register autoVulRepair.clearCache command to reset cache
    - Register autoVulRepair.showWelcome command to display welcome page
    - Register autoVulRepair.viewLogs command to open output channel
    - Register autoVulRepair.reportIssue command to open GitHub issues
    - _Requirements: 3.7, 3.8, 6.11, 11.7, 11.8, 15.3, 15.9_
  
  - [ ] 15.7 Implement cancel scan command
    - Register autoVulRepair.cancelScan command
    - Send DELETE request to backend
    - Close WebSocket connection
    - Remove progress indicator
    - _Requirements: 7.8, 7.9_
  
  - [ ] 15.8 Implement fuzzing commands
    - Register autoVulRepair.runFuzzingCampaign command
    - Prompt user for fuzzing duration
    - Send fuzzing request to backend
    - Display real-time fuzzing statistics
    - Show triage results in sidebar
    - Create diagnostics for crash locations
    - Register autoVulRepair.viewCrashInput command
    - Register autoVulRepair.generatePatchForCrash command
    - _Requirements: 9.1-9.10_
  
  - [ ] 15.9 Implement navigate to vulnerability command
    - Register autoVulRepair.navigateToVulnerability command
    - Open file at specified line
    - Scroll to and highlight the vulnerability location
    - _Requirements: 3.3_
  
  - [ ]* 15.10 Write unit tests for command handlers
    - Test each command with mock dependencies
    - Test error handling for each command
    - Test command availability based on context
    - _Requirements: 1.1-1.8, 5.1-5.11, 9.1-9.10_


- [ ] 16. Implement Code Actions Provider
  - [ ] 16.1 Create src/codeActionsProvider.ts with CodeActionsProvider class
    - Implement vscode.CodeActionProvider interface
    - Implement provideCodeActions(document, range, context): CodeAction[]
    - Check if range contains a diagnostic from AutoVulRepair
    - Get vulnerability from DiagnosticManager
    - _Requirements: 2.7, 5.1_
  
  - [ ] 16.2 Implement code actions for patches
    - Create "View Patch" code action if vulnerability has patch
    - Create "Apply Patch" code action if vulnerability has patch
    - Set code action kind to QuickFix
    - Link actions to appropriate commands
    - _Requirements: 2.7, 5.1_
  
  - [ ] 16.3 Implement code actions for fuzzing
    - Create "View Crash Input" code action for crash diagnostics
    - Create "Generate Patch for Crash" code action for crash diagnostics
    - _Requirements: 9.7, 9.8_
  
  - [ ]* 16.4 Write unit tests for Code Actions Provider
    - Test code action creation for vulnerabilities with patches
    - Test no code actions for vulnerabilities without patches
    - Test code actions for crash diagnostics
    - _Requirements: 2.7, 5.1_
  
  - [ ]* 16.5 Write property test for Code Actions Provider
    - **Property 5: Patch Code Action Availability**
    - **Validates: Requirements 2.7, 5.1**
    - Verify "View Patch" action present when patch exists, absent otherwise

- [ ] 17. Implement Extension Activation and Lifecycle
  - [ ] 17.1 Create src/extension.ts with activate() function
    - Initialize ConfigurationManager with extension context
    - Initialize APIClient with configuration
    - Initialize DiagnosticManager
    - Initialize PatchManager with DiagnosticManager
    - Initialize CacheManager with extension context
    - Initialize BackgroundScanner with dependencies
    - Initialize VulnerabilitySidebarProvider with DiagnosticManager
    - Initialize ProgressTracker
    - _Requirements: 15.1_
  
  - [ ] 17.2 Register all extension components
    - Register commands using registerCommands()
    - Register sidebar tree data provider
    - Register code actions provider
    - Register event listeners (onDidSaveTextDocument, onDidChangeTextDocument, onDidCloseTextDocument, onDidChangeConfiguration)
    - Add all disposables to extension context subscriptions
    - _Requirements: 4.1, 4.2_
  
  - [ ] 17.3 Implement deactivate() function
    - Close all WebSocket connections
    - Flush cache to workspace state
    - Dispose all diagnostics
    - Cleanup all resources
    - _Requirements: 10.9_
  
  - [ ] 17.4 Implement event listeners
    - onDidSaveTextDocument: Call BackgroundScanner.onFileSave()
    - onDidChangeTextDocument: Invalidate cache for modified file
    - onDidCloseTextDocument: Dispose WebSocket connections and cleanup
    - onDidChangeConfiguration: Update components with new configuration
    - _Requirements: 4.2, 8.11, 10.5, 10.9_
  
  - [ ]* 17.5 Write integration tests for extension lifecycle
    - Test extension activation
    - Test component initialization
    - Test event listener registration
    - Test extension deactivation and cleanup
    - _Requirements: 15.1_


- [ ] 18. Checkpoint - Core extension complete
  - Ensure all tests pass for UI components and extension lifecycle
  - Verify sidebar displays vulnerabilities correctly
  - Verify commands execute successfully
  - Verify code actions appear on diagnostics
  - Verify extension activates and deactivates cleanly
  - Ask the user if questions arise

- [ ] 19. Implement Configuration UI in package.json
  - [ ] 19.1 Add configuration contribution to package.json
    - Define autoVulRepair.backendURL setting (string, default: http://localhost:5000)
    - Define autoVulRepair.backgroundScanEnabled setting (boolean, default: false)
    - Define autoVulRepair.backgroundScanDelay setting (number, 100-10000, default: 2000)
    - Define autoVulRepair.maxFileSizeKB setting (number, 1-10240, default: 1024)
    - Define autoVulRepair.excludePatterns setting (array of strings, default: ['**/node_modules/**', '**/build/**'])
    - Define autoVulRepair.maxConcurrentScans setting (number, 1-10, default: 3)
    - Define autoVulRepair.enableWebSocketProgress setting (boolean, default: true)
    - Define autoVulRepair.autoApplyPatches setting (boolean, default: false)
    - Define autoVulRepair.defaultSeverityFilter setting (array, default: all severities)
    - Define autoVulRepair.enableTelemetry setting (boolean, default: false)
    - Define autoVulRepair.enableDebugLogging setting (boolean, default: false)
    - Define autoVulRepair.allowSelfSignedCerts setting (boolean, default: false)
    - Add descriptions and validation constraints for all settings
    - _Requirements: 8.1-8.10_
  
  - [ ] 19.2 Add commands contribution to package.json
    - Define all commands with titles and categories
    - Add keyboard shortcuts for primary commands
    - _Requirements: 14.1, 15.1_
  
  - [ ] 19.3 Add menus contribution to package.json
    - Add editor context menu items for C/C++ files
    - Add explorer context menu items for files and folders
    - Add command palette entries
    - Set appropriate when clauses for context-sensitive commands
    - _Requirements: 1.1, 1.2_
  
  - [ ] 19.4 Add views contribution to package.json
    - Define autoVulRepairSidebar view in activity bar
    - Set icon and title
    - _Requirements: 3.1_
  
  - [ ] 19.5 Add activation events to package.json
    - Activate on C/C++ file open (onLanguage:c, onLanguage:cpp)
    - Activate on workspace contains C/C++ files
    - Activate on command execution
    - _Requirements: 15.1_

- [ ] 20. Implement Security Features
  - [ ] 20.1 Implement secure token storage
    - Use VS Code SecretStorage API for authentication tokens
    - Never store tokens in plain text configuration
    - Implement token retrieval in APIClient
    - _Requirements: 12.6, 12.7_
  
  - [ ] 20.2 Implement SSL certificate validation
    - Validate SSL certificates by default
    - Reject self-signed certificates unless explicitly allowed
    - Show warning when self-signed certificates are enabled
    - _Requirements: 12.3, 12.4_
  
  - [ ] 20.3 Implement input validation
    - Validate file paths to prevent path traversal
    - Validate backend URL format and protocol
    - Validate API responses against expected schema
    - _Requirements: 12.1, 12.2_
  
  - [ ] 20.4 Implement privacy controls
    - Only send file contents to configured backend URL
    - Disable telemetry by default
    - Show warning when debug logging is enabled
    - Don't log file contents unless debug logging enabled
    - _Requirements: 12.5, 12.8, 12.9_
  
  - [ ]* 20.5 Write unit tests for security features
    - Test token storage and retrieval
    - Test SSL certificate validation
    - Test input validation (path traversal, URL validation)
    - Test privacy controls
    - _Requirements: 12.1-12.10_


- [ ] 21. Implement Error Handling and Recovery
  - [ ] 21.1 Implement error categorization and responses
    - Handle network errors (connection refused, timeout, DNS failure)
    - Handle backend errors (5xx responses) with retry
    - Handle validation errors (4xx responses) without retry
    - Handle authentication errors (401, 403)
    - Handle WebSocket errors with fallback to polling
    - Handle patch application errors
    - Handle internal errors with logging
    - _Requirements: 11.1-11.7_
  
  - [ ] 21.2 Implement user-friendly error messages
    - Display connection troubleshooting for network errors
    - Display backend error messages from response body
    - Display validation errors with configuration guidance
    - Provide "View Logs" button for internal errors
    - _Requirements: 1.6, 11.1-11.3, 11.9_
  
  - [ ] 21.3 Implement error recovery mechanisms
    - Graceful degradation (WebSocket → polling)
    - State cleanup on errors
    - User recovery options (clear cache, test connection, rescan)
    - _Requirements: 11.7, 11.8_
  
  - [ ]* 21.4 Write unit tests for error handling
    - Test each error category with appropriate responses
    - Test error message formatting
    - Test recovery mechanisms
    - Test circuit breaker activation
    - _Requirements: 11.1-11.10_
  
  - [ ]* 21.5 Write property test for error handling
    - **Property 17: Scan Cancellation Cleanup**
    - **Validates: Requirements 7.8**
    - Verify cancelled scans clean up all resources (WebSocket, progress, etc.)

- [ ] 22. Implement Performance Optimizations
  - [ ] 22.1 Implement background threading for API calls
    - Ensure all API calls execute asynchronously
    - Use Promise-based patterns for non-blocking operations
    - _Requirements: 10.1, 10.2_
  
  - [ ] 22.2 Implement incremental diagnostic rendering
    - Batch diagnostic creation in chunks of 50
    - Use setImmediate or requestIdleCallback for non-critical updates
    - _Requirements: 10.3_
  
  - [ ] 22.3 Implement resource cleanup
    - Dispose WebSocket connections when scans complete
    - Clear diagnostics for closed files
    - Implement LRU cache eviction
    - _Requirements: 10.9_
  
  - [ ]* 22.4 Write performance tests
    - Test diagnostic creation for 1000 vulnerabilities completes in <500ms
    - Test sidebar rendering with 1000 items completes in <500ms
    - Test extension activation completes in <2 seconds
    - Test memory usage stays under 200MB during normal operation
    - _Requirements: 10.1-10.3, Performance Requirements_
  
  - [ ]* 22.5 Write property tests for performance
    - **Property 24: UI Thread Non-Blocking**
    - **Validates: Requirements 10.2**
    - Verify no operation blocks UI thread for more than 50ms
    - **Property 25: Incremental Rendering for Large Reports**
    - **Validates: Requirements 10.3**
    - Verify reports with >100 vulnerabilities render incrementally


- [ ] 23. Implement Accessibility Features
  - [ ] 23.1 Add keyboard shortcuts
    - Define keyboard shortcuts for scan, view patch, apply patch, clear diagnostics
    - Ensure all commands are accessible via keyboard
    - _Requirements: 14.1_
  
  - [ ] 23.2 Add ARIA labels and screen reader support
    - Add ARIA labels to all sidebar UI elements
    - Implement screen reader announcements for scan completion
    - Implement screen reader announcements for vulnerability detection
    - _Requirements: 14.2, 14.3_
  
  - [ ] 23.3 Ensure keyboard navigation
    - Verify diff view is keyboard-navigable
    - Verify sidebar is keyboard-navigable
    - Ensure all interactive elements have visible focus indicators
    - _Requirements: 14.4, 14.7_
  
  - [ ] 23.4 Implement theme support
    - Use VS Code theme colors for all UI elements
    - Provide high-contrast icons for activity bar and context menu
    - Support VS Code zoom functionality
    - _Requirements: 14.5, 14.6, 14.9_
  
  - [ ] 23.5 Add tooltips
    - Add tooltips for all buttons and icons in sidebar
    - _Requirements: 14.8_
  
  - [ ]* 23.6 Test accessibility features
    - Test keyboard navigation through all UI components
    - Test screen reader announcements
    - Test high-contrast theme support
    - _Requirements: 14.1-14.10_

- [ ] 24. Implement State Persistence
  - [ ] 24.1 Implement diagnostic persistence
    - Store diagnostics in workspace state
    - Restore diagnostics on file reopen
    - _Requirements: 2.5, 2.6_
  
  - [ ] 24.2 Implement sidebar state persistence
    - Store active filters in workspace state
    - Store expanded items in workspace state
    - Store search query in workspace state
    - Restore sidebar state on VS Code restart
    - _Requirements: 3.10_
  
  - [ ]* 24.3 Write property tests for state persistence
    - **Property 12: Diagnostic Persistence**
    - **Validates: Requirements 2.5**
    - Verify diagnostics restored after file close/reopen
    - **Property 22: Sidebar State Persistence**
    - **Validates: Requirements 3.10**
    - Verify sidebar state (filters, expanded items, search) restored after VS Code restart

- [ ] 25. Checkpoint - Integration and testing complete
  - Ensure all unit tests pass with >80% code coverage
  - Ensure all 25 property-based tests pass with 100 iterations each
  - Verify extension works with mock backend
  - Verify all error scenarios handled gracefully
  - Verify performance benchmarks met
  - Verify accessibility features work correctly
  - Ask the user if questions arise


- [ ] 26. Integration Testing with Real Backend
  - [ ] 26.1 Set up integration test environment
    - Create test fixtures with sample C/C++ files containing known vulnerabilities
    - Document backend setup requirements
    - _Requirements: 15.5_
  
  - [ ] 26.2 Write integration tests for scan workflow
    - Test full scan workflow: initiate scan → receive progress → get results → display diagnostics
    - Test WebSocket progress updates
    - Test fallback to polling when WebSocket fails
    - Test scan cancellation
    - _Requirements: 1.1-1.8, 7.1-7.9_
  
  - [ ] 26.3 Write integration tests for patch workflow
    - Test patch preview generation
    - Test patch application
    - Test patch validation and rejection
    - _Requirements: 5.1-5.11_
  
  - [ ] 26.4 Write integration tests for fuzzing workflow
    - Test fuzzing campaign initiation
    - Test crash triage result display
    - Test crash input viewing
    - _Requirements: 9.1-9.10_
  
  - [ ] 26.5 Write integration tests for concurrent operations
    - Test multiple simultaneous scans
    - Test scan queueing when limit reached
    - Test background scanning during user-initiated scans
    - _Requirements: 10.6, 10.7_
  
  - [ ]* 26.6 Write property test for concurrent operations
    - **Property 9: Concurrent Scan Isolation**
    - **Validates: Requirements 1.7, 1.8, 10.6**
    - Verify concurrent scans on different files don't cross-contaminate results

- [ ] 27. Create Documentation
  - [ ] 27.1 Write README.md
    - Add installation instructions
    - Add prerequisites (VS Code version, backend service)
    - Add quick start guide with screenshots
    - Add feature overview with animated GIFs
    - Add configuration reference
    - Add troubleshooting guide
    - Add links to backend documentation
    - _Requirements: 15.1, 15.6, 15.7, 15.8_
  
  - [ ] 27.2 Write CHANGELOG.md
    - Document initial release version
    - Document all features included
    - _Requirements: 15.2_
  
  - [ ] 27.3 Write API.md
    - Document backend API contract
    - Document all endpoints with request/response formats
    - Document WebSocket message formats
    - Document error codes and responses
    - _Requirements: 15.10, 13.1-13.11_
  
  - [ ] 27.4 Create welcome page
    - Create HTML/Markdown welcome page with usage examples
    - Add tips and best practices
    - Add links to documentation
    - _Requirements: 15.3_
  
  - [ ] 27.5 Add inline documentation
    - Add JSDoc comments to all public methods
    - Add inline documentation for configuration options
    - _Requirements: 15.4_
  
  - [ ] 27.6 Create sample files
    - Create sample C/C++ files with known vulnerabilities for testing
    - Include in extension package or provide download link
    - _Requirements: 15.5_


- [ ] 28. Implement Logging and Telemetry
  - [ ] 28.1 Create output channel for logging
    - Create VS Code output channel named "AutoVulRepair"
    - Implement logging utility with levels (debug, info, warn, error)
    - Log API requests and responses when debug logging enabled
    - Log performance metrics (scan duration, API latency, memory usage)
    - _Requirements: 10.10, 11.8_
  
  - [ ] 28.2 Implement privacy-respecting telemetry
    - Implement telemetry collection (disabled by default)
    - Collect anonymous usage statistics (command usage, error rates)
    - Never collect file contents or vulnerability details
    - Respect user's telemetry preference
    - _Requirements: 12.9_
  
  - [ ] 28.3 Implement debug logging controls
    - Show warning when debug logging is enabled
    - Document that sensitive data may be logged
    - Provide easy way to disable debug logging
    - _Requirements: 12.5, 12.8_

- [ ] 29. Implement Welcome and Onboarding
  - [ ] 29.1 Create getting started walkthrough
    - Implement VS Code walkthrough contribution
    - Add steps for backend setup verification
    - Add steps for first scan
    - Add steps for patch application
    - Make walkthrough accessible from command palette
    - _Requirements: 14.10, 15.3_
  
  - [ ] 29.2 Implement first-run experience
    - Detect first activation of extension
    - Show welcome page on first run
    - Offer to run connection test
    - Provide link to documentation
    - _Requirements: 15.3_
  
  - [ ] 29.3 Implement report issue command
    - Create command to open GitHub issues
    - Pre-fill issue template with environment information (VS Code version, extension version, OS)
    - Include link to logs
    - _Requirements: 15.9_

- [ ] 30. Final Testing and Quality Assurance
  - [ ] 30.1 Run full test suite
    - Run all unit tests and verify >80% code coverage
    - Run all 25 property-based tests with 100 iterations each
    - Run all integration tests with real backend
    - Run performance tests and verify benchmarks met
    - _Requirements: All_
  
  - [ ] 30.2 Manual testing checklist
    - Test on Windows, macOS, and Linux
    - Test with VS Code Remote Development
    - Test with other C/C++ extensions installed
    - Test all commands from command palette
    - Test all context menu items
    - Test keyboard shortcuts
    - Test with various backend configurations (localhost, remote, HTTPS)
    - Test error scenarios (backend down, network issues, invalid responses)
    - _Requirements: Compatibility Requirements_
  
  - [ ] 30.3 Code quality checks
    - Run ESLint and fix all warnings
    - Run Prettier and format all code
    - Review all TODO comments and address or document
    - Check for console.log statements and replace with proper logging
    - _Requirements: Maintainability Requirements_
  
  - [ ] 30.4 Security review
    - Review all data transmission points
    - Verify no sensitive data logged without debug mode
    - Verify authentication tokens stored securely
    - Verify input validation on all user inputs
    - Verify SSL certificate validation
    - _Requirements: 12.1-12.10_
  
  - [ ] 30.5 Performance profiling
    - Profile extension activation time
    - Profile diagnostic creation with large reports
    - Profile sidebar rendering with many items
    - Profile memory usage during extended use
    - Optimize any bottlenecks found
    - _Requirements: Performance Requirements_


- [ ] 31. Package and Publish Extension
  - [ ] 31.1 Prepare extension package
    - Update package.json with final version number (1.0.0)
    - Add publisher information
    - Add repository, bugs, and homepage URLs
    - Add keywords for marketplace discoverability
    - Add icon and banner for marketplace listing
    - Review and update license
    - _Requirements: 15.1_
  
  - [ ] 31.2 Create marketplace assets
    - Create extension icon (128x128 PNG)
    - Create banner image for marketplace
    - Take screenshots of key features
    - Create animated GIFs demonstrating workflows
    - _Requirements: 15.8_
  
  - [ ] 31.3 Package extension
    - Run `vsce package` to create .vsix file
    - Test installation from .vsix file
    - Verify all files included in package
    - Verify package size is reasonable
    - _Requirements: 15.1_
  
  - [ ] 31.4 Publish to VS Code Marketplace
    - Create publisher account if needed
    - Run `vsce publish` to publish extension
    - Verify extension appears in marketplace
    - Test installation from marketplace
    - _Requirements: 15.1_
  
  - [ ] 31.5 Create GitHub release
    - Tag release in Git (v1.0.0)
    - Create GitHub release with changelog
    - Attach .vsix file to release
    - Update README with installation instructions

- [ ] 32. Post-Launch Tasks
  - [ ] 32.1 Monitor initial feedback
    - Monitor marketplace reviews and ratings
    - Monitor GitHub issues
    - Respond to user questions and bug reports
  
  - [ ] 32.2 Create user documentation site
    - Set up documentation website (GitHub Pages or similar)
    - Add detailed user guides
    - Add video tutorials
    - Add FAQ section
  
  - [ ] 32.3 Plan future enhancements
    - Collect feature requests from users
    - Prioritize enhancements based on feedback
    - Create roadmap for future versions

## Notes

- Tasks marked with `*` are optional testing tasks and can be skipped for faster MVP delivery
- Each task references specific requirements for traceability
- Property-based tests validate universal correctness properties across all inputs
- Unit tests validate specific examples and edge cases
- Integration tests validate end-to-end workflows with real backend
- Checkpoints ensure incremental validation and quality gates
- Backend API endpoints and WebSocket support must be implemented before extension development begins
- Extension requires VS Code 1.75.0 or later
- Extension requires Node.js 18+ for development
- All code should follow TypeScript strict mode and ESLint/Prettier rules

## Implementation Strategy

The tasks are organized into logical phases:

1. **Phase 1 (Tasks 1-7)**: Project setup and core communication layer
2. **Phase 2 (Tasks 8-12)**: Business logic components
3. **Phase 3 (Tasks 13-18)**: UI components and extension lifecycle
4. **Phase 4 (Tasks 19-25)**: Configuration, security, error handling, performance, accessibility, and state persistence
5. **Phase 5 (Tasks 26-30)**: Integration testing, documentation, and quality assurance
6. **Phase 6 (Tasks 31-32)**: Packaging, publishing, and post-launch

Each phase builds on the previous phase, with checkpoints to ensure quality and completeness before proceeding.

## Estimated Timeline

- Phase 1: 2-3 weeks
- Phase 2: 2-3 weeks
- Phase 3: 2-3 weeks
- Phase 4: 2-3 weeks
- Phase 5: 1-2 weeks
- Phase 6: 1 week

Total estimated time: 10-15 weeks for complete implementation with comprehensive testing and documentation.

For MVP (skipping optional testing tasks): 6-8 weeks.
