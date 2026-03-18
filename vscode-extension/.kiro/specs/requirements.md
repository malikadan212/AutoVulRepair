# Requirements Document

## Introduction

This document specifies the requirements for a VS Code extension that integrates AutoVulRepair directly into the developer's IDE. AutoVulRepair is an automated vulnerability detection and repair system for C/C++ code that performs static analysis, generates fuzz tests, triages crashes, and uses local LLM to generate patches. The extension will provide real-time vulnerability detection, inline diagnostics, and one-click patch application without leaving the editor.

## Glossary

- **Extension**: The VS Code extension component running in the IDE
- **Backend_Service**: The existing Flask web application running on localhost:5000
- **Vulnerability_Report**: A structured data object containing vulnerability details (type, severity, location, description)
- **Diagnostic**: A VS Code diagnostic object that displays inline warnings/errors with squiggly lines
- **Patch**: A code modification that fixes a detected vulnerability
- **Scan_Session**: A single execution of vulnerability analysis on one or more files
- **WebSocket_Channel**: A bidirectional communication channel for real-time updates
- **Diff_View**: A side-by-side comparison showing original and patched code
- **Severity_Level**: Classification of vulnerability impact (Critical, High, Medium, Low, Info)
- **Exploitability_Score**: Numeric assessment of how easily a vulnerability can be exploited
- **Fuzzing_Campaign**: An automated testing session using LibFuzzer to discover crashes
- **Triage_Result**: Analysis output categorizing crash severity and exploitability
- **Configuration_Panel**: VS Code settings UI for extension preferences
- **Context_Menu**: Right-click menu in the editor or file explorer
- **Sidebar_Panel**: A dedicated VS Code panel showing vulnerability list
- **Background_Scanner**: Automated scanning triggered by file save events
- **API_Client**: Component handling REST API communication with Backend_Service
- **Progress_Indicator**: Visual feedback showing scan progress and status

## Requirements

### Requirement 1: Context Menu Scanning

**User Story:** As a C/C++ developer, I want to right-click on files or folders to scan for vulnerabilities, so that I can quickly analyze specific code sections without manual setup.

#### Acceptance Criteria

1. WHEN a user right-clicks on a C or C++ file in the editor, THE Extension SHALL display a "Scan for Vulnerabilities" option in the Context_Menu
2. WHEN a user right-clicks on a folder in the file explorer, THE Extension SHALL display a "Scan Project for Vulnerabilities" option in the Context_Menu
3. WHEN a user selects "Scan for Vulnerabilities", THE Extension SHALL send the file contents to the Backend_Service via the API_Client
4. WHEN a scan is initiated, THE Extension SHALL display a Progress_Indicator showing scan status
5. WHEN the Backend_Service returns results, THE Extension SHALL create Diagnostic objects for each vulnerability
6. IF the Backend_Service is unreachable, THEN THE Extension SHALL display an error notification with connection troubleshooting guidance
7. THE Extension SHALL support scanning multiple selected files simultaneously
8. WHEN scanning multiple files, THE Extension SHALL aggregate results and display them in the Sidebar_Panel

### Requirement 2: Inline Diagnostic Display

**User Story:** As a C/C++ developer, I want to see vulnerabilities as inline squiggly lines in my code, so that I can identify issues immediately while editing.

#### Acceptance Criteria

1. WHEN a Vulnerability_Report is received, THE Extension SHALL create a Diagnostic at the specified line and column
2. THE Extension SHALL map Severity_Level to VS Code diagnostic severity (Critical/High → Error, Medium → Warning, Low/Info → Information)
3. WHEN a user hovers over a Diagnostic, THE Extension SHALL display a tooltip with vulnerability description, severity, and exploitability score
4. THE Extension SHALL display different colored squiggly lines based on Severity_Level
5. WHEN a file is closed and reopened, THE Extension SHALL restore all Diagnostic objects for that file
6. WHEN a user modifies code at a Diagnostic location, THE Extension SHALL preserve the Diagnostic until the next scan
7. THE Extension SHALL provide a code action "View Patch" when a Diagnostic has an available fix
8. FOR ALL Diagnostic objects, the line and column numbers SHALL match the exact vulnerability location in the source code

### Requirement 3: Vulnerability Sidebar Panel

**User Story:** As a security engineer, I want a dedicated panel listing all detected vulnerabilities with filtering options, so that I can review and prioritize security issues systematically.

#### Acceptance Criteria

1. THE Extension SHALL provide a Sidebar_Panel in the VS Code activity bar with an AutoVulRepair icon
2. THE Sidebar_Panel SHALL display all Vulnerability_Report objects grouped by file
3. WHEN a user clicks on a vulnerability in the Sidebar_Panel, THE Extension SHALL navigate to the corresponding file and line
4. THE Sidebar_Panel SHALL provide filter controls for Severity_Level (Critical, High, Medium, Low, Info)
5. THE Sidebar_Panel SHALL provide a search box to filter vulnerabilities by type or description
6. THE Sidebar_Panel SHALL display vulnerability count badges for each Severity_Level
7. THE Sidebar_Panel SHALL provide a "Clear All" button to remove all Diagnostic objects
8. THE Sidebar_Panel SHALL provide a "Rescan All" button to re-analyze all previously scanned files
9. WHEN vulnerabilities are updated, THE Sidebar_Panel SHALL refresh automatically without user interaction
10. THE Sidebar_Panel SHALL persist its state (filters, expanded items) across VS Code sessions

### Requirement 4: Background Scanning

**User Story:** As a C/C++ developer, I want automatic vulnerability scanning when I save files, so that I receive continuous security feedback without manual triggering.

#### Acceptance Criteria

1. WHERE background scanning is enabled in Configuration_Panel, THE Extension SHALL scan files on save events
2. WHEN a C or C++ file is saved, THE Background_Scanner SHALL send the file contents to the Backend_Service
3. THE Extension SHALL provide a configuration option to enable/disable background scanning (default: disabled)
4. THE Extension SHALL provide a configuration option to set scan delay after save (default: 2000ms)
5. WHEN multiple saves occur within the delay period, THE Background_Scanner SHALL debounce and perform only one scan
6. THE Extension SHALL provide a configuration option to exclude files by glob pattern from background scanning
7. WHILE a background scan is in progress, THE Extension SHALL display a subtle Progress_Indicator in the status bar
8. IF a background scan fails, THEN THE Extension SHALL log the error but not display intrusive notifications
9. THE Extension SHALL provide a configuration option to limit background scanning to files under a specified size (default: 1MB)

### Requirement 5: Patch Preview and Application

**User Story:** As a C/C++ developer, I want to preview and apply patches with one click, so that I can fix vulnerabilities quickly with confidence in the changes.

#### Acceptance Criteria

1. WHEN a Vulnerability_Report includes a Patch, THE Extension SHALL display a "View Patch" code action on the Diagnostic
2. WHEN a user selects "View Patch", THE Extension SHALL open a Diff_View showing original and patched code side-by-side
3. THE Diff_View SHALL highlight the exact lines being modified
4. THE Diff_View SHALL provide an "Apply Patch" button
5. WHEN a user clicks "Apply Patch", THE Extension SHALL replace the vulnerable code with the patched code
6. WHEN a Patch is applied, THE Extension SHALL create an undo checkpoint in VS Code's edit history
7. WHEN a Patch is applied, THE Extension SHALL remove the corresponding Diagnostic
8. THE Extension SHALL validate that the Patch applies cleanly to the current file contents before application
9. IF the file has been modified since the scan, THEN THE Extension SHALL warn the user and offer to rescan before applying
10. FOR ALL applied patches, undoing the edit SHALL restore the exact original code (round-trip property)
11. THE Extension SHALL log all applied patches with timestamp and vulnerability details for audit purposes

### Requirement 6: Backend Service Integration

**User Story:** As a DevOps engineer, I want the extension to communicate reliably with the Flask backend, so that vulnerability analysis leverages the existing AutoVulRepair infrastructure.

#### Acceptance Criteria

1. THE API_Client SHALL connect to the Backend_Service at a configurable URL (default: http://localhost:5000)
2. WHEN scanning a file, THE API_Client SHALL send a POST request to /api/scan with file contents and metadata
3. WHEN requesting scan status, THE API_Client SHALL send a GET request to /api/scan/{session_id}/status
4. WHEN retrieving results, THE API_Client SHALL send a GET request to /api/scan/{session_id}/results
5. THE API_Client SHALL include authentication tokens in request headers if configured
6. THE API_Client SHALL set request timeout to 30 seconds for scan initiation and 300 seconds for result retrieval
7. IF a request times out, THEN THE API_Client SHALL retry up to 3 times with exponential backoff
8. IF all retries fail, THEN THE Extension SHALL notify the user and log detailed error information
9. THE API_Client SHALL validate response schemas against expected Vulnerability_Report structure
10. IF the Backend_Service returns an invalid response, THEN THE Extension SHALL log the raw response and display a user-friendly error
11. THE Extension SHALL provide a "Test Connection" button in Configuration_Panel to verify Backend_Service availability

### Requirement 7: Real-Time Progress Updates

**User Story:** As a C/C++ developer, I want real-time progress updates during long-running scans, so that I know the analysis is progressing and can estimate completion time.

#### Acceptance Criteria

1. WHEN a Scan_Session is initiated, THE Extension SHALL establish a WebSocket_Channel to the Backend_Service
2. THE WebSocket_Channel SHALL connect to ws://localhost:5000/api/scan/{session_id}/progress
3. WHEN the Backend_Service sends progress updates, THE Extension SHALL update the Progress_Indicator with percentage and current stage
4. THE Progress_Indicator SHALL display stages: "Static Analysis", "Fuzzing", "Crash Triage", "Patch Generation"
5. WHEN a Scan_Session completes, THE Extension SHALL close the WebSocket_Channel
6. IF the WebSocket_Channel disconnects unexpectedly, THEN THE Extension SHALL fall back to polling /api/scan/{session_id}/status every 5 seconds
7. THE Extension SHALL provide a "Cancel Scan" button in the Progress_Indicator
8. WHEN a user clicks "Cancel Scan", THE Extension SHALL send a DELETE request to /api/scan/{session_id} and close the WebSocket_Channel
9. WHILE a scan is in progress, THE Extension SHALL prevent initiating new scans on the same file

### Requirement 8: Configuration Management

**User Story:** As a C/C++ developer, I want to configure extension behavior through VS Code settings, so that I can customize the tool to match my workflow preferences.

#### Acceptance Criteria

1. THE Extension SHALL provide a Configuration_Panel accessible via VS Code settings UI
2. THE Configuration_Panel SHALL include a text input for Backend_Service URL
3. THE Configuration_Panel SHALL include a toggle for enabling/disabling background scanning
4. THE Configuration_Panel SHALL include a number input for background scan delay (100-10000ms)
5. THE Configuration_Panel SHALL include a text input for file exclusion glob patterns
6. THE Configuration_Panel SHALL include a number input for maximum file size for background scanning (in KB)
7. THE Configuration_Panel SHALL include a dropdown for default Severity_Level filter in Sidebar_Panel
8. THE Configuration_Panel SHALL include a toggle for enabling/disabling WebSocket progress updates
9. THE Configuration_Panel SHALL include a text input for authentication token (masked input)
10. THE Configuration_Panel SHALL include a toggle for enabling/disabling automatic patch application without preview
11. WHEN a configuration value is changed, THE Extension SHALL apply the new setting immediately without requiring reload
12. THE Extension SHALL validate configuration values and display inline error messages for invalid inputs
13. THE Extension SHALL store all configuration in VS Code workspace settings to support per-project customization

### Requirement 9: Fuzzing Integration

**User Story:** As a security engineer, I want to trigger fuzzing campaigns from VS Code and view crash reports, so that I can discover runtime vulnerabilities through automated testing.

#### Acceptance Criteria

1. THE Extension SHALL provide a "Run Fuzzing Campaign" command in the Context_Menu for C/C++ files
2. WHEN a user selects "Run Fuzzing Campaign", THE Extension SHALL prompt for fuzzing duration (default: 60 seconds)
3. WHEN fuzzing is initiated, THE Extension SHALL send a POST request to /api/fuzz with file contents and duration
4. WHILE a Fuzzing_Campaign is running, THE Extension SHALL display real-time statistics (executions/sec, coverage, crashes found)
5. WHEN the Fuzzing_Campaign completes, THE Extension SHALL display Triage_Result objects in the Sidebar_Panel
6. THE Extension SHALL create Diagnostic objects for each crash location with Exploitability_Score in the tooltip
7. THE Extension SHALL provide a "View Crash Input" code action to display the input that triggered the crash
8. THE Extension SHALL provide a "Generate Patch for Crash" code action to request LLM-based fix generation
9. IF fuzzing discovers no crashes, THEN THE Extension SHALL display a success notification with coverage statistics
10. THE Extension SHALL log all fuzzing results to an output channel for detailed analysis

### Requirement 10: Performance and Responsiveness

**User Story:** As a C/C++ developer, I want the extension to remain responsive during scans, so that I can continue coding without interruption.

#### Acceptance Criteria

1. THE Extension SHALL perform all Backend_Service communication on background threads
2. THE Extension SHALL not block the VS Code UI thread for more than 50ms during any operation
3. WHEN processing large Vulnerability_Report objects (>100 vulnerabilities), THE Extension SHALL render Diagnostic objects incrementally
4. THE Extension SHALL cache Vulnerability_Report objects in memory to avoid redundant API calls
5. WHEN a file is modified, THE Extension SHALL invalidate cached results for that file only
6. THE Extension SHALL limit concurrent scan requests to 3 simultaneous Scan_Session objects
7. IF the user initiates more than 3 scans, THEN THE Extension SHALL queue additional requests
8. THE Extension SHALL provide a configuration option to adjust maximum concurrent scans (1-10)
9. THE Extension SHALL dispose of WebSocket_Channel objects and cached data when files are closed
10. THE Extension SHALL measure and log performance metrics (scan duration, API latency, memory usage) to an output channel

### Requirement 11: Error Handling and Recovery

**User Story:** As a C/C++ developer, I want clear error messages and recovery options when issues occur, so that I can troubleshoot problems without losing work.

#### Acceptance Criteria

1. IF the Backend_Service returns HTTP 500, THEN THE Extension SHALL display the error message from the response body
2. IF the Backend_Service returns HTTP 400, THEN THE Extension SHALL display validation errors and highlight problematic configuration
3. IF the Backend_Service is not running, THEN THE Extension SHALL display a notification with instructions to start the service
4. IF a WebSocket_Channel fails to connect, THEN THE Extension SHALL fall back to polling and log the connection error
5. IF a Patch fails to apply due to file changes, THEN THE Extension SHALL offer to rescan and regenerate the patch
6. IF the Extension crashes during a scan, THEN THE Extension SHALL clean up partial Diagnostic objects on restart
7. THE Extension SHALL provide a "Clear Extension Cache" command to reset all stored state
8. THE Extension SHALL provide a "View Logs" command to open the output channel with detailed diagnostic information
9. IF API_Client receives malformed JSON, THEN THE Extension SHALL log the raw response and display a generic error message
10. THE Extension SHALL implement circuit breaker pattern: after 5 consecutive failures, pause requests for 60 seconds

### Requirement 12: Security and Privacy

**User Story:** As a security engineer, I want the extension to handle code securely and respect privacy, so that sensitive source code is not exposed or leaked.

#### Acceptance Criteria

1. THE Extension SHALL only send file contents to the configured Backend_Service URL
2. THE Extension SHALL validate that the Backend_Service URL uses localhost or a trusted domain before sending data
3. WHERE HTTPS is used, THE Extension SHALL validate SSL certificates and reject self-signed certificates unless explicitly configured
4. THE Extension SHALL provide a configuration option to allow self-signed certificates (default: disabled)
5. THE Extension SHALL not log file contents or patches to output channels unless debug logging is explicitly enabled
6. THE Extension SHALL store authentication tokens using VS Code's secure storage API
7. THE Extension SHALL not transmit authentication tokens over unencrypted connections
8. WHEN debug logging is enabled, THE Extension SHALL display a warning that sensitive data may be logged
9. THE Extension SHALL provide a configuration option to disable telemetry and analytics (default: disabled)
10. THE Extension SHALL document all data transmission in the README with clear privacy implications

### Requirement 13: API Contract Specification

**User Story:** As a backend developer, I want a clearly defined API contract, so that I can ensure the Flask service meets the extension's requirements.

#### Acceptance Criteria

1. THE API_Client SHALL expect POST /api/scan to accept JSON with fields: {files: [{path: string, content: string}], options: {staticAnalysis: boolean, fuzzing: boolean}}
2. THE API_Client SHALL expect POST /api/scan to return JSON with fields: {sessionId: string, status: string, estimatedDuration: number}
3. THE API_Client SHALL expect GET /api/scan/{sessionId}/status to return JSON with fields: {status: string, progress: number, stage: string}
4. THE API_Client SHALL expect GET /api/scan/{sessionId}/results to return JSON with fields: {vulnerabilities: [{file: string, line: number, column: number, severity: string, type: string, description: string, patch: string?}]}
5. THE API_Client SHALL expect POST /api/fuzz to accept JSON with fields: {file: {path: string, content: string}, duration: number}
6. THE API_Client SHALL expect POST /api/fuzz to return JSON with fields: {sessionId: string, status: string}
7. THE API_Client SHALL expect WebSocket messages at ws://localhost:5000/api/scan/{sessionId}/progress with format: {progress: number, stage: string, details: string}
8. THE API_Client SHALL expect DELETE /api/scan/{sessionId} to return HTTP 204 on successful cancellation
9. THE API_Client SHALL send User-Agent header: "AutoVulRepair-VSCode/{version}"
10. THE API_Client SHALL send Content-Type header: "application/json" for all POST requests
11. FOR ALL API responses, parsing the JSON and re-serializing SHALL produce equivalent data structures (round-trip property)

### Requirement 14: User Experience and Accessibility

**User Story:** As a C/C++ developer with accessibility needs, I want the extension to be fully accessible, so that I can use all features with screen readers and keyboard navigation.

#### Acceptance Criteria

1. THE Extension SHALL provide keyboard shortcuts for all primary commands (scan, view patch, apply patch, clear diagnostics)
2. THE Extension SHALL ensure all UI elements in the Sidebar_Panel have proper ARIA labels
3. THE Extension SHALL provide screen reader announcements when scans complete or vulnerabilities are found
4. THE Extension SHALL ensure the Diff_View is navigable with keyboard only
5. THE Extension SHALL use VS Code's theme colors for all UI elements to respect user's color preferences
6. THE Extension SHALL provide high-contrast icons for the activity bar and Context_Menu
7. THE Extension SHALL ensure all interactive elements have visible focus indicators
8. THE Extension SHALL provide tooltips for all buttons and icons in the Sidebar_Panel
9. THE Extension SHALL support VS Code's zoom functionality without breaking layout
10. THE Extension SHALL provide a "Getting Started" walkthrough accessible from the command palette

### Requirement 15: Documentation and Onboarding

**User Story:** As a new user, I want comprehensive documentation and examples, so that I can quickly understand how to use the extension effectively.

#### Acceptance Criteria

1. THE Extension SHALL include a README.md with installation instructions, prerequisites, and quick start guide
2. THE Extension SHALL include a CHANGELOG.md documenting all version changes
3. THE Extension SHALL provide a "Show Welcome Page" command that displays usage examples and tips
4. THE Extension SHALL include inline documentation for all configuration options in the Configuration_Panel
5. THE Extension SHALL provide sample C/C++ files with known vulnerabilities for testing
6. THE Extension SHALL include troubleshooting guide for common issues (Backend_Service not running, connection failures)
7. THE Extension SHALL provide links to AutoVulRepair documentation from the Sidebar_Panel
8. THE Extension SHALL include animated GIFs or screenshots demonstrating key features in the README
9. THE Extension SHALL provide a "Report Issue" command that opens GitHub issues with pre-filled environment information
10. THE Extension SHALL include API documentation for the Backend_Service contract in a separate API.md file

## Non-Functional Requirements

### Performance Requirements

1. THE Extension SHALL display Diagnostic objects within 100ms of receiving a Vulnerability_Report
2. THE Extension SHALL render the Sidebar_Panel with 1000 vulnerabilities in under 500ms
3. THE Extension SHALL consume less than 200MB of memory during normal operation
4. THE Extension SHALL start up in under 2 seconds on a standard development machine

### Reliability Requirements

1. THE Extension SHALL handle Backend_Service unavailability gracefully without crashing
2. THE Extension SHALL recover from WebSocket_Channel disconnections automatically
3. THE Extension SHALL persist all Diagnostic objects across VS Code restarts
4. THE Extension SHALL maintain data consistency when multiple files are scanned concurrently

### Compatibility Requirements

1. THE Extension SHALL support VS Code version 1.75.0 and later
2. THE Extension SHALL work on Windows, macOS, and Linux operating systems
3. THE Extension SHALL be compatible with VS Code's Remote Development extensions
4. THE Extension SHALL not conflict with other C/C++ extensions (C/C++ IntelliSense, clangd)

### Maintainability Requirements

1. THE Extension SHALL be written in TypeScript with strict type checking enabled
2. THE Extension SHALL include unit tests with minimum 80% code coverage
3. THE Extension SHALL include integration tests for API_Client communication
4. THE Extension SHALL follow VS Code extension development best practices and guidelines
5. THE Extension SHALL use a linter (ESLint) and formatter (Prettier) with consistent configuration

## Correctness Properties for Testing

### Property 1: Diagnostic Consistency
FOR ALL Vulnerability_Report objects received, the number of Diagnostic objects created SHALL equal the number of vulnerabilities in the report.

### Property 2: Round-Trip Configuration
FOR ALL configuration values, reading from Configuration_Panel after writing SHALL return the exact value written.

### Property 3: Patch Application Idempotence
FOR ALL patches, applying the same Patch twice SHALL have the same effect as applying it once (the second application should be a no-op).

### Property 4: API Response Parsing
FOR ALL API responses, parsing the JSON response and serializing it back SHALL produce equivalent data (round-trip property).

### Property 5: Severity Mapping Invariant
FOR ALL Vulnerability_Report objects, the VS Code diagnostic severity SHALL correctly map to the Severity_Level according to the specification (Critical/High → Error, Medium → Warning, Low/Info → Information).

### Property 6: WebSocket Fallback Equivalence
FOR ALL Scan_Session objects, the final results obtained via WebSocket_Channel SHALL be equivalent to results obtained via polling.

### Property 7: Filter Correctness
FOR ALL filter combinations in Sidebar_Panel, the displayed vulnerabilities SHALL be a subset of all vulnerabilities matching the filter criteria.

### Property 8: Concurrent Scan Isolation
FOR ALL concurrent scans on different files, the Diagnostic objects SHALL be correctly associated with their respective files without cross-contamination.

### Property 9: Cache Invalidation
FOR ALL file modifications, cached Vulnerability_Report objects for the modified file SHALL be invalidated, and subsequent scans SHALL fetch fresh results.

### Property 10: Undo/Redo Correctness
FOR ALL applied patches, performing undo SHALL restore the exact original code, and performing redo SHALL reapply the exact patch (round-trip property).
