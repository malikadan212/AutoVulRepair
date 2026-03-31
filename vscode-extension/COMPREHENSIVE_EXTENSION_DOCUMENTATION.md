# AutoVulRepair VS Code Extension - Comprehensive Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Features](#features)
5. [Configuration](#configuration)
6. [Commands](#commands)
7. [User Interface](#user-interface)
8. [API Integration](#api-integration)
9. [Testing](#testing)
10. [Build System](#build-system)
11. [Development](#development)

## Overview

The AutoVulRepair VS Code Extension is a comprehensive security tool that provides automated vulnerability detection and repair for C/C++ code. It integrates with a backend service to perform static analysis, fuzzing, and AI-powered patch generation.

### Key Features
- **Real-time vulnerability detection** with inline diagnostics
- **Automated patch generation** and application
- **Background scanning** on file save
- **Interactive sidebar** for vulnerability management
- **Progress tracking** with status bar integration
- **Caching system** for performance optimization
- **Circuit breaker** for fault tolerance
- **WebSocket support** for real-time updates (with polling fallback)

## Architecture

The extension follows a modular architecture with clear separation of concerns:

```
Extension Entry Point (extension.ts)
├── Configuration Manager (configurationManager.ts)
├── API Client (apiClient.ts)
├── Diagnostic Manager (diagnosticManager.ts)
├── UI Components
│   ├── Sidebar Provider (sidebarProvider.ts)
│   ├── Progress Tracker (progressTracker.ts)
│   └── Code Actions Provider (codeActionsProvider.ts)
├── Background Services
│   ├── Background Scanner (backgroundScanner.ts)
│   ├── Cache Manager (cacheManager.ts)
│   └── WebSocket Handler (websocketHandler.ts)
├── Patch Management (patchManager.ts)
├── Commands (commands.ts)
└── Utilities
    ├── Circuit Breaker (circuitBreaker.ts)
    └── Type Definitions (types.ts)
```
## Core Components

### 1. Extension Entry Point (`extension.ts`)

The main extension file that handles activation and deactivation:

**Key Functions:**
- `activate(context)`: Initializes all components and registers event listeners
- `deactivate()`: Cleans up resources and disposes of services

**Initialization Flow:**
1. Creates configuration manager
2. Initializes API client with configuration
3. Sets up diagnostic manager for vulnerability display
4. Creates UI components (sidebar, progress tracker)
5. Registers commands and event listeners
6. Sets up background scanner for automatic scanning

**Event Listeners:**
- File save events for background scanning
- Configuration changes for dynamic updates
- Diagnostic changes for sidebar refresh

### 2. Configuration Manager (`configurationManager.ts`)

Manages all extension settings with type safety and validation:

**Key Methods:**
- `get<T>(key, defaultValue)`: Retrieves typed configuration values
- `set(key, value, global)`: Updates configuration settings
- `getSecure(key)` / `setSecure(key, value)`: Handles sensitive data via VS Code secrets
- `validate()`: Validates all configuration values
- `onDidChange(callback)`: Registers configuration change listeners

**Configuration Properties:**
- `backendURL`: Backend service endpoint
- `backgroundScanEnabled`: Auto-scan on file save
- `backgroundScanDelay`: Debounce delay for scanning
- `excludePatterns`: File patterns to exclude from scanning
- `maxFileSizeKB`: Maximum file size for background scanning
- `maxConcurrentScans`: Concurrent scan limit
- `defaultSeverityFilter`: Default sidebar filter
- `enableWebSocketProgress`: Real-time progress updates
- `allowSelfSignedCertificates`: SSL certificate handling

### 3. API Client (`apiClient.ts`)

Handles all communication with the AutoVulRepair backend:

**Key Features:**
- **Circuit Breaker Pattern**: Prevents cascading failures
- **Retry Logic**: Exponential backoff for failed requests
- **Request Timeout**: Configurable timeouts for different operations
- **Authentication**: Bearer token support
- **Error Formatting**: User-friendly error messages

**Main Methods:**
- `scan(request)`: Initiates vulnerability scan
- `getScanStatus(sessionId)`: Retrieves scan progress
- `getScanResults(sessionId)`: Gets vulnerability results
- `waitForScanResults(sessionId, onProgress)`: Polls until completion
- `cancelScan(sessionId)`: Cancels running scan
- `fuzz(request)`: Starts fuzzing campaign
- `testConnection()`: Health check

**Request/Response Flow:**
1. Validates request parameters
2. Applies circuit breaker protection
3. Executes request with retry logic
4. Formats errors for user display
5. Returns typed response objects
### 4. Diagnostic Manager (`diagnosticManager.ts`)

Manages VS Code diagnostics for vulnerability display:

**Core Functionality:**
- Creates inline squiggly lines for vulnerabilities
- Maps severity levels to VS Code diagnostic types
- Maintains vulnerability-to-file mapping
- Provides event notifications for UI updates

**Key Methods:**
- `createDiagnostics(fileUri, vulnerabilities)`: Creates diagnostics for a file
- `getVulnerability(fileUri, line)`: Retrieves vulnerability at specific location
- `getVulnerabilitiesForFile(fileUri)`: Gets all vulnerabilities for a file
- `getAllVulnerabilities()`: Returns complete vulnerability map
- `clearDiagnostics(fileUri?)`: Clears diagnostics for file or all files

**Severity Mapping:**
- Critical/High → Error (red squiggly)
- Medium → Warning (yellow squiggly)
- Low/Info → Information (blue squiggly)

### 5. Commands (`commands.ts`)

Implements all extension commands with comprehensive error handling:

**Available Commands:**
- `autoVulRepair.scanFile`: Scans current active file
- `autoVulRepair.scanFolder`: Scans entire folder/project
- `autoVulRepair.viewPatch`: Shows patch preview in diff view
- `autoVulRepair.applyPatch`: Applies patch to file
- `autoVulRepair.clearDiagnostics`: Clears all vulnerability markers
- `autoVulRepair.testConnection`: Tests backend connectivity
- `autoVulRepair.navigateToVulnerability`: Jumps to vulnerability location
- `autoVulRepair.clearCache`: Clears extension cache

**Scan File Command Flow:**
1. Validates active editor and file type (C/C++)
2. Sends code snippet to backend via API client
3. Shows progress indicator
4. Polls for results with progress updates
5. Transforms backend response to extension format
6. Creates diagnostics for found vulnerabilities
7. Updates sidebar and shows notification

### 6. Sidebar Provider (`sidebarProvider.ts`)

Provides tree view for vulnerability management:

**Tree Structure:**
```
📁 File Name (vulnerability count)
├── 🔴 [Critical] Buffer Overflow (Line 42)
├── 🟡 [Medium] Memory Leak (Line 58)
└── 🔵 [Low] Unused Variable (Line 73)
```

**Key Features:**
- **Hierarchical Display**: Files → Vulnerabilities
- **Severity Filtering**: Show/hide by severity level
- **Search Functionality**: Filter by vulnerability type/description
- **Click Navigation**: Jump to vulnerability location
- **Real-time Updates**: Refreshes when diagnostics change

**Tree Item Types:**
- **File Nodes**: Collapsible containers showing file name and count
- **Vulnerability Nodes**: Individual vulnerabilities with severity icons
### 7. Progress Tracker (`progressTracker.ts`)

Manages progress display across the extension:

**Display Methods:**
- **Status Bar**: Shows current scan progress
- **Modal Progress**: Full-screen progress with cancellation
- **Multiple Sessions**: Tracks concurrent scans

**Key Methods:**
- `showProgress(sessionId, message)`: Starts progress display
- `updateProgress(sessionId, progress, stage)`: Updates progress percentage
- `hideProgress(sessionId)`: Removes progress display
- `withProgress(title, task)`: Modal progress with cancellation

### 8. Background Scanner (`backgroundScanner.ts`)

Handles automatic scanning on file save:

**Features:**
- **Debouncing**: Prevents excessive scanning during rapid edits
- **Concurrency Control**: Limits simultaneous scans
- **File Filtering**: Respects exclusion patterns and size limits
- **Silent Operation**: Runs in background without user interruption

**Scan Decision Logic:**
1. Check if background scanning is enabled
2. Validate file extension (C/C++ only)
3. Check file size against limit
4. Apply exclusion patterns
5. Verify not already scanning
6. Check concurrent scan limit

### 9. Cache Manager (`cacheManager.ts`)

Implements LRU cache for scan results:

**Features:**
- **File Hash Validation**: Detects file changes
- **LRU Eviction**: Removes oldest entries when full
- **Persistent Storage**: Saves cache to workspace state
- **Performance Optimization**: Avoids redundant scans

**Cache Entry Structure:**
```typescript
{
  vulnerabilities: VulnerabilityReport[],
  timestamp: number,
  fileHash: string
}
```

### 10. Patch Manager (`patchManager.ts`)

Handles patch preview and application:

**Key Features:**
- **Diff Preview**: Shows before/after comparison
- **Patch Validation**: Ensures patch applicability
- **History Tracking**: Maintains audit trail
- **Workspace Integration**: Uses VS Code edit API

**Patch Application Flow:**
1. Validate patch exists for vulnerability
2. Check file hasn't changed since scan
3. Create workspace edit with patch content
4. Apply edit through VS Code API
5. Clear diagnostic for fixed vulnerability
6. Log patch application for audit
### 11. Code Actions Provider (`codeActionsProvider.ts`)

Provides quick fix actions in the editor:

**Available Actions:**
- **View Patch**: Opens diff preview
- **Apply Patch**: Directly applies fix (marked as preferred)

**Integration Points:**
- Appears in VS Code's lightbulb menu
- Triggered by diagnostics from AutoVulRepair
- Context-aware based on cursor position

### 12. WebSocket Handler (`websocketHandler.ts`)

Manages real-time progress updates:

**Features:**
- **Automatic Reconnection**: Handles connection drops
- **Fallback to Polling**: Graceful degradation
- **Message Validation**: Ensures data integrity
- **Connection State Tracking**: Monitors WebSocket status

**Connection Flow:**
1. Convert HTTP URL to WebSocket URL
2. Establish connection to `/api/scan/{sessionId}/progress`
3. Handle incoming progress messages
4. Implement reconnection with exponential backoff
5. Fall back to polling if WebSocket fails

### 13. Circuit Breaker (`circuitBreaker.ts`)

Implements fault tolerance pattern:

**States:**
- **CLOSED**: Normal operation, requests pass through
- **OPEN**: Failures exceeded threshold, requests blocked
- **HALF_OPEN**: Testing recovery, limited requests allowed

**Configuration:**
- Failure threshold: 5 consecutive failures
- Timeout: 60 seconds before attempting recovery

### 14. Type Definitions (`types.ts`)

Comprehensive type system for the extension:

**Core Types:**
- `SeverityLevel`: Vulnerability severity levels
- `ScanStatus`: Scan state enumeration
- `VulnerabilityReport`: Complete vulnerability information
- `ScanRequest/Response`: API communication types
- `ExtensionConfiguration`: Settings structure

## Features

### Real-time Vulnerability Detection
- Inline diagnostics with severity-based styling
- Automatic scanning on file save (configurable)
- Support for C/C++ file types
- Integration with cppcheck and CodeQL analysis tools

### Interactive Vulnerability Management
- Hierarchical sidebar showing files and vulnerabilities
- Severity-based filtering and search functionality
- Click-to-navigate to vulnerability locations
- Real-time updates when vulnerabilities change

### Automated Patch Management
- AI-powered patch generation through backend
- Side-by-side diff preview before applying patches
- One-click patch application with validation
- Audit trail for all patch applications

### Performance Optimization
- LRU cache for scan results with file hash validation
- Debounced background scanning to prevent excessive requests
- Concurrent scan limiting to manage resource usage
- Circuit breaker pattern for fault tolerance

### Progress Tracking
- Status bar integration for current scan progress
- Modal progress dialogs for long-running operations
- WebSocket-based real-time updates with polling fallback
- Support for multiple concurrent scan sessions
## Configuration

The extension provides comprehensive configuration options:

### Backend Configuration
```json
{
  "autoVulRepair.backendURL": "http://localhost:5000",
  "autoVulRepair.allowSelfSignedCertificates": false
}
```

### Scanning Behavior
```json
{
  "autoVulRepair.backgroundScanEnabled": false,
  "autoVulRepair.backgroundScanDelay": 2000,
  "autoVulRepair.maxFileSizeKB": 1024,
  "autoVulRepair.maxConcurrentScans": 3
}
```

### File Filtering
```json
{
  "autoVulRepair.excludePatterns": [
    "**/node_modules/**",
    "**/build/**",
    "**/dist/**"
  ]
}
```

### UI Preferences
```json
{
  "autoVulRepair.defaultSeverityFilter": "All",
  "autoVulRepair.enableWebSocketProgress": true
}
```

## Commands

### Available Commands
1. **Scan for Vulnerabilities** (`autoVulRepair.scanFile`)
   - Scans the currently active C/C++ file
   - Shows progress and displays results in sidebar
   - Available via right-click context menu

2. **Scan Project for Vulnerabilities** (`autoVulRepair.scanFolder`)
   - Scans all C/C++ files in selected folder
   - Batch processing with progress tracking
   - Available via explorer context menu

3. **View Patch** (`autoVulRepair.viewPatch`)
   - Shows side-by-side diff of proposed fix
   - Available via code actions (lightbulb menu)
   - Triggered from vulnerability diagnostics

4. **Apply Patch** (`autoVulRepair.applyPatch`)
   - Applies the suggested fix to the file
   - Validates patch applicability before applying
   - Preferred quick fix action

5. **Clear All Diagnostics** (`autoVulRepair.clearDiagnostics`)
   - Removes all vulnerability markers
   - Useful for clearing stale results
   - Available via command palette

6. **Test Backend Connection** (`autoVulRepair.testConnection`)
   - Verifies connectivity to backend service
   - Shows connection status in notification
   - Useful for troubleshooting

7. **Clear Extension Cache** (`autoVulRepair.clearCache`)
   - Removes cached scan results
   - Forces fresh scans for all files
   - Useful after backend updates

### Command Registration
Commands are registered in `extension.ts` during activation and bound to their respective handler functions in `commands.ts`.
## User Interface

### Activity Bar Integration
- Custom AutoVulRepair icon in the activity bar
- Dedicated sidebar panel for vulnerability management
- Badge showing total vulnerability count

### Sidebar Panel
- **Tree View**: Hierarchical display of files and vulnerabilities
- **Filtering**: Severity-based filters and search functionality
- **Navigation**: Click to jump to vulnerability location
- **Icons**: Severity-based icons (error, warning, info)

### Editor Integration
- **Inline Diagnostics**: Squiggly underlines for vulnerabilities
- **Hover Information**: Detailed vulnerability descriptions
- **Code Actions**: Quick fix menu with patch options
- **Context Menu**: Right-click scanning options

### Status Bar
- **Progress Indicator**: Shows current scan progress
- **Spinning Icon**: Indicates active scanning
- **Click Action**: Opens progress details

### Notifications
- **Scan Results**: Shows vulnerability count after scanning
- **Error Messages**: User-friendly error descriptions
- **Success Messages**: Confirmation of successful operations

## API Integration

### Backend Communication
The extension communicates with the AutoVulRepair backend service through a REST API:

### Endpoints Used
1. **POST /api/scan**
   - Initiates vulnerability scan
   - Payload: `{ code_snippet: string, analysis_tool: string }`
   - Response: `{ scanId: string, status: string, message: string }`

2. **GET /api/scan/{scanId}/status**
   - Retrieves scan progress
   - Response: `{ status: string, progress: number, stage: string }`

3. **GET /api/scan/{scanId}/results**
   - Gets vulnerability results
   - Response: `{ vulnerabilities: VulnerabilityReport[], summary: object }`

4. **DELETE /api/scan/{scanId}**
   - Cancels running scan
   - No response body

5. **GET /api/health**
   - Health check endpoint
   - Used for connection testing

### Request/Response Transformation
The extension transforms backend responses to match internal type definitions:

```typescript
// Backend response format
{
  id: string,
  type: string,
  severity: string,
  file: string,
  line: number,
  column: number,
  description: string,
  exploitability: number,  // Backend uses this field
  patch: string
}

// Extension internal format
{
  file: string,
  line: number,
  column: number,
  severity: SeverityLevel,
  type: string,
  description: string,
  exploitabilityScore: number,  // Extension uses this field
  patch: string
}
```

### Error Handling
- **Connection Errors**: User-friendly messages about backend availability
- **Timeout Errors**: Indicates backend overload or network issues
- **HTTP Errors**: Specific error messages based on status codes
- **Circuit Breaker**: Prevents cascading failures during backend issues
## Testing

### Test Structure
The extension includes comprehensive testing across multiple levels:

```
test/
├── unit/           # Unit tests for individual components
├── integration/    # Integration tests with mocked backend
└── property/       # Property-based tests for robustness
```

### Unit Tests
Each core component has dedicated unit tests:
- `apiClient.test.ts`: API communication and error handling
- `diagnosticManager.test.ts`: Diagnostic creation and management
- `configurationManager.test.ts`: Configuration validation and updates
- `sidebarProvider.test.ts`: Tree view functionality
- `progressTracker.test.ts`: Progress display logic
- `cacheManager.test.ts`: Caching behavior and LRU eviction
- `backgroundScanner.test.ts`: Background scanning logic
- `patchManager.test.ts`: Patch application and validation
- `codeActionsProvider.test.ts`: Quick fix actions
- `circuitBreaker.test.ts`: Fault tolerance behavior
- `websocketHandler.test.ts`: WebSocket connection handling

### Test Coverage
- **Target Coverage**: 80% for branches, functions, lines, and statements
- **Mocking**: VS Code API is mocked for isolated testing
- **Property Testing**: Uses fast-check for robustness testing

### Running Tests
```bash
# All tests
npm test

# Unit tests only
npm run test:unit

# Integration tests
npm run test:integration

# Property-based tests
npm run test:property
```

## Build System

### TypeScript Configuration
- **Target**: ES2020 for modern JavaScript features
- **Module**: CommonJS for Node.js compatibility
- **Strict Mode**: Enabled for type safety
- **Source Maps**: Generated for debugging

### Webpack Configuration
- **Target**: Node.js environment
- **Entry Point**: `src/extension.ts`
- **Output**: Single bundled file in `dist/extension.js`
- **Externals**: VS Code API excluded from bundle
- **Loaders**: TypeScript compilation with ts-loader

### Build Scripts
```bash
# Development build with watch mode
npm run watch

# Production build with optimization
npm run package

# Compile TypeScript only
npm run compile

# Run linting
npm run lint
```

### Package Structure
```
vscode-extension/
├── src/                 # Source code
├── test/               # Test files
├── dist/               # Compiled output
├── out/                # TypeScript compilation output
├── node_modules/       # Dependencies
├── package.json        # Extension manifest
├── tsconfig.json       # TypeScript configuration
├── webpack.config.js   # Build configuration
└── jest.config.js      # Test configuration
```
## Development

### Development Setup
1. **Prerequisites**:
   - Node.js 18+
   - VS Code 1.75+
   - TypeScript 5.0+

2. **Installation**:
   ```bash
   cd vscode-extension
   npm install
   ```

3. **Development Build**:
   ```bash
   npm run watch
   ```

4. **Testing**:
   ```bash
   npm test
   ```

5. **Packaging**:
   ```bash
   npm run package
   vsce package
   ```

### Code Organization
- **Modular Architecture**: Each component has a single responsibility
- **Type Safety**: Comprehensive TypeScript types for all interfaces
- **Error Handling**: Consistent error handling patterns throughout
- **Logging**: Structured logging for debugging and monitoring
- **Documentation**: JSDoc comments for all public methods

### Extension Lifecycle
1. **Activation**: Triggered by C/C++ file opening or workspace detection
2. **Initialization**: All components are created and configured
3. **Event Registration**: Commands, listeners, and providers are registered
4. **Runtime**: Extension responds to user actions and file changes
5. **Deactivation**: Resources are cleaned up and disposed

### Performance Considerations
- **Lazy Loading**: Components are initialized only when needed
- **Debouncing**: File save events are debounced to prevent excessive scanning
- **Caching**: Scan results are cached with file hash validation
- **Concurrency**: Multiple scans are limited to prevent resource exhaustion
- **Memory Management**: Proper disposal of resources and event listeners

### Extension Manifest (`package.json`)

The extension manifest defines all capabilities and metadata:

**Activation Events:**
- `onLanguage:c` - Activates when C files are opened
- `onLanguage:cpp` - Activates when C++ files are opened
- `workspaceContains:**/*.{c,cpp,cc,cxx,h,hpp}` - Activates when C/C++ files exist

**Contributed Commands:**
- 12 total commands covering scanning, patching, and utility functions
- Context menu integration for C/C++ files
- Explorer context menu for folder scanning

**Views and Containers:**
- Custom activity bar container with AutoVulRepair branding
- Dedicated sidebar view for vulnerability management
- Tree data provider for hierarchical vulnerability display

**Configuration Schema:**
- 9 configuration properties with validation
- Type-safe settings with defaults and constraints
- Secure storage integration for sensitive data

### Key Design Patterns

1. **Observer Pattern**: Used for configuration changes and diagnostic updates
2. **Circuit Breaker**: Prevents cascading failures in API communication
3. **Command Pattern**: All user actions are implemented as commands
4. **Factory Pattern**: Creates appropriate diagnostic types based on severity
5. **Singleton Pattern**: Single instances of managers and services
6. **Strategy Pattern**: Different scanning strategies for background vs manual scans

### Error Handling Strategy

The extension implements comprehensive error handling:

1. **API Errors**: Formatted for user understanding with actionable messages
2. **Network Errors**: Graceful degradation with offline capabilities
3. **File System Errors**: Proper handling of file access and permission issues
4. **Configuration Errors**: Validation with helpful error messages
5. **Runtime Errors**: Logging and recovery without extension crashes

### Security Considerations

- **Input Validation**: All user inputs and API responses are validated
- **Secure Storage**: Sensitive configuration uses VS Code's secret storage
- **HTTPS Enforcement**: Backend URLs must use HTTPS for remote connections
- **Certificate Validation**: Optional self-signed certificate support
- **Error Information**: Sensitive data is not exposed in error messages

This comprehensive documentation covers every aspect of the AutoVulRepair VS Code Extension, from high-level architecture to implementation details. The extension provides a robust, user-friendly interface for automated vulnerability detection and repair in C/C++ codebases, with enterprise-grade features like caching, fault tolerance, and comprehensive testing.