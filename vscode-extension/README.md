# AutoVulRepair VS Code Extension

Automated vulnerability detection and repair for C/C++ code, integrated directly into your IDE.

## Features

- **Context Menu Scanning**: Right-click on files or folders to scan for vulnerabilities
- **Inline Diagnostics**: See vulnerabilities as squiggly lines in your code
- **Vulnerability Sidebar**: Dedicated panel for managing and filtering security issues
- **Background Scanning**: Automatic scanning on file save (configurable)
- **One-Click Patches**: Preview and apply security fixes with confidence
- **Real-Time Progress**: Live updates during long-running scans
- **Fuzzing Integration**: Discover runtime vulnerabilities through automated testing

## Prerequisites

- VS Code 1.75.0 or later
- Node.js 18.x or later
- AutoVulRepair backend service running at `http://localhost:5000`

## Installation

1. Install the extension from the VS Code Marketplace
2. Ensure the AutoVulRepair backend service is running
3. Configure the backend URL in settings if different from default

## Quick Start

1. Open a C/C++ file
2. Right-click in the editor
3. Select "Scan for Vulnerabilities"
4. View results in the sidebar and inline diagnostics
5. Click "View Patch" on any vulnerability to see the fix
6. Click "Apply Patch" to fix the issue

## Configuration

Access settings via `File > Preferences > Settings` and search for "AutoVulRepair":

- `autoVulRepair.backendURL`: Backend service URL (default: `http://localhost:5000`)
- `autoVulRepair.backgroundScanEnabled`: Enable automatic scanning on save (default: `false`)
- `autoVulRepair.backgroundScanDelay`: Delay before scanning after save (default: `2000ms`)
- `autoVulRepair.maxConcurrentScans`: Maximum concurrent scans (default: `3`)

## Commands

- `AutoVulRepair: Scan for Vulnerabilities` - Scan current file
- `AutoVulRepair: Scan Project for Vulnerabilities` - Scan entire folder
- `AutoVulRepair: Run Fuzzing Campaign` - Start fuzzing test
- `AutoVulRepair: Clear All Diagnostics` - Remove all vulnerability markers
- `AutoVulRepair: Test Backend Connection` - Verify backend availability

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT
