# Contributing to AutoVulRepair VS Code Extension

## Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd vscode-extension
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the backend service**
   Ensure the AutoVulRepair Flask backend is running at `http://localhost:5000`

4. **Open in VS Code**
   ```bash
   code .
   ```

5. **Run the extension**
   - Press `F5` to open a new VS Code window with the extension loaded
   - Or use "Run > Start Debugging" from the menu

## Project Structure

```
vscode-extension/
├── src/                    # TypeScript source files
│   ├── extension.ts        # Extension entry point
│   ├── types.ts           # Type definitions
│   ├── apiClient.ts       # REST API communication
│   ├── websocketHandler.ts # WebSocket for progress
│   ├── diagnosticManager.ts # VS Code diagnostics
│   ├── patchManager.ts    # Patch preview/application
│   ├── backgroundScanner.ts # Auto-scan on save
│   ├── configurationManager.ts # Settings management
│   ├── cacheManager.ts    # Result caching
│   ├── circuitBreaker.ts  # Fault tolerance
│   ├── sidebarProvider.ts # Sidebar UI
│   ├── progressTracker.ts # Progress indicators
│   ├── commands.ts        # Command handlers
│   └── codeActionsProvider.ts # Quick fixes
├── test/                  # Test files
│   ├── unit/             # Unit tests
│   ├── property/         # Property-based tests
│   └── integration/      # Integration tests
├── .kiro/specs/          # Specification documents
│   ├── requirements.md   # Requirements specification
│   ├── design.md        # Design document
│   └── tasks.md         # Implementation tasks
└── resources/            # Icons and assets
```

## Development Workflow

### Running Tests

```bash
# Run all tests
npm test

# Run unit tests only
npm run test:unit

# Run property-based tests
npm run test:property

# Run integration tests
npm run test:integration
```

### Linting and Formatting

```bash
# Run linter
npm run lint

# Format code
npx prettier --write src/**/*.ts
```

### Building

```bash
# Development build
npm run compile

# Watch mode (auto-rebuild on changes)
npm run watch

# Production build
npm run package
```

## Implementation Guide

Follow the tasks in `.kiro/specs/tasks.md` in order:

1. **Phase 1: Project Setup** (Tasks 1-3)
   - ✅ Project scaffolding (complete)
   - Type definitions
   - Configuration Manager

2. **Phase 2: Communication Layer** (Tasks 4-7)
   - Circuit Breaker
   - API Client
   - WebSocket Handler

3. **Phase 3: Business Logic** (Tasks 8-12)
   - Diagnostic Manager
   - Cache Manager
   - Patch Manager
   - Background Scanner

4. **Phase 4: UI Components** (Tasks 13-17)
   - Sidebar Provider
   - Progress Tracker
   - Command Handlers
   - Code Actions Provider

5. **Phase 5: Integration & Testing** (Tasks 18-32)
   - Integration tests
   - Property-based tests
   - Documentation
   - Packaging

## Testing Guidelines

- Write unit tests for all new components
- Add property-based tests for critical logic
- Ensure 80% code coverage minimum
- Test error handling and edge cases

## Code Style

- Use TypeScript strict mode
- Follow ESLint and Prettier configurations
- Add JSDoc comments for public APIs
- Use meaningful variable and function names

## Submitting Changes

1. Create a feature branch
2. Implement changes with tests
3. Run linter and tests
4. Update CHANGELOG.md
5. Submit pull request

## Questions?

Open an issue or contact the maintainers.
