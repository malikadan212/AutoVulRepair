# AutoVulRepair Project Requirements

## Introduction

This document describes the functional and non-functional requirements for AutoVulRepair, a cloud-native automated vulnerability detection and repair system. The system provides a Flask web application that offers both authenticated and anonymous vulnerability scanning capabilities, processing code repositories through ephemeral containers and generating SARIF-compliant vulnerability reports.

## Functional Requirements

### Module 1 – Static Analysis

**Description:** This module identifies security vulnerabilities in C/C++ codebases through static analysis techniques. It integrates tools such as Cppcheck and CodeQL to scan source code for potential security flaws (use-after-free, buffer overflow, null dereference, etc.) and converts findings into machine-readable format for prioritization in remediation. The module integrates with a Flask web application to provide both authenticated and anonymous scanning capabilities.

#### FR1-1: Multi-Channel Code Intake and Web Interface
**User Story:** As a developer or security researcher, I want to submit code for analysis through multiple input methods with optional authentication so that I can scan both public and private code while maintaining privacy.

##### Acceptance Criteria
1. WHEN a user visits the home page THEN the system SHALL display options for both authenticated GitHub access and anonymous scanning
2. WHEN a user chooses GitHub authentication THEN the system SHALL use OAuth 2.0 to securely authenticate via GitHub API
3. WHEN a user selects anonymous scanning THEN the system SHALL provide access to public repository scanning, ZIP upload, and code snippet analysis
4. WHEN a user provides a GitHub repository URL THEN the system SHALL validate it matches the pattern `https://github.com/[user]/[repo]` and clone using `git clone --depth 1`
5. WHEN a user uploads a ZIP file THEN the system SHALL validate file size (max 100MB), scan for malicious content, and extract to ephemeral storage
6. WHEN a user pastes code snippets THEN the system SHALL accept text input up to 50KB and prepare it for analysis
7. WHEN processing any input type THEN the system SHALL create a unique scan ID and temporary workspace directory with automatic cleanup

#### FR1-2: Static Analysis Engine Integration
**User Story:** As a security analyst, I want the system to run comprehensive static analysis using industry-standard tools so that I can identify security vulnerabilities with high accuracy and minimal false positives.

##### Acceptance Criteria
1. WHEN a user submits code for analysis THEN the system SHALL allow the user to choose between Cppcheck or CodeQL as the analysis tool
2. WHEN Cppcheck is selected THEN the system SHALL run Cppcheck with security-focused rule sets to scan for C/C++ security flaws (use-after-free, buffer overflow, null dereference, etc.)
3. WHEN CodeQL is selected THEN the system SHALL run CodeQL with appropriate language detection and security queries for multi-language support
4. WHEN the selected analysis tool completes THEN the system SHALL collect findings into a unified format recording file, function, rule ID, severity, and confidence
5. WHEN tools generate raw output THEN the system SHALL normalize findings to consistent severity levels (Critical, High, Medium, Low)
6. WHEN duplicate vulnerabilities are detected within the selected tool's results THEN the system SHALL deduplicate based on file location and vulnerability type
7. WHEN static analysis completes THEN the system SHALL convert output into compact machine-readable format (static_findings.json)

#### FR1-3: Vulnerability Classification and Prioritization
**User Story:** As a developer, I want static analysis findings to be properly classified and prioritized so that I can focus remediation efforts on the most critical security issues.

##### Acceptance Criteria
1. WHEN static analysis completes THEN the system SHALL label findings by type (memory corruption, integer overflow, use-after-free, buffer overflow)
2. WHEN severity assessment occurs THEN the system SHALL compute numeric priority from severity and confidence scores
3. WHEN classification completes THEN priority SHALL guide the order in which vulnerabilities are reported and addressed
4. WHEN multiple vulnerabilities exist THEN the system SHALL rank them using CVSS-based scoring: Critical (9.0-10.0), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9)
5. WHEN findings are processed THEN the system SHALL evaluate vulnerability severity (Critical, High, Medium, Low) and confidence levels
6. WHEN prioritization occurs THEN the system SHALL consider exploitability, impact, and confidence in final ranking
7. WHEN classification is complete THEN the system SHALL prepare findings for SARIF report generation

#### FR1-4: SARIF Report Generation and Standards Compliance
**User Story:** As a developer, I want to receive standardized vulnerability reports in SARIF format so that I can integrate findings with existing development tools and workflows.

##### Acceptance Criteria
1. WHEN vulnerability detection completes THEN the system SHALL generate a valid SARIF 2.1.0 format report with all findings
2. WHEN creating SARIF output THEN the system SHALL include file paths, line numbers, vulnerability descriptions, CWE mappings, and severity levels
3. WHEN the selected tool contributes findings THEN the system SHALL generate a SARIF document with proper tool attribution
4. WHEN SARIF report is generated THEN it SHALL include tool metadata, scan timestamps, and rule information
5. WHEN findings are deduplicated THEN the system SHALL preserve the highest severity instance of each unique vulnerability
6. WHEN the report is complete THEN the system SHALL validate SARIF schema compliance before returning results
7. WHEN SARIF generation occurs THEN the system SHALL maintain traceability between static findings, dynamic results, and final report entries

#### FR1-5: Containerized Processing and Isolation
**User Story:** As a platform operator, I want all analysis operations to run in isolated containers so that the system remains secure and scalable while processing potentially malicious code.

##### Acceptance Criteria
1. WHEN a scan job is queued THEN the system SHALL create an isolated Docker container with Cppcheck and CodeQL tools
2. WHEN containers are created THEN they SHALL run with minimal privileges and no network access except for tool updates
3. WHEN scan processing begins THEN containers SHALL have access only to the specific code being analyzed
4. WHEN scans complete or timeout (15 minutes) THEN containers SHALL be automatically destroyed with all temporary data
5. WHEN multiple scans run concurrently THEN each SHALL operate in complete isolation with resource limits enforced
6. WHEN container resources are exhausted THEN new jobs SHALL queue until resources become available
7. WHEN containers are destroyed THEN all traces of processed code SHALL be cryptographically wiped from memory

#### FR1-6: Privacy-First Ephemeral Processing
**User Story:** As a privacy-conscious user, I want assurance that my code is never persistently stored and is completely removed after analysis so that my intellectual property remains secure.

##### Acceptance Criteria
1. WHEN code is received THEN the system SHALL store it only in temporary directories with automatic cleanup within 60 seconds
2. WHEN scan processing begins THEN all code SHALL reside only in container ephemeral storage
3. WHEN scan results are generated THEN only SARIF reports and vulnerability findings SHALL be retained in session storage
4. WHEN system restarts THEN any remaining temporary files SHALL be automatically purged
5. WHEN scan progress occurs THEN the system SHALL provide real-time status updates via API endpoints
6. WHEN errors occur THEN the system SHALL log technical details internally while showing user-friendly messages externally
7. WHEN user sessions expire THEN all associated scan data SHALL be permanently removed

## Representative Artifacts

### Static Findings Format (static_findings.json)
A single finding entry has the following structure:
```json
{
  "file": "demo/parse.cc",
  "function": "ParseFrame", 
  "rule_id": "bounds",
  "severity": "high",
  "confidence": "high",
  "message": "Possible out-of-bounds write in buffer copy"
}
```



## Non-Functional Requirements

### Reliability
- **REL-1:** The Flask web application SHALL maintain 99.5% uptime during normal operation
- **REL-2:** The system SHALL automatically retry failed container operations up to 3 times before reporting failure
- **REL-3:** Upon transient failures, the system SHALL preserve scan state and allow users to resume or restart
- **REL-4:** Container failures SHALL not affect other concurrent scans or web application stability

### Performance  
- **PER-1:** Static analysis for codebases under 10,000 LOC SHALL complete within 5 minutes

- **PER-3:** The web interface SHALL respond to user interactions within 2 seconds under normal load
- **PER-4:** The system SHALL support up to 10 concurrent scans without performance degradation exceeding 20%

### Security
- **SEC-1:** All web communications SHALL use HTTPS with TLS 1.2 or higher encryption
- **SEC-2:** All containers SHALL run in isolated, non-root user namespaces with restricted capabilities
- **SEC-3:** OAuth tokens and API keys SHALL be stored securely using environment variables and session management
- **SEC-4:** Uploaded code SHALL never be persistently stored and SHALL be cryptographically wiped after processing
- **SEC-5:** The system SHALL validate all user inputs to prevent injection attacks and malicious file uploads

### Usability
- **USE-1:** New users SHALL be able to perform their first scan within 2 minutes of accessing the application
- **USE-2:** The web interface SHALL provide clear progress indicators and estimated completion times for scans
- **USE-3:** Error messages SHALL be user-friendly while logging technical details for debugging
- **USE-4:** Scan results SHALL be presented with clear severity indicators and actionable remediation guidance

### Scalability
- **SCA-1:** The system SHALL automatically scale container instances based on queue depth and resource availability
- **SCA-2:** The Flask application SHALL support horizontal scaling through load balancing
- **SCA-3:** Session storage SHALL support distributed deployment across multiple application instances
- **SCA-4:** The system SHALL handle traffic spikes up to 5x normal load without service degradation

### Privacy
- **PRI-1:** Anonymous scans SHALL not require personal information or account creation
- **PRI-2:** All temporary files SHALL be automatically deleted within 60 seconds of scan completion
- **PRI-3:** Scan results SHALL be stored only in user sessions with automatic expiration
- **PRI-4:** The system SHALL provide clear privacy notices about ephemeral data handling policies