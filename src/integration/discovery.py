"""
Integration Target Discovery Module
Discovers API endpoints and component chains for integration fuzzing
"""

import os
import re
import ast
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class ComponentFunction:
    """Represents a function in a component chain"""
    name: str
    file_path: str
    line_number: int
    parameters: List[Dict]
    return_type: str
    calls: List[str]  # Functions this function calls
    is_entry_point: bool = False
    is_validation: bool = False
    is_auth: bool = False
    is_database: bool = False


@dataclass
class IntegrationChain:
    """Represents a chain of components for integration testing"""
    chain_id: str
    entry_point: ComponentFunction
    components: List[ComponentFunction]
    vulnerability_surface: List[str]
    data_flow: List[str]
    priority_score: float
    endpoint_type: str  # 'http', 'api', 'cli', 'file_processing'


class IntegrationTargetDiscovery:
    """Discovers integration fuzzing targets from codebase"""
    
    # Patterns for identifying different types of entry points
    HTTP_PATTERNS = [
        r'@app\.route\(',           # Flask routes
        r'@router\.',               # FastAPI routes  
        r'app\.(get|post|put|delete|patch)\(',  # Express.js style
        r'def\s+\w+.*request.*:',   # Request handlers
        r'class.*Handler.*:',       # Handler classes
        r'def\s+handle_\w+',        # Handle functions
    ]
    
    API_PATTERNS = [
        r'def\s+api_\w+',           # API functions
        r'class.*API.*:',           # API classes
        r'def\s+\w+_endpoint',      # Endpoint functions
        r'@api\.',                  # API decorators
        r'def\s+process_\w+',       # Processing functions
    ]
    
    CLI_PATTERNS = [
        r'def\s+main\(',            # Main functions
        r'if\s+__name__\s*==\s*["\']__main__["\']',  # Main blocks
        r'argparse\.',              # Command line parsing
        r'def\s+parse_args',        # Argument parsing
    ]
    
    FILE_PROCESSING_PATTERNS = [
        r'def\s+\w*parse\w*',       # Parse functions
        r'def\s+\w*process\w*',     # Process functions
        r'def\s+\w*load\w*',        # Load functions
        r'def\s+\w*read\w*',        # Read functions
        r'open\(',                  # File operations
    ]
    
    # Patterns for identifying component types
    VALIDATION_PATTERNS = [
        r'validate', r'check', r'verify', r'sanitize', r'clean'
    ]
    
    AUTH_PATTERNS = [
        r'auth', r'login', r'token', r'credential', r'permission', r'authorize'
    ]
    
    DATABASE_PATTERNS = [
        r'db', r'database', r'sql', r'query', r'insert', r'update', r'delete', r'select'
    ]
    
    def __init__(self, scan_dir: str):
        """Initialize discovery with scan directory"""
        self.scan_dir = scan_dir
        self.source_files = []
        self.functions = {}  # file_path -> List[ComponentFunction]
        self.call_graph = defaultdict(list)  # function_name -> [called_functions]
        
    def discover_source_files(self) -> List[str]:
        """Discover source files in the scan directory"""
        source_extensions = {'.py', '.cpp', '.c', '.cc', '.cxx', '.h', '.hpp', '.js', '.ts'}
        source_files = []
        
        for root, dirs, files in os.walk(self.scan_dir):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'build', 'dist']]
            
            for file in files:
                if any(file.endswith(ext) for ext in source_extensions):
                    file_path = os.path.join(root, file)
                    source_files.append(file_path)
        
        logger.info(f"Found {len(source_files)} source files")
        self.source_files = source_files
        return source_files
    
    def _extract_python_functions(self, file_path: str) -> List[ComponentFunction]:
        """Extract functions from Python source file"""
        functions = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Extract function info
                    func_name = node.name
                    line_number = node.lineno
                    
                    # Extract parameters
                    parameters = []
                    for arg in node.args.args:
                        param = {
                            'name': arg.arg,
                            'type': 'unknown',  # Python doesn't have static types by default
                            'annotation': ast.unparse(arg.annotation) if arg.annotation else None
                        }
                        parameters.append(param)
                    
                    # Extract function calls within this function
                    calls = []
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            if isinstance(child.func, ast.Name):
                                calls.append(child.func.id)
                            elif isinstance(child.func, ast.Attribute):
                                calls.append(child.func.attr)
                    
                    # Determine function characteristics
                    func_content = ast.unparse(node).lower()
                    is_entry_point = self._is_entry_point(func_name, func_content)
                    is_validation = any(pattern in func_name.lower() or pattern in func_content 
                                      for pattern in self.VALIDATION_PATTERNS)
                    is_auth = any(pattern in func_name.lower() or pattern in func_content 
                                for pattern in self.AUTH_PATTERNS)
                    is_database = any(pattern in func_name.lower() or pattern in func_content 
                                    for pattern in self.DATABASE_PATTERNS)
                    
                    func = ComponentFunction(
                        name=func_name,
                        file_path=file_path,
                        line_number=line_number,
                        parameters=parameters,
                        return_type='unknown',
                        calls=calls,
                        is_entry_point=is_entry_point,
                        is_validation=is_validation,
                        is_auth=is_auth,
                        is_database=is_database
                    )
                    
                    functions.append(func)
                    
        except Exception as e:
            logger.warning(f"Failed to parse Python file {file_path}: {e}")
        
        return functions
    
    def _extract_cpp_functions(self, file_path: str) -> List[ComponentFunction]:
        """Extract functions from C/C++ source file using regex patterns"""
        functions = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Simple regex-based function extraction for C/C++
            # This is basic but sufficient for integration discovery
            function_pattern = r'(?:^|\n)\s*(?:static\s+)?(?:inline\s+)?(?:\w+\s+)*(\w+)\s*\(\s*([^)]*)\s*\)\s*\{'
            
            for match in re.finditer(function_pattern, content, re.MULTILINE):
                func_name = match.group(1)
                params_str = match.group(2)
                line_number = content[:match.start()].count('\n') + 1
                
                # Skip common non-function matches
                if func_name in ['if', 'for', 'while', 'switch', 'return']:
                    continue
                
                # Parse parameters (basic)
                parameters = []
                if params_str.strip():
                    for param in params_str.split(','):
                        param = param.strip()
                        if param and param != 'void':
                            parts = param.split()
                            if len(parts) >= 2:
                                param_type = ' '.join(parts[:-1])
                                param_name = parts[-1].strip('*&')
                                parameters.append({
                                    'name': param_name,
                                    'type': param_type,
                                    'annotation': None
                                })
                
                # Extract function calls (basic pattern matching)
                func_body_start = match.end()
                brace_count = 1
                func_body_end = func_body_start
                
                for i, char in enumerate(content[func_body_start:], func_body_start):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            func_body_end = i
                            break
                
                func_body = content[func_body_start:func_body_end]
                
                # Find function calls in body
                call_pattern = r'(\w+)\s*\('
                calls = []
                for call_match in re.finditer(call_pattern, func_body):
                    call_name = call_match.group(1)
                    if call_name not in ['if', 'for', 'while', 'switch', 'return', 'sizeof']:
                        calls.append(call_name)
                
                # Determine function characteristics
                func_content = (func_name + ' ' + func_body).lower()
                is_entry_point = self._is_entry_point(func_name, func_content)
                is_validation = any(pattern in func_name.lower() or pattern in func_content 
                                  for pattern in self.VALIDATION_PATTERNS)
                is_auth = any(pattern in func_name.lower() or pattern in func_content 
                            for pattern in self.AUTH_PATTERNS)
                is_database = any(pattern in func_name.lower() or pattern in func_content 
                                for pattern in self.DATABASE_PATTERNS)
                
                func = ComponentFunction(
                    name=func_name,
                    file_path=file_path,
                    line_number=line_number,
                    parameters=parameters,
                    return_type='unknown',
                    calls=list(set(calls)),  # Remove duplicates
                    is_entry_point=is_entry_point,
                    is_validation=is_validation,
                    is_auth=is_auth,
                    is_database=is_database
                )
                
                functions.append(func)
                
        except Exception as e:
            logger.warning(f"Failed to parse C/C++ file {file_path}: {e}")
        
        return functions
    
    def _is_entry_point(self, func_name: str, func_content: str) -> bool:
        """Determine if function is an entry point"""
        # Check function name patterns
        entry_point_names = ['main', 'handler', 'endpoint', 'route', 'api', 'process']
        if any(pattern in func_name.lower() for pattern in entry_point_names):
            return True
        
        # Check content patterns
        all_patterns = (self.HTTP_PATTERNS + self.API_PATTERNS + 
                       self.CLI_PATTERNS + self.FILE_PROCESSING_PATTERNS)
        
        for pattern in all_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                return True
        
        return False
    
    def analyze_functions(self) -> Dict[str, List[ComponentFunction]]:
        """Analyze all source files and extract functions"""
        logger.info("Analyzing functions in source files...")
        
        for file_path in self.source_files:
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext == '.py':
                functions = self._extract_python_functions(file_path)
            elif file_ext in ['.cpp', '.c', '.cc', '.cxx', '.h', '.hpp']:
                functions = self._extract_cpp_functions(file_path)
            else:
                # For other file types, we could add more parsers
                continue
            
            if functions:
                self.functions[file_path] = functions
                logger.debug(f"Found {len(functions)} functions in {file_path}")
        
        total_functions = sum(len(funcs) for funcs in self.functions.values())
        logger.info(f"Analyzed {total_functions} functions across {len(self.functions)} files")
        
        return self.functions
    
    def build_call_graph(self) -> Dict[str, List[str]]:
        """Build call graph from analyzed functions"""
        logger.info("Building call graph...")
        
        # Create function name to function mapping
        func_map = {}
        for file_funcs in self.functions.values():
            for func in file_funcs:
                func_map[func.name] = func
        
        # Build call graph
        for file_funcs in self.functions.values():
            for func in file_funcs:
                for called_func in func.calls:
                    if called_func in func_map:
                        self.call_graph[func.name].append(called_func)
        
        logger.info(f"Built call graph with {len(self.call_graph)} nodes")
        return dict(self.call_graph)
    
    def _trace_data_flow(self, entry_point: ComponentFunction, max_depth: int = 5) -> List[ComponentFunction]:
        """Trace data flow from entry point through component chain"""
        visited = set()
        chain = []
        
        def dfs(func_name: str, depth: int):
            if depth >= max_depth or func_name in visited:
                return
            
            visited.add(func_name)
            
            # Find function object
            func_obj = None
            for file_funcs in self.functions.values():
                for func in file_funcs:
                    if func.name == func_name:
                        func_obj = func
                        break
                if func_obj:
                    break
            
            if func_obj:
                chain.append(func_obj)
                
                # Continue tracing through called functions
                for called_func in func_obj.calls:
                    dfs(called_func, depth + 1)
        
        dfs(entry_point.name, 0)
        return chain
    
    def _analyze_vulnerability_surface(self, chain: List[ComponentFunction]) -> List[str]:
        """Analyze vulnerability surface of component chain"""
        vulnerabilities = []
        
        # Check for common vulnerability patterns
        has_input_parsing = any('parse' in func.name.lower() for func in chain)
        has_validation = any(func.is_validation for func in chain)
        has_auth = any(func.is_auth for func in chain)
        has_database = any(func.is_database for func in chain)
        
        # Identify potential vulnerability classes
        if has_input_parsing and not has_validation:
            vulnerabilities.append('input_validation_bypass')
        
        if has_auth and has_input_parsing:
            vulnerabilities.append('authentication_bypass')
        
        if has_database and has_input_parsing:
            vulnerabilities.append('injection_vulnerability')
        
        if len(chain) > 3:  # Complex chains are more likely to have integration bugs
            vulnerabilities.append('component_interaction_bug')
        
        # Check for state management issues
        state_functions = [func for func in chain if 'state' in func.name.lower() or 'session' in func.name.lower()]
        if state_functions:
            vulnerabilities.append('state_corruption')
        
        return vulnerabilities
    
    def _calculate_priority_score(self, chain: List[ComponentFunction], vulnerabilities: List[str]) -> float:
        """Calculate priority score for integration chain"""
        base_score = 5.0
        
        # Boost for entry points (more likely to be attack surface)
        if any(func.is_entry_point for func in chain):
            base_score += 2.0
        
        # Boost for authentication chains
        if any(func.is_auth for func in chain):
            base_score += 3.0
        
        # Boost for database chains
        if any(func.is_database for func in chain):
            base_score += 2.0
        
        # Boost for validation chains
        if any(func.is_validation for func in chain):
            base_score += 1.5
        
        # Boost for vulnerability surface
        base_score += len(vulnerabilities) * 1.0
        
        # Boost for chain complexity
        base_score += min(len(chain) * 0.5, 3.0)
        
        return round(base_score, 2)
    
    def _determine_endpoint_type(self, entry_point: ComponentFunction) -> str:
        """Determine the type of endpoint"""
        func_content = (entry_point.name + ' ' + str(entry_point.calls)).lower()
        
        # Check for HTTP patterns
        for pattern in self.HTTP_PATTERNS:
            if re.search(pattern, func_content, re.IGNORECASE):
                return 'http'
        
        # Check for API patterns
        for pattern in self.API_PATTERNS:
            if re.search(pattern, func_content, re.IGNORECASE):
                return 'api'
        
        # Check for CLI patterns
        for pattern in self.CLI_PATTERNS:
            if re.search(pattern, func_content, re.IGNORECASE):
                return 'cli'
        
        # Check for file processing patterns
        for pattern in self.FILE_PROCESSING_PATTERNS:
            if re.search(pattern, func_content, re.IGNORECASE):
                return 'file_processing'
        
        return 'unknown'
    
    def discover_integration_chains(self) -> List[IntegrationChain]:
        """Discover integration chains for fuzzing"""
        logger.info("Discovering integration chains...")
        
        # First analyze functions and build call graph
        self.analyze_functions()
        self.build_call_graph()
        
        # Find entry points
        entry_points = []
        for file_funcs in self.functions.values():
            for func in file_funcs:
                if func.is_entry_point:
                    entry_points.append(func)
        
        logger.info(f"Found {len(entry_points)} entry points")
        
        # Generate integration chains
        chains = []
        for entry_point in entry_points:
            # Trace data flow from entry point
            component_chain = self._trace_data_flow(entry_point)
            
            # Skip chains that are too short (not interesting for integration testing)
            if len(component_chain) < 2:
                continue
            
            # Analyze vulnerability surface
            vulnerabilities = self._analyze_vulnerability_surface(component_chain)
            
            # Calculate priority
            priority = self._calculate_priority_score(component_chain, vulnerabilities)
            
            # Determine endpoint type
            endpoint_type = self._determine_endpoint_type(entry_point)
            
            # Create data flow description
            data_flow = [f"{func.name}({len(func.parameters)} params)" for func in component_chain]
            
            chain = IntegrationChain(
                chain_id=f"integration_{entry_point.name}_{len(chains)}",
                entry_point=entry_point,
                components=component_chain,
                vulnerability_surface=vulnerabilities,
                data_flow=data_flow,
                priority_score=priority,
                endpoint_type=endpoint_type
            )
            
            chains.append(chain)
        
        # Sort by priority (highest first)
        chains.sort(key=lambda c: c.priority_score, reverse=True)
        
        logger.info(f"Discovered {len(chains)} integration chains")
        return chains
    
    def export_chains_to_json(self, chains: List[IntegrationChain], output_path: str) -> None:
        """Export discovered chains to JSON file"""
        chains_data = []
        
        for chain in chains:
            chain_data = {
                'chain_id': chain.chain_id,
                'entry_point': {
                    'name': chain.entry_point.name,
                    'file_path': chain.entry_point.file_path,
                    'line_number': chain.entry_point.line_number,
                    'parameters': chain.entry_point.parameters
                },
                'components': [
                    {
                        'name': comp.name,
                        'file_path': comp.file_path,
                        'line_number': comp.line_number,
                        'is_validation': comp.is_validation,
                        'is_auth': comp.is_auth,
                        'is_database': comp.is_database,
                        'calls': comp.calls
                    }
                    for comp in chain.components
                ],
                'vulnerability_surface': chain.vulnerability_surface,
                'data_flow': chain.data_flow,
                'priority_score': chain.priority_score,
                'endpoint_type': chain.endpoint_type
            }
            chains_data.append(chain_data)
        
        output_data = {
            'generated_at': json.dumps(None, default=str),  # Will be replaced by datetime
            'scan_dir': self.scan_dir,
            'total_chains': len(chains),
            'chains': chains_data
        }
        
        # Replace the datetime placeholder
        import datetime
        output_data['generated_at'] = datetime.datetime.now().isoformat()
        
        # Create directory if output_path has a directory component
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Exported {len(chains)} integration chains to {output_path}")
    
    def generate_summary_report(self, chains: List[IntegrationChain]) -> Dict:
        """Generate summary report of discovered chains"""
        if not chains:
            return {
                'total_chains': 0,
                'endpoint_types': {},
                'vulnerability_classes': {},
                'top_priority_chains': []
            }
        
        # Count endpoint types
        endpoint_types = defaultdict(int)
        for chain in chains:
            endpoint_types[chain.endpoint_type] += 1
        
        # Count vulnerability classes
        vulnerability_classes = defaultdict(int)
        for chain in chains:
            for vuln in chain.vulnerability_surface:
                vulnerability_classes[vuln] += 1
        
        # Get top priority chains
        top_chains = chains[:5]  # Top 5 by priority
        
        return {
            'total_chains': len(chains),
            'endpoint_types': dict(endpoint_types),
            'vulnerability_classes': dict(vulnerability_classes),
            'average_priority': sum(c.priority_score for c in chains) / len(chains),
            'average_chain_length': sum(len(c.components) for c in chains) / len(chains),
            'top_priority_chains': [
                {
                    'chain_id': chain.chain_id,
                    'entry_point': chain.entry_point.name,
                    'priority_score': chain.priority_score,
                    'endpoint_type': chain.endpoint_type,
                    'vulnerability_surface': chain.vulnerability_surface,
                    'chain_length': len(chain.components)
                }
                for chain in top_chains
            ]
        }


def main():
    """CLI interface for integration discovery"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Discover integration fuzzing targets')
    parser.add_argument('scan_dir', help='Directory to scan for source files')
    parser.add_argument('--output', '-o', default='integration_chains.json', 
                       help='Output file for discovered chains')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')
    
    # Run discovery
    discovery = IntegrationTargetDiscovery(args.scan_dir)
    chains = discovery.discover_integration_chains()
    
    # Export results
    discovery.export_chains_to_json(chains, args.output)
    
    # Print summary
    summary = discovery.generate_summary_report(chains)
    print(f"\nDiscovery Summary:")
    print(f"Total chains: {summary['total_chains']}")
    print(f"Endpoint types: {summary['endpoint_types']}")
    print(f"Vulnerability classes: {summary['vulnerability_classes']}")
    
    if summary['top_priority_chains']:
        print(f"\nTop Priority Chains:")
        for chain in summary['top_priority_chains']:
            print(f"  {chain['chain_id']}: {chain['entry_point']} (priority: {chain['priority_score']})")


if __name__ == '__main__':
    main()