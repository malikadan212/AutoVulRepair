"""
Signature Extraction Module
Extracts function signatures from C/C++ source code
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Dict


@dataclass
class Parameter:
    """Function parameter information"""
    name: str
    type: str
    is_pointer: bool = False
    is_const: bool = False
    is_reference: bool = False
    array_size: Optional[int] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'type': self.type,
            'is_pointer': self.is_pointer,
            'is_const': self.is_const,
            'is_reference': self.is_reference,
            'array_size': self.array_size
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Parameter':
        """Create from dictionary"""
        return cls(
            name=data['name'],
            type=data['type'],
            is_pointer=data.get('is_pointer', False),
            is_const=data.get('is_const', False),
            is_reference=data.get('is_reference', False),
            array_size=data.get('array_size')
        )
    
    def get_base_type(self) -> str:
        """Get base type without qualifiers"""
        base = self.type.replace('const', '').replace('*', '').replace('&', '').strip()
        return base


@dataclass
class FunctionSignature:
    """Function signature information"""
    function_name: str
    return_type: str
    parameters: List[Parameter]
    is_const: bool = False
    is_static: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'function_name': self.function_name,
            'return_type': self.return_type,
            'parameters': [p.to_dict() for p in self.parameters],
            'param_count': len(self.parameters),
            'is_const': self.is_const,
            'is_static': self.is_static
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'FunctionSignature':
        """Create from dictionary"""
        return cls(
            function_name=data['function_name'],
            return_type=data['return_type'],
            parameters=[Parameter.from_dict(p) for p in data['parameters']],
            is_const=data.get('is_const', False),
            is_static=data.get('is_static', False)
        )


class SignatureExtractor:
    """Extract function signatures from C/C++ source code"""
    
    # Regex patterns for function signature extraction
    SIGNATURE_PATTERNS = [
        # Standard: return_type function_name(params)
        r'\b(\w+(?:\s*\*)*)\s+(\w+)\s*\((.*?)\)\s*(?:;|{)',
        
        # With modifiers: static/const/inline return_type function_name(params)
        r'\b(static|const|inline)\s+(\w+(?:\s*\*)*)\s+(\w+)\s*\((.*?)\)\s*(?:;|{)',
        
        # Pointer return: return_type* function_name(params)
        r'\b(\w+)\s*(\*+)\s*(\w+)\s*\((.*?)\)\s*(?:;|{)',
        
        # Template functions: template<...> return_type function_name(params)
        r'template\s*<[^>]+>\s*(\w+(?:\s*\*)*)\s+(\w+)\s*\((.*?)\)\s*(?:;|{)',
        
        # Extern "C": extern "C" return_type function_name(params)
        r'extern\s+"C"\s+(\w+(?:\s*\*)*)\s+(\w+)\s*\((.*?)\)\s*(?:;|{)',
        
        # Multiple modifiers: static inline return_type function_name(params)
        r'\b(static|const|inline)\s+(static|const|inline)\s+(\w+(?:\s*\*)*)\s+(\w+)\s*\((.*?)\)\s*(?:;|{)',
    ]
    
    def extract_function_signature(
        self,
        source_code: str,
        function_name: str
    ) -> Optional[FunctionSignature]:
        """
        Extract function signature from source code
        
        Args:
            source_code: Source file content
            function_name: Target function name
            
        Returns:
            FunctionSignature object or None if not found
        """
        # Try patterns in order from most specific to least specific
        # This ensures modifiers are detected before falling back to standard pattern
        pattern_order = [5, 1, 3, 4, 2, 0]  # Multiple modifiers, single modifier, template, extern, pointer, standard
        
        for pattern_idx in pattern_order:
            # Create pattern specific to the function name
            if pattern_idx == 0:
                # Standard pattern
                pattern = rf'\b(\w+(?:\s*\*)*)\s+{re.escape(function_name)}\s*\((.*?)\)\s*(?:;|{{)'
            elif pattern_idx == 1:
                # With single modifier
                pattern = rf'\b(static|const|inline)\s+(\w+(?:\s*\*)*)\s+{re.escape(function_name)}\s*\((.*?)\)\s*(?:;|{{)'
            elif pattern_idx == 2:
                # Pointer return
                pattern = rf'\b(\w+)\s*(\*+)\s*{re.escape(function_name)}\s*\((.*?)\)\s*(?:;|{{)'
            elif pattern_idx == 3:
                # Template
                pattern = rf'template\s*<[^>]+>\s*(\w+(?:\s*\*)*)\s+{re.escape(function_name)}\s*\((.*?)\)\s*(?:;|{{)'
            elif pattern_idx == 4:
                # Extern "C"
                pattern = rf'extern\s+"C"\s+(\w+(?:\s*\*)*)\s+{re.escape(function_name)}\s*\((.*?)\)\s*(?:;|{{)'
            elif pattern_idx == 5:
                # Multiple modifiers
                pattern = rf'\b(static|const|inline)\s+(static|const|inline)\s+(\w+(?:\s*\*)*)\s+{re.escape(function_name)}\s*\((.*?)\)\s*(?:;|{{)'
            else:
                continue
            
            match = re.search(pattern, source_code, re.MULTILINE | re.DOTALL)
            if match:
                return self._parse_match(match, function_name, pattern_idx)
        
        return None
    
    def _parse_match(
        self,
        match: re.Match,
        function_name: str,
        pattern_idx: int
    ) -> FunctionSignature:
        """Parse regex match into FunctionSignature"""
        is_static = False
        is_const = False
        return_type = ""
        params_str = ""
        
        groups = match.groups()
        
        if pattern_idx == 0:
            # Standard pattern: (return_type, params)
            return_type = groups[0].strip()
            params_str = groups[1].strip()
        elif pattern_idx == 1:
            # With modifier: (modifier, return_type, params)
            modifier = groups[0].strip().lower()
            is_static = modifier == 'static'
            is_const = modifier == 'const'
            return_type = groups[1].strip()
            params_str = groups[2].strip()
        elif pattern_idx == 2:
            # Pointer return: (base_type, pointer, params)
            return_type = groups[0].strip() + groups[1].strip()
            params_str = groups[2].strip()
        elif pattern_idx == 3:
            # Template: (return_type, params)
            return_type = groups[0].strip()
            params_str = groups[1].strip()
        elif pattern_idx == 4:
            # Extern "C": (return_type, params)
            return_type = groups[0].strip()
            params_str = groups[1].strip()
        elif pattern_idx == 5:
            # Multiple modifiers: (modifier1, modifier2, return_type, params)
            is_static = 'static' in [groups[0].lower(), groups[1].lower()]
            is_const = 'const' in [groups[0].lower(), groups[1].lower()]
            return_type = groups[2].strip()
            params_str = groups[3].strip()
        
        # Parse parameters
        parameters = self.parse_parameters(params_str)
        
        return FunctionSignature(
            function_name=function_name,
            return_type=return_type,
            parameters=parameters,
            is_const=is_const,
            is_static=is_static
        )
    
    def parse_parameters(self, param_string: str) -> List[Parameter]:
        """
        Parse parameter string into structured parameter list
        
        Args:
            param_string: Raw parameter string from function declaration
            
        Returns:
            List of Parameter objects
        """
        if not param_string or param_string.strip() == '' or param_string.strip() == 'void':
            return []
        
        parameters = []
        
        # Split by comma, but be careful with nested templates
        param_parts = self._split_parameters(param_string)
        
        for idx, param in enumerate(param_parts):
            param = param.strip()
            if not param:
                continue
            
            # Parse individual parameter
            parsed = self._parse_single_parameter(param, idx)
            if parsed:
                parameters.append(parsed)
        
        return parameters
    
    def _split_parameters(self, param_string: str) -> List[str]:
        """Split parameter string by commas, respecting nested brackets"""
        params = []
        current = []
        depth = 0
        
        for char in param_string:
            if char in '<([':
                depth += 1
                current.append(char)
            elif char in '>)]':
                depth -= 1
                current.append(char)
            elif char == ',' and depth == 0:
                params.append(''.join(current))
                current = []
            else:
                current.append(char)
        
        if current:
            params.append(''.join(current))
        
        return params
    
    def _parse_single_parameter(self, param: str, idx: int) -> Optional[Parameter]:
        """Parse a single parameter declaration"""
        # Check for const
        is_const = 'const' in param
        
        # Check for pointer
        is_pointer = '*' in param
        
        # Check for reference
        is_reference = '&' in param
        
        # Check for array
        array_size = None
        array_match = re.search(r'\[(\d+)\]', param)
        if array_match:
            array_size = int(array_match.group(1))
        
        # Remove const, *, &, [] to get base type and name
        cleaned = param.replace('const', '').replace('*', '').replace('&', '')
        cleaned = re.sub(r'\[\d*\]', '', cleaned).strip()
        
        # Split into type and name
        parts = cleaned.split()
        
        if len(parts) == 0:
            return None
        elif len(parts) == 1:
            # Only type, no name - generate a name
            param_type = parts[0]
            param_name = f'param{idx}'
        else:
            # Last part is name, rest is type
            param_name = parts[-1]
            param_type = ' '.join(parts[:-1])
        
        # Reconstruct full type with qualifiers
        full_type = param_type
        if is_const:
            full_type = 'const ' + full_type
        if is_pointer:
            full_type = full_type + '*'
        if is_reference:
            full_type = full_type + '&'
        
        return Parameter(
            name=param_name,
            type=full_type.strip(),
            is_pointer=is_pointer,
            is_const=is_const,
            is_reference=is_reference,
            array_size=array_size
        )
