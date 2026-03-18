"""
Parameter Mapping Module
Maps function parameters to fuzzer data preparation code
"""

from dataclasses import dataclass
from typing import List, Dict
from src.harness.signature_extractor import Parameter, FunctionSignature


@dataclass
class ParameterMapping:
    """Parameter mapping strategy for harness generation"""
    parameters: List[Parameter]
    preparation_code: str
    function_call: str
    includes: List[str]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'parameters': [p.to_dict() for p in self.parameters],
            'preparation_code': self.preparation_code,
            'function_call': self.function_call,
            'includes': self.includes
        }


class ParameterMapper:
    """Maps function parameters to fuzzer data preparation strategies"""
    
    # Type categories for parameter classification
    STRING_TYPES = ['char*', 'const char*', 'std::string', 'const std::string&']
    BUFFER_TYPES = ['uint8_t*', 'const uint8_t*', 'void*', 'const void*', 'unsigned char*', 'const unsigned char*']
    SIZE_TYPES = ['size_t', 'int', 'unsigned int', 'uint32_t', 'unsigned', 'long', 'unsigned long']
    INTEGER_TYPES = ['int', 'long', 'short', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
                     'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'unsigned', 'signed']
    BOOLEAN_TYPES = ['bool', '_Bool']
    FLOAT_TYPES = ['float', 'double', 'long double']
    
    def map_parameters(
        self,
        signature: FunctionSignature,
        harness_type: str = 'parser_wrapper'
    ) -> ParameterMapping:
        """
        Create parameter mapping strategy for signature
        
        Args:
            signature: Function signature information
            harness_type: Type of harness being generated
            
        Returns:
            ParameterMapping with preparation and call code
        """
        if not signature.parameters:
            # No parameters - simple call
            return ParameterMapping(
                parameters=[],
                preparation_code="  // No parameters needed\n",
                function_call=f"{signature.function_name}()",
                includes=[]
            )
        
        # Detect common parameter patterns
        pattern = self._detect_parameter_pattern(signature.parameters)
        
        if pattern:
            return self._generate_pattern_mapping(signature, pattern, harness_type)
        else:
            return self._generate_generic_mapping(signature, harness_type)
    
    def _detect_parameter_pattern(self, parameters: List[Parameter]) -> str:
        """Detect common parameter patterns"""
        if len(parameters) == 1:
            param = parameters[0]
            if self._is_string_type(param):
                return 'single_string'
            elif self._is_buffer_type(param):
                return 'single_buffer'
            elif self._is_integer_type(param):
                return 'single_integer'
        
        elif len(parameters) == 2:
            # Check for buffer + size pattern
            if (self._is_buffer_type(parameters[0]) and 
                self._is_size_type(parameters[1])):
                return 'buffer_size'
            # Check for size + buffer pattern (less common)
            elif (self._is_size_type(parameters[0]) and 
                  self._is_buffer_type(parameters[1])):
                return 'size_buffer'
        
        return ''
    
    def _generate_pattern_mapping(
        self,
        signature: FunctionSignature,
        pattern: str,
        harness_type: str
    ) -> ParameterMapping:
        """Generate mapping for detected pattern"""
        if pattern == 'single_string':
            return self._map_single_string(signature)
        elif pattern == 'single_buffer':
            return self._map_single_buffer(signature)
        elif pattern == 'single_integer':
            return self._map_single_integer(signature)
        elif pattern == 'buffer_size':
            return self._map_buffer_size(signature)
        elif pattern == 'size_buffer':
            return self._map_size_buffer(signature)
        else:
            return self._generate_generic_mapping(signature, harness_type)
    
    def _generate_generic_mapping(
        self,
        signature: FunctionSignature,
        harness_type: str
    ) -> ParameterMapping:
        """Generate generic mapping for any parameter list"""
        includes = ['<fuzzer/FuzzedDataProvider.h>']
        prep_lines = []
        call_args = []
        
        prep_lines.append("  // Initialize FuzzedDataProvider")
        prep_lines.append("  FuzzedDataProvider fdp(data, size);")
        prep_lines.append("")
        
        for idx, param in enumerate(signature.parameters):
            param_prep, param_arg = self._generate_param_preparation(param, idx, 'fdp')
            prep_lines.append(param_prep)
            call_args.append(param_arg)
        
        preparation_code = '\n'.join(prep_lines)
        function_call = f"{signature.function_name}({', '.join(call_args)})"
        
        return ParameterMapping(
            parameters=signature.parameters,
            preparation_code=preparation_code,
            function_call=function_call,
            includes=includes
        )
    
    def _map_single_string(self, signature: FunctionSignature) -> ParameterMapping:
        """Map single string parameter"""
        param = signature.parameters[0]
        param_name = param.name
        
        prep_code = f"""  // Prepare null-terminated string
  std::string str_data(reinterpret_cast<const char*>(data), size);
  const char* {param_name} = str_data.c_str();"""
        
        function_call = f"{signature.function_name}({param_name})"
        
        return ParameterMapping(
            parameters=signature.parameters,
            preparation_code=prep_code,
            function_call=function_call,
            includes=['<string>']
        )
    
    def _map_single_buffer(self, signature: FunctionSignature) -> ParameterMapping:
        """Map single buffer parameter"""
        param = signature.parameters[0]
        param_name = param.name
        param_type = param.type.replace('const', '').strip()
        
        prep_code = f"""  // Use fuzzer data as buffer
  {param.type} {param_name} = reinterpret_cast<{param_type}>(data);"""
        
        function_call = f"{signature.function_name}({param_name})"
        
        return ParameterMapping(
            parameters=signature.parameters,
            preparation_code=prep_code,
            function_call=function_call,
            includes=[]
        )
    
    def _map_single_integer(self, signature: FunctionSignature) -> ParameterMapping:
        """Map single integer parameter"""
        param = signature.parameters[0]
        param_name = param.name
        
        prep_code = f"""  // Extract integer from fuzzer data
  if (size < sizeof({param.type})) return 0;
  {param.type} {param_name} = *reinterpret_cast<const {param.type}*>(data);"""
        
        function_call = f"{signature.function_name}({param_name})"
        
        return ParameterMapping(
            parameters=signature.parameters,
            preparation_code=prep_code,
            function_call=function_call,
            includes=[]
        )
    
    def _map_buffer_size(self, signature: FunctionSignature) -> ParameterMapping:
        """Map buffer + size parameter pattern"""
        buffer_param = signature.parameters[0]
        size_param = signature.parameters[1]
        
        buffer_name = buffer_param.name
        size_name = size_param.name
        buffer_type = buffer_param.type.replace('const', '').strip()
        
        prep_code = f"""  // Use fuzzer data as buffer with size
  {buffer_param.type} {buffer_name} = reinterpret_cast<{buffer_type}>(data);
  {size_param.type} {size_name} = static_cast<{size_param.type}>(size);"""
        
        function_call = f"{signature.function_name}({buffer_name}, {size_name})"
        
        return ParameterMapping(
            parameters=signature.parameters,
            preparation_code=prep_code,
            function_call=function_call,
            includes=[]
        )
    
    def _map_size_buffer(self, signature: FunctionSignature) -> ParameterMapping:
        """Map size + buffer parameter pattern (less common)"""
        size_param = signature.parameters[0]
        buffer_param = signature.parameters[1]
        
        size_name = size_param.name
        buffer_name = buffer_param.name
        buffer_type = buffer_param.type.replace('const', '').strip()
        
        prep_code = f"""  // Use fuzzer data as buffer with size
  {size_param.type} {size_name} = static_cast<{size_param.type}>(size);
  {buffer_param.type} {buffer_name} = reinterpret_cast<{buffer_type}>(data);"""
        
        function_call = f"{signature.function_name}({size_name}, {buffer_name})"
        
        return ParameterMapping(
            parameters=signature.parameters,
            preparation_code=prep_code,
            function_call=function_call,
            includes=[]
        )
    
    def _generate_param_preparation(
        self,
        param: Parameter,
        param_index: int,
        fdp_var: str = 'fdp'
    ) -> tuple[str, str]:
        """
        Generate code to prepare a single parameter from fuzzer data
        
        Args:
            param: Parameter information
            param_index: Index in parameter list
            fdp_var: Name of FuzzedDataProvider variable
            
        Returns:
            Tuple of (preparation_code, argument_name)
        """
        param_name = param.name if param.name else f'param{param_index}'
        
        # Classify parameter type
        if self._is_string_type(param):
            prep = f"  std::string {param_name}_str = {fdp_var}.ConsumeRandomLengthString();\n"
            prep += f"  const char* {param_name} = {param_name}_str.c_str();"
            return (prep, param_name)
        
        elif self._is_buffer_type(param):
            prep = f"  std::vector<uint8_t> {param_name}_vec = {fdp_var}.ConsumeRemainingBytes<uint8_t>();\n"
            prep += f"  {param.type} {param_name} = reinterpret_cast<{param.type}>({param_name}_vec.data());"
            return (prep, param_name)
        
        elif self._is_boolean_type(param):
            prep = f"  bool {param_name} = {fdp_var}.ConsumeBool();"
            return (prep, param_name)
        
        elif self._is_float_type(param):
            if 'double' in param.type:
                prep = f"  double {param_name} = {fdp_var}.ConsumeFloatingPoint<double>();"
            else:
                prep = f"  float {param_name} = {fdp_var}.ConsumeFloatingPoint<float>();"
            return (prep, param_name)
        
        elif self._is_integer_type(param):
            base_type = param.get_base_type()
            prep = f"  {param.type} {param_name} = {fdp_var}.ConsumeIntegral<{base_type}>();"
            return (prep, param_name)
        
        else:
            # Unknown type - use raw bytes
            prep = f"  // TODO: Unknown parameter type '{param.type}'\n"
            prep += f"  // Manual implementation may be required\n"
            prep += f"  auto {param_name}_bytes = {fdp_var}.ConsumeBytes<uint8_t>(sizeof({param.type}));\n"
            prep += f"  {param.type} {param_name} = *reinterpret_cast<{param.type}*>({param_name}_bytes.data());"
            return (prep, param_name)
    
    def _is_string_type(self, param: Parameter) -> bool:
        """Check if parameter is a string type"""
        normalized = param.type.replace(' ', '')
        return any(st.replace(' ', '') in normalized for st in self.STRING_TYPES)
    
    def _is_buffer_type(self, param: Parameter) -> bool:
        """Check if parameter is a buffer type"""
        normalized = param.type.replace(' ', '')
        return any(bt.replace(' ', '') in normalized for bt in self.BUFFER_TYPES)
    
    def _is_size_type(self, param: Parameter) -> bool:
        """Check if parameter is a size type"""
        base_type = param.get_base_type()
        return base_type in self.SIZE_TYPES
    
    def _is_integer_type(self, param: Parameter) -> bool:
        """Check if parameter is an integer type"""
        base_type = param.get_base_type()
        return base_type in self.INTEGER_TYPES
    
    def _is_boolean_type(self, param: Parameter) -> bool:
        """Check if parameter is a boolean type"""
        base_type = param.get_base_type()
        return base_type in self.BOOLEAN_TYPES
    
    def _is_float_type(self, param: Parameter) -> bool:
        """Check if parameter is a floating point type"""
        base_type = param.get_base_type()
        return base_type in self.FLOAT_TYPES
