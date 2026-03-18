"""
Control Flow Graph Builder for MemFix
Parses C code and builds CFG with normalized commands
"""
import logging
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import re

logger = logging.getLogger(__name__)


class CommandType(Enum):
    """CFG command types"""
    ALLOC = "alloc"  # malloc/calloc
    FREE = "free"  # free()
    SET = "set"  # assignment
    USE = "use"  # dereference/read
    NOP = "nop"  # no pointer effect


@dataclass
class CFGNode:
    """Control Flow Graph Node"""
    node_id: int
    command_type: CommandType
    line_num: int
    original_code: str
    
    # Command-specific data
    lvalue: Optional[str] = None  # For SET
    rvalue: Optional[str] = None  # For SET
    ptr: Optional[str] = None  # For ALLOC, FREE, USE
    
    # CFG edges
    successors: List[int] = None
    predecessors: List[int] = None
    
    def __post_init__(self):
        if self.successors is None:
            self.successors = []
        if self.predecessors is None:
            self.predecessors = []
    
    def __str__(self):
        if self.command_type == CommandType.ALLOC:
            return f"Node{self.node_id}: alloc({self.ptr}) [line {self.line_num}]"
        elif self.command_type == CommandType.FREE:
            return f"Node{self.node_id}: free({self.ptr}) [line {self.line_num}]"
        elif self.command_type == CommandType.SET:
            return f"Node{self.node_id}: set({self.lvalue}, {self.rvalue}) [line {self.line_num}]"
        elif self.command_type == CommandType.USE:
            return f"Node{self.node_id}: use({self.ptr}) [line {self.line_num}]"
        else:
            return f"Node{self.node_id}: nop [line {self.line_num}]"


class CFG:
    """Control Flow Graph"""
    
    def __init__(self):
        self.nodes: Dict[int, CFGNode] = {}
        self.entry_node: Optional[int] = None
        self.exit_node: Optional[int] = None
        self.next_node_id = 0
    
    def add_node(self, node: CFGNode) -> int:
        """Add node to CFG"""
        self.nodes[node.node_id] = node
        return node.node_id
    
    def add_edge(self, from_id: int, to_id: int):
        """Add edge between nodes"""
        if from_id in self.nodes and to_id in self.nodes:
            self.nodes[from_id].successors.append(to_id)
            self.nodes[to_id].predecessors.append(from_id)
    
    def get_node(self, node_id: int) -> Optional[CFGNode]:
        """Get node by ID"""
        return self.nodes.get(node_id)
    
    def get_predecessors(self, node_id: int) -> List[int]:
        """Get predecessor node IDs"""
        node = self.nodes.get(node_id)
        return node.predecessors if node else []
    
    def get_successors(self, node_id: int) -> List[int]:
        """Get successor node IDs"""
        node = self.nodes.get(node_id)
        return node.successors if node else []


class SimpleCFGBuilder:
    """
    Simplified CFG builder for MemFix
    Focuses on memory allocation/deallocation operations
    """
    
    def __init__(self):
        self.node_counter = 0
    
    def build_cfg(self, source_code: str) -> CFG:
        """
        Build CFG from C source code
        
        Args:
            source_code: C source code
            
        Returns:
            CFG object
        """
        cfg = CFG()
        lines = source_code.split('\n')
        
        # Create entry node
        entry = CFGNode(
            node_id=self._next_id(),
            command_type=CommandType.NOP,
            line_num=0,
            original_code="<entry>"
        )
        cfg.entry_node = entry.node_id
        cfg.add_node(entry)
        
        prev_node_id = entry.node_id
        
        # Parse each line
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue
            
            # Parse command
            node = self._parse_line(line_num, line)
            if node:
                cfg.add_node(node)
                cfg.add_edge(prev_node_id, node.node_id)
                prev_node_id = node.node_id
        
        # Create exit node
        exit_node = CFGNode(
            node_id=self._next_id(),
            command_type=CommandType.NOP,
            line_num=len(lines) + 1,
            original_code="<exit>"
        )
        cfg.exit_node = exit_node.node_id
        cfg.add_node(exit_node)
        cfg.add_edge(prev_node_id, exit_node.node_id)
        
        logger.info(f"Built CFG with {len(cfg.nodes)} nodes")
        return cfg
    
    def _next_id(self) -> int:
        """Generate next node ID"""
        node_id = self.node_counter
        self.node_counter += 1
        return node_id
    
    def _parse_line(self, line_num: int, line: str) -> Optional[CFGNode]:
        """
        Parse a line into a CFG node
        
        Args:
            line_num: Line number
            line: Source line
            
        Returns:
            CFGNode or None
        """
        # Remove trailing semicolon
        line = line.rstrip(';').strip()
        
        # Check for malloc/calloc (alloc)
        alloc_match = re.search(r'(\w+)\s*=\s*(?:\([^)]+\))?\s*(malloc|calloc)\s*\(', line)
        if alloc_match:
            var = alloc_match.group(1)
            return CFGNode(
                node_id=self._next_id(),
                command_type=CommandType.ALLOC,
                line_num=line_num,
                original_code=line,
                ptr=var
            )
        
        # Check for fopen (alloc for FILE*)
        fopen_match = re.search(r'(\w+)\s*=\s*fopen\s*\(', line)
        if fopen_match:
            var = fopen_match.group(1)
            return CFGNode(
                node_id=self._next_id(),
                command_type=CommandType.ALLOC,
                line_num=line_num,
                original_code=line,
                ptr=var
            )
        
        # Check for C++ new (alloc)
        new_match = re.search(r'(\w+)\s*=\s*new\s+', line)
        if new_match:
            var = new_match.group(1)
            return CFGNode(
                node_id=self._next_id(),
                command_type=CommandType.ALLOC,
                line_num=line_num,
                original_code=line,
                ptr=var
            )
        
        # Check for free (free)
        free_match = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
        if free_match:
            var = free_match.group(1)
            return CFGNode(
                node_id=self._next_id(),
                command_type=CommandType.FREE,
                line_num=line_num,
                original_code=line,
                ptr=var
            )
        
        # Check for fclose (free for FILE*)
        fclose_match = re.search(r'fclose\s*\(\s*(\w+)\s*\)', line)
        if fclose_match:
            var = fclose_match.group(1)
            return CFGNode(
                node_id=self._next_id(),
                command_type=CommandType.FREE,
                line_num=line_num,
                original_code=line,
                ptr=var
            )
        
        # Check for C++ delete (free)
        delete_match = re.search(r'delete\s*(?:\[\s*\])?\s*(\w+)', line)
        if delete_match:
            var = delete_match.group(1)
            return CFGNode(
                node_id=self._next_id(),
                command_type=CommandType.FREE,
                line_num=line_num,
                original_code=line,
                ptr=var
            )
        
        # Check for assignment (set)
        assign_match = re.search(r'(\w+)\s*=\s*(.+)', line)
        if assign_match:
            lval = assign_match.group(1)
            rval = assign_match.group(2).strip()
            return CFGNode(
                node_id=self._next_id(),
                command_type=CommandType.SET,
                line_num=line_num,
                original_code=line,
                lvalue=lval,
                rvalue=rval
            )
        
        # Check for pointer dereference (use)
        if '*' in line or '->' in line or '[' in line:
            # Extract pointer variable
            ptr_match = re.search(r'[\*\->]\s*(\w+)|(\w+)\s*->', line)
            if ptr_match:
                var = ptr_match.group(1) or ptr_match.group(2)
                return CFGNode(
                    node_id=self._next_id(),
                    command_type=CommandType.USE,
                    line_num=line_num,
                    original_code=line,
                    ptr=var
                )
        
        # Default: nop
        return CFGNode(
            node_id=self._next_id(),
            command_type=CommandType.NOP,
            line_num=line_num,
            original_code=line
        )
