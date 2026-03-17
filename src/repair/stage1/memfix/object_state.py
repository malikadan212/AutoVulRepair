"""
Object State Representation for MemFix
Tracks allocation sites and their pointer aliasing through program execution
"""
from dataclasses import dataclass, field
from typing import Set, FrozenSet
from functools import cached_property


@dataclass(frozen=True)
class AccessPath:
    """
    Pointer access path (e.g., p, *p, p->f)
    Bounded length to keep domain finite
    """
    path: str
    
    def __str__(self):
        return self.path
    
    def __hash__(self):
        return hash(self.path)


@dataclass(frozen=True)
class Patch:
    """
    A patch candidate: free(expr) inserted after cfg_node
    """
    cfg_node: int  # NodeID where patch is inserted
    expr: AccessPath  # Pointer expression to free
    alloc_site: int = 0  # Allocation site (for determining alloc_type)
    
    def __str__(self):
        return f"free({self.expr}) after node {self.cfg_node}"
    
    def __hash__(self):
        return hash((self.cfg_node, self.expr, self.alloc_site))


@dataclass(frozen=True)
class ObjectState:
    """
    6-tuple tracking an allocated object through the program
    
    Invariants:
    - must ⊆ may
    - may ∩ mustNot = ∅
    - patch ∩ patchNot = ∅
    """
    o: int  # Allocation site (CFG node ID)
    may: FrozenSet[AccessPath] = field(default_factory=frozenset)  # MAY point to object
    must: FrozenSet[AccessPath] = field(default_factory=frozenset)  # MUST point to object
    mustNot: FrozenSet[AccessPath] = field(default_factory=frozenset)  # MUST NOT point to object
    patch: FrozenSet[Patch] = field(default_factory=frozenset)  # Safe patches
    patchNot: FrozenSet[Patch] = field(default_factory=frozenset)  # Unsafe patches
    alloc_type: str = 'malloc'  # Type of allocator: 'malloc', 'new', 'new[]'
    
    def __post_init__(self):
        """Validate invariants"""
        # Invariant A: must ⊆ may AND may ∩ mustNot = ∅
        if not self.must.issubset(self.may):
            raise ValueError(f"Invariant violated: must ⊄ may")
        if self.may.intersection(self.mustNot):
            raise ValueError(f"Invariant violated: may ∩ mustNot ≠ ∅")
        
        # Invariant B: patch ∩ patchNot = ∅
        if self.patch.intersection(self.patchNot):
            raise ValueError(f"Invariant violated: patch ∩ patchNot ≠ ∅")
    
    @cached_property
    def is_leaked(self) -> bool:
        """Check if object has no safe patches (memory leak)"""
        return len(self.patch) == 0
    
    def with_updates(self, **kwargs) -> 'ObjectState':
        """Create new ObjectState with updated fields"""
        updates = {
            'o': self.o,
            'may': self.may,
            'must': self.must,
            'mustNot': self.mustNot,
            'patch': self.patch,
            'patchNot': self.patchNot,
            'alloc_type': self.alloc_type
        }
        updates.update(kwargs)
        return ObjectState(**updates)
    
    def __str__(self):
        return (f"ObjectState(o={self.o}, "
                f"may={{{','.join(str(p) for p in self.may)}}}, "
                f"must={{{','.join(str(p) for p in self.must)}}}, "
                f"patch={len(self.patch)}, patchNot={len(self.patchNot)})")
    
    def __hash__(self):
        return hash((self.o, self.may, self.must, self.mustNot, self.patch, self.patchNot))


def create_initial_state(alloc_site: int, var_name: str, alloc_type: str = 'malloc') -> ObjectState:
    """
    Create initial ObjectState for a fresh allocation
    
    Args:
        alloc_site: CFG node ID of malloc/calloc/new
        var_name: Variable name assigned the allocation
        alloc_type: Type of allocator ('malloc', 'new', 'new[]')
        
    Returns:
        Fresh ObjectState
    """
    ap = AccessPath(var_name)
    return ObjectState(
        o=alloc_site,
        may=frozenset([ap]),
        must=frozenset([ap]),
        mustNot=frozenset(),
        patch=frozenset([Patch(alloc_site, ap, alloc_site)]),  # Can free immediately after alloc
        patchNot=frozenset(),
        alloc_type=alloc_type
    )
