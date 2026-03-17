"""
MemFix Stage 1 - Memory Deallocation Error Repair
Based on Lee, Hong & Oh - ESEC/FSE 2018

Repairs:
- Memory Leak (CWE-401)
- Double-Free (CWE-415)
- Use-After-Free (CWE-416)
"""

from .memfix_repair import MemFixRepair

__all__ = ['MemFixRepair']
