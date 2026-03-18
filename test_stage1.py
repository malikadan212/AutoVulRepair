from src.repair.stage1 import Stage1RepairEngine
from src.repair.stage1.classifier import classify_vulnerability

vuln = {'id': 'cppcheck_getsCalled_6', 'rule_id': 'getsCalled', 'severity': 'medium', 'line': 6, 'file': '/work/source/snippet.cpp', 'description': 'gets called'}
c = classify_vulnerability(vuln)
print('Classification:', c)
e = Stage1RepairEngine()
print('Repairable:', e.can_repair(vuln))
source = '    gets(buffer);\n'
patch = e.generate_patch(vuln, source, '/work/source/snippet.cpp')
print('Patch:', patch)
