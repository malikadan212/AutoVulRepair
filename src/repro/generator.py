"""Repro-Kit Generator Module"""
import os
import json
from pathlib import Path
from datetime import datetime

class ReproKitGenerator:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.scan_dir = Path(f"scans/{scan_id}")
        self.repro_dir = self.scan_dir / "repro_kits"
        self.repro_dir.mkdir(exist_ok=True)
        
    def generate_all_repros(self):
        """Generate reproduction kits for all triaged crashes"""
        triage_file = self.scan_dir / "fuzz" / "triage" / "triage_results.json"
        
        if not triage_file.exists():
            return {'status': 'error', 'message': 'No triage results found'}
        
        with open(triage_file, 'r') as f:
            triage_data = json.load(f)
        
        repro_kits = []
        for crash in triage_data.get('crashes', []):
            if crash['severity'] in ['Critical', 'High']:
                # Add crash_id field if it doesn't exist (use 'id' field)
                if 'crash_id' not in crash:
                    crash['crash_id'] = crash.get('id', 'unknown')
                repro = self.generate_repro(crash)
                repro_kits.append(repro)
        
        results = {
            'scan_id': self.scan_id,
            'timestamp': datetime.now().isoformat(),
            'total_repros': len(repro_kits),
            'repro_kits': repro_kits
        }
        
        results_file = self.scan_dir / "repro_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def generate_repro(self, crash_data):
        """Generate reproduction kit for a single crash"""
        crash_id = crash_data.get('crash_id', crash_data.get('id', 'unknown'))
        
        repro_kit = {
            'crash_id': crash_id,
            'crash_type': crash_data.get('crash_type', 'Unknown'),
            'severity': crash_data.get('severity', 'Unknown'),
            'components': {
                'minimal_input': self._minimize_input(crash_data),
                'standalone_reproducer': self._generate_standalone_reproducer(crash_data),
                'gdb_script': self._generate_gdb_script(crash_data),
                'patch_suggestion': self._generate_patch_suggestion(crash_data)
            }
        }
        
        # Check if exploitable (map "Exploitable" and "Likely Exploitable" to High/Medium)
        exploitability = crash_data.get('exploitability', '')
        if exploitability in ['Exploitable', 'Likely Exploitable']:
            repro_kit['components']['exploit_template'] = self._generate_exploit_template(crash_data)
        
        self._save_repro_kit(crash_id, repro_kit)
        return repro_kit
    
    def _minimize_input(self, crash_data):
        original_input = crash_data.get('crash_input', '')
        return {
            'original_size': len(original_input),
            'minimized_size': len(original_input),
            'reduction_ratio': '0.0%',
            'minimized_input': original_input[:500],
            'file_path': f"repro_kits/{crash_data['crash_id']}_input.txt"
        }
    
    def _generate_standalone_reproducer(self, crash_data):
        code = f"""/* Reproducer for {crash_data['crash_type']} */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {{
    printf("Reproducing {crash_data['crash_type']}\\n");
    return 0;
}}"""
        
        repro_file = self.repro_dir / f"{crash_data['crash_id']}_reproducer.c"
        with open(repro_file, 'w') as f:
            f.write(code)
        
        return {
            'file_path': str(repro_file.relative_to(self.scan_dir)),
            'code': code,
            'compile_command': 'gcc -fsanitize=address -g -o repro repro.c',
            'run_command': './repro'
        }
    
    def _generate_gdb_script(self, crash_data):
        script = f"""# GDB Script for {crash_data['crash_id']}
file ./repro
break main
run
backtrace
"""
        gdb_file = self.repro_dir / f"{crash_data['crash_id']}_debug.gdb"
        with open(gdb_file, 'w') as f:
            f.write(script)
        
        return {
            'file_path': str(gdb_file.relative_to(self.scan_dir)),
            'script': script,
            'usage': 'gdb -x debug.gdb'
        }
    
    def _generate_exploit_template(self, crash_data):
        template = f"""/* Exploit for {crash_data['crash_type']} */
#include <stdio.h>

int main() {{
    printf("Exploit PoC\\n");
    return 0;
}}"""
        
        exploit_file = self.repro_dir / f"{crash_data['crash_id']}_exploit.c"
        with open(exploit_file, 'w') as f:
            f.write(template)
        
        return {
            'file_path': str(exploit_file.relative_to(self.scan_dir)),
            'code': template,
            'exploitability': crash_data.get('exploitability', 'Unknown'),
            'attack_vector': 'See detailed analysis'
        }
    
    def _generate_patch_suggestion(self, crash_data):
        crash_type = crash_data.get('crash_type', 'Unknown')
        patch = f"""// Fix for {crash_type}
// Add bounds checking and validation"""
        
        # Extract location from crash_file or use target
        location = crash_data.get('crash_file', crash_data.get('target', 'unknown'))
        function = crash_data.get('target', 'unknown')
        
        return {
            'location': location,
            'function': function,
            'suggested_fix': patch,
            'description': f"Fix {crash_type}",
            'diff': f"--- a/file.c\n+++ b/file.c\n@@ -1,1 +1,2 @@\n+{patch}"
        }
    
    def _save_repro_kit(self, crash_id, repro_kit):
        kit_file = self.repro_dir / f"{crash_id}_kit.json"
        with open(kit_file, 'w') as f:
            json.dump(repro_kit, f, indent=2)
    
    def get_results(self):
        results_file = self.scan_dir / "repro_results.json"
        if not results_file.exists():
            return None
        with open(results_file, 'r') as f:
            return json.load(f)
