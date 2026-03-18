import os
import sys
import uuid
import shutil
import argparse
import logging
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_pipeline(source_dir, tool='cppcheck', fail_on_vuln=False):
    logger.info(f"Starting AutoVulRepair CLI for source: {source_dir} using {tool}")
    
    # Initialize the database and models
    from src.models.scan import create_database, get_session, Scan
    from src.queue.tasks import analyze_code_sync
    from src.fuzz_plan.generator import FuzzPlanGenerator
    from src.harness.generator import HarnessGenerator
    from src.intrepair.pipeline import IntRepairPipeline
    
    create_database()
    session = get_session()
    
    # Create a unique scan ID
    scan_id = str(uuid.uuid4())
    logger.info(f"Scan ID: {scan_id}")
    
    # Setup scan directory
    scans_root = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_root, scan_id)
    source_dest = os.path.join(scan_dir, 'source')
    os.makedirs(source_dest, exist_ok=True)
    
    # Copy the code to scan
    logger.info(f"Copying source code from {source_dir} to {source_dest}")
    # Using ignore pattern to skip .git and build directories to speed up copy
    shutil.copytree(source_dir, source_dest, dirs_exist_ok=True, 
                    ignore=shutil.ignore_patterns('.git', 'build', 'node_modules', '__pycache__'))
                    
    # Create the scan record
    new_scan = Scan(
        id=scan_id,
        repo_url='github-action-local',
        source_type='Directory',
        analysis_tool=tool,
        status='queued'
    )
    session.add(new_scan)
    session.commit()
    
    has_vulnerabilities = False
    
    # Step 1: Run Static Analysis
    logger.info(f"=== Module 1: Running Static Analysis using {tool} ===")
    try:
        result = analyze_code_sync(scan_id, tool)
        
        if result['status'] == 'failed':
            logger.error(f"Analysis failed: {result.get('error')}")
            sys.exit(1)
            
        vuln_count = result.get('vulnerabilities', 0)
        logger.info(f"Analysis completed. Found {vuln_count} vulnerabilities.")
        
        # Reload scan record
        scan_record = session.query(Scan).filter_by(id=scan_id).first()
        vulns = scan_record.vulnerabilities_json or []
        
        if vuln_count > 0:
            has_vulnerabilities = True
            logger.warning(f"Found {vuln_count} vulnerabilities in the codebase!")
            for i, v in enumerate(vulns):
                file_path = v.get('file', 'Unknown')
                line = v.get('line', 'Unknown')
                desc = v.get('description', 'No description')
                severity = v.get('severity', 'Unknown')
                logger.warning(f"  [{i+1}] {severity.upper()}: {file_path}:{line} -> {desc}")
                
            # Step 2: Fuzz Plan Generation
            logger.info("=== Module 2: Generating Fuzz Plan ===")
            static_findings_path = os.path.join(scan_dir, 'static_findings.json')
            fuzz_dir = os.path.join(scan_dir, 'fuzz')
            os.makedirs(fuzz_dir, exist_ok=True)
            fuzz_plan_path = os.path.join(fuzz_dir, 'fuzzplan.json')
            
            if os.path.exists(static_findings_path):
                plan_generator = FuzzPlanGenerator(static_findings_path, source_dir=source_dest)
                plan_generator.save_fuzz_plan(fuzz_plan_path, generate_seeds=True)
                logger.info(f"Fuzz plan generated at {fuzz_plan_path}")
                
                # Step 3: Harness Generation
                logger.info("=== Module 3: Generating Fuzzing Harnesses ===")
                harness_dir = os.path.join(fuzz_dir, 'harnesses')
                harness_generator = HarnessGenerator(fuzz_plan_path)
                harnesses = harness_generator.generate_all_harnesses(harness_dir)
                logger.info(f"Generated {len(harnesses)} harnesses at {harness_dir}")
                harness_generator.generate_build_script(harness_dir, harnesses)
                harness_generator.generate_readme(harness_dir, harnesses)
                
            else:
                 logger.warning("static_findings.json not found, skipping fuzz plan and harness generation.")

            # Step 4: Automated Repair (INTREPAIR)
            logger.info("=== Module 4: Automated Patch Generation ===")
            
            # Keep track of generated patches for GitHub PR comment
            all_repairs = []
            
            # Find all unique vulnerable files
            vulnerable_files = set([v.get('file') for v in vulns if v.get('file')])
            
            for rel_file in vulnerable_files:
                # Resolve the absolute path
                abs_file = os.path.join(source_dest, rel_file)
                if not os.path.exists(abs_file):
                    # Sometimes the path prefixes might differ
                    # Basic fallback search
                    found = False
                    for root, _, files in os.walk(source_dest):
                         if os.path.basename(rel_file) in files:
                             abs_file = os.path.join(root, os.path.basename(rel_file))
                             found = True
                             break
                    if not found:
                         logger.warning(f"Could not locate {rel_file} for repair.")
                         continue
                
                logger.info(f"Attempting to repair {abs_file}...")
                
                # Define output path for the repaired file
                repaired_file_path = f"{abs_file}.repaired"
                
                try:
                    pipeline = IntRepairPipeline(source_path=abs_file, output_path=repaired_file_path, auto_apply=True)
                    repair_result = pipeline.run()
                    
                    if repair_result.faults_found > 0 and repair_result.repairs_applied > 0:
                        logger.info(f"Successfully repaired {repair_result.repairs_applied} faults in {rel_file}.")
                        all_repairs.append({
                            'file': rel_file,
                            'original': abs_file,
                            'repaired': repaired_file_path,
                            'details': repair_result.fault_details
                        })
                except Exception as e:
                    logger.error(f"Repair pipeline failed on {rel_file}: {e}")
                    
            # Generate Markdown Report for GitHub Action
            workflow_report_path = os.getenv('GITHUB_STEP_SUMMARY', '')
            if workflow_report_path:
                generate_github_summary(workflow_report_path, tool, vuln_count, vulns, all_repairs, scan_dir)
             
            if fail_on_vuln:
                logger.info("Failing build due to vulnerabilities as configured.")
                sys.exit(1)
            else:
                logger.info("Vulnerabilities found but pipeline configured to pass.")
                sys.exit(0)
        else:
            logger.info("No vulnerabilities found. Code is secure.")
            
            # Generate success summary
            workflow_report_path = os.getenv('GITHUB_STEP_SUMMARY', '')
            if workflow_report_path:
                with open(workflow_report_path, 'w') as f:
                    f.write("# 🛡️ AutoVulRepair Scan Complete\n\n")
                    f.write("✅ **No vulnerabilities found.** Your code is secure!\n")
                    
            sys.exit(0)
            
    except Exception as e:
        logger.error(f"Pipeline execution failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        session.close()

def generate_github_summary(summary_path, tool, vuln_count, vulns, repairs, scan_dir):
    """Generates a Markdown summary for the GitHub Actions UI"""
    try:
        with open(summary_path, 'a') as f:
            f.write("# 🛡️ AutoVulRepair Security Audit Report\n\n")
            f.write(f"**Scanner Used:** `{tool}`\n")
            f.write(f"**Vulnerabilities Found:** 🚨 {vuln_count}\n\n")
            
            f.write("## 📄 Findings\n\n")
            f.write("| Severity | File | Line | Description |\n")
            f.write("|----------|------|------|-------------|\n")
            
            # List top 10 vulnerabilities
            for v in vulns[:10]:
                sev = "🔴 High" if v.get('severity') == "high" else ("🟠 Medium" if v.get('severity') == "medium" else "🟡 Low")
                f.write(f"| {sev} | `{v.get('file')}` | {v.get('line')} | {v.get('description')} |\n")
            
            if vuln_count > 10:
                f.write(f"| ... | | | *and {vuln_count - 10} more* |\n")
            f.write("\n")
            
            # Show Auto-Repair Results
            f.write("## 🤖 Auto-Repair (INTREPAIR) Results\n\n")
            if not repairs:
                 f.write("*No automated patches could be generated for these vulnerabilities.*\n\n")
            else:
                 f.write("I have automatically generated patches to fix the integer overflows/underflows found in this PR!\n\n")
                 
                 for repair in repairs:
                     f.write(f"### Proposed Fix for `{repair['file']}`\n")
                     f.write(f"Repaired {len(repair['details'])} fault(s):\n")
                     for detail in repair['details']:
                         f.write(f"- Line {detail['line']}: `{detail['statement']}`\n")
                         
                     # Generate a diff snippet if we can
                     try:
                         import subprocess
                         diff_result = subprocess.run(['diff', '-u', repair['original'], repair['repaired']], 
                                                      capture_output=True, text=True)
                         if diff_result.stdout:
                             f.write("\n**Unified Diff:**\n```diff\n")
                             f.write(diff_result.stdout[:2000] + ("\n... [truncated]" if len(diff_result.stdout) > 2000 else ""))
                             f.write("\n```\n")
                     except Exception:
                         pass
                     f.write("\n")
                     
            f.write("---\n*Analysis completely autonomously by AutoVulRepair Action.*")
            
    except Exception as e:
        logger.error(f"Failed to write GitHub summary: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoVulRepair CLI for CI/CD pipelines")
    parser.add_argument("--tool", default="cppcheck", help="Analysis tool (cppcheck or codeql)")
    parser.add_argument("--source-dir", required=True, help="Directory of the source code to scan")
    parser.add_argument("--github-event-path", default="", help="Path to GitHub event payload (optional)")
    # Default to False because GitHub Actions entrypoint.sh handles the exit code override if needed
    parser.add_argument("--fail-on-vuln", action="store_true", help="Fail pipeline if vulns found")
    
    args = parser.parse_args()
    
    fail_on_vuln = os.getenv("FAIL_ON_VULN", "false").lower() == "true" or args.fail_on_vuln
    
    run_pipeline(args.source_dir, args.tool, fail_on_vuln)
