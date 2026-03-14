"""
Patching Routes for AutoVulRepair

Add these routes to your app.py file.
"""

from flask import render_template, request, jsonify, flash, redirect, url_for
from ai_patch_generator import AIPatchGenerator
import os
import json

# Initialize patch generator (add near top of app.py)
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if GEMINI_API_KEY:
    patch_generator = AIPatchGenerator(gemini_api_key=GEMINI_API_KEY, index_name='cve-full')
    logger.info("✓ AI Patch Generator initialized")
else:
    patch_generator = None
    logger.warning("⚠ GEMINI_API_KEY not set - Patching features disabled")


# ============================================================================
# PATCHING ROUTES
# ============================================================================

@app.route('/patch/<scan_id>')
def patch_dashboard(scan_id):
    """
    Main patching dashboard showing all vulnerabilities
    """
    if not patch_generator:
        flash('AI Patching is not available. Please set GEMINI_API_KEY.', 'error')
        return redirect(url_for('detailed_findings', scan_id=scan_id))
    
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        
        if not scan:
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        # Get vulnerabilities from scan
        vulnerabilities = scan.vulnerabilities_json or []
        
        # Load existing patches if any
        scans_dir = os.getenv('SCANS_DIR', './scans')
        patches_file = os.path.join(scans_dir, scan_id, 'patches.json')
        
        existing_patches = {}
        if os.path.exists(patches_file):
            with open(patches_file, 'r') as f:
                existing_patches = json.load(f)
        
        # Add patch status to vulnerabilities
        for i, vuln in enumerate(vulnerabilities):
            vuln['index'] = i
            vuln['patch_status'] = existing_patches.get(str(i), {}).get('status', 'not_started')
        
        return render_template('patch_dashboard.html',
                             scan_id=scan_id,
                             scan=scan,
                             vulnerabilities=vulnerabilities,
                             total_vulns=len(vulnerabilities),
                             patched_count=sum(1 for v in vulnerabilities if v['patch_status'] == 'applied'),
                             pending_count=sum(1 for v in vulnerabilities if v['patch_status'] == 'not_started'))
    finally:
        session_db.close()


@app.route('/patch/<scan_id>/vulnerability/<int:vuln_index>')
def patch_vulnerability(scan_id, vuln_index):
    """
    Detailed patching page for a specific vulnerability
    """
    if not patch_generator:
        flash('AI Patching is not available. Please set GEMINI_API_KEY.', 'error')
        return redirect(url_for('detailed_findings', scan_id=scan_id))
    
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        
        if not scan:
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        vulnerabilities = scan.vulnerabilities_json or []
        
        if vuln_index >= len(vulnerabilities):
            flash('Vulnerability not found.', 'error')
            return redirect(url_for('patch_dashboard', scan_id=scan_id))
        
        vulnerability = vulnerabilities[vuln_index]
        vulnerability['index'] = vuln_index
        
        # Load existing patch if any
        scans_dir = os.getenv('SCANS_DIR', './scans')
        patches_file = os.path.join(scans_dir, scan_id, 'patches.json')
        
        existing_patch = None
        if os.path.exists(patches_file):
            with open(patches_file, 'r') as f:
                patches = json.load(f)
                existing_patch = patches.get(str(vuln_index))
        
        return render_template('patch_vulnerability.html',
                             scan_id=scan_id,
                             scan=scan,
                             vulnerability=vulnerability,
                             existing_patch=existing_patch,
                             vuln_index=vuln_index,
                             total_vulns=len(vulnerabilities))
    finally:
        session_db.close()


@app.route('/api/patch/<scan_id>/generate/<int:vuln_index>', methods=['POST'])
def generate_patch_api(scan_id, vuln_index):
    """
    API endpoint to generate patch for a vulnerability
    """
    if not patch_generator:
        return jsonify({'error': 'AI Patching not available'}), 503
    
    try:
        session_db = get_session()
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = scan.vulnerabilities_json or []
        
        if vuln_index >= len(vulnerabilities):
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        vulnerability = vulnerabilities[vuln_index]
        
        # Add code snippet if available
        if vulnerability.get('file') and vulnerability.get('line'):
            code_snippet = extract_code_context(
                scan_id,
                vulnerability['file'],
                vulnerability['line'],
                context_lines=10
            )
            if code_snippet:
                vulnerability['code_snippet'] = '\n'.join([c['code'] for c in code_snippet])
        
        # Generate patch
        logger.info(f"Generating patch for vulnerability {vuln_index} in scan {scan_id}")
        patch_data = patch_generator.generate_patch(vulnerability)
        
        # Save patch
        scans_dir = os.getenv('SCANS_DIR', './scans')
        scan_dir = os.path.join(scans_dir, scan_id)
        os.makedirs(scan_dir, exist_ok=True)
        
        patches_file = os.path.join(scan_dir, 'patches.json')
        
        # Load existing patches
        patches = {}
        if os.path.exists(patches_file):
            with open(patches_file, 'r') as f:
                patches = json.load(f)
        
        # Add new patch
        patches[str(vuln_index)] = patch_data
        
        # Save
        with open(patches_file, 'w') as f:
            json.dump(patches, f, indent=2)
        
        session_db.close()
        
        logger.info(f"Patch generated and saved for vulnerability {vuln_index}")
        
        return jsonify({
            'success': True,
            'patch': patch_data
        })
        
    except Exception as e:
        logger.error(f"Error generating patch: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/patch/<scan_id>/apply/<int:vuln_index>', methods=['POST'])
def apply_patch_api(scan_id, vuln_index):
    """
    Mark patch as applied (or actually apply it to the file)
    """
    try:
        data = request.json
        action = data.get('action', 'mark_applied')  # 'mark_applied' or 'apply_to_file'
        
        scans_dir = os.getenv('SCANS_DIR', './scans')
        patches_file = os.path.join(scans_dir, scan_id, 'patches.json')
        
        if not os.path.exists(patches_file):
            return jsonify({'error': 'No patches found'}), 404
        
        # Load patches
        with open(patches_file, 'r') as f:
            patches = json.load(f)
        
        if str(vuln_index) not in patches:
            return jsonify({'error': 'Patch not found'}), 404
        
        # Update status
        patches[str(vuln_index)]['status'] = 'applied'
        patches[str(vuln_index)]['applied_at'] = datetime.now().isoformat()
        
        # Save
        with open(patches_file, 'w') as f:
            json.dump(patches, f, indent=2)
        
        return jsonify({
            'success': True,
            'message': 'Patch marked as applied'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/patch/<scan_id>/batch-generate', methods=['POST'])
def batch_generate_patches(scan_id):
    """
    Generate patches for all vulnerabilities
    """
    if not patch_generator:
        return jsonify({'error': 'AI Patching not available'}), 503
    
    try:
        session_db = get_session()
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = scan.vulnerabilities_json or []
        
        # Add code snippets
        for vuln in vulnerabilities:
            if vuln.get('file') and vuln.get('line'):
                code_snippet = extract_code_context(
                    scan_id,
                    vuln['file'],
                    vuln['line'],
                    context_lines=10
                )
                if code_snippet:
                    vuln['code_snippet'] = '\n'.join([c['code'] for c in code_snippet])
        
        # Generate patches
        logger.info(f"Batch generating patches for {len(vulnerabilities)} vulnerabilities")
        patches_data = patch_generator.generate_batch_patches(vulnerabilities)
        
        # Save patches
        scans_dir = os.getenv('SCANS_DIR', './scans')
        scan_dir = os.path.join(scans_dir, scan_id)
        os.makedirs(scan_dir, exist_ok=True)
        
        patches_file = os.path.join(scan_dir, 'patches.json')
        
        patches = {}
        for i, patch_data in enumerate(patches_data):
            patches[str(i)] = patch_data
        
        with open(patches_file, 'w') as f:
            json.dump(patches, f, indent=2)
        
        session_db.close()
        
        return jsonify({
            'success': True,
            'total': len(patches_data),
            'generated': sum(1 for p in patches_data if p.get('status') == 'generated'),
            'failed': sum(1 for p in patches_data if p.get('status') == 'failed')
        })
        
    except Exception as e:
        logger.error(f"Error in batch generation: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/patch/<scan_id>/export')
def export_patches(scan_id):
    """
    Export all patches as a downloadable file
    """
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        patches_file = os.path.join(scans_dir, scan_id, 'patches.json')
        
        if not os.path.exists(patches_file):
            return jsonify({'error': 'No patches found'}), 404
        
        return send_file(patches_file,
                        as_attachment=True,
                        download_name=f'patches_{scan_id[:8]}.json',
                        mimetype='application/json')
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
