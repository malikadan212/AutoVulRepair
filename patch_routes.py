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
    Main patching dashboard showing all vulnerabilities - migrated to use new database system
    """
    if not patch_generator:
        flash('AI Patching is not available. Please set GEMINI_API_KEY.', 'error')
        return redirect(url_for('detailed_findings', scan_id=scan_id))
    
    try:
        # Try new database system first
        results = scan_service.get_scan_results(scan_id)
        if results and 'error' not in results:
            scan = results['scan']
            vulnerabilities = results['findings']
            
            # Filter out false positives from patch generation
            vulnerabilities = [
                v for v in vulnerabilities 
                if not v.get('metadata_json', {}).get('is_false_positive', False)
            ]
            
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
        
        # Fallback to legacy system
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
            
    except Exception as e:
        flash(f'Error loading patch dashboard: {str(e)}', 'error')
        return redirect(url_for('no_login_scan'))


@app.route('/patch/<scan_id>/vulnerability/<int:vuln_index>')
def patch_vulnerability(scan_id, vuln_index):
    """
    Detailed patching page for a specific vulnerability - migrated to use new database system
    """
    if not patch_generator:
        flash('AI Patching is not available. Please set GEMINI_API_KEY.', 'error')
        return redirect(url_for('detailed_findings', scan_id=scan_id))
    
    try:
        # Try new database system first
        results = scan_service.get_scan_results(scan_id)
        if results and 'error' not in results:
            scan = results['scan']
            vulnerabilities = results['findings']
            
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
        
        # Fallback to legacy system
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
            
    except Exception as e:
        flash(f'Error loading vulnerability: {str(e)}', 'error')
        return redirect(url_for('patch_dashboard', scan_id=scan_id))


@app.route('/api/patch/<scan_id>/generate/<int:vuln_index>', methods=['POST'])
def generate_patch_api(scan_id, vuln_index):
    """
    API endpoint to generate patch for a vulnerability - migrated to use new database system
    """
    if not patch_generator:
        return jsonify({'error': 'AI Patching not available'}), 503
    
    try:
        # Try new database system first
        results = scan_service.get_scan_results(scan_id)
        if results and 'error' not in results:
            scan = results['scan']
            vulnerabilities = results['findings']
            
            if vuln_index >= len(vulnerabilities):
                return jsonify({'error': 'Vulnerability not found'}), 404
            
            vulnerability = vulnerabilities[vuln_index]
            
            # Add code snippet if available
            if vulnerability.get('file_path') and vulnerability.get('line_number'):
                code_snippet = extract_code_context(
                    scan_id,
                    vulnerability['file_path'],
                    vulnerability['line_number'],
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
            
            logger.info(f"Patch generated and saved for vulnerability {vuln_index}")
            
            return jsonify({
                'success': True,
                'patch': patch_data
            })
        
        # Fallback to legacy system
        session_db = get_session()
        try:
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
            
            logger.info(f"Patch generated and saved for vulnerability {vuln_index}")
            
            return jsonify({
                'success': True,
                'patch': patch_data
            })
        finally:
            session_db.close()
        
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
    Generate patches for all vulnerabilities - migrated to use new database system
    """
    if not patch_generator:
        return jsonify({'error': 'AI Patching not available'}), 503
    
    try:
        # Try new database system first
        results = scan_service.get_scan_results(scan_id)
        if results and 'error' not in results:
            scan = results['scan']
            vulnerabilities = results['findings']
            
            # Add code snippets
            for vuln in vulnerabilities:
                if vuln.get('file_path') and vuln.get('line_number'):
                    code_snippet = extract_code_context(
                        scan_id,
                        vuln['file_path'],
                        vuln['line_number'],
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
            
            return jsonify({
                'success': True,
                'total': len(patches_data),
                'generated': sum(1 for p in patches_data if p.get('status') == 'generated'),
                'failed': sum(1 for p in patches_data if p.get('status') == 'failed')
            })
        
        # Fallback to legacy system
        session_db = get_session()
        try:
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
            
            return jsonify({
                'success': True,
                'total': len(patches_data),
                'generated': sum(1 for p in patches_data if p.get('status') == 'generated'),
                'failed': sum(1 for p in patches_data if p.get('status') == 'failed')
            })
        finally:
            session_db.close()
        
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


# ============================================================================
# PATCH BATCH ROUTES (NEW)
# ============================================================================

from src.services.patch_batch_service import PatchBatchService

@app.route('/api/scans/<scan_id>/patch-batch/status', methods=['GET'])
def get_patch_batch_status(scan_id):
    """
    Get current patch batch status for a scan
    
    Returns:
        JSON with batch status including stage completion and patch counts
    """
    try:
        batch_service = PatchBatchService()
        status = batch_service.get_batch_status(scan_id)
        
        if not status:
            return jsonify({
                'error': 'No patch batch found',
                'scan_id': scan_id
            }), 404
        
        # Calculate progress percentage
        total_vulns = status['stage1_vulnerabilities_count'] + status['stage2_vulnerabilities_count']
        total_patches = status['stage1_patches_count'] + status['stage2_patches_count']
        
        if total_vulns > 0:
            progress_percent = int((total_patches / total_vulns) * 100)
        else:
            progress_percent = 0
        
        return jsonify({
            'batch_id': status['id'],
            'scan_id': status['scan_id'],
            'status': status['status'],
            'stage1': {
                'complete': status['stage1_complete'],
                'vulnerabilities_count': status['stage1_vulnerabilities_count'],
                'patches_count': status['stage1_patches_count'],
                'completed_at': status['stage1_completed_at'].isoformat() if status['stage1_completed_at'] else None
            },
            'stage2': {
                'complete': status['stage2_complete'],
                'vulnerabilities_count': status['stage2_vulnerabilities_count'],
                'patches_count': status['stage2_patches_count'],
                'completed_at': status['stage2_completed_at'].isoformat() if status['stage2_completed_at'] else None
            },
            'total_patches_count': status['total_patches_count'],
            'all_ready': status['all_ready'],
            'progress_percent': progress_percent,
            'applied_at': status['applied_at'].isoformat() if status['applied_at'] else None,
            'commit_sha': status['commit_sha'],
            'pr_url': status['pr_url'],
            'branch_name': status['branch_name']
        })
    
    except Exception as e:
        logger.error(f"Error getting patch batch status: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/patch-batches/<batch_id>/patches', methods=['GET'])
def get_batch_patches(batch_id):
    """
    Get all patches in a batch
    
    Query params:
        stage: Optional filter by stage (1 or 2)
    
    Returns:
        JSON with list of patches
    """
    try:
        stage = request.args.get('stage', type=int)
        
        batch_service = PatchBatchService()
        patches = batch_service.get_batch_patches(batch_id, stage=stage)
        
        # Convert to JSON-serializable format
        patches_json = []
        for patch in patches:
            patch_dict = dict(patch)
            if patch_dict.get('created_at'):
                patch_dict['created_at'] = patch_dict['created_at'].isoformat()
            patches_json.append(patch_dict)
        
        return jsonify({
            'batch_id': batch_id,
            'patches': patches_json,
            'count': len(patches_json)
        })
    
    except Exception as e:
        logger.error(f"Error getting batch patches: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/patch-batches/<batch_id>/apply', methods=['POST'])
def apply_patch_batch(batch_id):
    """
    Apply all patches in a batch
    
    Request body:
        {
            "selected_patch_ids": ["id1", "id2", ...],  // Optional
            "create_pr": true  // Optional, default true
        }
    
    Returns:
        JSON with application result
    """
    try:
        data = request.json or {}
        selected_patch_ids = data.get('selected_patch_ids')
        create_pr = data.get('create_pr', True)
        
        # Get current user ID (adjust based on your auth system)
        user_id = getattr(current_user, 'id', 'system')
        
        batch_service = PatchBatchService()
        
        result = batch_service.apply_batch(
            batch_id=batch_id,
            user_id=user_id,
            selected_patch_ids=selected_patch_ids,
            create_pr=create_pr
        )
        
        return jsonify({
            'success': True,
            'batch_id': batch_id,
            'commit_sha': result['commit_sha'],
            'pr_url': result['pr_url'],
            'branch_name': result['branch_name'],
            'patches_applied': result['patches_applied'],
            'files_modified': result['files_modified'],
            'modified_files': result['modified_files']
        })
    
    except Exception as e:
        logger.error(f"Error applying patch batch: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/patches/<patch_id>/select', methods=['POST'])
def update_patch_selection(patch_id):
    """
    Update whether a patch is selected for application
    
    Request body:
        {
            "selected": true/false
        }
    
    Returns:
        JSON with success status
    """
    try:
        data = request.json or {}
        selected = data.get('selected', True)
        
        batch_service = PatchBatchService()
        batch_service.update_patch_selection(patch_id, selected)
        
        return jsonify({
            'success': True,
            'patch_id': patch_id,
            'selected': selected
        })
    
    except Exception as e:
        logger.error(f"Error updating patch selection: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/scans/<scan_id>/generate-patches', methods=['POST'])
def trigger_patch_generation(scan_id):
    """
    Trigger patch generation for a scan (both Stage 1 and Stage 2)
    
    Returns:
        JSON with batch ID and status
    """
    try:
        # This will be called by the scan completion handler
        # For now, return the batch status
        batch_service = PatchBatchService()
        status = batch_service.get_batch_status(scan_id)
        
        if not status:
            return jsonify({
                'error': 'No patch batch found. Patches may not have been generated yet.'
            }), 404
        
        return jsonify({
            'success': True,
            'batch_id': status['id'],
            'status': status['status']
        })
    
    except Exception as e:
        logger.error(f"Error triggering patch generation: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
