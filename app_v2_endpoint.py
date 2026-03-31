#!/usr/bin/env python3
"""
New API endpoint that uses database storage instead of files
This will run alongside your existing app.py without breaking anything
"""

import os
import uuid
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def get_database_connection():
    """Get database connection with error handling"""
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        raise Exception("DATABASE_URL not found in environment variables")
    
    try:
        engine = create_engine(database_url, pool_pre_ping=True)
        return engine
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
        raise

@app.route('/api/v2/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        engine = get_database_connection()
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/v2/scans', methods=['POST'])
def create_scan_v2():
    """
    Create a new scan using database storage (no files!)
    This replaces the file-based scan creation
    """
    try:
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Extract scan parameters
        source_code = data.get('code_snippet', '')
        analysis_tool = data.get('analysis_tool', 'cppcheck')
        repo_url = data.get('repo_url', '')
        
        if not source_code:
            return jsonify({'error': 'code_snippet is required'}), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Connect to database
        engine = get_database_connection()
        
        with engine.connect() as conn:
            # Insert scan record
            insert_scan_query = text("""
                INSERT INTO scans_v2 (scan_id, repo_url, source_type, analysis_tool, status, metadata)
                VALUES (:scan_id, :repo_url, :source_type, :analysis_tool, :status, :metadata)
                RETURNING id, scan_id, created_at
            """)
            
            scan_result = conn.execute(insert_scan_query, {
                'scan_id': scan_id,
                'repo_url': repo_url,
                'source_type': 'code_snippet',
                'analysis_tool': analysis_tool,
                'status': 'queued',
                'metadata': json.dumps({
                    'api_version': 'v2',
                    'storage_type': 'database',
                    'source_length': len(source_code)
                })
            })
            
            scan_row = scan_result.fetchone()
            
            # Store source code in database (not files!)
            insert_source_query = text("""
                INSERT INTO scan_sources (scan_id, file_path, file_content, file_size, file_hash)
                VALUES (:scan_id, :file_path, :file_content, :file_size, :file_hash)
            """)
            
            import hashlib
            file_hash = hashlib.sha256(source_code.encode()).hexdigest()
            
            conn.execute(insert_source_query, {
                'scan_id': scan_id,
                'file_path': 'main.cpp',  # Default filename for code snippets
                'file_content': source_code,
                'file_size': len(source_code),
                'file_hash': file_hash
            })
            
            conn.commit()
            
            logger.info(f"Created scan {scan_id} in database (no files created!)")
            
            return jsonify({
                'scan_id': scan_id,
                'status': 'queued',
                'created_at': scan_row[2].isoformat(),
                'storage_type': 'database',
                'message': 'Scan created successfully using database storage'
            })
    
    except Exception as e:
        logger.error(f"Error creating scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v2/scans/<scan_id>', methods=['GET'])
def get_scan_v2(scan_id):
    """
    Get scan details from database (no file reading!)
    """
    try:
        engine = get_database_connection()
        
        with engine.connect() as conn:
            # Get scan details
            scan_query = text("""
                SELECT s.scan_id, s.status, s.source_type, s.analysis_tool, 
                       s.created_at, s.started_at, s.completed_at, s.metadata,
                       COUNT(src.id) as source_files,
                       COUNT(f.id) as findings_count
                FROM scans_v2 s
                LEFT JOIN scan_sources src ON s.scan_id = src.scan_id
                LEFT JOIN static_findings f ON s.scan_id = f.scan_id
                WHERE s.scan_id = :scan_id
                GROUP BY s.scan_id, s.status, s.source_type, s.analysis_tool, 
                         s.created_at, s.started_at, s.completed_at, s.metadata
            """)
            
            result = conn.execute(scan_query, {'scan_id': scan_id})
            row = result.fetchone()
            
            if not row:
                return jsonify({'error': 'Scan not found'}), 404
            
            # Get source files
            source_query = text("""
                SELECT file_path, file_size, file_hash, created_at
                FROM scan_sources
                WHERE scan_id = :scan_id
            """)
            
            source_result = conn.execute(source_query, {'scan_id': scan_id})
            source_files = [
                {
                    'file_path': src_row[0],
                    'file_size': src_row[1],
                    'file_hash': src_row[2],
                    'created_at': src_row[3].isoformat()
                }
                for src_row in source_result.fetchall()
            ]
            
            # Get findings
            findings_query = text("""
                SELECT rule_id, severity, confidence, file_path, line_number, message
                FROM static_findings
                WHERE scan_id = :scan_id
                ORDER BY severity DESC, line_number ASC
                LIMIT 10
            """)
            
            findings_result = conn.execute(findings_query, {'scan_id': scan_id})
            findings = [
                {
                    'rule_id': f_row[0],
                    'severity': f_row[1],
                    'confidence': f_row[2],
                    'file_path': f_row[3],
                    'line_number': f_row[4],
                    'message': f_row[5]
                }
                for f_row in findings_result.fetchall()
            ]
            
            return jsonify({
                'scan_id': row[0],
                'status': row[1],
                'source_type': row[2],
                'analysis_tool': row[3],
                'created_at': row[4].isoformat(),
                'started_at': row[5].isoformat() if row[5] else None,
                'completed_at': row[6].isoformat() if row[6] else None,
                'metadata': json.loads(row[7]) if row[7] else {},
                'source_files': source_files,
                'findings': findings,
                'storage_type': 'database',
                'message': 'Data retrieved from database (no file system access)'
            })
    
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v2/scans', methods=['GET'])
def list_scans_v2():
    """
    List all scans from database
    """
    try:
        engine = get_database_connection()
        
        with engine.connect() as conn:
            query = text("""
                SELECT s.scan_id, s.status, s.source_type, s.analysis_tool, 
                       s.created_at, COUNT(f.id) as findings_count
                FROM scans_v2 s
                LEFT JOIN static_findings f ON s.scan_id = f.scan_id
                GROUP BY s.scan_id, s.status, s.source_type, s.analysis_tool, s.created_at
                ORDER BY s.created_at DESC
                LIMIT 20
            """)
            
            result = conn.execute(query)
            scans = [
                {
                    'scan_id': row[0],
                    'status': row[1],
                    'source_type': row[2],
                    'analysis_tool': row[3],
                    'created_at': row[4].isoformat(),
                    'findings_count': row[5]
                }
                for row in result.fetchall()
            ]
            
            return jsonify({
                'scans': scans,
                'total': len(scans),
                'storage_type': 'database',
                'message': 'Scans retrieved from database (no file system scanning)'
            })
    
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting AutoVulRepair V2 API (Database Storage)")
    print("This runs alongside your existing app.py without breaking anything!")
    print()
    print("New endpoints:")
    print("  GET  /api/v2/health       - Health check")
    print("  POST /api/v2/scans        - Create scan (database storage)")
    print("  GET  /api/v2/scans        - List scans (from database)")
    print("  GET  /api/v2/scans/<id>   - Get scan details (from database)")
    print()
    print("Key differences from old system:")
    print("  ✅ No file/folder creation")
    print("  ✅ All data stored in database")
    print("  ✅ Faster queries and responses")
    print("  ✅ Better scalability")
    print()
    
    app.run(host='0.0.0.0', port=5001, debug=True)  # Different port than main app