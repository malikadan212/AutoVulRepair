"""
AutoVulRepair + CVE RAG Integration Example

This shows how to integrate the RAG system into your AutoVulRepair Flask app.

Add these routes to your app.py file.
"""

from flask import jsonify, request
from cve_rag_system import CVERAGSystem
import os

# Initialize RAG system (add this near the top of app.py, after other imports)
try:
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
    if GEMINI_API_KEY:
        cve_rag = CVERAGSystem(gemini_api_key=GEMINI_API_KEY, index_name='cve-full')
        print("✓ CVE RAG System initialized")
    else:
        cve_rag = None
        print("⚠ GEMINI_API_KEY not set - RAG features disabled")
except Exception as e:
    cve_rag = None
    print(f"⚠ CVE RAG System initialization failed: {e}")


# ============================================================================
# RAG-Enhanced Routes for AutoVulRepair
# ============================================================================

@app.route('/api/cve/explain/<cve_id>')
def explain_cve(cve_id):
    """
    Get AI explanation of a specific CVE
    
    Example: /api/cve/explain/CVE-2023-12345
    """
    if not cve_rag:
        return jsonify({'error': 'RAG system not available'}), 503
    
    try:
        result = cve_rag.ask(
            f"Explain {cve_id} in detail. Include severity, impact, and mitigation steps.",
            top_k=3
        )
        
        return jsonify({
            'cve_id': cve_id,
            'explanation': result['answer'],
            'related_cves': result['sources']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vulnerability/analyze', methods=['POST'])
def analyze_vulnerability():
    """
    Analyze a vulnerability finding using RAG
    
    POST body:
    {
        "description": "SQL injection in login form",
        "file": "login.php",
        "line": 42
    }
    """
    if not cve_rag:
        return jsonify({'error': 'RAG system not available'}), 503
    
    try:
        data = request.json
        description = data.get('description', '')
        
        if not description:
            return jsonify({'error': 'Description required'}), 400
        
        # Ask RAG system
        question = f"""Analyze this vulnerability:
        
Description: {description}
File: {data.get('file', 'unknown')}
Line: {data.get('line', 'unknown')}

Provide:
1. Severity assessment
2. Related CVEs
3. Exploitation risk
4. Remediation steps
"""
        
        result = cve_rag.ask(question, top_k=5)
        
        return jsonify({
            'analysis': result['answer'],
            'related_cves': result['sources'],
            'confidence': 'high' if len(result['sources']) > 0 else 'low'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cve/ask')
def ask_cve_question():
    """
    Ask any question about CVEs
    
    Example: /api/cve/ask?q=What are the most dangerous SQL injection CVEs?
    """
    if not cve_rag:
        return jsonify({'error': 'RAG system not available'}), 503
    
    try:
        question = request.args.get('q', '').strip()
        top_k = int(request.args.get('top_k', 5))
        
        if not question:
            return jsonify({'error': 'Question parameter "q" required'}), 400
        
        result = cve_rag.ask(question, top_k=top_k)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<scan_id>/enrich', methods=['POST'])
def enrich_scan_with_rag(scan_id):
    """
    Enrich scan results with AI-powered CVE analysis
    
    This adds intelligent explanations to each vulnerability found.
    """
    if not cve_rag:
        return jsonify({'error': 'RAG system not available'}), 503
    
    try:
        session_db = get_session()
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = scan.vulnerabilities_json or []
        
        # Enrich each vulnerability
        enriched = []
        for vuln in vulnerabilities[:10]:  # Limit to first 10 to avoid rate limits
            try:
                # Get AI explanation
                result = cve_rag.ask(
                    f"Explain this vulnerability and suggest fixes: {vuln['description']}",
                    top_k=3
                )
                
                vuln['ai_explanation'] = result['answer']
                vuln['related_cves'] = [
                    {
                        'cve_id': cve['cve_id'],
                        'severity': cve['severity'],
                        'cvss_score': cve.get('cvss_score')
                    }
                    for cve in result['sources']
                ]
                
            except Exception as e:
                vuln['ai_explanation'] = f"Error: {str(e)}"
                vuln['related_cves'] = []
            
            enriched.append(vuln)
        
        session_db.close()
        
        return jsonify({
            'scan_id': scan_id,
            'enriched_vulnerabilities': enriched
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cve/recommend')
def recommend_cves():
    """
    Get CVE recommendations based on context
    
    Example: /api/cve/recommend?context=PHP web application
    """
    if not cve_rag:
        return jsonify({'error': 'RAG system not available'}), 503
    
    try:
        context = request.args.get('context', '').strip()
        
        if not context:
            return jsonify({'error': 'Context parameter required'}), 400
        
        question = f"""Based on this context: {context}

What are the most important CVEs I should be aware of?
Provide:
1. Top 5 most critical CVEs
2. Why they're relevant
3. Priority order for patching
"""
        
        result = cve_rag.ask(question, top_k=10)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Enhanced Template Routes (Update existing routes)
# ============================================================================

@app.route('/detailed-findings/<scan_id>')
def detailed_findings_enhanced(scan_id):
    """Enhanced version with RAG explanations"""
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        
        if not scan:
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        vulnerabilities = scan.vulnerabilities_json or []
        
        # Add AI explanations if RAG is available
        if cve_rag:
            for vuln in vulnerabilities[:5]:  # Limit to avoid rate limits
                try:
                    result = cve_rag.ask(
                        f"Briefly explain: {vuln['description']}",
                        top_k=2
                    )
                    vuln['ai_summary'] = result['answer'][:200] + "..."
                except:
                    vuln['ai_summary'] = None
        
        return render_template('detailed_findings.html',
                             scan_id=scan_id,
                             vulnerabilities=vulnerabilities,
                             rag_enabled=cve_rag is not None)
    finally:
        session_db.close()


# ============================================================================
# Usage in Templates
# ============================================================================

"""
Add to your detailed_findings.html template:

{% if rag_enabled %}
<div class="ai-explanation">
    <h4>🤖 AI Analysis</h4>
    {% if vuln.ai_summary %}
        <p>{{ vuln.ai_summary }}</p>
        <button onclick="getFullExplanation('{{ vuln.id }}')">
            Get Detailed Explanation
        </button>
    {% endif %}
</div>

<script>
async function getFullExplanation(vulnId) {
    const response = await fetch(`/api/vulnerability/analyze`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            description: vulnDescription,
            file: vulnFile,
            line: vulnLine
        })
    });
    
    const data = await response.json();
    
    // Display full analysis
    document.getElementById('analysis').innerHTML = data.analysis;
    
    // Show related CVEs
    data.related_cves.forEach(cve => {
        console.log(`Related: ${cve.cve_id} - ${cve.severity}`);
    });
}
</script>
{% endif %}
"""


# ============================================================================
# Environment Setup
# ============================================================================

"""
Add to your .env file:

GEMINI_API_KEY=your_gemini_api_key_here

Get your key from: https://makersuite.google.com/app/apikey
"""


# ============================================================================
# Testing
# ============================================================================

"""
Test the integration:

1. Start your Flask app:
   python app.py

2. Test endpoints:
   curl "http://localhost:5000/api/cve/ask?q=What+are+SQL+injection+CVEs"
   curl "http://localhost:5000/api/cve/explain/CVE-2023-12345"
   
3. Test in browser:
   http://localhost:5000/detailed-findings/YOUR_SCAN_ID
"""
