"""
CVE RAG API - REST API for CVE Question Answering

Provides REST endpoints for asking questions about CVEs using RAG.

Usage:
    python cve_rag_api.py --gemini-key YOUR_KEY --port 5001
    
Then access:
    http://localhost:5001/api/ask?q=What are SQL injection CVEs?
"""

import argparse
import os
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from cve_rag_system import CVERAGSystem

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global RAG system instance
rag_system = None


# HTML template for web interface
WEB_INTERFACE = """
<!DOCTYPE html>
<html>
<head>
    <title>CVE RAG System</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }
        .input-group {
            margin: 20px 0;
        }
        input[type="text"] {
            width: 100%;
            padding: 15px;
            font-size: 16px;
            border: 2px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        button {
            background: #4CAF50;
            color: white;
            padding: 15px 30px;
            font-size: 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 10px;
        }
        button:hover {
            background: #45a049;
        }
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .response {
            margin-top: 30px;
            padding: 20px;
            background: #f9f9f9;
            border-left: 4px solid #4CAF50;
            border-radius: 5px;
            display: none;
        }
        .sources {
            margin-top: 20px;
            padding: 15px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 5px;
        }
        .source-item {
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 3px;
        }
        .loading {
            text-align: center;
            padding: 20px;
            display: none;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #4CAF50;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .examples {
            margin: 20px 0;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 5px;
        }
        .example-btn {
            background: #2196F3;
            margin: 5px;
            padding: 10px 15px;
            font-size: 14px;
        }
        .example-btn:hover {
            background: #0b7dda;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 CVE RAG System</h1>
        <p>Ask me anything about CVEs! I'll search through 316,437 vulnerabilities and provide intelligent answers.</p>
        
        <div class="examples">
            <strong>Example Questions:</strong><br>
            <button class="example-btn" onclick="askExample('What are the most dangerous SQL injection CVEs?')">SQL Injection CVEs</button>
            <button class="example-btn" onclick="askExample('Explain buffer overflow vulnerabilities')">Buffer Overflows</button>
            <button class="example-btn" onclick="askExample('What are critical remote code execution CVEs?')">RCE CVEs</button>
            <button class="example-btn" onclick="askExample('How do XSS vulnerabilities work?')">XSS Explained</button>
        </div>
        
        <div class="input-group">
            <input type="text" id="question" placeholder="Ask a question about CVEs..." onkeypress="if(event.key==='Enter') askQuestion()">
            <button onclick="askQuestion()" id="askBtn">Ask Question</button>
        </div>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Searching CVEs and generating answer...</p>
        </div>
        
        <div class="response" id="response">
            <h3>Answer:</h3>
            <div id="answer"></div>
            
            <div class="sources" id="sources" style="display:none;">
                <h4>📚 Sources:</h4>
                <div id="sourcesList"></div>
            </div>
        </div>
    </div>
    
    <script>
        function askExample(question) {
            document.getElementById('question').value = question;
            askQuestion();
        }
        
        async function askQuestion() {
            const question = document.getElementById('question').value.trim();
            if (!question) return;
            
            // Show loading
            document.getElementById('loading').style.display = 'block';
            document.getElementById('response').style.display = 'none';
            document.getElementById('askBtn').disabled = true;
            
            try {
                const response = await fetch(`/api/ask?q=${encodeURIComponent(question)}`);
                const data = await response.json();
                
                if (data.error) {
                    alert('Error: ' + data.error);
                    return;
                }
                
                // Display answer
                document.getElementById('answer').innerHTML = data.answer.replace(/\\n/g, '<br>');
                
                // Display sources
                if (data.sources && data.sources.length > 0) {
                    const sourcesList = document.getElementById('sourcesList');
                    sourcesList.innerHTML = '';
                    
                    data.sources.forEach((source, i) => {
                        const div = document.createElement('div');
                        div.className = 'source-item';
                        div.innerHTML = `
                            <strong>${i+1}. ${source.cve_id}</strong> - ${source.severity}
                            ${source.cvss_score ? ` (CVSS: ${source.cvss_score})` : ''}<br>
                            <small>${source.description.substring(0, 150)}...</small>
                        `;
                        sourcesList.appendChild(div);
                    });
                    
                    document.getElementById('sources').style.display = 'block';
                } else {
                    document.getElementById('sources').style.display = 'none';
                }
                
                document.getElementById('response').style.display = 'block';
                
            } catch (error) {
                alert('Error: ' + error.message);
            } finally {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('askBtn').disabled = false;
            }
        }
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    """Web interface"""
    return render_template_string(WEB_INTERFACE)


@app.route('/api/ask', methods=['GET'])
def ask_question():
    """
    Ask a question about CVEs
    
    Query Parameters:
        q: Question to ask (required)
        top_k: Number of CVEs to retrieve (default: 5)
        sources: Include sources (default: true)
    
    Returns:
        JSON with answer and sources
    """
    try:
        # Get parameters
        question = request.args.get('q', '').strip()
        top_k = int(request.args.get('top_k', 5))
        show_sources = request.args.get('sources', 'true').lower() != 'false'
        
        if not question:
            return jsonify({'error': 'Question parameter "q" is required'}), 400
        
        # Get answer
        result = rag_system.ask(question, top_k=top_k, show_sources=show_sources)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'CVE RAG API',
        'index': rag_system.searcher.index_name if rag_system else None,
        'total_cves': rag_system.searcher.index.ntotal if rag_system else 0
    })


@app.route('/api/stats', methods=['GET'])
def stats():
    """Get system statistics"""
    if not rag_system:
        return jsonify({'error': 'RAG system not initialized'}), 500
    
    stats = rag_system.searcher.get_stats()
    return jsonify(stats)


def main():
    parser = argparse.ArgumentParser(description='CVE RAG API Server')
    
    parser.add_argument('--gemini-key', required=True, help='Google Gemini API key')
    parser.add_argument('--index-name', default='cve-full', help='FAISS index name (default: cve-full)')
    parser.add_argument('--port', type=int, default=5001, help='Port to run on (default: 5001)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    
    args = parser.parse_args()
    
    # Initialize RAG system
    global rag_system
    print("Initializing CVE RAG System...")
    rag_system = CVERAGSystem(
        gemini_api_key=args.gemini_key,
        index_name=args.index_name
    )
    
    print(f"\n{'='*80}")
    print(f"CVE RAG API Server Starting...")
    print(f"{'='*80}")
    print(f"\nWeb Interface: http://localhost:{args.port}/")
    print(f"API Endpoint: http://localhost:{args.port}/api/ask?q=YOUR_QUESTION")
    print(f"Health Check: http://localhost:{args.port}/api/health")
    print(f"\nPress Ctrl+C to stop\n")
    
    # Run Flask app
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == '__main__':
    main()
