"""
VulnHawk Web Dashboard
Flask-based web interface for the vulnerability scanner
"""

import os
import json
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, send_from_directory

import config
from vulnhawk import VulnHawk

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Store for scan results
scan_results = {}
scan_status = {"running": False, "target": None, "progress": ""}

# HTML Templates
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnHawk Dashboard</title>
    <style>
        :root {
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --border: #30363d;
            --accent: #58a6ff;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --success: #3fb950;
            --warning: #d29922;
            --danger: #f85149;
            --critical: #da3633;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: var(--bg-card);
            border-bottom: 1px solid var(--border);
            padding: 15px 0;
            margin-bottom: 30px;
        }
        header .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--accent);
        }
        .logo span { color: var(--danger); }
        nav a {
            color: var(--text-muted);
            text-decoration: none;
            margin-left: 20px;
            transition: color 0.2s;
        }
        nav a:hover { color: var(--accent); }
        .scan-form {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
        }
        .scan-form h2 {
            margin-bottom: 20px;
            color: var(--accent);
        }
        .form-row {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: flex-end;
        }
        .form-group {
            flex: 1;
            min-width: 200px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 10px 15px;
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 1rem;
        }
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: var(--accent);
        }
        .checkbox-group {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 15px;
        }
        .checkbox-group label {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
        }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary {
            background: var(--accent);
            color: #000;
        }
        .btn-primary:hover { background: #79b8ff; }
        .btn-primary:disabled {
            background: var(--border);
            cursor: not-allowed;
        }
        .btn-danger {
            background: var(--danger);
            color: #fff;
        }
        .status-bar {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 15px 20px;
            margin-bottom: 30px;
            display: none;
        }
        .status-bar.active { display: block; }
        .status-bar .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid var(--border);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 10px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
        }
        .stat-card h3 {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 10px;
        }
        .stat-card .value {
            font-size: 2.5rem;
            font-weight: bold;
        }
        .stat-card.critical .value { color: var(--critical); }
        .stat-card.warning .value { color: var(--warning); }
        .stat-card.success .value { color: var(--success); }
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
        }
        .section h2 {
            color: var(--accent);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th { color: var(--text-muted); font-weight: 600; }
        tr:hover { background: rgba(88, 166, 255, 0.05); }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical { background: var(--critical); color: #fff; }
        .severity-high { background: #f97316; color: #fff; }
        .severity-medium { background: var(--warning); color: #000; }
        .severity-low { background: var(--success); color: #000; }
        .port-badge {
            display: inline-block;
            padding: 4px 10px;
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 4px;
            margin: 2px;
            font-family: monospace;
        }
        .port-badge.risky {
            border-color: var(--danger);
            color: var(--danger);
        }
        .risk-meter {
            height: 10px;
            background: var(--bg-dark);
            border-radius: 5px;
            overflow: hidden;
            margin-top: 10px;
        }
        .risk-meter-fill {
            height: 100%;
            transition: width 0.5s;
        }
        .risk-low { background: var(--success); }
        .risk-medium { background: var(--warning); }
        .risk-high { background: #f97316; }
        .risk-critical { background: var(--critical); }
        .history-item {
            padding: 15px;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .history-item:hover { border-color: var(--accent); cursor: pointer; }
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-muted);
        }
        .download-links { margin-top: 15px; }
        .download-links a {
            color: var(--accent);
            margin-right: 15px;
            text-decoration: none;
        }
        .download-links a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="logo">
                <span>🦅</span> VulnHawk
            </div>
            <nav>
                <a href="/">Dashboard</a>
                <a href="/history">Scan History</a>
                <a href="/reports">Reports</a>
            </nav>
        </div>
    </header>

    <div class="container">
        <div class="scan-form">
            <h2>🔍 New Vulnerability Scan</h2>
            <form id="scanForm">
                <div class="form-row">
                    <div class="form-group">
                        <label for="target">Target (IP/Hostname/Subnet)</label>
                        <input type="text" id="target" name="target" placeholder="192.168.1.1 or 192.168.1.0/24" required>
                    </div>
                    <div class="form-group">
                        <label for="ports">Port Range</label>
                        <input type="text" id="ports" name="ports" placeholder="1-1024" value="1-1024">
                    </div>
                    <div class="form-group">
                        <label for="severity">Min. Severity</label>
                        <select id="severity" name="severity">
                            <option value="LOW">Low</option>
                            <option value="MEDIUM">Medium</option>
                            <option value="HIGH">High</option>
                            <option value="CRITICAL">Critical</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary" id="scanBtn">Start Scan</button>
                </div>
                <div class="checkbox-group">
                    <label><input type="checkbox" name="aggressive"> Aggressive Scan</label>
                    <label><input type="checkbox" name="udp"> Include UDP</label>
                    <label><input type="checkbox" name="local_checks"> Local Checks</label>
                    <label><input type="checkbox" name="quick"> Quick Scan</label>
                </div>
            </form>
        </div>

        <div class="status-bar" id="statusBar">
            <span class="spinner"></span>
            <span id="statusText">Scanning...</span>
        </div>

        <div id="results" style="display: none;">
            <div class="results-grid">
                <div class="stat-card">
                    <h3>Open Ports</h3>
                    <div class="value" id="statOpenPorts">0</div>
                </div>
                <div class="stat-card warning">
                    <h3>Risky Ports</h3>
                    <div class="value" id="statRiskyPorts">0</div>
                </div>
                <div class="stat-card">
                    <h3>Services Detected</h3>
                    <div class="value" id="statServices">0</div>
                </div>
                <div class="stat-card critical">
                    <h3>CVEs Found</h3>
                    <div class="value" id="statCves">0</div>
                </div>
                <div class="stat-card warning">
                    <h3>Misconfigurations</h3>
                    <div class="value" id="statMisconfigs">0</div>
                </div>
                <div class="stat-card">
                    <h3>Risk Level</h3>
                    <div class="value" id="statRisk">-</div>
                    <div class="risk-meter">
                        <div class="risk-meter-fill" id="riskMeter" style="width: 0%"></div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>📡 Open Ports</h2>
                <div id="portsContainer"></div>
            </div>

            <div class="section" id="servicesSection" style="display: none;">
                <h2>🔍 Detected Services</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Product</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody id="servicesTable"></tbody>
                </table>
            </div>

            <div class="section" id="cvesSection" style="display: none;">
                <h2>🔓 Vulnerabilities</h2>
                <table>
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Severity</th>
                            <th>CVSS Score</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody id="cvesTable"></tbody>
                </table>
            </div>

            <div class="section" id="misconfigSection" style="display: none;">
                <h2>⚠️ Misconfigurations</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Issue</th>
                            <th>Description</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody id="misconfigTable"></tbody>
                </table>
            </div>

            <div class="download-links" id="downloadLinks">
                <strong>Download Report:</strong>
                <a href="#" id="downloadJson">JSON</a>
                <a href="#" id="downloadHtml">HTML</a>
                <a href="#" id="downloadTxt">Text</a>
            </div>
        </div>

        <div class="empty-state" id="emptyState">
            <h3>No scans yet</h3>
            <p>Enter a target above to start a vulnerability scan</p>
        </div>
    </div>

    <script>
        const scanForm = document.getElementById('scanForm');
        const scanBtn = document.getElementById('scanBtn');
        const statusBar = document.getElementById('statusBar');
        const statusText = document.getElementById('statusText');
        const resultsDiv = document.getElementById('results');
        const emptyState = document.getElementById('emptyState');

        let pollInterval;

        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(scanForm);
            const data = {
                target: formData.get('target'),
                ports: formData.get('ports'),
                severity: formData.get('severity'),
                aggressive: formData.has('aggressive'),
                udp: formData.has('udp'),
                local_checks: formData.has('local_checks'),
                quick: formData.has('quick')
            };

            scanBtn.disabled = true;
            statusBar.classList.add('active');
            statusText.textContent = 'Starting scan...';
            emptyState.style.display = 'none';
            resultsDiv.style.display = 'none';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                if (response.ok) {
                    pollInterval = setInterval(checkStatus, 2000);
                }
            } catch (error) {
                statusText.textContent = 'Error starting scan';
                scanBtn.disabled = false;
            }
        });

        async function checkStatus() {
            try {
                const response = await fetch('/api/status');
                const status = await response.json();

                statusText.textContent = status.progress || 'Scanning...';

                if (!status.running) {
                    clearInterval(pollInterval);
                    scanBtn.disabled = false;
                    statusBar.classList.remove('active');
                    
                    if (status.results) {
                        displayResults(status.results);
                    }
                }
            } catch (error) {
                console.error('Status check failed:', error);
            }
        }

        function displayResults(data) {
            resultsDiv.style.display = 'block';
            
            // Update stats
            document.getElementById('statOpenPorts').textContent = data.open_ports?.length || 0;
            document.getElementById('statRiskyPorts').textContent = data.risky_ports?.length || 0;
            document.getElementById('statServices').textContent = data.services?.length || 0;
            document.getElementById('statCves').textContent = data.cves?.length || 0;
            document.getElementById('statMisconfigs').textContent = data.misconfigurations?.length || 0;

            // Risk level
            const riskLevel = calculateRisk(data);
            document.getElementById('statRisk').textContent = riskLevel;
            const riskMeter = document.getElementById('riskMeter');
            const riskPercent = { 'LOW': 25, 'MEDIUM': 50, 'HIGH': 75, 'CRITICAL': 100 };
            riskMeter.style.width = (riskPercent[riskLevel] || 0) + '%';
            riskMeter.className = 'risk-meter-fill risk-' + riskLevel.toLowerCase();

            // Ports
            const portsContainer = document.getElementById('portsContainer');
            portsContainer.innerHTML = '';
            const riskyPortNums = (data.risky_ports || []).map(p => p.port);
            (data.hosts || []).forEach(host => {
                (host.ports || []).forEach(port => {
                    const badge = document.createElement('span');
                    badge.className = 'port-badge' + (riskyPortNums.includes(port.port) ? ' risky' : '');
                    badge.textContent = `${port.port}/${port.protocol} (${port.service})`;
                    portsContainer.appendChild(badge);
                });
            });

            // Services
            if (data.services?.length) {
                document.getElementById('servicesSection').style.display = 'block';
                const tbody = document.getElementById('servicesTable');
                tbody.innerHTML = data.services.map(s => `
                    <tr>
                        <td>${s.port}</td>
                        <td>${s.service_name}</td>
                        <td>${s.product || '-'}</td>
                        <td>${s.version || '-'}</td>
                    </tr>
                `).join('');
            }

            // CVEs
            if (data.cves?.length) {
                document.getElementById('cvesSection').style.display = 'block';
                const tbody = document.getElementById('cvesTable');
                tbody.innerHTML = data.cves.map(c => `
                    <tr>
                        <td>${c.cve_id}</td>
                        <td><span class="severity-badge severity-${c.severity?.toLowerCase()}">${c.severity}</span></td>
                        <td>${c.cvss_score}</td>
                        <td>${c.description?.substring(0, 150)}...</td>
                    </tr>
                `).join('');
            }

            // Misconfigurations
            if (data.misconfigurations?.length) {
                document.getElementById('misconfigSection').style.display = 'block';
                const tbody = document.getElementById('misconfigTable');
                tbody.innerHTML = data.misconfigurations.map(m => `
                    <tr>
                        <td><span class="severity-badge severity-${m.severity?.toLowerCase()}">${m.severity}</span></td>
                        <td>${m.check_name}</td>
                        <td>${m.description}</td>
                        <td>${m.remediation}</td>
                    </tr>
                `).join('');
            }
        }

        function calculateRisk(data) {
            let score = 0;
            (data.cves || []).forEach(c => {
                if (c.cvss_score >= 9) score += 10;
                else if (c.cvss_score >= 7) score += 7;
                else if (c.cvss_score >= 4) score += 4;
                else score += 1;
            });
            score += (data.risky_ports?.length || 0) * 3;
            (data.misconfigurations || []).forEach(m => {
                const weights = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 2, INFO: 1 };
                score += weights[m.severity] || 1;
            });
            
            if (score >= 50) return 'CRITICAL';
            if (score >= 30) return 'HIGH';
            if (score >= 15) return 'MEDIUM';
            return 'LOW';
        }
    </script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    """Render main dashboard"""
    return render_template_string(DASHBOARD_TEMPLATE)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a new vulnerability scan"""
    global scan_status, scan_results
    
    if scan_status["running"]:
        return jsonify({"error": "Scan already in progress"}), 400
    
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "").strip()
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    # Build options
    options = {
        "ports": data.get("ports", config.DEFAULT_PORTS),
        "aggressive": data.get("aggressive", False),
        "udp": data.get("udp", False),
        "local_checks": data.get("local_checks", False),
        "min_severity": data.get("severity", "LOW"),
        "skip_report": True  # We'll generate reports separately
    }
    
    if data.get("quick"):
        options["ports"] = ",".join(map(str, config.COMMON_PORTS))
    
    # Start scan in background thread
    def run_scan():
        global scan_status, scan_results
        scan_status = {"running": True, "target": target, "progress": "Initializing scan..."}
        
        try:
            scanner = VulnHawk(target, options)
            
            scan_status["progress"] = "Running port scan..."
            scanner.run_port_scan()
            
            if scanner.scan_data["open_ports"]:
                scan_status["progress"] = "Detecting services..."
                scanner.run_service_detection()
            
            if not options.get("skip_cve"):
                scan_status["progress"] = "Looking up CVEs..."
                scanner.run_cve_lookup()
            
            if not options.get("skip_misconfig"):
                scan_status["progress"] = "Checking misconfigurations..."
                scanner.run_misconfig_checks()
            
            scan_results = scanner.scan_data
            scan_status["progress"] = "Scan complete!"
            
        except Exception as e:
            scan_status["progress"] = f"Error: {str(e)}"
            scan_results = {}
        
        finally:
            scan_status["running"] = False
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({"status": "started", "target": target})


@app.route("/api/status")
def get_status():
    """Get current scan status"""
    return jsonify({
        "running": scan_status["running"],
        "target": scan_status["target"],
        "progress": scan_status["progress"],
        "results": scan_results if not scan_status["running"] else None
    })


@app.route("/api/results")
def get_results():
    """Get scan results"""
    return jsonify(scan_results)


@app.route("/history")
def history():
    """View scan history"""
    # List report files
    reports_dir = Path(config.REPORT_OUTPUT_DIR)
    if not reports_dir.exists():
        return render_template_string("""
            <html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:40px;">
            <h1>No scan history yet</h1>
            <p><a href="/" style="color:#58a6ff;">Run a scan</a></p>
            </body></html>
        """)
    
    reports = list(reports_dir.glob("*.json"))
    report_list = []
    
    for report in reports[:20]:  # Limit to 20 most recent
        try:
            with open(report) as f:
                data = json.load(f)
                report_list.append({
                    "filename": report.name,
                    "target": data.get("report_info", {}).get("target", "Unknown"),
                    "date": data.get("report_info", {}).get("generated_at", "Unknown"),
                    "risk": data.get("summary", {}).get("risk_score", "Unknown")
                })
        except:
            pass
    
    return render_template_string("""
        <html><head><style>
        body { background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:40px; }
        h1 { color:#58a6ff; }
        .item { background:#161b22;border:1px solid #30363d;padding:15px;margin:10px 0;border-radius:8px; }
        a { color:#58a6ff; }
        </style></head><body>
        <h1>Scan History</h1>
        <p><a href="/">← Back to Dashboard</a></p>
        {% for r in reports %}
        <div class="item">
            <strong>{{ r.target }}</strong><br>
            <small>{{ r.date }} | Risk: {{ r.risk }}</small><br>
            <a href="/reports/{{ r.filename }}">Download JSON</a>
        </div>
        {% endfor %}
        </body></html>
    """, reports=report_list)


@app.route("/reports/<path:filename>")
def download_report(filename):
    """Download a report file"""
    return send_from_directory(config.REPORT_OUTPUT_DIR, filename)


def run_dashboard(host: str = None, port: int = None, debug: bool = False):
    """Run the web dashboard"""
    host = host or config.FLASK_HOST
    port = port or config.FLASK_PORT
    debug = debug or config.FLASK_DEBUG
    
    print(f"\n🦅 VulnHawk Dashboard starting at http://{host}:{port}\n")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="VulnHawk Web Dashboard")
    parser.add_argument("--host", default=config.FLASK_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=config.FLASK_PORT, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    run_dashboard(args.host, args.port, args.debug)
