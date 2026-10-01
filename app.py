"""
DNS Security Monitoring & Malicious Domain Detection System.
Flask Application Entry Point and API Router.
"""

import os
from pathlib import Path
from flask import Flask, jsonify, render_template, request

import config
from core import database
from core.analyzer import analyze_domain
from simulator.dns_simulator import get_simulator

app = Flask(__name__)

# Ensure database tables exist at startup
database.init_db()
simulator = get_simulator()


@app.route("/")
def index():
    """Main SOC Security Operations Dashboard."""
    stats = database.get_dashboard_stats()
    recent_requests = database.get_recent_requests(limit=15)
    recent_alerts = database.get_recent_alerts(limit=6)
    is_running = simulator.is_running
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_requests=recent_requests,
        recent_alerts=recent_alerts,
        is_running=is_running,
    )


@app.route("/analyzer", methods=["GET", "POST"])
def analyzer():
    """Manual Domain Security Analyzer page."""
    analysis_result = None
    domain_input = ""

    if request.method == "POST":
        domain_input = request.form.get("domain", "").strip()
        if domain_input:
            analysis_result = analyze_domain(domain_input)

    return render_template(
        "analyzer.html",
        domain_input=domain_input,
        analysis=analysis_result,
    )


# --- REST API Endpoints for Dynamic Dashboard Polling ---


@app.route("/api/stats")
def api_stats():
    """Return live dashboard KPI statistics."""
    stats = database.get_dashboard_stats()
    stats["simulator_running"] = simulator.is_running
    return jsonify(stats)


@app.route("/api/recent-requests")
def api_recent_requests():
    """Return the most recent DNS requests in JSON."""
    limit = request.args.get("limit", default=15, type=int)
    requests = database.get_recent_requests(limit=min(limit, 50))
    return jsonify(requests)


@app.route("/api/recent-alerts")
def api_recent_alerts():
    """Return the most recent security alerts in JSON."""
    limit = request.args.get("limit", default=8, type=int)
    alerts = database.get_recent_alerts(limit=min(limit, 50))
    return jsonify(alerts)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """API endpoint to analyze an arbitrary domain string."""
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain parameter is required."}), 400

    result = analyze_domain(domain)
    return jsonify(result)


@app.route("/api/simulator/start", methods=["POST"])
def api_simulator_start():
    """Start the background mock DNS simulator."""
    data = request.get_json(silent=True) or {}
    interval = float(data.get("interval", config.DEFAULT_SIMULATOR_INTERVAL))
    started = simulator.start_background(interval=interval)
    return jsonify({
        "status": "started" if started else "already_running",
        "running": simulator.is_running,
        "interval": simulator.interval,
    })


@app.route("/api/simulator/stop", methods=["POST"])
def api_simulator_stop():
    """Stop the background mock DNS simulator."""
    stopped = simulator.stop()
    return jsonify({
        "status": "stopped" if stopped else "not_running",
        "running": simulator.is_running,
    })


@app.route("/api/simulator/status")
def api_simulator_status():
    """Query current status of the background simulator."""
    return jsonify({
        "running": simulator.is_running,
        "interval": simulator.interval,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")

    print("\n" + "=" * 65)
    print("  DNS Security Monitoring and Malicious Domain Detection System")
    print("  SOC Prototype Web Dashboard")
    print(f"  Server listening on: http://{host}:{port}")
    print("=" * 65 + "\n")
    app.run(host=host, port=port, debug=False)
