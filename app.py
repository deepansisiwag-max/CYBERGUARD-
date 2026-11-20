from flask import Flask, jsonify, send_from_directory, request
import ipaddress
from datetime import datetime

app = Flask(__name__)

# =====================================
# CYBERGUARD - LOGIN ACTIVITY ANALYZER
# =====================================

# START WITH EMPTY LOGIN RECORDS
login_data = []
print("CYBERGUARD VERSION 2 - EMPTY LOGIN DATA")


# HOME PAGE
@app.route("/")
def home():
    return send_from_directory(".", "index.html")


# CSS
@app.route("/style.css")
def css():
    return send_from_directory(".", "style.css")


# JAVASCRIPT
@app.route("/script.js")
def javascript():
    return send_from_directory(".", "script.js")


# DASHBOARD ANALYSIS
@app.route("/api/analysis")
def analysis():
    total = len(login_data)

    failed = sum(
        1 for login in login_data
        if login["status"] == "Failed"
    )

    ip_attempts = {}

    for login in login_data:
        if login["status"] == "Failed":
            ip = login["ip"]
            ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

    suspicious_ips = [
        ip for ip, count in ip_attempts.items()
        if count >= 3
    ]

    maximum_attempts = max(ip_attempts.values(), default=0)

    if maximum_attempts >= 3:
        security_status = "DANGER"
    elif maximum_attempts == 2:
        security_status = "HIGH RISK"
    elif maximum_attempts == 1:
        security_status = "WARNING"
    else:
        security_status = "SAFE"

    return jsonify({
        "total_logins": total,
        "failed_logins": failed,
        "suspicious_activities": len(suspicious_ips),
        "security_status": security_status,
        "suspicious_ips": suspicious_ips,
        "login_records": login_data
    })


# ADD SIMULATED LOGIN
@app.route("/api/login", methods=["POST"])
def add_login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON request body."
        }), 400

    username = str(data.get("username", "")).strip()
    ip = str(data.get("ip", "")).strip()
    status = str(data.get("status", "")).strip()

    if not username or not ip:
        return jsonify({
            "error": "Username and IP are required."
        }), 400

    if status not in ["Success", "Failed"]:
        return jsonify({
            "error": "Invalid login status."
        }), 400

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({
            "error": "Invalid IP address."
        }), 400

    login = {
        "username": username,
        "ip": ip,
        "status": status,
        "time": datetime.now().strftime(
            "%d-%m-%Y %I:%M:%S %p"
        )
    }

    login_data.append(login)

    return jsonify({
        "message": "Login record added successfully!",
        "login": login
    }), 201


# IP ADDRESS ANALYSIS
@app.route("/api/ip-analysis")
def ip_analysis():
    ip = request.args.get("ip", "").strip()

    if not ip:
        return jsonify({
            "error": "Please enter an IP address."
        }), 400

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({
            "error": "Invalid IP address. Please enter a valid IP."
        }), 400

    if address.is_loopback:
        network_type = "Loopback"
    elif address.is_private:
        network_type = "Private"
    elif address.is_link_local:
        network_type = "Link-local"
    elif address.is_multicast:
        network_type = "Multicast"
    elif address.is_reserved:
        network_type = "Reserved"
    elif address.is_unspecified:
        network_type = "Unspecified"
    elif address.is_global:
        network_type = "Public"
    else:
        network_type = "Special-purpose / Non-global"

    return jsonify({
        "ip": str(address),
        "status": "Valid",
        "version": "IPv" + str(address.version),
        "network_type": network_type,
        "message": "IP address successfully analyzed."
    })


# START SERVER
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )