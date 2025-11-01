import subprocess
import re
import time
import threading
import logging
import platform
from collections import defaultdict, deque
from flask import Flask, jsonify, render_template_string, request, redirect
import warnings
import matplotlib
import socket
import requests
from flask_cors import CORS
from urllib.parse import urlparse
# ================== Flask Setup ==================
app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

matplotlib.use("Agg")
warnings.filterwarnings("ignore", category=UserWarning)

# ================== Traceroute Module ==================


class TracerouteAnalyzer:
    def __init__(self):
        self.traceroute_cache = {}
        self.cache_ttl = 300  # 5 minutes cache

    def run_traceroute(self, host):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["tracert", "-h", "20", "-w", "1000", host],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            else:
                result = subprocess.run(
                    ["traceroute", "-m", "20", "-w", "1", host],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

            if result.returncode == 0:
                return self.parse_traceroute(result.stdout, platform.system())
            else:
                logging.error(f"Traceroute failed for {host}: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logging.error(f"Traceroute timeout for {host}")
            return None
        except FileNotFoundError:
            logging.error("Traceroute command not found. Please install it.")
            return None
        except Exception as e:
            logging.error(f"Traceroute error for {host}: {str(e)}")
            return None

    def parse_traceroute(self, output, os_type):
        hops = []

        if os_type == "Windows":
            lines = output.split('\n')
            for line in lines:
                match = re.search(
                    r'\s*(\d+)\s+(?:(<?\d+)\s*ms\s*)?(?:(<?\d+)\s*ms\s*)?(?:(<?\d+)\s*ms\s*)?\s+(.+)', line)
                if match:
                    hop_num = int(match.group(1))
                    latencies = [match.group(i) for i in range(2, 5)
                                 if match.group(i) and match.group(i) != '*']
                    latencies = [int(l.replace('<', ''))
                                 for l in latencies if l.replace('<', '').isdigit()]
                    hop_address = match.group(5).strip()
                    ip_match = re.search(r'\[?([\d\.]+)\]?', hop_address)
                    ip = ip_match.group(1) if ip_match else None
                    hostname = hop_address.split('[')[0].strip(
                    ) if '[' in hop_address else hop_address
                    if latencies:
                        hops.append({
                            'hop': hop_num,
                            'ip': ip,
                            'hostname': hostname if hostname != ip else None,
                            'latency_avg': sum(latencies) / len(latencies),
                            'latency_min': min(latencies),
                            'latency_max': max(latencies),
                            'loss': len([l for l in [match.group(i) for i in range(2, 5)] if l == '*']) > 0
                        })
        else:
            lines = output.split('\n')
            for line in lines:
                match = re.search(
                    r'\s*(\d+)\s+(.+?)\s+\(([\d\.]+)\)\s+(.*)', line)
                if match:
                    hop_num = int(match.group(1))
                    hostname = match.group(2).strip()
                    ip = match.group(3)
                    latencies = [float(l) for l in re.findall(
                        r'([\d\.]+)\s*ms', match.group(4))]
                    if latencies:
                        hops.append({
                            'hop': hop_num,
                            'ip': ip,
                            'hostname': hostname if hostname != ip else None,
                            'latency_avg': sum(latencies) / len(latencies),
                            'latency_min': min(latencies),
                            'latency_max': max(latencies),
                            'loss': False
                        })
        return hops if hops else None

    def analyze_hops(self, hops):
        if not hops or len(hops) < 2:
            return None
        problems = []
        for i in range(len(hops) - 1):
            c, n = hops[i], hops[i + 1]
            inc = n['latency_avg'] - c['latency_avg']
            if inc > 50 or (c['latency_avg'] > 0 and inc / c['latency_avg'] > 0.5):
                problems.append({
                    'type': 'latency_spike',
                    'description': f"Latency jump {inc:.1f}ms between hop {c['hop']} and {n['hop']}"
                })
        for hop in hops:
            if hop.get('loss'):
                problems.append({
                    'type': 'packet_loss',
                    'description': f"Packet loss at hop {hop['hop']} ({hop['ip']})"
                })
        if hops[-1]['latency_avg'] > 200:
            problems.append({
                'type': 'high_final_latency',
                'description': f"High final latency: {hops[-1]['latency_avg']:.1f}ms"
            })
        return problems if problems else None

    def get_cached_traceroute(self, host):
        if host in self.traceroute_cache:
            t, data = self.traceroute_cache[host]
            if time.time() - t < self.cache_ttl:
                return data
        return None

    def traceroute_with_analysis(self, host):
        cached = self.get_cached_traceroute(host)
        if cached:
            return cached
        hops = self.run_traceroute(host)
        if hops:
            problems = self.analyze_hops(hops)
            total_latency = hops[-1]['latency_avg'] if hops else 0
            result = {
                'host': host,
                'timestamp': time.time(),
                'hops': hops,
                'hop_count': len(hops),
                'total_latency': total_latency,
                'problems': problems
            }
            self.traceroute_cache[host] = (time.time(), result)
            return result
        return None


# ================== Main Network Controller ==================
class RealNetController:
    def __init__(self, hosts, poll_interval=3, ema_alpha=0.3):
        self.hosts = hosts
        self.poll_interval = poll_interval
        self.ema_alpha = ema_alpha
        self.running = False
        self.link_ema = {}
        self.link_hist = defaultdict(lambda: deque(maxlen=10))
        self.alerts = deque(maxlen=50)
        self.traceroute_results = {}
        self.lock = threading.Lock()
        self.tracer = TracerouteAnalyzer()
        self.last_traceroute_time = {}
        self.traceroute_cooldown = 180

    def ping_host(self, host):
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["ping", "-n", "1", "-w", "1000", host],
                                              stderr=subprocess.STDOUT, text=True)
                m = re.search(r"Average = (\d+)ms", out)
            else:
                out = subprocess.check_output(["ping", "-c", "1", "-W", "1", host],
                                              stderr=subprocess.STDOUT, text=True)
                m = re.search(r"time=([\d.]+)\s*ms", out)
            if m:
                return max(int(float(m.group(1))), 1)
        except Exception:
            pass
        try:
            url = host if host.startswith("http") else f"https://{host}"
            start = time.time()
            r = requests.get(url, timeout=3)
            latency = int((time.time() - start) * 1000)
            if r.status_code < 500:
                return max(latency, 1)
        except Exception:
            pass
        return None

    def should_run_traceroute(self, host):
        return time.time() - self.last_traceroute_time.get(host, 0) > self.traceroute_cooldown

    def handle_anomaly(self, host, latency, threshold):
        msg = f"[ALERT] {host}: latency {latency}ms (threshold≈{threshold:.1f}ms)"
        logging.warning(msg)
        with self.lock:
            self.alerts.append((time.time(), msg, "anomaly"))
        if self.should_run_traceroute(host):
            self.last_traceroute_time[host] = time.time()
            threading.Thread(target=self._run_traceroute_analysis,
                             args=(host, latency), daemon=True).start()

    def _run_traceroute_analysis(self, host, trigger_latency):
        result = self.tracer.traceroute_with_analysis(host)
        if result:
            with self.lock:
                self.traceroute_results[host] = result
                if result['problems']:
                    for p in result['problems']:
                        self.alerts.append(
                            (time.time(), f"[TRACEROUTE] {host}: {p['description']}", "traceroute"))
                else:
                    self.alerts.append(
                        (time.time(), f"[TRACEROUTE] {host}: No issues detected", "traceroute"))
        else:
            with self.lock:
                self.alerts.append(
                    (time.time(), f"[TRACEROUTE] {host}: Failed to complete", "error"))

    def poll_once(self):
        for host in list(self.hosts):
            latency = self.ping_host(host)
            key = ("LOCAL", host)
            if latency is None:
                msg = f"[FAILURE] Host {host} unreachable."
                with self.lock:
                    self.alerts.append((time.time(), msg, "failure"))
                if self.should_run_traceroute(host):
                    self.last_traceroute_time[host] = time.time()
                    threading.Thread(target=self._run_traceroute_analysis, args=(
                        host, 9999), daemon=True).start()
                continue
            prev = self.link_ema.get(key, latency)
            ema = self.ema_alpha * latency + (1 - self.ema_alpha) * prev
            self.link_ema[key] = ema
            self.link_hist[key].append(latency)
            hist = self.link_hist[key]
            if len(hist) >= 5:
                mean = sum(hist) / len(hist)
                stdev = (sum((x - mean) ** 2 for x in hist) / len(hist)) ** 0.5
                thr = mean + 2.5 * stdev
            else:
                thr = ema * 2.5
            if latency > thr:
                self.handle_anomaly(host, latency, thr)
            logging.info(f"{host:<20} latency={latency:>4}ms  ema={ema:>5.1f}")

    def _loop(self):
        while self.running:
            self.poll_once()
            time.sleep(self.poll_interval)

    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False

    def add_host(self, host):
        if host not in self.hosts:
            self.hosts.append(host)
            logging.info(f"Host {host} added.")

    def remove_host(self, host):
        if host in self.hosts:
            self.hosts.remove(host)
            logging.info(f"Host {host} removed.")

    def get_traceroute_result(self, host):
        with self.lock:
            return self.traceroute_results.get(host)


    def dump_metrics(self):
        with self.lock:
            metrics = {
                h: {
                    "ema": round(self.link_ema.get(("LOCAL", h), 0), 1),
                    "latest": self.link_hist[("LOCAL", h)][-1] if self.link_hist[("LOCAL", h)] else None,
                    "has_traceroute": h in self.traceroute_results
                }
                for h in self.hosts
            }
            alerts = list(self.alerts)[-20:]
        return {"metrics": metrics, "alerts": alerts}
# ---------------------------------------
# 🌍 Utility: Get IP and location info
# ---------------------------------------


def get_ip_info(host):
    """Fetch IP location and organization info for a host or domain."""
    try:
        # If it's a URL, extract just the domain
        if host.startswith("http"):
            host = urlparse(host).netloc

        # Try to resolve domain to IP
        ip = host
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            try:
                ip = socket.gethostbyname(host)
                print(f"[DEBUG] Resolved {host} → {ip}")
            except Exception as e:
                print(f"[ERROR] DNS resolution failed for {host}: {e}")
                return None

        # Query ip-api.com for location + org info
        res = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,query,org",
            timeout=4,
        )
        data = res.json()

        if data.get("status") == "success":
            return {
                "ip": data.get("query"),
                "city": data.get("city"),
                "region": data.get("regionName"),
                "country": data.get("country"),
                "org": data.get("org"),
            }
        else:
            print(f"[DEBUG] Lookup failed for {host}: {data}")
    except Exception as e:
        print(f"[ERROR] IP info fetch failed for {host}: {e}")
    return None




# ================== Flask Routes ==================
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

hosts = ["8.8.8.8", "1.1.1.1", "google.com"]
ctrl = RealNetController(hosts)
ctrl.start()

HTML = """
<h2>🌐 AutoNetSim Dashboard</h2>
<form method="POST" action="/add_host">
  <input type="text" name="host" placeholder="Add host (example.com)">
  <button type="submit">Add Host</button>
</form>
<table border=1>
<tr><th>Host</th><th>Latest (ms)</th><th>EMA</th><th>Traceroute</th></tr>
{% for h, v in metrics.items() %}
<tr>
  <td>{{h}}</td>
  <td>{{v.latest}}</td>
  <td>{{v.ema}}</td>
  <td>{% if v.has_traceroute %}<a href="/traceroute/{{h}}">View</a>{% endif %}</td>
</tr>
{% endfor %}
</table>
<h3>Recent Alerts</h3>
<ul>
{% for a in alerts %}
  <li>{{a[1]}}</li>
{% endfor %}
</ul>
"""

TRACEROUTE_HTML = """
<h2>Traceroute for {{data.host}}</h2>
<table border=1>
<tr><th>Hop</th><th>IP</th><th>Hostname</th><th>Avg (ms)</th></tr>
{% for h in data.hops %}
<tr><td>{{h.hop}}</td><td>{{h.ip}}</td><td>{{h.hostname}}</td><td>{{h.latency_avg}}</td></tr>
{% endfor %}
</table>
{% if data.problems %}
<h3>Detected Problems</h3>
<ul>
{% for p in data.problems %}
  <li>{{p.description}}</li>
{% endfor %}
</ul>
{% endif %}
<a href="/">Back</a>
"""


@app.route("/")
def home():
    data = ctrl.dump_metrics()
    return render_template_string(HTML, metrics=data["metrics"], alerts=data["alerts"])


@app.route("/metrics")
def metrics():
    return jsonify(ctrl.dump_metrics())


@app.route("/api/traceroute/<host>")
def api_traceroute(host):
    """API endpoint for traceroute data (returns JSON)"""
    r = ctrl.get_traceroute_result(host)
    if r:
        return jsonify(r)
    return jsonify({"error": "No traceroute data available"}), 404


@app.route("/traceroute/<host>")
def view_traceroute(host):
    """HTML view for traceroute data"""
    r = ctrl.get_traceroute_result(host)
    if r:
        return render_template_string(TRACEROUTE_HTML, data=r)
    return f"<h3>No traceroute data for {host}</h3><a href='/'>Back</a>", 404


@app.route("/add_host", methods=["POST"])
def add_host():
    host = request.form.get("host")
    if host:
        ctrl.add_host(host)
    return redirect("/")


@app.route("/ipinfo/<host>")
def ipinfo(host):
    info = get_ip_info(host)
    if info:
        return jsonify(info)
    return jsonify({"error": "Info not found"}), 404


@app.route("/remove_host", methods=["POST"])
def remove_host():
    host = request.form.get("host")
    if host:
        ctrl.remove_host(host)
    return redirect("/")


if __name__ == "__main__":
    print("=" * 60)
    print("🌐 AutoNetSim - Intelligent Network Monitor")
    print("=" * 60)
    print("Dashboard running at: http://127.0.0.1:5000")
    try:
        app.run(debug=False, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        ctrl.stop()
