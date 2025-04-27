from flask import Flask, render_template, request
import jinja2
import datetime
import os

app = Flask(__name__)

# Configuración (ajusta estos valores según tu hardware y configuración)
CPU_CORES = 4
CPU_UTILIZATION_LIMIT = 0.8
MEMORY_GB = 8

def calculate_nginx_plus_processing(rps=None, tps=None, concurrent_users=None, ssl_requests=None):
    """Calcula el procesamiento de un proxy reverso en Nginx Plus."""

    # Estimaciones (ajusta estos valores según tu hardware y configuración)
    cpu_per_rps = 0.001
    memory_per_rps = 0.0001
    cpu_per_tps = 0.002
    memory_per_tps = 0.0002
    cpu_per_user = 0.0005
    memory_per_user = 0.00005
    cpu_per_ssl = 0.0015
    memory_per_ssl = 0.00015

    estimated_cpu = 0
    total_memory_usage = 0

    if rps:
        estimated_cpu += rps * cpu_per_rps
        total_memory_usage += rps * memory_per_rps
    if tps:
        estimated_cpu += tps * cpu_per_tps
        total_memory_usage += tps * memory_per_tps
    if concurrent_users:
        estimated_cpu += concurrent_users * cpu_per_user
        total_memory_usage += concurrent_users * memory_per_user
    if ssl_requests:
        estimated_cpu += ssl_requests * cpu_per_ssl
        total_memory_usage += ssl_requests * memory_per_ssl

    cpu_overload = estimated_cpu > (CPU_CORES * CPU_UTILIZATION_LIMIT)
    memory_overload = total_memory_usage > MEMORY_GB

    return {
        "rps": rps,
        "tps": tps,
        "concurrent_users": concurrent_users,
        "ssl_requests": ssl_requests,
        "estimated_cpu": estimated_cpu,
        "total_memory_usage": total_memory_usage,
        "cpu_overload": cpu_overload,
        "memory_overload": memory_overload,
        "cpu_cores": CPU_CORES,
        "cpu_utilization_limit": CPU_UTILIZATION_LIMIT,
        "memory_gb": MEMORY_GB
    }

@app.route("/", methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        try:
            rps = int(request.form.get("rps") or 0)
            tps = int(request.form.get("tps") or 0)
            concurrent_users = int(request.form.get("concurrent_users") or 0)
            ssl_requests = int(request.form.get("ssl_requests") or 0)
        except ValueError:
            return "Entrada inválida. Por favor, ingrese números enteros.", 400

        results = calculate_nginx_plus_processing(rps=rps, tps=tps, concurrent_users=concurrent_users, ssl_requests=ssl_requests)

    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)  # Deshabilitar debug en producción