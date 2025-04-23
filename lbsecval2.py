import ssl
import socket
import requests
from jinja2 import Template
import datetime

# Reemplaza con tu clave de API de VirusTotal
VIRUSTOTAL_API_KEY = '274ebcf7e576eef574e42957839dd854c3d77f8060b9cbb23e782dcf6421b64f'

def check_certificate(hostname, port):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, port))
            cert = s.getpeercert()
            tls_version = s.version()  # Obtener la versión de TLS utilizada
            return cert, tls_version
    except Exception as e:
        return f"Error checking certificate: {e}", None

def check_hsts(url):
    try:
        response = requests.get(url)
        hsts = response.headers.get('Strict-Transport-Security', None)
        return hsts is not None, hsts
    except Exception as e:
        return False, str(e)

def check_csp(url):
    try:
        response = requests.get(url)
        csp = response.headers.get('Content-Security-Policy', None)
        return csp is not None, csp
    except Exception as e:
        return False, str(e)

def check_csrf(url):
    try:
        response = requests.get(url)
        csrf_token = response.headers.get('X-CSRF-Token', None)
        return csrf_token is not None, csrf_token
    except Exception as e:
        return False, str(e)

def check_cors(url):
    try:
        response = requests.get(url)
        cors = response.headers.get('Access-Control-Allow-Origin', None)
        return cors is not None, cors
    except Exception as e:
        return False, str(e)

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org')
        return response.text
    except Exception as e:
        return f"Error fetching public IP: {e}"

def check_virustotal(hostname):
    url = f"https://www.virustotal.com/api/v3/domains/{hostname}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            return {
                "listed": any(value > 0 for value in result['data']['attributes']['last_analysis_stats'].values()),
                "details": result['data']['attributes']['last_analysis_stats']
            }
        else:
            return f"Error fetching from VirusTotal: {response.status_code}"
    except Exception as e:
        return f"Error checking VirusTotal: {e}"

def generate_html_report(hostname, report):
    template = Template("""
    <html>
        <head>
            <title>Security Evaluation Report</title>
            <style>
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                pre { background: #f4f4f4; padding: 10px; }
                .status { font-weight: bold; }
            </style>
        </head>
        <body>
            <h1>Security Evaluation Report for {{ hostname }}</h1>
            <h2>Certificate Details:</h2>
            <pre>{{ report['Certificate'] }}</pre>
            <h2>TLS Version:</h2>
            <p class="status">{{ report['TLS Version'] }}</p>
            <h2>HSTS Status:</h2>
            <p class="status">{{ 'Present' if report['HSTS'][0] else 'Missing' }}</p>
            <p>{{ report['HSTS'][1] }}</p>
            <h2>CSP Status:</h2>
            <p class="status">{{ 'Present' if report['CSP'][0] else 'Missing' }}</p>
            <p>{{ report['CSP'][1] }}</p>
            <h2>CSRF Header Status:</h2>
            <p class="status">{{ 'Present' if report['CSRF'][0] else 'Missing' }}</p>
            <p>{{ report['CSRF'][1] }}</p>
            <h2>CORS Header Status:</h2>
            <p class="status">{{ 'Present' if report['CORS'][0] else 'Missing' }}</p>
            <p>{{ report['CORS'][1] }}</p>
            <h2>Public IP:</h2>
            <p>{{ report['Public IP'] }}</p>
            <h2>VirusTotal Status:</h2>
            <p class="status">{{ 'Listed' if report['VirusTotal']['listed'] else 'Not Listed' }}</p>
            <pre>{{ report['VirusTotal']['details'] }}</pre>
            <h2>Response Headers:</h2>
            <pre>{{ report['Headers'] }}</pre>
            <footer>
                <p>Report generated on {{ timestamp }}</p>
            </footer>
        </body>
    </html>
    """)
    return template.render(hostname=hostname, report=report, timestamp=datetime.datetime.now())

def evaluate_website_security(hostname, port):
    url = f"https://{hostname}"
    certificate, tls_version = check_certificate(hostname, port)
    hsts_result = check_hsts(url)
    csp_result = check_csp(url)
    csrf_result = check_csrf(url)
    cors_result = check_cors(url)
    public_ip = get_public_ip()
    headers = requests.get(url).headers  # Get all headers for the report
    virustotal_result = check_virustotal(hostname)

    report = {
        "Certificate": certificate,
        "TLS Version": tls_version,
        "HSTS": hsts_result,
        "CSP": csp_result,
        "CSRF": csrf_result,
        "CORS": cors_result,
        "Public IP": public_ip,
        "Headers": headers,
        "VirusTotal": virustotal_result,
    }
    return report

if __name__ == "__main__":
    # Leer el hostname desde un archivo de texto
    with open('hostnames.txt', 'r') as file:
        hostnames = file.readlines()

    port = 443
    for hostname in hostnames:
        hostname = hostname.strip()  # Eliminar espacios en blanco

        if hostname:  # Asegurarse de que el hostname no esté vacío
            report = evaluate_website_security(hostname, port)

            # Generar el reporte HTML
            html_report = generate_html_report(hostname, report)

            # Crear nombre de archivo para el reporte
            report_filename = f"security_report_{hostname}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

            with open(report_filename, "w") as f:
                f.write(html_report)

            print(f"Security report saved as {report_filename}")