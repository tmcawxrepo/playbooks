import ssl
import socket
import requests
from jinja2 import Template
import datetime

def check_certificate(hostname, port):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, port))
            cert = s.getpeercert()
            return cert
    except Exception as e:
        return f"Error checking certificate: {e}"

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

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org')
        return response.text
    except Exception as e:
        return f"Error fetching public IP: {e}"

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
            <h2>HSTS Status:</h2>
            <p class="status">{{ 'Present' if report['HSTS'][0] else 'Missing' }}</p>
            <p>{{ report['HSTS'][1] }}</p>
            <h2>CSP Status:</h2>
            <p class="status">{{ 'Present' if report['CSP'][0] else 'Missing' }}</p>
            <p>{{ report['CSP'][1] }}</p>
            <h2>Public IP:</h2>
            <p>{{ report['Public IP'] }}</p>
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
    certificate = check_certificate(hostname, port)
    hsts_result = check_hsts(url)
    csp_result = check_csp(url)
    public_ip = get_public_ip()
    headers = requests.get(url).headers  # Get all headers for the report

    report = {
        "Certificate": certificate,
        "HSTS": hsts_result,
        "CSP": csp_result,
        "Public IP": public_ip,
        "Headers": headers,
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