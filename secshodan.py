import shodan
import argparse
from jinja2 import Template
import datetime
import os

def shodan_scan(target, api_key):
    """Realiza un escaneo de Shodan en el objetivo especificado."""
    try:
        api = shodan.Shodan(api_key)
        results = api.search(target)
        return results
    except shodan.APIError as e:
        print(f"Error al escanear con Shodan: {e}")
        return None

def generate_html_report(target, results):
    """Genera un reporte HTML con los resultados del escaneo de Shodan."""
    template = Template("""
    <html>
        <head>
            <title>Shodan Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                pre { background: #f4f4f4; padding: 10px; }
                .status { font-weight: bold; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Shodan Security Report for {{ target }}</h1>
            <p>Report generated on {{ timestamp }}</p>
            {% if results and results.matches %}
            <h2>Results:</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Port</th>
                        <th>Hostnames</th>
                        <th>Organization</th>
                        <th>Data</th>
                    </tr>
                </thead>
                <tbody>
                    {% for result in results.matches %}
                    <tr>
                        <td>{{ result.ip_str }}</td>
                        <td>{{ result.port }}</td>
                        <td>{{ result.hostnames }}</td>
                        <td>{{ result.org }}</td>
                        <td><pre>{{ result.data }}</pre></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No results found or an error occurred.</p>
            {% endif %}
        </body>
    </html>
    """)
    return template.render(
        target=target,
        results=results,
        timestamp=datetime.datetime.now()
    )

def main():
    """Función principal para realizar el escaneo de Shodan y generar el reporte HTML."""
    parser = argparse.ArgumentParser(description="Evalúa la seguridad de un sitio o dominio con Shodan y genera un reporte HTML.")
    parser.add_argument("--target", required=True, help="Sitio o dominio a escanear.")
    parser.add_argument("--api_key", required=True, help="Clave de API de Shodan.")
    parser.add_argument("--report_file", required=True, help="Nombre del archivo HTML para el reporte.")

    args = parser.parse_args()

    # Realizar el escaneo de Shodan
    results = shodan_scan(args.target, args.api_key)

    # Generar el reporte HTML
    html_report = generate_html_report(args.target, results)

    # Guardar el reporte en un archivo
    with open(args.report_file, "w") as f:
        f.write(html_report)

    print(f"Reporte HTML generado en {args.report_file}")

if __name__ == "__main__":
    main()