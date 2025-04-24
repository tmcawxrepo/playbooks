import requests
import json
import base64
import datetime
from jinja2 import Template
import argparse  # Importa el módulo argparse
import os

def read_config_from_file(config_file):
    """Lee la configuración desde un archivo."""
    config = {}
    try:
        with open(config_file, 'r') as f:
            for line in f:
                key, value = line.strip().split('=')
                config[key.strip()] = value.strip()
        return config
    except FileNotFoundError:
        print(f"Error: El archivo de configuración '{config_file}' no se encontró.")
        exit(1)
    except Exception as e:
        print(f"Error al leer el archivo de configuración: {e}")
        exit(1)

def get_mars_usage(api_key, api_secret, account_id, month=None, group_id=None):
    """Obtiene el consumo de MARS de Fivetran para una cuenta."""

    url = f"https://api.fivetran.com/v1/accounts/{account_id}/usage"
    headers = {
        "Authorization": "Basic " + base64.b64encode(f"{api_key}:{api_secret}".encode('utf-8')).decode('utf-8'),
        "Content-Type": "application/json"
    }
    params = {}
    if month:
        params['month'] = month
    if group_id:
        params['group_id'] = group_id

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Lanza una excepción para códigos de error HTTP
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error en la solicitud a la API de Fivetran: {e}")
        return None

def generate_html_report(mars_usage, account_id, month=None, group_id=None):
    """Genera un reporte HTML con la información de MARS."""

    template = Template("""
    <html>
        <head>
            <title>Fivetran MARS Usage Report</title>
            <style>
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                h2 { color: #555; }
                table { border-collapse: collapse; width: 80%; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Fivetran MARS Usage Report</h1>
            <p>Report generated on {{ timestamp }}</p>
            <h2>Account ID: {{ account_id }}</h2>
            {% if month %}
                <h2>Month: {{ month }}</h2>
            {% endif %}
            {% if group_id %}
                <h2>Group ID: {{ group_id }}</h2>
            {% endif %}

            {% if mars_usage %}
                <h2>Total MARS: {{ mars_usage.get('total_mars', 'N/A') }}</h2>

                {% if mars_usage.get('groups') %}
                    <h2>MARS Usage by Group:</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Group ID</th>
                                <th>Group Name</th>
                                <th>MARS</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for group in mars_usage.groups %}
                                <tr>
                                    <td>{{ group.group_id }}</td>
                                    <td>{{ group.group_name }}</td>
                                    <td>{{ group.mars }}</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p>No group-level MARS usage data available.</p>
                {% endif %}
            {% else %}
                <p>Error: Could not retrieve MARS usage data.</p>
            {% endif %}
        </body>
    </html>
    """)

    return template.render(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        account_id=account_id,
        month=month,
        group_id=group_id,
        mars_usage=mars_usage
    )

def main():
    """Función principal para obtener información de MARS de Fivetran y generar un reporte HTML."""

    # Configuración del parser de argumentos
    parser = argparse.ArgumentParser(description="Obtiene información de MARS de Fivetran y genera un reporte HTML.")
    parser.add_argument("--config_file", required=True, help="Archivo de configuración con los parámetros.")
    args = parser.parse_args()

    # Leer la configuración desde el archivo
    config = read_config_from_file(args.config_file)

    try:
        api_key = config['api_key']
        api_secret = config['api_secret']
        account_id = config['account_id']
    except KeyError as e:
        print(f"Error: Falta la clave '{e}' en el archivo de configuración.")
        exit(1)

    month = config.get('month')  # Opcional: Mes para el que quieres el reporte (YYYY-MM)
    group_id = config.get('group_id')  # Opcional: ID del grupo

    mars_usage = get_mars_usage(api_key, api_secret, account_id, month, group_id)

    if mars_usage:
        html_report = generate_html_report(mars_usage, account_id, month, group_id)

        # Guardar el reporte en un archivo
        with open("fivetran_mars_report.html", "w") as f:
            f.write(html_report)

        print("Reporte HTML generado en fivetran_mars_report.html")
    else:
        print("No se pudo generar el reporte.")

if __name__ == "__main__":
    main()