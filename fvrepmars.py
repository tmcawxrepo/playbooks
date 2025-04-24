import requests
from requests.auth import HTTPBasicAuth
import json
import colorama
from colorama import Fore, Back, Style
from jinja2 import Template
import datetime
import argparse

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

def atlas(api_key, api_secret, method, endpoint, payload=None):
    """Realiza una solicitud a la API de Fivetran."""
    base_url = 'https://api.fivetran.com/v1'
    a = HTTPBasicAuth(api_key, api_secret)
    h = {
        'Authorization': f'Bearer {api_key}:{api_secret}'  # This line is likely incorrect and can be removed
    }
    url = f'{base_url}/{endpoint}'

    try:
        if method == 'GET':
            response = requests.get(url, headers=h, auth=a)
        elif method == 'POST':
            response = requests.post(url, headers=h, json=payload, auth=a)
        elif method == 'PATCH':
            response = requests.patch(url, headers=h, json=payload, auth=a)
        elif method == 'DELETE':
            response = requests.delete(url, headers=h, auth=a)
        else:
            raise ValueError('Invalid request method.')

        response.raise_for_status()  # Raise exception for 4xx or 5xx responses

        return response.json()
    except requests.exceptions.RequestException as e:
        print(f'Request failed: {e}')
        return None

def generate_html_report(response, group_id):
    """Genera un reporte HTML con la información de los conectores."""
    template = Template("""
    <html>
    <head>
        <title>Fivetran Connector Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            h1 { color: #333; }
            table { border-collapse: collapse; width: 80%; margin: 20px 0; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Fivetran Connector Report</h1>
        <p>Report generated on {{ timestamp }}</p>
        <h2>Group ID: {{ group_id }}</h2>

        {% if response and response.data and response.data.items %}
        <table>
            <thead>
                <tr>
                    <th>Service</th>
                    <th>Status</th>
                    <th>Frequency</th>
                </tr>
            </thead>
            <tbody>
                {% for connector in response.data.items %}
                <tr>
                    <td>{{ connector.service }}</td>
                    <td>{{ connector.status.sync_state }}</td>
                    <td>{{ connector.sync_frequency }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No connector data found or an error occurred.</p>
        {% endif %}
    </body>
    </html>
    """)

    return template.render(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        group_id=group_id,
        response=response
    )

def main():
    """Función principal para obtener información de conectores de Fivetran y generar un reporte HTML."""

    # Configuración del parser de argumentos
    parser = argparse.ArgumentParser(description="Obtiene información de conectores de Fivetran y genera un reporte HTML.")
    parser.add_argument("--config_file", required=True, help="Archivo de configuración con los parámetros.")
    args = parser.parse_args()

    # Leer la configuración desde el archivo
    config = read_config_from_file(args.config_file)

    try:
        api_key = config['api_key']
        api_secret = config['api_secret']
        group_id = config['group_id']
    except KeyError as e:
        print(f"Error: Falta la clave '{e}' en el archivo de configuración.")
        exit(1)

    method = 'GET'
    endpoint = 'groups/' + group_id + '/connectors'
    payload = None

    # Submit
    response = atlas(api_key, api_secret, method, endpoint, payload)

    # Generate HTML report
    if response is not None:
        html_report = generate_html_report(response, group_id)

        # Save the report to a file
        with open("fivetran_connector_report.html", "w") as f:
            f.write(html_report)

        print("Reporte HTML generado en fivetran_connector_report.html")
    else:
        print("No se pudo generar el reporte.")

if __name__ == "__main__":
    main()