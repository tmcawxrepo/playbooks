import requests
import json
import argparse
from jinja2 import Template
import datetime
import os

def read_config_from_file(config_file):
    """Lee la configuración desde un archivo."""
    try:
        print(f"Leyendo configuración desde el archivo: {config_file}")
        config = {}
        with open(config_file, 'r') as f:
            for line in f:
                key, value = line.strip().split('=')
                config[key.strip()] = value.strip()
        print(f"Configuración leída: {config}")
        return config
    except Exception as e:
        print(f"Error al leer el archivo de configuración: {e}")
        sys.exit(1)

def fivetran_api_request(api_key, api_secret, endpoint, method='GET', data=None):
    """Realiza una solicitud a la API de Fivetran."""
    url = f"https://api.fivetran.com/v1/{endpoint}"
    headers = {
        "Authorization": f"Basic {api_key}:{api_secret}",
        "Content-Type": "application/json"
    }
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, data=json.dumps(data))
        elif method == 'PATCH':
            response = requests.patch(url, headers=headers, data=json.dumps(data))
        else:
            raise ValueError(f"Método HTTP no soportado: {method}")

        response.raise_for_status()  # Lanza una excepción para códigos de error HTTP
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error en la solicitud a la API de Fivetran: {e}")
        return None

def get_mars_info(api_key, api_secret, group_id):
    """Obtiene información de MARS (Managed Accounts and Resource Sharing) para un grupo."""
    endpoint = f"groups/{group_id}/managed-accounts"
    return fivetran_api_request(api_key, api_secret, endpoint)

def generate_html_report(mars_info, config):
    """Genera un reporte HTML con la información de MARS."""
    template = Template("""
    <html>
        <head>
            <title>Fivetran MARS Report</title>
            <style>
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                pre { background: #f4f4f4; padding: 10px; }
                .status { font-weight: bold; }
            </style>
        </head>
        <body>
            <h1>Fivetran MARS Report</h1>
            <p>Report generated on {{ timestamp }}</p>

            <h2>MARS Info (Group ID: {{ group_id }}):</h2>
            {% if mars_info and mars_info.data %}
            <pre>{{ mars_info.data | tojson(indent=4) }}</pre>
            {% else %}
            <p>No MARS info found or an error occurred.</p>
            {% endif %}

            <h2>Configuración:</h2>
            <pre>{{ config | tojson(indent=4) }}</pre>

        </body>
    </html>
    """)

    return template.render(
        timestamp=datetime.datetime.now(),
        mars_info=mars_info,
        group_id=config['group_id'],
        config=config
    )

def main():
    """Función principal para extraer información de MARS de Fivetran y generar un reporte HTML."""
    parser = argparse.ArgumentParser(description="Extrae información de MARS de Fivetran y genera un reporte HTML.")
    parser.add_argument("--config_file", required=True, help="Archivo de configuración con los parámetros.")

    args = parser.parse_args()

    # Leer la configuración desde el archivo
    config = read_config_from_file(args.config_file)

    try:
        # Obtener los parámetros desde la configuración
        api_key = config['api_key']
        api_secret = config['api_secret']
        group_id = config['group_id']
        report_file = config['report_file']

        # Obtener información de MARS
        mars_info = get_mars_info(api_key, api_secret, group_id)

        # Generar el reporte HTML
        html_report = generate_html_report(mars_info, config)

        # Guardar el reporte en un archivo
        with open(report_file, "w") as f:
            f.write(html_report)

        print(f"Reporte HTML generado en {report_file}")

    except Exception as e:
        print(f"Ocurrió un error: {e}")
        sys.exit(1)  # Salir con código 1 para indicar error

if __name__ == "__main__":
    main()