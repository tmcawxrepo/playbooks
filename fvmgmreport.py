import requests
import json
import argparse
from jinja2 import Template
import datetime
import os
import pandas as pd
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error

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

def fivetran_api_request(api_key, endpoint, method='GET', data=None):
    """Realiza una solicitud a la API de Fivetran."""
    url = f"https://api.fivetran.com/v1/{endpoint}"
    headers = {
        "Authorization": f"Basic {api_key}",
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

def get_mars_info(api_key, group_id):
    """Obtiene información de MARS (Managed Accounts and Resource Sharing) para un grupo."""
    endpoint = f"groups/{group_id}/managed-accounts"
    return fivetran_api_request(api_key, endpoint)

def get_mers_info(api_key, account_id):
    """Obtiene información de MERS (Managed External Resources) para una cuenta."""
    endpoint = f"accounts/{account_id}/external-resources"
    return fivetran_api_request(api_key, endpoint)

def analyze_mars_trend(mars_data, anomaly_threshold_percent):
    """Analiza la tendencia de consumo de MARS y detecta anomalías."""
    if not mars_data or not mars_data['data']:
        return "No MARS data available", False  # No data to analyze

    # Convertir los datos en un DataFrame de Pandas
    df = pd.DataFrame(mars_data['data'])

    # Asegurarse de que haya una columna de tiempo y una columna de consumo
    # Adaptar esto según la estructura de tus datos MARS
    if 'created_at' not in df.columns or 'resource_units' not in df.columns:
        return "Missing required columns (created_at, resource_units)", False

    # Convertir la columna de tiempo a datetime
    df['created_at'] = pd.to_datetime(df['created_at'])

    # Ordenar los datos por tiempo
    df = df.sort_values('created_at')

    # Crear una columna numérica para el tiempo (días desde el inicio)
    df['time'] = (df['created_at'] - df['created_at'].min()).dt.days

    # Dividir los datos en conjuntos de entrenamiento y prueba
    X_train, X_test, y_train, y_test = train_test_split(df[['time']], df['resource_units'], test_size=0.2, shuffle=False)

    # Crear y entrenar el modelo de regresión lineal
    model = LinearRegression()
    model.fit(X_train, y_train)

    # Predecir los valores en el conjunto de prueba
    y_pred = model.predict(X_test)

    # Calcular el error cuadrático medio
    mse = mean_squared_error(y_test, y_pred)

    # Calcular el rango de valores esperados (umbral de anomalía)
    expected_range = y_train.mean() * (anomaly_threshold_percent / 100)

    # Detectar anomalías
    is_anomaly = mse > expected_range

    # Calcular la tendencia (pendiente de la regresión lineal)
    trend = model.coef_[0]

    # Interpretar la tendencia
    if trend > 0:
        trend_description = "Tendencia al alza en el consumo de MARS."
    elif trend < 0:
        trend_description = "Tendencia a la baja en el consumo de MARS."
    else:
        trend_description = "Sin tendencia clara en el consumo de MARS."

    # Crear un mensaje descriptivo
    message = f"{trend_description} Error cuadrático medio: {mse:.2f}. "
    if is_anomaly:
        message += f"¡ANOMALÍA DETECTADA! El consumo se desvía significativamente de la tendencia esperada (umbral: {anomaly_threshold_percent}%)."
    else:
        message += f"Consumo dentro de los límites esperados (umbral: {anomaly_threshold_percent}%)."

    return message, is_anomaly

def generate_html_report(api_key, group_id, account_id, anomaly_threshold_percent, config):
    """Genera un reporte HTML con la información de Fivetran."""
    mars_info = get_mars_info(api_key, group_id)
    mers_info = get_mers_info(api_key, account_id)

    # Analizar la tendencia de MARS
    mars_analysis_message, mars_anomaly = analyze_mars_trend(mars_info, anomaly_threshold_percent)

    template = Template("""
    <html>
        <head>
            <title>Fivetran Report</title>
            <style>
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                pre { background: #f4f4f4; padding: 10px; }
                .status { font-weight: bold; }
                .anomaly { color: red; }
            </style>
        </head>
        <body>
            <h1>Fivetran Report</h1>
            <p>Report generated on {{ timestamp }}</p>

            <h2>MARS Info (Group ID: {{ group_id }}):</h2>
            {% if mars_info and mars_info.data %}
            <pre>{{ mars_info.data | tojson(indent=4) }}</pre>
            <p>{{ mars_analysis_message }}</p>
            {% if mars_anomaly %}
            <p class="anomaly">¡ANOMALÍA DETECTADA!</p>
            {% endif %}
            {% else %}
            <p>No MARS info found or an error occurred.</p>
            {% endif %}

            <h2>MERS Info (Account ID: {{ account_id }}):</h2>
            {% if mers_info and mers_info.data %}
            <pre>{{ mers_info.data | tojson(indent=4) }}</pre>
            {% else %}
            <p>No MERS info found or an error occurred.</p>
            {% endif %}

            <h2>Configuración:</h2>
            <pre>{{ config | tojson(indent=4) }}</pre>

        </body>
    </html>
    """)

    return template.render(
        timestamp=datetime.datetime.now(),
        mars_info=mars_info,
        mers_info=mers_info,
        group_id=group_id,
        account_id=account_id,
        mars_analysis_message=mars_analysis_message,
        mars_anomaly=mars_anomaly,
        anomaly_threshold_percent=anomaly_threshold_percent,
        config=config
    )

def main():
    """Función principal para generar el reporte de Fivetran."""
    parser = argparse.ArgumentParser(description="Genera un reporte HTML con información de Fivetran.")
    parser.add_argument("--config_file", required=True, help="Archivo de configuración con los parámetros.")

    args = parser.parse_args()

    # Leer la configuración desde el archivo
    config = read_config_from_file(args.config_file)

    try:
        # Obtener los parámetros desde la configuración
        api_key = config['api_key']
        group_id = config['group_