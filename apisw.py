from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/create_config', methods=['POST'])
def create_config():
    """
    API endpoint para crear un archivo de configuración con los datos recibidos en el POST request.
    """
    try:
        data = request.get_json()

        # Validar que los datos necesarios estén presentes
        if not all(key in data for key in ['host', 'credentials_file', 'vlan_id', 'vlan_name', 'report_file']):
            return jsonify({'error': 'Faltan parámetros requeridos en el request.'}), 400

        # Construir el contenido del archivo de configuración
        config_content = f"""host={data['host']}
credentials_file={data['credentials_file']}
vlan_id={data['vlan_id']}
vlan_name={data['vlan_name']}
report_file={data['report_file']}
"""
        if 'enable_secret' in data:
            config_content += f"enable_secret={data['enable_secret']}\n"

        # Definir la ruta del archivo de configuración
        config_file_path = '/tmp/config.txt'  # Puedes cambiar la ruta si es necesario

        # Escribir el contenido en el archivo
        with open(config_file_path, 'w') as f:
            f.write(config_content)

        return jsonify({'message': f'Archivo de configuración creado exitosamente en {config_file_path}'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)  # Escuchar en todas las interfaces y puerto 5000