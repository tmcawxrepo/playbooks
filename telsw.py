import telnetlib
import time
import argparse
import sys
from jinja2 import Template
import datetime

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

def read_credentials_from_file(credentials_file):
    """Lee el nombre de usuario y la contraseña desde un archivo."""
    try:
        print(f"Leyendo credenciales desde el archivo: {credentials_file}")
        with open(credentials_file, 'r') as f:
            lines = f.readlines()
            username = lines[0].strip()
            password = lines[1].strip()
            print(f"Usuario leído: {username}")
            print(f"Contraseña leída (oculta por seguridad)")  # No mostrar la contraseña
            return username, password
    except Exception as e:
        print(f"Error al leer el archivo de credenciales: {e}")
        sys.exit(1)

def create_vlan(tn, vlan_id, vlan_name):
    """Crea una VLAN en el switch."""
    try:
        print(f"Creando VLAN {vlan_id} con el nombre {vlan_name}...")
        tn.write(b"configure terminal\n")
        time.sleep(0.5)
        tn.write(b"vlan " + str(vlan_id).encode('ascii') + b"\n")
        time.sleep(0.5)
        tn.write(b"name " + str(vlan_name).encode('ascii') + b"\n")
        time.sleep(0.5)
        tn.write(b"exit\n")
        time.sleep(0.5)
        tn.write(b"exit\n")
        time.sleep(0.5)
        tn.write(b"end\n")  # Agregado para salir del modo de configuración
        time.sleep(0.5)
        tn.write(b"write memory\n")  # Agregado para guardar la configuración
        time.sleep(0.5)
        output = tn.read_very_eager().decode('ascii')
        print(f"VLAN {vlan_id} creada con éxito.")
        return True, output
    except Exception as e:
        print(f"Error al crear la VLAN: {e}")
        return False, str(e)

def generate_html_report(hostname, vlan_id, vlan_name, creation_success, creation_output):
    """Genera un reporte HTML."""
    template = Template("""
    <html>
        <head>
            <title>VLAN Creation Report</title>
            <style>
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                pre { background: #f4f4f4; padding: 10px; }
                .status { font-weight: bold; }
            </style>
        </head>
        <body>
            <h1>VLAN Creation Report for {{ hostname }}</h1>
            <h2>VLAN ID:</h2>
            <p>{{ vlan_id }}</p>
            <h2>VLAN Name:</h2>
            <p>{{ vlan_name }}</p>
            <h2>VLAN Creation Status:</h2>
            <p class="status">{{ 'Success' if creation_success else 'Failed' }}</p>
            <h2>VLAN Creation Output:</h2>
            <pre>{{ creation_output }}</pre>
            <footer>
                <p>Report generated on {{ timestamp }}</p>
            </footer>
        </body>
    </html>
    """)
    return template.render(
        hostname=hostname,
        vlan_id=vlan_id,
        vlan_name=vlan_name,
        creation_success=creation_success,
        creation_output=creation_output,
        timestamp=datetime.datetime.now()
    )

def main():
    """Función principal para crear VLANs."""
    parser = argparse.ArgumentParser(description="Crea una VLAN en un switch Cisco Catalyst via Telnet.")
    parser.add_argument("--config_file", required=True, help="Archivo de configuración con los parámetros.")

    args = parser.parse_args()

    # Leer la configuración desde el archivo
    config = read_config_from_file(args.config_file)

    try:
        # Obtener los parámetros desde la configuración
        host = config['host']
        credentials_file = config['credentials_file']
        vlan_id = int(config['vlan_id'])
        vlan_name = config['vlan_name']
        report_file = config['report_file']
        enable_secret = config.get('enable_secret', None)  # Opcional

        # Leer el nombre de usuario y la contraseña desde el archivo de credenciales
        username, password = read_credentials_from_file(credentials_file)

        print(f"Conectando a {host} via Telnet...")
        tn = telnetlib.Telnet(host)

        tn.read_until(b"Username: ")
        print("Enviando nombre de usuario...")
        tn.write(username.encode('ascii') + b"\n")
        time.sleep(0.5)

        tn.read_until(b"Password: ")
        print("Enviando contraseña...")
        tn.write(password.encode('ascii') + b"\n")
        time.sleep(0.5)

        # Si se proporciona un enable secret, intentar entrar en modo enable
        if enable_secret:
            print("Enviando comando enable...")
            tn.write(b"enable\n")
            time.sleep(0.5)
            tn.read_until(b"Password: ")
            tn.write(enable_secret.encode('ascii') + b"\n")
            time.sleep(0.5)

        creation_success, creation_output = create_vlan(tn, vlan_id, vlan_name)

        # Generar el reporte HTML
        html_report = generate_html_report(
            host,
            vlan_id,
            vlan_name,
            creation_success,
            creation_output
        )

        with open(report_file, "w") as f:
            f.write(html_report)

        print(f"Reporte HTML generado en {report_file}")
        sys.exit(0 if creation_success else 1)  # Salir con código 0 si la creación fue exitosa, 1 si falló

    except Exception as e:
        print(f"Ocurrió un error: {e}")
        sys.exit(1)  # Salir con código 1 para indicar error
    finally:
        if 'tn' in locals():
            print("Cerrando la conexión Telnet...")
            tn.close()
            print("Conexión cerrada.")

if __name__ == "__main__":
    main()