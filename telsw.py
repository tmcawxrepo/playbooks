import telnetlib
import time
import argparse
import sys
from jinja2 import Template
import datetime

def check_vlan_exists(tn, vlan_id):
    """Verifica si una VLAN existe en el switch."""
    print(f"Verificando si la VLAN {vlan_id} existe...")
    tn.write(b"show vlan id " + str(vlan_id).encode('ascii') + b"\n")
    time.sleep(1)  # Espera a que se complete el comando
    output = tn.read_very_eager().decode('ascii')
    exists = "VLAN not found" not in output
    if exists:
        print(f"VLAN {vlan_id} encontrada.")
    else:
        print(f"VLAN {vlan_id} no encontrada.")
    return exists, output

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

def generate_html_report(hostname, vlan_id, vlan_name, vlan_exists, vlan_output, creation_success, creation_output):
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
            <h2>VLAN Exists:</h2>
            <p class="status">{{ 'Yes' if vlan_exists else 'No' }}</p>
            <h2>VLAN Check Output:</h2>
            <pre>{{ vlan_output }}</pre>
            {% if not vlan_exists %}
            <h2>VLAN Creation Status:</h2>
            <p class="status">{{ 'Success' if creation_success else 'Failed' }}</p>
            <h2>VLAN Creation Output:</h2>
            <pre>{{ creation_output }}</pre>
            {% endif %}
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
        vlan_exists=vlan_exists,
        vlan_output=vlan_output,
        creation_success=creation_success,
        creation_output=creation_output,
        timestamp=datetime.datetime.now()
    )

def main():
    """Función principal para verificar y crear VLANs."""
    parser = argparse.ArgumentParser(description="Verifica y crea VLANs en un switch Cisco Catalyst via Telnet.")
    parser.add_argument("--host", required=True, help="Dirección IP del switch.")
    parser.add_argument("--username", required=True, help="Nombre de usuario para la conexión al switch.")
    parser.add_argument("--password", required=True, help="Contraseña para la conexión al switch.")
    parser.add_argument("--vlan_id", required=True, type=int, help="ID de la VLAN a verificar/crear.")
    parser.add_argument("--vlan_name", required=True, help="Nombre de la VLAN a crear.")
    parser.add_argument("--enable_secret", required=False, help="Contraseña para el modo enable (si es necesario).")
    parser.add_argument("--report_file", required=True, help="Nombre del archivo HTML para el reporte.")

    args = parser.parse_args()

    try:
        print(f"Conectando a {args.host} via Telnet...")
        tn = telnetlib.Telnet(args.host)

        tn.read_until(b"Username: ")
        print("Enviando nombre de usuario...")
        tn.write(args.username.encode('ascii') + b"\n")
        time.sleep(0.5)

        tn.read_until(b"Password: ")
        print("Enviando contraseña...")
        tn.write(args.password.encode('ascii') + b"\n")
        time.sleep(0.5)

        # Si se proporciona un enable secret, intentar entrar en modo enable
        if args.enable_secret:
            print("Enviando comando enable...")
            tn.write(b"enable\n")
            time.sleep(0.5)
            tn.read_until(b"Password: ")
            tn.write(args.enable_secret.encode('ascii') + b"\n")
            time.sleep(0.5)

        vlan_exists, vlan_output = check_vlan_exists(tn, args.vlan_id)

        if vlan_exists:
            print(f"VLAN {args.vlan_id} ya existe. No se requiere acción.")
            creation_success = True
            creation_output = "VLAN ya existía."
        else:
            print(f"VLAN {args.vlan_id} no existe. Procediendo a la creación...")
            creation_success, creation_output = create_vlan(tn, args.vlan_id, args.vlan_name)

        # Generar el reporte HTML
        html_report = generate_html_report(
            args.host,
            args.vlan_id,
            args.vlan_name,
            vlan_exists,
            vlan_output,
            creation_success,
            creation_output
        )

        with open(args.report_file, "w") as f:
            f.write(html_report)

        print(f"Reporte HTML generado en {args.report_file}")
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