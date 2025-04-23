import telnetlib
import time
import argparse
import sys

def read_credentials_from_file(credentials_file):
    """Lee el nombre de usuario y la contraseña desde un archivo."""
    try:
        print(f"Leyendo credenciales desde el archivo: {credentials_file}")
        with open(credentials_file, 'r') as f:
            lines = f.readlines()
            username = lines[0].strip()
            password = lines[1].strip()
            print(f"Usuario leído: {username}")
            print(f"Contraseña leída (oculta por seguridad)") # No mostrar la contraseña
            return username, password
    except Exception as e:
        print(f"Error al leer el archivo de credenciales: {e}")
        sys.exit(1)

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
    return exists

def create_vlan(tn, vlan_id, vlan_name):
    """Crea una VLAN en el switch."""
    print(f"Creando VLAN {vlan_id} con el nombre {vlan_name}...")
    tn.write(b"enable\n")
    time.sleep(0.5)
    tn.write(b"configure terminal\n")
    time.sleep(0.5)
    tn.write(b"vlan " + str(vlan_id).encode('ascii') + b"\n")
    time.sleep(0.5)
    tn.write(b"name " + str(vlan_name).encode('ascii') + b"\n")
    time.sleep(0.5)
    tn.write(b"end\n")
    time.sleep(0.5)
    tn.write(b"write memory\n") #Guarda la configuracion
    time.sleep(0.5)
    tn.write(b"exit\n")
    time.sleep(0.5)
    output = tn.read_very_eager().decode('ascii')
    print(f"VLAN {vlan_id} creada con éxito.")
    return output

def main():
    """Función principal para verificar y crear VLANs."""
    parser = argparse.ArgumentParser(description="Verifica y crea VLANs en un switch Cisco Catalyst via Telnet.")
    parser.add_argument("--host", required=True, help="Dirección IP del switch.")
    parser.add_argument("--credentials_file", required=True, help="Archivo de texto con usuario y contraseña (una por línea).")
    parser.add_argument("--enable_secret", required=False, help="Contraseña para el modo enable (si es necesario).")
    parser.add_argument("--vlan_id", required=True, type=int, help="ID de la VLAN a verificar/crear.")
    parser.add_argument("--vlan_name", required=True, help="Nombre de la VLAN a crear.")

    args = parser.parse_args()

    # Leer el nombre de usuario y la contraseña desde el archivo
    username, password = read_credentials_from_file(args.credentials_file)

    try:
        print(f"Conectando a {args.host} via Telnet...")
        tn = telnetlib.Telnet(args.host)

        print("Enviando nombre de usuario...")
        tn.read_until(b"Username: ")
        tn.write(username.encode('ascii') + b"\n")
        time.sleep(0.5)

        print("Enviando contraseña...")
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")
        time.sleep(0.5)

        # Si se proporciona un enable secret, intentar entrar en modo enable
        if args.enable_secret:
            print("Enviando comando enable...")
            tn.write(b"enable\n")
            time.sleep(0.5)
            tn.read_until(b"Password: ")
            tn.write(args.enable_secret.encode('ascii') + b"\n")
            time.sleep(0.5)

        vlan_exists = check_vlan_exists(tn, args.vlan_id)

        if vlan_exists:
            print(f"VLAN {args.vlan_id} ya existe. No se requiere acción.")
            sys.exit(0)  # Salir con código 0 para indicar éxito
        else:
            print(f"VLAN {args.vlan_id} no existe. Procediendo a la creación...")
            output = create_vlan(tn, args.vlan_id, args.vlan_name)
            print(output)
            print(f"VLAN {args.vlan_id} creada con el nombre {args.vlan_name}.")
            sys.exit(0)  # Salir con código 0 para indicar éxito

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