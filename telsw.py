import telnetlib
import time
import argparse
import sys

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
        return output
    except Exception as e:
        print(f"Error al crear la VLAN: {e}")
        return None

def main():
    """Función principal para crear VLANs."""
    parser = argparse.ArgumentParser(description="Crea una VLAN en un switch Cisco Catalyst via Telnet.")
    parser.add_argument("--host", required=True, help="Dirección IP del switch.")
    parser.add_argument("--username", required=True, help="Nombre de usuario para la conexión al switch.")
    parser.add_argument("--password", required=True, help="Contraseña para la conexión al switch.")
    parser.add_argument("--vlan_id", required=True, type=int, help="ID de la VLAN a crear.")
    parser.add_argument("--vlan_name", required=True, help="Nombre de la VLAN a crear.")
    parser.add_argument("--enable_secret", required=False, help="Contraseña para el modo enable (si es necesario).")

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

        output = create_vlan(tn, args.vlan_id, args.vlan_name)

        if output:
            print(output)
            print(f"VLAN {args.vlan_id} creada con el nombre {args.vlan_name}.")
            sys.exit(0)  # Salir con código 0 para indicar éxito
        else:
            print("La creación de la VLAN falló.")
            sys.exit(1)  # Salir con código 1 para indicar error

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