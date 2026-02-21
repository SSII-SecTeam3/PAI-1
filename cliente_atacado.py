import socket
import seguridad
import logging

HOST = '127.0.0.1'
PORT = 4000

logging.basicConfig(filename='prueba_negativa.log', encoding='utf-8', level=logging.INFO, format='%(asctime)s - %(message)s')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))

    msgRegOLog = client.recv(1024).decode()
    logging.info(f"[S->C] {msgRegOLog}")
    print(msgRegOLog)
    regOLog = input()
    client.send(regOLog.encode())
    while regOLog.upper() not in ["L", "R"]:
        msgInvalidOption = client.recv(1024).decode()
        logging.info(f"[S->C] {msgInvalidOption}")
        print(msgInvalidOption)
        regOLog = input()
        client.send(regOLog.encode())

    mgsUserPass = client.recv(1024).decode()
    logging.info(f"[S->C] {mgsUserPass}")
    print(mgsUserPass)
    user = input(">> Usuario: ")
    logging.info(f"[C] Usuario: {user}")
    password = input(">> Password: ")
    logging.info(f"[C] Password: {password}")
    client.send(f"{user}|{password}".encode())

    clave_sesion = seguridad.derivar_clave(password)
    nonces_usados = set()

    msgUserRegisteredOrLogged = client.recv(1024).decode()
    logging.info(f"[S->C] {msgUserRegisteredOrLogged}")
    print(msgUserRegisteredOrLogged)

    if "Login correcto" not in msgUserRegisteredOrLogged and "registrado correctamente" not in msgUserRegisteredOrLogged:
        logging.info(f"[C] Login fallido. Cerrando conexión.")
        print("Login fallido. Cerrando conexión.")
    else:
        newTransaction = "S"
        while newTransaction.upper() == "S":

            try:
                msgTrans = client.recv(1024).decode()
                logging.info(f"[S->C] {msgTrans}")
                print(msgTrans)

                origen = input(">> Cuenta origen: ")
                logging.info(f"[C] Cuenta origen: {origen}")
                destino = input(">> Cuenta destino: ")
                logging.info(f"[C] Cuenta destino: {destino}")
                cantidad = input(">> Cantidad: ")
                logging.info(f"[C] Cantidad: {cantidad}")

                mensaje_plano = f"{origen}|{destino}|{cantidad}"
                mensaje = seguridad.crear_mensaje_seguro(clave_sesion, mensaje_plano)
                client.send(mensaje.encode())

                msgResultTrans = client.recv(4096).decode()
                logging.info(f"[S->C] {msgResultTrans}")
                
                valido, msg, error = seguridad.verificar_integridad(
                    clave_sesion, msgResultTrans, nonces_usados
                )

                if valido:
                    logging.info(f"[C] Respuesta del servidor: {msg}")
                    print("Respuesta del servidor:", msg)
                else:
                    logging.error(f"[C] Error de verificación: {error}")
                    print(error)
                    break

                msgNewTransaction = client.recv(1024).decode()
                logging.info(f"[S->C] {msgNewTransaction}")
                print(msgNewTransaction)
                newTransaction = input()
                client.send(newTransaction.encode())
                
            except KeyboardInterrupt:
                logging.info(f"[C] Saliendo por KeyboardInterrupt.")
                print("\nSaliendo...")
                break