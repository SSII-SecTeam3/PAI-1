import socket
import seguridad

HOST = '127.0.0.1'
PORT = 5000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))

    msgRegOLog = client.recv(1024).decode()
    print(msgRegOLog)
    regOLog = input()
    client.send(regOLog.encode())
    while regOLog.upper() not in ["L", "R"]:
        msgInvalidOption = client.recv(1024).decode()
        print(msgInvalidOption)
        regOLog = input()
        client.send(regOLog.encode())

    mgsUserPass = client.recv(1024).decode()
    print(mgsUserPass)
    user = input(">> Usuario: ")
    password = input(">> Password: ")
    client.send(f"{user}|{password}".encode())

    clave_sesion = seguridad.derivar_clave(password)
    nonces_usados = set()

    msgUserRegisteredOrLogged = client.recv(1024).decode()
    print(msgUserRegisteredOrLogged)

    if "Login correcto" not in msgUserRegisteredOrLogged and "registrado correctamente" not in msgUserRegisteredOrLogged:
        print("Login fallido. Cerrando conexión.")
    else:
        newTransaction = "S"
        while newTransaction.upper() == "S":

            try:
                msgTrans = client.recv(1024).decode()
                print(msgTrans)

                origen = input(">> Cuenta origen: ")
                destino = input(">> Cuenta destino: ")
                cantidad = input(">> Cantidad: ")

                mensaje_plano = f"{origen}|{destino}|{cantidad}"
                mensaje = seguridad.crear_mensaje_seguro(clave_sesion, mensaje_plano)
                client.send(mensaje.encode())

                msgResultTrans = client.recv(4096).decode()
                
                valido, msg, error = seguridad.verificar_integridad(
                    clave_sesion, msgResultTrans, nonces_usados
                )

                if valido:
                    print("Respuesta del servidor:", msg)
                else:
                    print(error)
                    break

                msgNewTransaction = client.recv(1024).decode()
                print(msgNewTransaction)
                newTransaction = input()
                client.send(newTransaction.encode())
                
            except KeyboardInterrupt:
                print("\nSaliendo...")
                break