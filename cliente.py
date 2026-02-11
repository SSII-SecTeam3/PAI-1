import socket

HOST = '127.0.0.1'
PORT = 5000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))

    msgRegOLog = client.recv(1024).decode() # Recibe el mensaje sobre si quiere loguearse o registrarse
    print(msgRegOLog)
    regOLog = input()
    client.send(regOLog.encode())
    while regOLog.upper() not in ["L", "R"]:
        msgInvalidOption = client.recv(1024).decode() # Recibe mensaje de opción no válida
        print(msgInvalidOption)
        regOLog = input()
        client.send(regOLog.encode())

    mgsUserPass = client.recv(1024).decode() # Recibe el mensaje pidiendo usuario y contraseña
    print(mgsUserPass)
    user = input("Usuario: ")
    password = input("Password: ")
    client.send(f"{user}|{password}".encode())

    msgUserRegisteredOrLogged = client.recv(1024).decode() # Recibe mensaje de usuario registrado o logueado
    print(msgUserRegisteredOrLogged)

    newTransaction = "S"
    while newTransaction.upper() == "S":
        msgTrans = client.recv(1024).decode() # Recibe mensaje pidiendo datos de la transacción
        print(msgTrans)

        origen = input("Cuenta origen: ")
        destino = input("Cuenta destino: ")
        cantidad = input("Cantidad: ")
        mensaje = f"{origen}|{destino}|{cantidad}"
        client.send(mensaje.encode())

        msgResultTrans = client.recv(1024).decode()
        print("Respuesta del servidor:", msgResultTrans)

        msgNewTransaction = client.recv(1024).decode()
        print(msgNewTransaction)
        newTransaction = input()
        client.send(newTransaction.encode())

