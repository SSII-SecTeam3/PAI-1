import socket

HOST = '127.0.0.1'
PORT = 5000

def registerUser(socket, user, password):
    socket.send(f"Registrando usuario: {user} con contraseña: {password}".encode())

def loginUser(socket, user, password):
    socket.send(f"Logueando usuario: {user} con contraseña: {password}".encode())

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen()
    print("Servidor escuchando...")
    conn, addr = server.accept() # Sirve para un solo cliente
    with conn: # conn es el socket para comunicarse con el cliente
        print(f"Conectado desde {addr}")
        conn.send("¿Quiere loguearse o registrarse? (L/R)".encode())
        regOLog = conn.recv(1024).decode()
        while regOLog.upper() not in ["L", "R"]:
            conn.send("Opción no válida. Por favor, introduzca L para loguearse o R para registrarse.".encode())
            regOLog = conn.recv(1024).decode()

        conn.send("Introduzca a continuación su usuario y contraseña.".encode())
        user, password = conn.recv(1024).decode().split("|")

        if(regOLog.upper() == "L"):
            loginUser(conn, user, password)
        elif(regOLog.upper() == "R"):
            registerUser(conn, user, password)

        newTransaction = "S"
        while newTransaction.upper() == "S":
            conn.send("Introduzca a continuación la cuenta origen, destino y cantidad de la transacción".encode())
            data = conn.recv(1024).decode()
            if not data:
                break
            try:
                origen, destino, cantidad = data.split("|")

                cantidad = float(cantidad)

                print("\n--- DATOS RECIBIDOS ---")
                print("Cuenta origen:", origen)
                print("Cuenta destino:", destino)
                print("Cantidad:", cantidad)

                respuesta = "TRANSACCION RECIBIDA"

            except Exception as e:
                respuesta = "ERROR EN FORMATO"

            conn.send(respuesta.encode())
            conn.send("¿Desea realizar otra transacción? (S/N)".encode())
            newTransaction = conn.recv(1024).decode()
