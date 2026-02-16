import socket

import psycopg2
from populatedb import get_connection
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

HOST = '127.0.0.1'
PORT = 5000

ph = PasswordHasher()
logged_users = {}

def registerUser(socket, user, password):
    try:
        db = get_connection()
        cur = db.cursor()
        password_hash = ph.hash(password)

        cur.execute(
            "INSERT INTO users (username, password_hash, balance) VALUES (%s, %s, %s)",
            (user, password_hash, 1000)  # saldo inicial 1000
        )
        db.commit()
        socket.send("Usuario registrado correctamente.".encode())

    except psycopg2.errors.UniqueViolation:
        db.rollback()
        socket.send("Error: usuario ya existe.".encode())

    except Exception as e:
        db.rollback()
        print("ERROR REAL EN REGISTRO:", e)
        socket.send("Error interno del servidor.".encode())

    finally:
        cur.close()
        db.close()
        socket.send(f"Registrando usuario: {user} con contraseña: {password}".encode())

def loginUser(socket, user, password):
    try:
        db = get_connection()
        cur = db.cursor()

        cur.execute(
            "SELECT password_hash FROM users WHERE username=%s",
            (user,)
        )
        result = cur.fetchone()

        if not result:
            socket.send("Usuario no encontrado.".encode())
            return False

        stored_hash = result[0]

        try:
            ph.verify(stored_hash, password)
            socket.send("Login correcto.".encode())
            logged_users[socket] = user
            return True
        except VerifyMismatchError:
            socket.send("Contraseña incorrecta.".encode())
            return False

    except Exception:
        socket.send("Error en login.".encode())
        return False
    
    finally:
        db.close()

def realizar_transferencia(origen, destino, cantidad):
    db = get_connection()
    cur = db.cursor()
    try:
        db.autocommit = False
        cur.execute(
            "SELECT balance FROM users WHERE username=%s FOR UPDATE",
            (origen,)
        )
        row = cur.fetchone()

        if not row:
            return "Cuenta origen no existe."

        balance_origen = float(row[0])

        if balance_origen < cantidad:
            return "Saldo insuficiente."

        cur.execute(
            "SELECT balance FROM users WHERE username=%s FOR UPDATE",
            (destino,)
        )
        if not cur.fetchone():
            return "Cuenta destino no existe."

        cur.execute(
            "UPDATE users SET balance = balance - %s WHERE username=%s",
            (cantidad, origen)
        )

        cur.execute(
            "UPDATE users SET balance = balance + %s WHERE username=%s",
            (cantidad, destino)
        )
        db.commit()
        return "TRANSFERENCIA REALIZADA"

    except Exception:
        db.rollback()
        return "ERROR EN TRANSFERENCIA"

    finally:
        db.close()


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

        login_correcto = False

        if(regOLog.upper() == "L"):
            login_correcto = loginUser(conn, user, password)
        elif(regOLog.upper() == "R"):
            registerUser(conn, user, password)
            login_correcto = True
            logged_users[conn] = user
        if not login_correcto:
            conn.close()
        else:
            newTransaction = "S"
            while newTransaction.upper() == "S":
                conn.send("Introduzca a continuación la cuenta origen, destino y cantidad de la transacción".encode())
                data = conn.recv(1024).decode()
                if not data:
                    break
                try:
                    origen, destino, cantidad = data.split("|")

                    cantidad = float(cantidad)
                    if conn not in logged_users:
                        conn.send("Debe iniciar sesión.".encode())
                    elif logged_users[conn] != origen:
                        conn.send("No puede transferir desde otra cuenta.".encode())
                    else:
                        resultado = realizar_transferencia(origen, destino, cantidad)
                        conn.send(resultado.encode())
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

                if conn in logged_users:
                    del logged_users[conn]
