import socket
import time
import psycopg2
from populatedb import get_connection
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

HOST = '127.0.0.1'
PORT = 5000

ph = PasswordHasher()
logged_users = {}

def registerUser(socket, user, password):
    db = None
    cur = None
    try:
        db = get_connection()
        cur = db.cursor()
        password_hash = ph.hash(password)

        cur.execute(
            "INSERT INTO users (username, password_hash, balance) VALUES (%s, %s, %s) RETURNING id",
            (user, password_hash, 1000)
        )
        new_id = cur.fetchone()[0]
        db.commit()

        mensaje = f"Usuario registrado correctamente. Su Nª de Cuenta es: {new_id}"
        socket.send(mensaje.encode())
        return new_id

    except psycopg2.errors.UniqueViolation:
        db.rollback()
        socket.send("ERROR: usuario ya existe.".encode())

    except Exception as e:
        db.rollback()
        print("ERROR REAL EN REGISTRO:", e)
        socket.send("ERROR interno del servidor.".encode())

    finally:
        if cur: cur.close()
        if db: db.close()

def loginUser(socket, user, password):
    db = None
    cur = None
    try:
        db = get_connection()
        cur = db.cursor()

        cur.execute(
            "SELECT id, password_hash FROM users WHERE username=%s",
            (user,)
        )
        result = cur.fetchone()

        if not result:
            socket.send("Usuario no encontrado.".encode())
            return False
        
        user_id = result[0]
        stored_hash = result[1]

        try:
            ph.verify(stored_hash, password)
            mensaje = f"Login correcto. Su Nª de cuenta es: {user_id}"
            socket.send(mensaje.encode())
            return user_id
        except VerifyMismatchError:
            socket.send("Contraseña incorrecta.".encode())
            return None

    except Exception as e:
        print(f"Error login: {e}")
        socket.send("ERROR en login.".encode())
        return None
    
    finally:
        if cur: cur.close()
        if db: db.close()

def realizar_transferencia(origen, destino, cantidad):
    db = None
    cur = None
    try:
        db = get_connection()
        cur = db.cursor()
        db.autocommit = False
        cur.execute(
            "SELECT balance FROM users WHERE id=%s FOR UPDATE",
            (origen,)
        )
        row = cur.fetchone()

        if not row:
            return "La cuenta origen no existe."

        balance_origen = float(row[0])

        if balance_origen < cantidad:
            return "Saldo insuficiente."

        cur.execute(
            "SELECT balance FROM users WHERE id=%s FOR UPDATE",
            (destino,)
        )
        if not cur.fetchone():
            return "La cuenta destino no existe."

        cur.execute(
            "UPDATE users SET balance = balance - %s WHERE id=%s",
            (cantidad, origen)
        )

        cur.execute(
            "UPDATE users SET balance = balance + %s WHERE id=%s",
            (cantidad, destino)
        )
        db.commit()
        return "TRANSFERENCIA REALIZADA"

    except Exception:
        db.rollback()
        return "ERROR EN TRANSFERENCIA"

    finally:
        if cur: cur.close()
        if db: db.close()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen()
    print("Servidor escuchando...")

    while True:
        try:
            conn, addr = server.accept()

            with conn:
                print(f"Conectado desde {addr}")
                conn.send("> ¿Quiere loguearse o registrarse? (L/R)".encode())
                regOLog = conn.recv(1024).decode()

                if not regOLog: 
                    continue

                while regOLog.upper() not in ["L", "R"]:
                    conn.send("Opción no válida. Por favor, introduzca L para loguearse o R para registrarse.".encode())
                    regOLog = conn.recv(1024).decode()

                conn.send("> Introduzca a continuación su usuario y contraseña.".encode())
                datos_login = conn.recv(1024).decode()

                if "|" not in datos_login:
                    conn.close()
                    continue
                    
                user, password = datos_login.split("|")

                user_id = None

                if(regOLog.upper() == "L"):
                    user_id = loginUser(conn, user, password)
                elif(regOLog.upper() == "R"):
                    user_id = registerUser(conn, user, password)
                
                if not user_id:
                    conn.close()
                else:
                    newTransaction = "S"
                    logged_users[conn] = user_id
                    while newTransaction.upper() == "S":

                        time.sleep(0.2)

                        try:
                            conn.send("> Introduzca a continuación la cuenta origen, destino y cantidad de la transacción".encode())
                            data = conn.recv(1024).decode()
                            if not data:
                                break

                            respuesta = ""
                            try:
                                origen, destino, cantidad = data.split("|")
                                cantidad = float(cantidad)

                                if conn not in logged_users:
                                    respuesta = "Debe iniciar sesión."
                                elif str(logged_users[conn]) != str(origen):
                                    respuesta = "No puede transferir desde otra cuenta."
                                else:
                                    resultado = realizar_transferencia(origen, destino, cantidad)
                                    respuesta = resultado
                                    print("\n--- DATOS RECIBIDOS ---")
                                    print("Cuenta origen:", origen)
                                    print("Cuenta destino:", destino)
                                    print("Cantidad:", cantidad)
                                    print("---------\n")

                            except ValueError:
                                respuesta = "ERROR EN FORMATO (Use: origen|destino|cantidad)"
                            except Exception as e:
                                respuesta = "ERROR EN PROCESAMIENTO"
                                
                            conn.send(respuesta.encode())
                            time.sleep(0.2)
                            conn.send("> ¿Desea realizar otra transacción? (S/N)".encode())
                            newTransaction = conn.recv(1024).decode()
                        
                        except ConnectionResetError:
                            print("Cliente desconectado forzosamente.")
                            break

                if conn in logged_users:
                    del logged_users[conn]

        except KeyboardInterrupt:
            print("\nApagando servidor...")
            break
        except Exception as e:
            print(f"ERROR general en el servidor: {e}")
