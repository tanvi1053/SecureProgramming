import socket
import threading

class User:
    def __init__(self, data):
        self.username = data['data']['username']
        self.is_admin = data['data']['admin']

members = {}
admins = {}

def handle_admin(conn, addr, username):
    print(f"Admin {username} ({addr}) is connected to server")
    admins[username] = conn
    while True:
        command = conn.recv(1024).decode()
        if command.lower() == 'exit':
            for member_conn in members.values():
                member_conn.send('exit'.encode())
            break
        if command.lower() == 'input':
            prompt = conn.recv(1024).decode()
            for member_conn in members.values():
                member_conn.send('input'.encode())
                member_conn.send(prompt.encode())
                user_input = member_conn.recv(1024).decode()
                conn.send(user_input.encode())
        else:
            for member_conn in members.values():
                member_conn.send(command.encode())
                output = member_conn.recv(1024).decode()
                conn.send(output.encode())
    conn.close()
    del admins[username]

def handle_member(conn, addr, username):
    print(f"Member {username} ({addr}) is connected to server")
    members[username] = conn
    return conn

def main():
    s = socket.socket()
    host = socket.gethostname()
    port = 8080
    s.bind(('', port))
    s.listen(5)
    print("Server is listening...")

    while True:
        conn, addr = s.accept()
        role_data = conn.recv(1024).decode().strip().split(':')
        role = role_data[0].lower()
        username = role_data[1]

        if role == 'member':
            threading.Thread(target=handle_member, args=(conn, addr, username)).start()
        elif role == 'admin':
            threading.Thread(target=handle_admin, args=(conn, addr, username)).start()
        else:
            conn.close()
            print(f"Connection from {addr} closed due to invalid role.")

if __name__ == "__main__":
    main()