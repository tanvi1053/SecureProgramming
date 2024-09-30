# Secure Programming Backdoored Implementation

DISCLAIMER: THE CURRENT IMPLEMENTATION DOES NOT HAVE THE SERVER NEIGHBOURHOOD ASPECT IMPLEMENTED. WE WERE NOT ABLE TO FINISH THIS TO A SATISFACTORY LEVEL AND THEREFORE HAVE SUBMITTED AN IMPLEMENTATION WITH A SINGLE SERVER THAT HANDLES ALL CLIENTS THAT CONNECT. 

<br> IF YOU WANT TO CLONE THE GITHUB REPOSITORY DO THE FOLLOWING:

1. Git clone the SecureProgramming repository onto your computer.
    <br/> Clone the link: https://github.com/tanvi1053/SecureProgramming.git 

2. Download the latest version of Python onto your machine if you do not already have it.

3. Open a terminal and run the following:
    <br/> pip install websockets
    <br/> pip install pycryptodome
    <br/> pip install aiohttp

4. In the first terminal, run the server using the following:
    <br/> python3 server.py

5. Open a second terminal to run the client using the following:
    <br/> python3 client.py
    <br><br> You can run as many client instances as you would like. Just open a new terminal and run the command "python3 server.py" in the directory where the file is saved.

6. Follow the prompts in the client terminal and chat with other clients in the server!

