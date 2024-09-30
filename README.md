# Secure Programming Backdoored Implementation

DISCLAIMER: THE CURRENT IMPLEMENTATION DOES NOT HAVE THE SERVER NEIGHBOURHOOD ASPECT IMPLEMENTED. WE WERE NOT ABLE TO FINISH THIS TO A SATISFACTORY LEVEL AND THEREFORE HAVE SUBMITTED AN IMPLEMENTATION WITH A SINGLE SERVER THAT HANDLES ALL CLIENTS THAT CONNECT. 

<br> IF YOU WANT TO CLONE THE GITHUB REPOSITORY DO THE FOLLOWING:

1. Open VSCode and navigate to your desired directory. 

2. Open a terminal and git clone the SecureProgramming repository into your directory.
    <br/> Clone the link: https://github.com/tanvi1053/SecureProgramming.git 
    <br><br> Make sure you are in the "main" branch by running the command "git branch"

2. Download the latest version of Python onto your machine if you do not already have it.

3. After you've downloaded Python, in the same terminal run the following:
    <br/> pip install websockets
    <br/> pip install pycryptodome
    <br/> pip install aiohttp
    <br/> pip install aiofiles

<br> YOU ARE NOW READY TO RUN THE SERVER AND CLIENT!

4. In the same VSCode terminal, run the server using the following:
    <br/> python3 server.py

5. Open a second terminal in VSCode to run the client using the following:
    <br/> python3 client.py
    <br><br> You can run as many client instances as you would like. Just open a new terminal and run the command "python3 server.py" in the directory where the file is saved. We recommend using a split terminal.

6. Follow the prompts in the client terminal and chat with other clients in the server!

