Secure Programming Backdoored Implementation

DISCLAIMER: THE CURRENT IMPLEMENTATION DOES NOT HAVE THE SERVER NEIGHBOURHOOD ASPECT IMPLEMENTED. WE WERE NOT ABLE TO FINISH THIS TO A SATISFACTORY LEVEL AND THEREFORE HAVE SUBMITTED AN IMPLEMENTATION WITH A SINGLE SERVER THAT HANDLES ALL CLIENTS THAT CONNECT.


IF YOU WANT TO CLONE THE GITHUB REPOSITORY DO THE FOLLOWING:

1. Open VSCode and navigate to your desired directory.

2. Open a terminal and git clone the SecureProgramming repository into your directory.
    Clone the link: https://github.com/tanvi1053/SecureProgramming.git

3. Make sure you are in the "main" branch by running the command "git branch"

4. Download the latest version of Python onto your machine if you do not already have it.

5. After you've downloaded Python, in the same terminal run the following:
        pip install websockets
        pip install pycryptodome
        pip install aiohttp

YOU ARE NOW READY TO RUN THE SERVER AND CLIENT!

6. In the same VSCode terminal, run the server using the following:
python3 server.py

7. Open a second terminal in VSCode to run the client using the following:
python3 client.py

8. You can run as many client instances as you would like. Just open a new terminal and run the command "python3 server.py" in the directory where the file is saved. We recommend using a split terminal.

9. Follow the prompts in the client terminal and chat with other clients in the server!



IF YOU ONLY WANT TO USE THE FILES UPLOADED - DO THE FOLLOWING:

1. Download the latest version of Python onto your machine if you do not already have it.

2. Open a terminal in whatever form you prefer (VSCode, Command Prompt, Powershell, Ubuntu... etc)

3. After you've downloaded Python and opended a terminal, in that same terminal run the following:
        pip install websockets
        pip install pycryptodome
        pip install aiohttp

YOU ARE NOW READY TO RUN THE SERVER AND CLIENT!

4. In the same terminal, run the server using the following:
    -    python3 server.py

5. Open a second terminal in the same manner as the first to run the client code. Use the following command:
    -    python3 client.py

You can run as many client instances as you would like. 
Just open a new terminal in the same manner as the previous and run the command "python3 client.py" in the directory where the file is saved. 

6. Follow the prompts in the client terminal and chat with other clients in the server!


