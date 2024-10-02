# Secure Programming Backdoored Implementation

DISCLAIMER: THE CURRENT IMPLEMENTATION DOES NOT HAVE THE SERVER NEIGHBOURHOOD ASPECT IMPLEMENTED. WE WERE NOT ABLE TO FINISH THIS TO A SATISFACTORY LEVEL AND THEREFORE HAVE SUBMITTED AN IMPLEMENTATION WITH A SINGLE SERVER THAT HANDLES ALL CLIENTS THAT CONNECT. 

THERE ARE 4 INTENTIONAL VULNERABILITIES IN THIS CODE

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
        pip install aiofiles

YOU ARE NOW READY TO RUN THE SERVER AND CLIENT!

6. In the same VSCode terminal, run the server using the following:
python3 VulnerableServer.py

7. Open a second terminal in VSCode to run the client using the following:
python3 VulnerableClient.py

8. You can run as many client instances as you would like. Just open a new terminal and run the command "python3 VulnerableClient.py" in the directory where the file is saved. We recommend using a split terminal.

9. Follow the prompts in the client terminal and chat with other clients in the server!


