### Secure Programming Neighbourhood Server Implementation by:
    - Tanvi Srivastava / axxxxxxx
    - Kirsten Pope / a1860519
    - Leona Heng / axxxxxxx

## Project Overview
This project is a chat application that lets users communicate over a network. Users can communicate publicly or privately, list all online users, upload files, download files and exit at their will. The application server is based on the OLAF/Neighbourhood Protocol described [here](https://github.com/xvk-64/2024-secure-programming-protocol/blob/main/readme.md) with a few minor tweaks.

This implementation contains 4 key files: 
    - VulnerableClient.py
    - VulnerableServer.py
    - FinalClient.py
    - FinalServer.py

The files labelled "Vulnerable" contain 4 intentional code vulnerabilities that have been omitted in the "Final" versions. Please run vulnerable code in a safe virtual environment!

# To clone the repository:

1. Open VSCode and navigate to your desired directory.

2. Open a terminal and git clone the SecureProgramming repository into your directory.
    Clone the link: https://github.com/tanvi1053/SecureProgramming.git

3. Make sure you are in the "main" branch by running the command "git branch"

4. Download the latest version of Python onto your machine if you do not already have it.

5. After you've downloaded Python, in the same terminal run the following:
```
        pip install websockets
        pip install pycryptodome
        pip install aiohttp
        pip install aiofiles
```
YOU ARE NOW READY TO RUN THE SERVER AND CLIENT!

6. In the same VSCode terminal, run the server using the following:
```
    -    python3 FinalServer.py
```
                or
```
    -    python3 VulnerableServer.py
```
    *If python3 does not work, you likely need to try "python" instead*

7. Open a second terminal in VSCode to run the client using the following:
```
    -    python3 FinalClient.py
```
                or
```
    -    python3 VulnerableClient.py
```

8. Follow the prompts in the client terminal and chat with other clients in the servers!



# To run solely the uploaded files:

1. Download the latest version of Python onto your machine if you do not already have it.

2. Download all the files submitted onto your machine and save them in the same folder.

2. Open a terminal in whatever form you prefer (VSCode, Command Prompt, Powershell, Ubuntu... etc) and navigate to this folder.

3. After you've downloaded Python and opened a terminal, in that same terminal run the following:
```
        pip install websockets
        pip install pycryptodome
        pip install aiohttp
        pip install aiofiles
```
YOU ARE NOW READY TO RUN THE SERVER AND CLIENT!

4. In the same terminal, run a server using the following:
```
    -    python3 FinalServer.py
```
                or
```
    -    python3 VulnerableServer.py
```
    *If python3 does not work, you likely need to try "python" instead*

5. Open a second terminal in the same manner as the first to run the client code. Use the following command:
```
    -    python3 FinalClient.py
```
                or
```
    -    python3 VulnerableClient.py
```

6. Follow the prompts in the client terminal and chat with other clients in the servers!


