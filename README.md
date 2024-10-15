### Secure Programming Neighbourhood Server Implementation by:
- Tanvi Srivastava / a1860959
- Kirsten Pope / a1860519
- Leona Heng / a1791093

## Project Overview
This project is a chat application that lets users communicate over a network. The application server is based on the OLAF/Neighbourhood Protocol described [here](https://github.com/xvk-64/2024-secure-programming-protocol/blob/main/readme.md) with a few minor tweaks. Users communicate with other users through their parent servers following a Client-Server-Server-Client structure.

# Features:
**Private Messages:**
A user can choose to make a private message. They will be prompted as to who they want to message, and then the message they wish to send. If the two users are on the same server, their shared server will forward the message to the desired user. If the two users are in different servers then the sender's server will forward the message to the recipient's server and then to the recipient.

**Public Messages:** 
A user can choose to make a public message. They will be prompted as to what message they wish to send. Their server will then direct the message to all other neighbouring servers who will direct it to all their clients.

**Listing Online Users:** 
A user can choose to list all connected users. By selecting this option, the user sends a list request and the server generates a list of all connected servers and their connected clients which is sent back to the user to display.

**File Upload:** 
A user can choose to upload a file to a user's client. The user will be prompted to specify a file path and then the user they wish to send the file to. Upon a valid file path, the file will be uploaded to the receiver's "uploads" folder.

**File Download:** 
A user can choose to download a file from their uploaded files folder. The user is shown a list of URLs for files that they can download (files that have been uploaded to them). Upon entering one of the URLs if it is valid it will be downloaded.

# File information
This implementation contains 4 key files: 
- VulnerableClient.py
- VulnerableServer.py
- FinalClient.py
- FinalServer.py

The files labelled "Vulnerable" contain 4 intentional code vulnerabilities that have been omitted in the "Final" versions. Please run vulnerable code in a safe virtual environment!

# To run the uploaded files:

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
You are now ready to run the server and client!

4. In the same terminal, run a server using the following:
```
python3 FinalServer.py
```
or
```
python3 VulnerableServer.py
```
*If "python3" does not work, you likely need to try "python" instead*

5. Open a second terminal in the same manner as the first to run the client code. Use the following command:
```
python3 FinalClient.py
```
or
```
python3 VulnerableClient.py
```

6. Follow the prompts in the client terminal and chat with other clients on the servers!


