from socket import *

if __name__ == '__main__':
    port = 51000
    stored_CBF = {}

    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('localhost', port))

    # Queue size may need to be increased based on spec. 
    serverSocket.listen(5)

    while 1:
        connectionSocket, address = serverSocket.accept()
        message = connectionSocket.recv(1024)

        CBFRecv = message.decode('utf-8').split("||")
        CBF = CBFRecv[0]
        nodeID = CBFRecv[1]
    

        stored_CBF[nodeID] = CBF

        connectionSocket.send("UPLOAD SUCCESSFUl")
        connectionSocket.close()


