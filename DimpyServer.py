from socket import *
import pickle

if __name__ == '__main__':
    port = 51000
    stored_CBF = {}

    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('localhost', port))

    # Queue size may need to be increased based on spec. 
    serverSocket.listen(5)
    print("Waiting for connection ...")

    while 1:
        connectionSocket, address = serverSocket.accept()
        message = connectionSocket.recv(1024)
        deloadPickle = pickle.loads(message)

        CBF = deloadPickle['cbf']
        nodeID = deloadPickle['node_id']
    

        stored_CBF[nodeID] = CBF
        print("UPLOAD SUCCESSFUl")
        connectionSocket.send("UPLOAD SUCCESSFUl")
        connectionSocket.close()


