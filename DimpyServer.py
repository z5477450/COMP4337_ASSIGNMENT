from socket import *
from bloom_filter import BloomFilter
import base64
from bitarray import bitarray
"""
pip install bitarray
"""
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
        
        tempBF = BloomFilter(max_elements=1000, error_rate=0.1)

        receivedBytes = base64.b64decode(message)
        receivedCBF = bitarray()
        receivedCBF.frombytes(receivedBytes)

        tempBF.backend.array_ = receivedCBF

        response = "CBF upload successful."
        connectionSocket.send(response)

        connectionSocket.close()

