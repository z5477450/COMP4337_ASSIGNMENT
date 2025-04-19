from socket import *
from custom_bloom_filter import BloomFilter
import base64
from bitarray import bitarray
"""
pip install bitarray
"""
if __name__ == '__main__':
    port = 51000
    storedCBF = []

    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('localhost', port))

    # Queue size may need to be increased based on spec. 
    serverSocket.listen(5)
    print("Waiting for connection ...")

    while 1:
        connectionSocket, address = serverSocket.accept()
        data = connectionSocket.recv(1024)
        
        print(f"Received data: {data}")
        
        tempBF = BloomFilter(size_bits=100000*8, num_hashes=3, error_rate=0.1)
        print(f"Initialized BloomFilter: {tempBF}")

        if tempBF is None or tempBF.backend is None:
            print("Error: tempBF or its backend is None")

        parts = data.split(b"|")
        tagType = parts[0].decode()
        message = parts[1]


        receivedBytes = base64.b64decode(message)
        receivedCBF = bitarray()
        receivedCBF.frombytes(receivedBytes)

        print(f"Received bitarray: {receivedCBF}")
        print(f"Backend before assignment: {tempBF.backend}")

        tempBF.backend.array_ = receivedCBF

        if tagType == "CBF":
            print(f"CBF received: {tempBF}")
            storedCBF.append(tempBF)

            response = "CBF upload successful.".encode('utf-8')
            connectionSocket.send(response)

        elif len(storedCBF) != 0:
            print(f"QBF received: {tempBF}")
            for cbf in storedCBF:
                intersectBits = tempBF.backend.array_ & cbf.backend.array_
                interesected = (intersectBits.any())

                print(interesected)

        connectionSocket.close()

