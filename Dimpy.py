import sys
import time
import threading
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import random
from socket import *

myChunks = []

def listenShares(chunksNeeded):
    global myChunks
    chunks = []

    nodeSocket = socket(AF_INET, SOCK_DGRAM)
    nodeSocket.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    nodeSocket.bind(("", 50000))

    while True:
        data, address = nodeSocket.recvfrom(1024)
        chunk = data.decode('utf-8')
        
        if chunk in myChunks:
            continue

        sendProbability = random.random()

        if sendProbability < 0.5:
            continue
        
        # Add the chunks received to the chunks array.
        chunks.append(chunk)
        print(f"[>>] Received Chunk: {chunk}")

        if len(chunks ==chunksNeeded):
            k out of n chunks has been received, receiver can now reconstruct the secret.

    
    nodeSocket.close()



def broadcastShares(chunks):
    length = len(chunks)

    # Setup UDP connection
    nodeSocket = socket(AF_INET, SOCK_DGRAM)
    nodeSocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

    for i in range(0, length):
        print(f"[>] Broadcasting: {str(chunks[i])}")
        nodeSocket.sendto(str(chunks[i]).encode('utf-8'), ("127.0.0.1", 50000))
        time.sleep(3)
    
    nodeSocket.close()
    

def ShamirGraphicalFunction(x, coefficients, secret):
    y = secret
    degree = len(coefficients) + 1
    for value in coefficients:
        y += value * ((x)^degree)
        degree -= 1
    return y

def shamirSecretSharing(secret):
    k = int(sys.argv[2])
    n = int(sys.argv[3])

    degree = k -1 
    pieces = []
    # These are randomly generated coefficients for the shamir f(x) function.
    coefficients = []

    for i in range(0, degree):
        coefficients.append(random.randint(1, 100))


    for i in range(1, n+1):
        share = ShamirGraphicalFunction(i, coefficients, secret)
        pieces.append(str((i, share)))
    
    return pieces

        

def generateEphemeral(t):
    while True:
        global myChunks

        EphID_priv = X25519PrivateKey.generate()
        EphID = EphID_priv.public_key()

        EphID_bytes = EphID.public_bytes(
            encoding=serialization.Encoding.Raw, 
            format=serialization.PublicFormat.Raw 
        )
        EphID_int = int.from_bytes(EphID_bytes, byteorder='big')

        myChunks = shamirSecretSharing(EphID_int)
       
        broadcastShares(myChunks)

        time.sleep(t)

def main():
    tSet = {15, 18, 21, 24, 27, 30}

    if len(sys.argv) != 4:
        print("This programs expects 3 arguments: t, k, n")
        sys.exit(1)
    
    t = int(sys.argv[1])
    k = int(sys.argv[2])
    n = int(sys.argv[3])


    if t not in tSet:
        print(f"t value must be an element of the set {tSet}")
        print("Usage: python3 Dimpy.py [t] [k] [n]")
        sys.exit(1)
    elif k < 3:
        print("k must be greater than or equal to 3")
        print("Usage: python3 Dimpy.py [t] [k] [n]")
        sys.exit(1)
    elif n < 5: 
        print("n must be greater than or equal to 5")
        print("Usage: python3 Dimpy.py [t] [k] [n]")
        sys.exit(1)
    elif k >= n:
        print("k must be less than n")
        print("Usage: python3 Dimpy.py [t] [k] [n]")
        sys.exit(1)

    # Start listening for broadcasts.
    chunkListen = threading.Thread(target=listenShares, args=(k,), daemon=True)  
    chunkListen.start()

    generateEphemeral(t)


    
    try:
        while True:
            k -= 1
    except Exception as e:
        print("Closing program.")

        sys.exit(1)



if __name__ == "__main__":
    main()