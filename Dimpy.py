import sys
import time
import threading
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import random
from socket import *
from decimal import Decimal
import ast
from subrosa import split_secret, recover_secret, Share


myChunks = []

def reconstructedSecret(shares):
    secret = recover_secret(shares)
    return int.from_bytes(secret, byteorder='big')

def listenShares(chunksNeeded):
    global myChunks
    collectedChunks = []
    prevHash = None


    nodeSocket = socket(AF_INET, SOCK_DGRAM)
    nodeSocket.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    nodeSocket.bind(("", 50000))

    while True:
        data, address = nodeSocket.recvfrom(1024)
        chunk = data.decode('utf-8').split("||")


        chunkRecv = eval(chunk[0])
        hashRecv = eval(chunk[1])

        # Ignoring chunks received from self. 
        if chunkRecv in myChunks:
            continue

        sendProbability = random.random()
        if sendProbability < 0.5:
            continue
        
        if prevHash is None:
            prevHash = hashRecv
        elif prevHash != hashRecv:
            prevHash = hashRecv
            collectedChunks = []

        collectedChunks.append(chunkRecv)
        
        # Add the chunks received to the chunks array.
        print(f"[>] Received Chunk {len(collectedChunks)} out of {chunksNeeded}: {chunkRecv}")

        prevHash = hashRecv
        shares = [Share.from_bytes(share) for share in collectedChunks]

        if len(collectedChunks) == chunksNeeded:
            shares = [Share.from_bytes(share) for share in collectedChunks]
            secretRecv = reconstructedSecret(shares)

            if hashRecv == hash(secretRecv):
                print("Correct secret has been found.")



    
    nodeSocket.close()



def broadcastShares(chunks, ephIDhash):
    length = len(chunks)

    # Setup UDP connection
    nodeSocket = socket(AF_INET, SOCK_DGRAM)
    nodeSocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

    for i in range(0, length):
        print(f"[>] Broadcasting: {str(chunks[i])}")

        message = str(chunks[i]) + "||" 
        message += str(ephIDhash)
        nodeSocket.sendto(message.encode('utf-8'), ("127.0.0.1", 50000))

        time.sleep(3)
    
    nodeSocket.close()
        

def generateEphemeral(t, k, n):
    while True:
        global myChunks
        ephIDprivKey = X25519PrivateKey.generate()
        EphID = ephIDprivKey.public_key()

        ephIDBytes = EphID.public_bytes(
            encoding=serialization.Encoding.Raw, 
            format=serialization.PublicFormat.Raw 
        )
        ephIDInt = int.from_bytes(ephIDBytes, byteorder='big')
        ephIDhash = hash(ephIDInt)
        print(f"My EPH ID {ephIDInt}")

        chunks = split_secret(ephIDBytes, k, n)
        myChunks = [bytes(chunk) for chunk in chunks]

        broadcastShares(myChunks, ephIDhash)

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

    generateEphemeral(t, k, n)


    
    try:
        while True:
            k -= 1
    except Exception as e:
        print("Closing program.")

        sys.exit(1)



if __name__ == "__main__":
    main()