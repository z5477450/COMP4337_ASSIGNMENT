import sys
import time
import threading
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
import random
from socket import *
from decimal import Decimal
import ast
from subrosa import split_secret, recover_secret, Share
from bloom_filter import BloomFilter
import datetime
from socket import socket, AF_INET, SOCK_DGRAM
import copy

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 50000

myChunks = []
DBF = BloomFilter(max_elements=1000, error_rate=0.1)
QBF = BloomFilter(max_elements=1000, error_rate=0.1)
CBF = BloomFilter(max_elements=1000, error_rate=0.1)
DBFlist = []
DBFTimeStamp = []
localNodeID = str(random.randint(1, 10))
encidList = []
allDBFs = []

def reconstructedSecret(shares):
    secret = recover_secret(shares)
    return int.from_bytes(secret, byteorder='big')

def listenShares(chunksNeeded):
    global myChunks
    collectedChunks = []
    prevHash = None


    nodeSocket = socket(AF_INET, SOCK_DGRAM)
    nodeSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    nodeSocket.bind(("", 50000))

    while True:
        data, address = nodeSocket.recvfrom(1024)
        chunk = data.decode('utf-8').split("||")


        chunkRecv = eval(chunk[0])
        hashRecv = eval(chunk[1])
        senderID = chunk[2].strip()
        # Ignoring chunks received from self. 
        if senderID == localNodeID:
            continue
        # Ignoring chunks received from self. 
        if chunkRecv in myChunks:
            continue
        

        sendProbability = random.random()
        # if sendProbability < 0.5:
        #     continue
        
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
            try:
                shares = [Share.from_bytes(share) for share in collectedChunks]
                secretRecv = reconstructedSecret(shares)
                if hashRecv == hash(secretRecv):
                    print("Correct secret has been found.")
                    secretRecvBytes = secretRecv.to_bytes((secretRecv.bit_length() + 7) // 8, byteorder='big')
                    handle_diffie_hellman_exchange(ephIDprivKey, secretRecvBytes, senderID)
                collectedChunks = []
                
            except Exception as e:
                print(f"Error processing chunks: {e}")
                collectedChunks = []

    
    nodeSocket.close()



def broadcastShares(chunks, ephIDhash):
    length = len(chunks)

    # Setup UDP connection
    nodeSocket = socket(AF_INET, SOCK_DGRAM)
    nodeSocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

    for i in range(0, length):
        print(f"[>] Broadcasting: {str(chunks[i])}")

        message = str(chunks[i]) + "||" 
        message += str(ephIDhash) + "||"
        message += localNodeID
        nodeSocket.sendto(message.encode('utf-8'), ("255.255.255.255", 50000))

        time.sleep(3)
    
    nodeSocket.close()
        

def generateEphemeral(t, k, n):
    while True:
        global myChunks, ephIDBytes, ephIDprivKey

        ephIDprivKey = X25519PrivateKey.generate()
        EphID = ephIDprivKey.public_key()

        ephIDBytes = EphID.public_bytes(
            encoding=serialization.Encoding.Raw, 
            format=serialization.PublicFormat.Raw 
        )
        ephIDInt = int.from_bytes(ephIDBytes, byteorder='big')
        ephIDhash = hash(ephIDInt)
        print(f"EphIDInt: {ephIDInt}")

        chunks = split_secret(ephIDBytes, k, n)
        myChunks = [bytes(chunk) for chunk in chunks]

        broadcastShares(myChunks, ephIDhash)

        time.sleep(t)

"""
Task 5
"""
def generateEncid(privateKey, nodeEphID):
    global encid
    try:
        # Calculate the node pk with ephIDBytes
        nodePublicKey = X25519PublicKey.from_public_bytes(nodeEphID)
        shareKey = privateKey.exchange(nodePublicKey)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shareKey)
        encid = digest.finalize()
        print("===========================Task5===========================")
        print("computing the shared secret EncID by using Diffie Hellman key exchange mechanism.")
        print(f"$$ EncID Created: {encid.hex()}\n")
        return encid
    
    
    except Exception as e:
        print(f"Failed to generate DHKE: {e}")

def handle_diffie_hellman_exchange(private_key, nodeEphID, sender_id):  
    try:
        encid = generateEncid(private_key, nodeEphID)
        
        if encid:
            print("===========================Task5B===========================")
            print(f"LocalNode {localNodeID} and remoteNode {sender_id} have arrived at the same EncID value. ")

            
            # encoding the generated EncID to DBF
            encodingAndDeletingEncID(encid)
    except Exception as e:
        print(f"Error in Diffie-Hellman exchange: {e}")




"""
task 6
"""
# Add the encoded EncID to the Daily Bloom Filter
def encodingAndDeletingEncID(encid):
    print("===========================Task6===========================")
    global DBF,encid_hex
    DBF = BloomFilter(max_elements=1000, error_rate=0.1)
    encid_hex = encid.hex()
    encidList.append(encid_hex)
    encid_hex_list = encidList.copy()


    for encid_hex in encid_hex_list:
        DBF.add(encid_hex)
        print("[>] Encoding to DBF")
        encidList.remove(encid_hex)
        print(f"[>] EncID {encid_hex} deleted after adding to Bloom Filter.\n")
        addEncIDToDBF(encid_hex)
        print(f"[>] EncID {encid_hex} added to Daily Bloom Filter.\n")


    #print(DBF)
    #rint(f"[>] EncID {encid_hex} added to Daily Bloom Filter.\n")
    # Delete the encid after added to the Bloom Filter
    encid_hex_list.remove(encid_hex)
    #print(f"[>] EncID {encid_hex} deleted after adding to Bloom Filter.\n")



"""
task 7
"""
def addEncIDToDBF(encid_hex):
    global DBFlist, DBFTimeStamp
    
    current_time = datetime.datetime.now()
    
    # initialize timestamp
    if not DBFTimeStamp:
        DBFTimeStamp.append(current_time)
        DBFlist = []
       
    DBFlist.append(encid_hex)
    
    print("===========================Task7-A===========================")
    print(f"[>][{DBFTimeStamp[0].strftime('%Y-%m-%d %H:%M:%S')}] Current DBF has: {len(DBFlist)} EncIDs stored")
    for encid_hex in encidList:
        if encid_hex not in DBF:
            DBF.add(encid_hex)
        if encid_hex in DBF:
            print("\n[>] EncIDs in current DBF:")
            for i in range(len(DBFlist)):
                print(f"    {i+1}. {DBFlist[i]}")
            # while len(encidList):
            #     print(f"[>] EncID {encid_hex} added to Daily Bloom Filter.")
                break
    #display all encid in DBF





def DBF_manager(t):
    global DBF, DBFlist, DBFTimeStamp, allDBFs
    
    if 'allDBFs' not in globals():
        global allDBFs
        allDBFs = [] 
    
    # time duration for QBF
    delete_duration = t * 6 * 6
    
    while True:
        time.sleep(t * 6) 
        
        current_time = datetime.datetime.now()
        
        if DBFlist and DBFTimeStamp:
            allDBFs.append((DBFTimeStamp[0], DBFlist.copy()))
        
        # initialize new DBF
        DBF = BloomFilter(max_elements=1000, error_rate=0.1)
        DBFlist = []
        DBFTimeStamp = [current_time]
        
        # delete old DBF
        allDBFs = [(ts, encids) for ts, encids in allDBFs 
                   if (current_time - ts).total_seconds() <= delete_duration]
        # only keep avaliable DBF
        if len(allDBFs) > 6:
            allDBFs.pop(0)
        
        # Showing DBF infos
        print("====================Task 7-B====================")
        print("\n[>] All stored DBFs and their EncIDs:")
        for i, (timestamp, encids) in enumerate(allDBFs):
            age_seconds = (current_time - timestamp).total_seconds()
            print(f"\n    DBF {i+1}: Created at {timestamp.strftime('%Y-%m-%d %H:%M:%S')} ({age_seconds:.1f} seconds ago)")
            print(f"    Contains {len(encids)} EncIDs:")
            

            for j, encid in enumerate(encids):
                print(f"        {j+1}. {encid}")

        print("\n")




"""
task 8
"""
def combineDBFtoQBF(t):
    QBF = BloomFilter(max_elements=10000, error_rate=0.1)
    Dt = t * 6 * 6
    while True:
        time.sleep(Dt)  # Sleep for Dt minutes (converted to seconds)

        current_time = datetime.datetime.now()
        print(f"[>] Combining DBFs into QBF at {current_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Combine all the EncIDs from the stored DBFs into the QBF
        for timestamp, encid_hex, DBF in allDBFs:
        # retrive the elements in BF instead of modified the original data in DBF
            temp_dbf = copy.deepcopy(DBF)
            QBF |= temp_dbf

        # After combining, reset the list of DBFs
        allDBFs = []

        # Display the current state of the QBF after combining
        print(f"[>] QBF now contains {len(QBF)} EncIDs.")

        print("[>] Current QBF contains the following EncIDs:")
        for i, encid in enumerate(QBF):
            print(f"    {i + 1}. {encid}")




"""
task 9
"""
def combineDBFtoCBF(t):
    CBF = BloomFilter(max_elements=10000, error_rate=0.1)

    current_time = datetime.datetime.now()
    print(f"[>] Combining DBFs into CBF at {current_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Combine all the EncIDs from the stored DBFs into the QBF
    for timestamp, encid_hex, CBF in allDBFs:
        # retrive the elements in BF instead of modified the original data in DBF
        temp_dbf = copy.deepcopy(DBF)
        CBF |= temp_dbf

    # After combining, reset the list of DBFs
    allDBFs = []

    # Display the current state of the CBF after combining
    print(f"[>] QBF now contains {len(CBF)} EncIDs.")

    print("[>] Current QBF contains the following EncIDs:")
    for i, encid in enumerate(CBF):
        print(f"    {i + 1}. {encid}")



def main():
    global localNodeID, ephIDprivKey, ephIDBytes, t, k, n
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
    print("=" * 60)
    print(f"DIMY Client starting")
    print(f"Local_Node_ID: {localNodeID}")
    print("=" * 60)
    dbf_thread = threading.Thread(target=DBF_manager, args=(t,))
    dbf_thread.daemon = True
    dbf_thread.start()
    # Start listening for broadcasts.
    chunkListen = threading.Thread(target=listenShares, args=(k,), daemon=True)  
    chunkListen.start()


    qbf_thread = threading.Thread(target=combineDBFtoQBF, args=(t,), daemon=True)
    qbf_thread.start()

    cbf_thread = threading.Thread(target=combineDBFtoQBF, args=(t,), daemon=True)
    cbf_thread.start()

    ephid_thread = threading.Thread(target=generateEphemeral, args=(t, k, n), daemon=True)
    ephid_thread.start()

    
    try:
        while True:
            k -= 1
            time.sleep(0.1)
    except Exception as e:
        print("Closing program.")

        sys.exit(1)


if __name__ == "__main__":
    main()