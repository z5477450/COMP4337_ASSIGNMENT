from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from custom_bloom_filter import BloomFilter
import pickle
from bitarray import bitarray

if __name__ == '__main__':
    PORT = 51001
    storedCBF = []

    serverSocket = socket(AF_INET, SOCK_STREAM)
    # # allow quick restart
    # serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(('localhost', PORT))
    serverSocket.listen(5)
    print(f"[Server] Listening on port {PORT}...")

    while True:
        conn, addr = serverSocket.accept()
        print(f"[Server] Connection from {addr}")

        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk


        receivedFilter = pickle.loads(data)
        tagType, receivedBF = receivedFilter


        print(f"[Server] Received tag='{tagType}', BloomFilter={receivedBF}")


        if tagType == "CBF":
            storedCBF.append(receivedBF)
            CBF_length = len(storedCBF)
            print(f"Stored {CBF_length} CBF in total")
            conn.sendall(b"CBF upload successful.")

        elif tagType == "QBF":
            print("[Server] Recieveing QBF from client")

            bitarray_in_bits = receivedBF.backend.array_
            bitarray_in_bytes = bitarray_in_bits.tobytes()
            tempBF = bitarray()
            tempBF.frombytes(bitarray_in_bytes)
            

            if not storedCBF:
                conn.sendall("Not close contact".encode('utf-8'))
            else:
                match = False
                for cbf in storedCBF:
                    CBF_bitarray = cbf.backend.array_
                    CBF_bytes = CBF_bitarray.tobytes()
                    tempCBF = bitarray()
                    tempCBF.frombytes(CBF_bitarray)

                    CBF_matching = (tempBF & tempCBF).any()
                    if CBF_matching:
                        match = True
                        break

                if match:
                    reply = "\nCLOSE CONTACT\n" + "!" * 60
                    conn.sendall(reply.encode('utf-8'))



                

        conn.close()
