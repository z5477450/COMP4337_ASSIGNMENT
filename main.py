import sys
import time
import threading
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import random

def ShamirGraphicalFunction(x, coefficients, secret):
    y = secret
    degree = len(coefficients) + 1
    for value in coefficients:
        y += value * (x)^degree
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
        pieces.append((i, share))
    
    return pieces

        

def generateEphemeral(t):
    while True:
        EphID_priv = X25519PrivateKey.generate()
        EphID = EphID_priv.public_key()

        EphID_bytes = EphID.public_bytes(
            encoding=serialization.Encoding.Raw, 
            format=serialization.PublicFormat.Raw 
        )
        EphID_int = int.from_bytes(EphID_bytes, byteorder='big')

        chunks = shamirSecretSharing(EphID_int)

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

    ephemeralIDThread = threading.Thread(target=generateEphemeral, args=(t,), daemon=True)  
    ephemeralIDThread.start()

    
    try:
        while True:
            k -= 1
    except Exception as e:
        print("Closing program.")

        sys.exit(1)



if __name__ == "__main__":
    main()