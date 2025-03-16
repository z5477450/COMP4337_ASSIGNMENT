import sys
import time
import threading
from random import randbytes


def generateEphemeral(t):
    while True:
        eID = randbytes(32)
        time.sleep(t)



def main():
    tSet = {15, 18, 21, 24, 27, 30}

    if len(sys.argv) != 4:
        print("This programs expects 3 arguments: t, k, n")
        sys.exit(1)
    
    t = int(sys.argv[1])
    k = sys.argv[2]
    n = sys.argv[3]

    if t not in tSet:
        print(f"t value must be an element of the set {tSet}")
        sys.exit(1)

    try: 
        ephemeralIDThread = threading.Thread(target=generateEphemeral, args=(t,), daemon=True)  
        ephemeralIDThread.start()
    except Exception as e:
        print("Threading closed")
        sys.exit(1)
    



if __name__ == "__main__":
    main()