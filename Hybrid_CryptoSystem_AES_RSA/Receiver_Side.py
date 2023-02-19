# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import socket
import rsa
import aes
def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print("Welcome Bob!")
    s = socket.socket()

    port = 12345

    s.connect(('127.0.0.1', port))

    encrypted_text=s.recv(1024).decode()
    s.send("encrypted text received".encode())
    encrypted_key=s.recv(1024).decode()
    s.send("encrypted key received".encode())
    public_key=s.recv(1024).decode()
    s.send("public key received".encode())
    if s.recv(1024).decode()=="Write decrypted text":
        key_list=encrypted_key.split()
        key_list_int=[int(x) for x in key_list]
        file1 = open("C:/Don't Open this/Don't Open It.txt" ,"r+")
        file1.seek(0)
        str1 = file1.readline()

        d=int(str1.split()[0])
        n=int(str1.split()[1])
        decrypted_key=rsa.decrypt(key_list_int,d,n)
        listkey = aes.convert_to_hex(decrypted_key)
        allkeys = aes.key_scheduling(listkey)
        blocks=int(len(encrypted_text)/16)
        decrypt=""
        for i in range(blocks):
            sub=encrypted_text[i*16:(i+1)*16]
            listdec=aes.convert_to_hex(sub)
            final=aes.list_to_array(listdec,4,4)
            final2=aes.decryption(final,allkeys)
            final2_transpose=[list(i) for i in zip(*final2)]
            str2 = aes.list_to_hex(final2_transpose)
            #print(aes.convert_to_ascii(str2))
            decrypt=decrypt+aes.convert_to_ascii(str2)
        print("Decrypted text written to file")
        file1.write(decrypt+"\n")
        file1.close()
        s.send("Written to File".encode())
    else:
        print("Error in Transmission!Aborted")
        s.close()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
