# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import socket
import aes
import rsa
import math
import os
def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

    s = socket.socket()
    print("Socket successfully created")
    port = 12345

    s.bind(('', port))
    print("socket binded to %s" % (port))

    s.listen(5)
    print("socket is listening")
    print("Welcome Alice!")
    plain_text = input("Enter plaintext\n")
    #print(plain_text)
    given_key = input("Enter Key\n")
    #print(given_key)
    length = len(plain_text)
    lengthkey = len(given_key)
    rem = length % 16
    blocks = length / 16
    blocks = math.floor(blocks)
    if rem != 0:
        padding = 16 - rem
        for i in range(padding):
            plain_text = plain_text + " "
        blocks = blocks + 1
    if lengthkey < 16:
        padding = 16 - lengthkey
        for i in range(padding):
            given_key = given_key + " "
    if lengthkey > 16:
        given_key = given_key[0:16]
    listkey = aes.convert_to_hex(given_key)
    allkeys = aes.key_scheduling(listkey)
    finalstring = ""
    for i in range(blocks):
        substring = plain_text[i * 16:(i + 1) * 16]
        listtext = aes.convert_to_hex(substring)
        state_matrix = aes.list_to_array(listtext, 4, 4)
        #print(state_matrix)
        final = aes.encryption(state_matrix,allkeys)
        final_transpose = [list(i) for i in zip(*final)]
        string = aes.list_to_hex(final_transpose)
        #print(aes.convert_to_ascii(string))
        finalstring = finalstring + aes.convert_to_ascii(string)
    #print(finalstring)
    k = input("Enter value of k for RSA\n")
    generated_keys = rsa.generate_key(k)
    encrypted = rsa.encrypt(given_key, generated_keys[0][0], generated_keys[0][1])
    #print(encrypted)
    encrypted_key=""
    for i in range(len(encrypted)):
        encrypted_key=encrypted_key+str(encrypted[i])+" "
    public_key=str(generated_keys[0][0])+" "+str(generated_keys[0][1])
    # Directory
    directory = "Don't Open this"

    # Parent Directory path
    parent_dir = "C:/"
    path = os.path.join(parent_dir, directory)
    if not os.path.exists(path):
        os.mkdir(path)
    file1 = open(path+"/Don't Open It.txt", "w+")
    file1.write(str(generated_keys[1][0])+" "+str(generated_keys[1][1])+"\n")
    file1.close()

    while True:

        c, addr = s.accept()
        print('Got connection from', addr)

        c.send(finalstring.encode())
        str1=c.recv(1024).decode()

        if str1=="encrypted text received":
            c.send(encrypted_key.encode())
            str2=c.recv(1024).decode()

            if str2=="encrypted key received":
                c.send(public_key.encode())
                str3=c.recv(1024).decode()
                if str3=="public key received":
                    c.send("Write decrypted text".encode())
                    str4=c.recv(1024).decode()
                    if str4=="Written to File":
                        file2=open(path+"/Don't Open It.txt", "r+")
                        lines=file2.readlines()[1:]
                        text=lines[0].rstrip()
                        # print("de"+text)
                        # print(plain_text)
                        if text==plain_text.rstrip():
                            print("Plain text and Decrypted text match")
                        else:
                            print("Plain text and decrypted text dont match")

                else:
                    print("Receiver did not receive text.Transmission aborted!!\n")
                    # Close the connection with the client
                    c.close()

                    # Breaking once connection closed
                    break

            else :
                print("Receiver did not receive text.Transmission aborted!!\n")
                # Close the connection with the client
                c.close()

                # Breaking once connection closed
                break
        else :
            print("Receiver did not receive text.Transmission aborted!!\n")
        # Close the connection with the client
            c.close()

        # Breaking once connection closed
            break

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
