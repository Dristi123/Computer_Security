# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import math
import random
import time
key_expansion_time=0
encryption_time=0
decryption_time=0

from BitVector import *

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.
def generate_prime(k):
    bv = BitVector(intVal=0)
    range=int((int(k)/2))
    while 1:
        bv = bv.gen_random_bits(range)
        check = bv.test_for_primality()
        if check!=0:
            return bv.intValue()
def check_coprime(a,b):
    return math.gcd(a,b)==1
def multiplicative_inverse(e,phi):
    bv_modulus = BitVector(intVal=phi)
    bv = BitVector(intVal=e)
    bv_result = bv.multiplicative_inverse(bv_modulus)
    if bv_result is not None:
        return bv_result.intValue()# 17
    else:
        print("No multiplicative inverse in this case")
        return

def generate_key(k):
    p=generate_prime(k)
    q=generate_prime(k)
    n=p*q
    phi=(p-1)*(q-1)
    while 1:
        e=random.randrange(1,phi)
        if check_coprime(e,phi):
            break
    d=multiplicative_inverse(e,phi)
    keys=[[e,n],[d,n]]
    return keys
def encrypt(plaintext,e,n):
    cipher=[]
    for i in range(len(plaintext)):
        cipher.append(pow(ord(plaintext[i]),e,n))
    return cipher
def decrypt(ciphertext,d,n):
    plaintext=""
    for i in range(len(ciphertext)):
        plaintext=plaintext+chr(pow(ciphertext[i],d,n))
    return plaintext
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    text = input("Enter plaintext\n")

    k = 16
    k_list=[16,32,64,128]
    key_time_list=[]
    en_time_list=[]
    dec_time_list=[]
    while 1:
        key_expansion_time = time.perf_counter_ns()
        generated_keys=generate_key(k)
        key_expansion_time = time.perf_counter_ns() - key_expansion_time
        encryption_time = time.perf_counter_ns()
        encrypted=encrypt(text,generated_keys[0][0],generated_keys[0][1])
        encryption_time = time.perf_counter_ns() - encryption_time
        decryption_time = time.perf_counter_ns()
        decypted=decrypt(encrypted,generated_keys[1][0],generated_keys[1][1])
        decryption_time = time.perf_counter_ns() - decryption_time
        print("For k="+str(k))
        print("Plain Text:")
        print(text+"\n")
        print("Ciphered Text:")
        encrypted_key = ""
        for i in range(len(encrypted)):
            encrypted_key = encrypted_key + str(encrypted[i]) + " "
        print(encrypted_key+"\n")
        print("Deciphered Text:")
        print(text+"\n")
        print("Execution Time:")
        print("Key Generation time:" + str(key_expansion_time/1000)+" microseconds")
        key_time_list.append(str(key_expansion_time/1000))
        print("Encryption time:" + str(encryption_time/1000)+" microseconds")
        en_time_list.append(str(encryption_time/1000))
        print("Decryption time:" + str(decryption_time/1000)+" microseconds")
        dec_time_list.append(str(decryption_time/1000))
        k=k*2
        if k==256:
            break

    print("<Report>(All times are in microsecond)")
    print("K        Key Generation      Encryption      Decryption")
    for i in range(len(k_list)):
        print(str(k_list[i])+"          "+key_time_list[i]+"            "+en_time_list[i]+"             "+dec_time_list[i])
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
