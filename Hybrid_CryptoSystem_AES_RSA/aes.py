# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import math
import time
key_expansion_time=0
encryption_time=0
decryption_time=0
from BitVector import *
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]
def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.

def convert_to_hex(plain_text):
    hexlist=[]
    for i in range(len(plain_text)):
        hexlist.append(format(ord(plain_text[i]),"x"))
    return  hexlist
def convert_byte_to_hex(bytelist):
    hexlist=[]
    for i in range(len(bytelist)):
        hexlist.append(bytelist[i].hex())
    return hexlist
def convert_to_ascii(string):
    #print(string)
    b3=BitVector(hexstring=string)
    return b3.get_bitvector_in_ascii()
def list_to_hex(list1):
    string=""
    for i in range(len(list1)):
        for j in range(len(list1[0])):
            string=string+list1[i][j]
    return string
def twod_list_to_oned(list1):
    list2=[]
    for i in range(len(list1)):
        for j in range(len(list1[0])):
            list2.append(list1[i][j])
    return list2
def convert_hex_to_byte(hexlist):
    bytelist=[]
    for i in range(len(hexlist)):
        bytelist.append(byte.fromhex(hexlist[i]))
    return bytelist
def list_to_string(list2):
    string=""
    for i in range(len(list2)):
        string=string+str(list2[i])
    return string
def list_to_array(list1, rows, columns):
    result = []
    for i in range(rows):
        row=[]
        row.append(list1[0+i])
        row.append(list1[4+i])
        row.append(list1[8 + i])
        row.append(list1[12 + i])
        result.append(row)
    return result

def key_scheduling(key):
    roundkeys = []
    rcon = ['01', '00', '00', '00']
    rc=rcon[0]
    roundkeys.append(key)
    for i in range(1,11):
        w0=key[0:4]
        w1=key[4:8]
        w2=key[8:12]
        w3=key[12:16]
        left_shifted=w3[1:] + w3[:1]
        gw3=[]
        if i>1:
            if BitVector(hexstring=rc)<BitVector(hexstring="80"):
                rcon[0]=(BitVector(hexstring=rc).shift_left(1)).get_bitvector_in_hex()
            else:
                bv=((BitVector(hexstring=rc).shift_left(1))^(BitVector(hexstring="11B")))
                bv=bv[-8:]
                rcon[0]=bv.get_bitvector_in_hex()
            rc=rcon[0]
        for i in range(4) :
            b = BitVector(hexstring=left_shifted[i])
            int_val = b.intValue()
            s = Sbox[int_val]
            s = BitVector(intVal=s, size=8)
            b2 = BitVector(hexstring=rcon[i])
            b3 = s ^ b2
            gw3.append(b3.get_bitvector_in_hex())
        w4=[]
        w5=[]
        w6=[]
        w7=[]
        for i in range(4):
            w4.append((BitVector(hexstring=w0[i])^BitVector(hexstring=gw3[i])).get_bitvector_in_hex())
        for i in range(4):
            w5.append((BitVector(hexstring=w4[i])^BitVector(hexstring=w1[i])).get_bitvector_in_hex())
        for i in range(4):
            w6.append((BitVector(hexstring=w5[i])^BitVector(hexstring=w2[i])).get_bitvector_in_hex())
        for i in range(4):
            w7.append((BitVector(hexstring=w6[i])^BitVector(hexstring=w3[i])).get_bitvector_in_hex())
        keys=w4+w5+w6+w7
        roundkeys.append(keys)
        key=keys
    return roundkeys

def subbytes(state):
    new_matrix = []
    for i in range(4):
        matrix = []
        for j in range(4):
            b = BitVector(hexstring=state[i][j])
            int_val = b.intValue()
            s = Sbox[int_val]
            s = BitVector(intVal=s, size=8)
            matrix.append(s.get_bitvector_in_hex())
        new_matrix.append(matrix)
    return new_matrix
def inverse_subbytes(state):
    new_matrix = []
    for i in range(4):
        matrix = []
        for j in range(4):
            b = BitVector(hexstring=state[i][j])
            int_val = b.intValue()
            s = InvSbox[int_val]
            s = BitVector(intVal=s, size=8)
            matrix.append(s.get_bitvector_in_hex())
        new_matrix.append(matrix)
    return new_matrix

def add_round_key(state, key_matrix):
    new_matrix=[]
    for i in range(4):
        matrix=[]
        for j in range(4):
            bv1=BitVector(hexstring=state[i][j])
            bv2=BitVector(hexstring=key_matrix[i][j])
            bv3=bv1^bv2
            matrix.append(bv3.get_bitvector_in_hex())
        new_matrix.append(matrix)
    return new_matrix
def shift_row(state):
    for i in range(4):
        state[i] = state[i][i:] + state[i][: i]
    return state
def inverse_shift_row(state):
    for i in range(4):
        state[i] = state[i][-i:] + state[i][: -i]
    return state
def multiply(bv1,bv2):
    AES_modulus = BitVector(bitstring='100011011')
    bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
    return bv3

def mix_coloumn(state) :
    result=[['0','0','0','0'],['0','0','0','0'],['0','0','0','0'],['0','0','0','0']]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                val=multiply(Mixer[i][k],BitVector(hexstring=state[k][j]))
                bv=BitVector(hexstring=result[i][j])
                bv=bv^val
                result[i][j]=bv.get_bitvector_in_hex()
    return result
def inv_mix_coloumn(state) :
    result=[['0','0','0','0'],['0','0','0','0'],['0','0','0','0'],['0','0','0','0']]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                val=multiply(InvMixer[i][k],BitVector(hexstring=state[k][j]))
                bv=BitVector(hexstring=result[i][j])
                bv=bv^val
                result[i][j]=bv.get_bitvector_in_hex()
    return result

def intermediate_round(state,all_keys):
    for i in range(1,10):
        result=subbytes(state)
        result2=shift_row(result)
        result3=mix_coloumn(result2)
        result4=add_round_key(result3,list_to_array(all_keys[i],4,4))
        state=result4
    return state
def inv_intermediate_round(state,all_keys):
    for i in range(1, 10):
        result=inverse_shift_row(state)
        result2=add_round_key(inverse_subbytes(result),list_to_array(all_keys[10-i],4,4))
        result3=inv_mix_coloumn(result2)
        state=result3
    #print(state)
    return state

def inv_round_ten(state,all_keys):
    res=inverse_subbytes(inverse_shift_row(state))
    return add_round_key(res,list_to_array(all_keys[0],4,4))
def round_zero(state_matrix,all_keys):
    key_zero=list_to_array(all_keys[0], 4, 4)
    return add_round_key(state_matrix,key_zero)
def inv_round_zero(state_matrix,all_keys):
    key_zero=list_to_array(all_keys[10], 4, 4)
    return add_round_key(state_matrix,key_zero)
def round_ten(state,all_keys):
    result=subbytes(state)
    return add_round_key(shift_row(result),list_to_array(all_keys[10],4,4))
def encryption(state_matrix,all_keys):
    round1 = round_zero(state_matrix,all_keys)
    round2 = intermediate_round(round1,all_keys)
    final = round_ten(round2,all_keys)
    return final
def decryption(state,all_keys):
    round1=inv_round_zero(state,all_keys)
    round2=inv_intermediate_round(round1,all_keys)
    final=inv_round_ten(round2,all_keys)
    #print(final)
    return final
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    choice=input("1.Text? 2.File?\n")
    if choice==str(1):
        plain_text = input("Enter plaintext\n")
        # f=open("input.txt","r")
        # plain_text=f.read()
        given_key = input("Enter Key\n")
        length=len(plain_text)
        lengthkey=len(given_key)
        rem=length%16
        blocks=length/16
        blocks=math.floor(blocks)
        if rem!=0:
            padding=16-rem
            for i in range(padding):
                plain_text=plain_text+" "
            blocks=blocks+1
        if lengthkey<16:
            padding=16-lengthkey
            for i in range(padding):
                given_key=given_key+" "
        if lengthkey>16:
            given_key=given_key[0:16]
        listkey = convert_to_hex(given_key)
        key_expansion_time=time.time_ns()
        allkeys = key_scheduling(listkey)
        print("Plain Text:")
        print(plain_text+"    [IN ASCII]")
        print(list_to_string(convert_to_hex(plain_text))+"    [IN HEX]\n")
        print("Key:")
        print(given_key + "    [IN ASCII]")
        print(list_to_string(listkey) + "    [IN HEX]\n")
        key_expansion_time=time.time_ns()-key_expansion_time
        finalstring=""
        decrypt=""
        en_hex=""
        dec_hex=""
        encryption_time=time.time_ns()
        for i in range(blocks):
            substring=plain_text[i*16:(i+1)*16]
            listtext=convert_to_hex(substring)
            state_matrix=list_to_array(listtext,4,4)
            final=encryption(state_matrix,allkeys)
            final_transpose=[list(i) for i in zip(*final)]
            string=list_to_hex(final_transpose)
            en_hex=en_hex+string
            finalstring=finalstring+convert_to_ascii(string)
        encryption_time=time.time_ns()-encryption_time
        print("Ciphered Text:")
        print(en_hex + "    [IN HEX]")
        print(finalstring + "    [IN ASCII]\n")
        decryption_time=time.time_ns()
        for i in range(blocks):
            sub=finalstring[i*16:(i+1)*16]
            listdec=convert_to_hex(sub)
            final=list_to_array(listdec,4,4)
            final2=decryption(final,allkeys)
            final2_transpose=[list(i) for i in zip(*final2)]
            str2 = list_to_hex(final2_transpose)
            dec_hex=dec_hex+str2
            decrypt=decrypt+convert_to_ascii(str2)
        decryption_time=time.time_ns()-decryption_time
        print("Deciphered Text:")
        print(dec_hex + "    [IN HEX]")
        print(decrypt + "    [IN ASCII]\n")
        print("Execution Time")
        print("Key scheduling time:"+str(key_expansion_time/1000000000)+" seconds")
        print("Encryption time:" + str(encryption_time/1000000000)+" seconds")
        print("Decryption time:" + str(decryption_time/1000000000)+" seconds")

    else:
        filename=input("Provide File Name\n")
        extension=filename.split(".")[1]
        new_file="decrypted"+"."+extension
        dec_file=open(new_file,"wb")
        input_file=open(filename,"rb")
        byte=input_file.read(1)
        bytes=[]
        while byte:
            bytes.append(byte)
            byte=input_file.read(1)
        input_file.close()
        given_key = input("Enter Key\n")
        length = len(bytes)
        lengthkey = len(given_key)
        rem = length % 16
        blocks = length / 16
        blocks = math.floor(blocks)
        if rem != 0:
            padding = 16 - rem
            for i in range(padding):
                bytes.append(byte.fromhex("20"))
            blocks = blocks + 1
        if lengthkey < 16:
            padding = 16 - lengthkey
            for i in range(padding):
                given_key = given_key + " "
        if lengthkey > 16:
            given_key = given_key[0:16]
        listkey = convert_to_hex(given_key)
        key_expansion_time = time.time_ns()
        allkeys = key_scheduling(listkey)
        print("Key:")
        print(given_key + "    [IN ASCII]")
        print(list_to_string(listkey) + "    [IN HEX]\n")
        key_expansion_time = time.time_ns() - key_expansion_time
        finalstring = ""
        decrypt = ""
        en_hex = ""
        dec_hex = ""
        encryption_time = time.time_ns()
        byte_array=[]
        for i in range(blocks):
            sub_bytes = bytes[i * 16:(i + 1) * 16]
            listfile = convert_byte_to_hex(sub_bytes)
            state_matrix = list_to_array(listfile, 4, 4)
            final = encryption(state_matrix, allkeys)
            final_transpose = [list(i) for i in zip(*final)]
            one_d=twod_list_to_oned(final_transpose)
            byte_array=byte_array+convert_hex_to_byte(one_d)
        print("Ciphered Byte Array:")
        print(byte_array)
        encryption_time = time.time_ns() - encryption_time
        decryption_time = time.time_ns()
        byte_array2=[]
        for i in range(blocks):
            sub = byte_array[i * 16:(i + 1) * 16]
            listdec = convert_to_hex(sub)
            final = list_to_array(listdec, 4, 4)
            final2 = decryption(final, allkeys)
            final2_transpose = [list(i) for i in zip(*final2)]
            str2 = twod_list_to_oned(final2_transpose)
            byte_array2 = byte_array2 + convert_hex_to_byte(str2)
        print("Deciphered Byte Array:")
        print(byte_array2)
        for i in range(len(byte_array2)):
            dec_file.write(byte_array2[i])
        decryption_time = time.time_ns() - decryption_time
        print("Execution Time")
        print("Key scheduling time:" + str(key_expansion_time / 1000000000) + " seconds")
        print("Encryption time:" + str(encryption_time / 1000000000) + " seconds")
        print("Decryption time:" + str(decryption_time / 1000000000) + " seconds")


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
