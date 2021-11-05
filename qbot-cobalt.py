#!/usr/bin/env python3

import sys
import os
import pefile
import socket
import argparse

from capstone import *
from capstone.x86 import *

import json



shellcode_code_config_object = {}



def parse_arguments():
    """Read arguments from a command line."""
    parser = argparse.ArgumentParser(description='Arguments get parsed via --commands')
    parser.add_argument("-file", metavar='input file', required=True,
        help='pass a Qbot module that you suspect to be cobalt strike module') 
    args = parser.parse_args()
    
    return args


def diasm_bin(code):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return (md.disasm(code, 0x100))
     
     
def check_if_module_contains_cobalt_strike(pe):
    #read Decryption function

    bin = pe.get_data(0x1094, 0x2A)
    x86_instruction = diasm_bin(bin)
    #parse addresses and keys
    binary_elemnts =[]
    for instruction in x86_instruction:
        #fetch encrypted shellcode address and value 
        if (instruction.address == 0x101):
          if (len(instruction.operands) > 1):
              for i in instruction.operands:
                  if i.type == X86_OP_IMM:
                      print("[+] Encrypted shellcode address found at ---> ", hex(i.value.imm))
                      binary_elemnts.append(hex(i.value.imm & 0xFFFF ))
                 
       
        #fetch XOR key address and vlaue
        if (instruction.address == 0x110):
              if (len(instruction.operands) > 0):
               for i in instruction.operands:
                  if i.type == X86_OP_MEM:
                      print("[+] Key  address found at ---> ", hex(i.value.mem.disp))
                      binary_elemnts.append(hex(i.value.mem.disp & 0xFFFF ))
                  
        
        #fetch shellcode size 
        if (instruction.address == 0x11c):
              if (len(instruction.operands) > 0):
               for i in instruction.operands:
                  if i.type == X86_OP_IMM:
                      print("[+] shellcode size ---> ", hex(i.value.imm))
                      binary_elemnts.append(hex(i.value.imm ))
                  
        #fetch xor key index 
        if (instruction.address == 0x10d):
              if (len(instruction.operands) > 0):
               for i in instruction.operands:
                  if i.type == X86_OP_IMM:
                      print("[+] key index  ---> ", hex(i.value.imm))
                      binary_elemnts.append(hex(i.value.imm ))
                 
                       
    return(binary_elemnts)


def ge_IP_address_string(shellcode):
    IP_address = ''
    for byte in shellcode[0x331:0x343]:
       #if the byte has value add it to the string
       if str(byte) != '\x00':  
        IP_address +=str(byte)
    #check if the IP address is valid
    try:
     socket.inet_aton(IP_address)
     shellcode_code_config_object['C2_Address'] = IP_address
     socket.close(0)
    # legal
    except socket.error:
    # Not legal
     pass
     

      
def get_uesr_agent(shellcode):    
    user_agent = ''
    for byte in shellcode[0x264:0x2ae]:
           #if the byte has value add it to the string
        user_agent +=str(byte)
    shellcode_code_config_object['User_Agent'] = user_agent
        
   

def get_http_config(shellcode):
    http_profile = ''
    for byte in shellcode[0x222:0x243]:
           #if the byte has value add it to the string
        http_profile +=str(byte)
    shellcode_code_config_object['HTTP_Profile'] = http_profile

def get_http_uri(shellcode):
    http_uri = ''
    for byte in shellcode[0x168:0x181]:
        http_uri +=str(byte)
    shellcode_code_config_object['HTTP_URI'] = http_uri
     
def decrypt_shellcode(cobalt_strike_module):
 try:
    size = 0
    decrypted_shellcode = ''
    dec_bytes = bytearray()
    pe =  pefile.PE(cobalt_strike_module)
    binary_elements = check_if_module_contains_cobalt_strike(pe)
    
    
    while(size < int(binary_elements[3],16)):
      #get byte at encrypted shellcode data   
      bin = pe.get_data(int(binary_elements[0], 16)+size, 1)
      #get key byte   
      key = pe.get_data(int(binary_elements[2], 16) + (size & int(binary_elements[1], 16)), 1 )
      dec_byte = int.from_bytes(bin, "little") ^ int.from_bytes(key, "little")
      size+=1
      decrypted_shellcode += chr(dec_byte)
      dec_bytes.extend((dec_byte).to_bytes(2, byteorder='little'))
    ge_IP_address_string(decrypted_shellcode)
    get_uesr_agent(decrypted_shellcode)
    get_http_config(decrypted_shellcode)
    get_http_uri(decrypted_shellcode)
    print(json.dumps(shellcode_code_config_object, indent=2))
 except:
     print("[-] Failed to decrypt shellcode possibly not a Qbot-CobaltStrike loader ")   

    

    

if __name__ == '__main__':
    args = parse_arguments()
    decrypt_shellcode(args.file)
