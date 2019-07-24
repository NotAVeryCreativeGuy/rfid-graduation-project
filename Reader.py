#!/usr/bin/env python2
import os
import binascii
import hmac
from MILibrary import * 
from coloredtext import *
from Crypto.Cipher import AES

continue_reading = True
uid = []
tag_uid = [81,80,155,32,186]
reader_uid = [225, 184, 209, 32, 168]
master_key = "1234567890ABCDEF"
key = [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF]


print white("[*] Reader program started...")
while continue_reading:

    print white("[*] Searching for tags to read...")
    (status,uid)  = select_card(tag_uid)

    print green("[*] Tag found")
    print white("[*] Reading card TID and calculating key...")
    tag_tid = read_blocks(8, 9, key, uid)
    card_key = hmac.new(master_key, convert_to_hex(tag_tid))

    print white("\t- Current TID:\t") + cyan(convert_to_hex(tag_tid))
    print white("\t- Current key:\t") + cyan(card_key.hexdigest())

    print white("[*] Calculating new TID and key...")
    new_tid = os.urandom(16)
    new_key = hmac.new(master_key, binascii.hexlify(new_tid))

    print white("\t- New TID:\t") + cyan(binascii.hexlify(new_tid))
    print white("\t- New key:\t") + cyan(new_key.hexdigest())

    print white("[*] Calculating value of A...")
    cipher = AES.new(card_key.digest(), AES.MODE_CBC, card_key.hexdigest()[16:])
    A_decrypt = card_key.hexdigest() + binascii.hexlify(new_tid) + new_key.hexdigest()
    A = cipher.encrypt(card_key.digest() + new_tid + new_key.digest())
    print white("\t- A =\t") + cyan(binascii.hexlify(A))

    cipher = AES.new(new_key.digest(), AES.MODE_CBC, new_key.hexdigest()[16:])
    B_expected = binascii.hexlify(cipher.encrypt(new_key.digest()))

    print white("[*] Transmitting value of A...")
    select_card(reader_uid)
    write_data(8, key, reader_uid, A)
    print green("[*] Value of A has been written.")

    print white("[*] Waiting for value of B from tag...")
    select_card(tag_uid)
    B_received = convert_to_hex(read_blocks(10, 11, key, tag_uid))
    print white("\t- B received =\t") + cyan(B_received)
    print white("\t- B expected =\t") + cyan(B_expected)

    if B_received == B_expected:
        print green("----- VALUES MATCHED. AUTHENTICATED SUCCESSFULLY -----")
    else:
        print red("----- VALUES MISMATCHED. AUTHENTICATION FAILED -----")



