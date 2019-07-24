#!/usr/bin/env python

import RPi.GPIO as GPIO
import os
import binascii
from Crypto.Cipher import AES
import hmac
import MFRC522
from MILibrary import * 


continue_reading = True
uid = []
tag_uid = [81,80,155,32,186]
reader_uid = [225, 184, 209, 32, 168]
master_key = "1234567890ABCDEF"
key = [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF]



print white("[*] Tag program started...")
while continue_reading:

	print white("[*] Waiting to receive value of A...")
	select_card(reader_uid)
	A = read_blocks(8, 11, key, reader_uid)
	print white("\t- A = ") + cyan(convert_to_hex(A))
    
	print white("[*] Decrypting A and extracting values...")
	select_card(tag_uid)
	card_key = read_blocks(9, 10, key, tag_uid)
	card_key = "".join(map(chr, card_key))

	cipher = AES.new(card_key, AES.MODE_CBC, binascii.hexlify(card_key)[16:])
	decrypted_A = cipher.decrypt("".join(map(chr, A)))

	key_received = binascii.hexlify(decrypted_A[0:16])
	new_tid = decrypted_A[16:32]
	new_key = decrypted_A[32:48]

	print white("\t- Extracted key =\t") + cyan(key_received)
	print white("\t- Extracted new TID =\t") + cyan(binascii.hexlify(new_tid))
	print white("\t- Extracted new key =\t") + cyan(binascii.hexlify(new_key))

    
	print white("[*] Checking if extracted key matches stored key...")
	if binascii.hexlify(card_key) == key_received:
		print green("----- Key matched! -----")
	else:
		print red("----- Key mismatched! -----\nTerminating session...")
		continue


	print white("[*] Writing new TID and key to memory...")
	select_card(tag_uid)
	write_data(8, key, tag_uid, new_tid)
	print green("[*] TID value updated.")

	write_data(9, key, tag_uid, new_key)
	print green("[*] Key value updated.")

	print white("[*] Calculating value of B...")
	cipher = AES.new(new_key, AES.MODE_CBC, binascii.hexlify(new_key)[16:])
	B = cipher.encrypt(new_key)
	print white("\t- B = ") + cyan(binascii.hexlify(B))
	write_data(10, key, tag_uid, B)

	MIFAREReader.MFRC522_StopCrypto1()


