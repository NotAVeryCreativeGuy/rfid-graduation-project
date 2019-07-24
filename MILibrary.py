import binascii
import MFRC522
import signal
from math import ceil
from termcolor import colored

def white(string):
    return colored(string, "white")

def green(string):
    return colored(string, "green")

def cyan(string):
    return colored(string, "cyan")

def red(string):
    return colored(string, "red")


def authenticate_card(blockNum, key, uid):
    i = 0
    status = MIFAREReader.MFRC522_Auth(MIFAREReader.PICC_AUTHENT1A, blockNum, key, uid)
    while status != MIFAREReader.MI_OK and i < 10:
        status = MIFAREReader.MFRC522_Auth(MIFAREReader.PICC_AUTHENT1A, blockNum, key, uid)
        i+= 1
        if i == 10:
            select_card(uid)
            i = 0

def read_from_block(blockNum, key, uid):
    authenticate_card(blockNum, key, uid)
    backData = MIFAREReader.MFRC522_Read(blockNum)
    return backData

def read_blocks(start_block, end_block, key, uid):
    data = []
    blockNum = start_block
    while blockNum < end_block:
        blockData = read_from_block(blockNum, key, uid)
        if blockData != None:
            data.extend(blockData)
            blockNum+=1
    return data


def select_card(wanted_uid):
    MIFAREReader.MFRC522_StopCrypto1()
    uid = []  
    while uid != wanted_uid:
        (status,TagType) = MIFAREReader.MFRC522_Request(MIFAREReader.PICC_REQIDL)
        (status,uid) = MIFAREReader.MFRC522_Anticoll()
    MIFAREReader.MFRC522_SelectTag(wanted_uid)
    return (status, uid)


def write_to_block(blockNum, key, uid, data):
    authenticate_card(blockNum, key, uid)
    data = [ord(x) for x in data]
    return (True if MIFAREReader.MFRC522_Write(blockNum, data) else False)


def write_data(start_block, key, uid, data):
	i = 0
	number_of_blocks = ceil(len(data)/16)
	while i < number_of_blocks:
		if write_to_block(start_block+i, key, uid, data[i*16:16+i*16]):
			i+=1

def convert_to_hex(byteData):
	return binascii.hexlify("".join(map(chr, byteData)))

MIFAREReader = MFRC522.MFRC522()
