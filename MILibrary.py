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
    """ Authenticate with a tag to read/write a block.

    Arguments: 
    blockNum -- the block you need to access.
    key -- the key to be used to authenticate with the tag.
    uid -- the UID of the tag to be authenticated with.
    """
    i = 0
    status = MIFAREReader.MFRC522_Auth(MIFAREReader.PICC_AUTHENT1A, blockNum, key, uid)
    while status != MIFAREReader.MI_OK and i < 10:
        status = MIFAREReader.MFRC522_Auth(MIFAREReader.PICC_AUTHENT1A, blockNum, key, uid)
        i+= 1
        if i == 10:
            select_card(uid)
            i = 0

def read_from_block(blockNum, key, uid):
    """ Read a specific block from the tag's memory. 

    NOTE: that authentication is automatically handled inside the method.

    Arguments:
    blockNum -- the block you need to read.
    key -- the key to be used to authenticate with the tag.
    uid -- the UID of the tag you need to read
    """
    authenticate_card(blockNum, key, uid)
    backData = MIFAREReader.MFRC522_Read(blockNum)
    return backData

def read_blocks(start_block, end_block, key, uid):
    """ Read a number of blocks and return them as an array of integers.

    Arguments:
    start_block -- the block you want to start reading at.
    end_block -- the block you want to stop the reading at (this block is NOT read).
    key -- the key to be used to authenticate with the tag.
    uid -- the UID of the tag you need to read.
    """
    data = []
    blockNum = start_block
    while blockNum < end_block:
        blockData = read_from_block(blockNum, key, uid)
        if blockData != None:
            data.extend(blockData)
            blockNum+=1
    return data


def select_card(wanted_uid):
    """ Select a card to be able to authenticate and do operations on.

    Arguments:
    wanted_uid -- the UID of the card you want to select.
    """
    MIFAREReader.MFRC522_StopCrypto1()
    uid = []  
    while uid != wanted_uid:
        (status,TagType) = MIFAREReader.MFRC522_Request(MIFAREReader.PICC_REQIDL)
        (status,uid) = MIFAREReader.MFRC522_Anticoll()
    MIFAREReader.MFRC522_SelectTag(wanted_uid)
    return (status, uid)


def write_to_block(blockNum, key, uid, data):
    """ Write to a specific block from the tag's memory.

    NOTE: that authentication is automatically handled inside the method.

    Arguments:
    blockNum -- the block you need to write to.
    key -- the key to be used to authenticate with the tag.
    uid -- the UID of the tag you need to write to.
    data -- the data you need written on the block as a string of bytes.
    """
    authenticate_card(blockNum, key, uid)
    data = [ord(x) for x in data]
    return (True if MIFAREReader.MFRC522_Write(blockNum, data) else False)


def write_data(start_block, key, uid, data):
    """ Write a number of blocks to the tag's memory.

    WARNING: make sure you do not overwrite sectors containing
    authentication keys when using this method.

    Arguments:
    start_block -- the block you want to start the writing at.
    key -- the key to be used to authenticate with the tag.
    uid -- the UID of the tag you need to write to.
    data -- the data to be written to the tag.
    """
    i = 0
    number_of_blocks = ceil(len(data)/16)
    while i < number_of_blocks:
        if write_to_block(start_block+i, key, uid, data[i*16:16+i*16]):
            i+=1

def convert_to_hex(byteData):
    """ Takes an array of integers and returns it as a string containing
    hexadecimal representation of the values.

    Arguments:
    byteData -- the integer array to convert to hex.
    """
    return binascii.hexlify("".join(map(chr, byteData)))

MIFAREReader = MFRC522.MFRC522()
