#!/usr/bin/python

import codecs

from struct import pack, unpack
from itertools import cycle
from Cryptodome.Cipher import AES, DES3

# Do a lot of prints?
DEBUG = False


def hexdecode(string):
    """Decode HEX string"""

    return codecs.decode(string, "hex")


def gen_subkeys(K, cipher):
    """Generate subkeys of cipher"""

    K0 = cipher.encrypt(hexdecode("00000000000000000000000000000000"))
    K0High = unpack(">Q", K0[:8])[0]
    K0Low = unpack(">Q", K0[8:])[0]
    if DEBUG:
        print("_(gen_subkeys) K0......:{}".format(":".join("%02X" % b for b in K0)))
        print("_(gen_subkeys) K0High..:{:X}".format(K0High))
        print("_(gen_subkeys) K0Low...:{:X}".format(K0Low))

    K1High = ((K0High << 1) | (K0Low >> 63)) & 0xFFFFFFFFFFFFFFFF
    K1Low = (K0Low << 1) & 0xFFFFFFFFFFFFFFFF

    if K0High >> 63:
        K1Low ^= 0x87

    K2High = ((K1High << 1) | (K1Low >> 63)) & 0xFFFFFFFFFFFFFFFF
    K2Low = ((K1Low << 1)) & 0xFFFFFFFFFFFFFFFF

    if K1High >> 63:
        K2Low ^= 0x87

    K1 = pack(">QQ", K1High, K1Low)
    K2 = pack(">QQ", K2High, K2Low)

    return K1, K2


def xor(data, key):
    """XOR function"""

    xored = "".join("{:02X}".format(x ^ y) for (x, y) in list(zip(data, cycle(key))))

    if DEBUG:
        print("_(xor) data..:{}".format(":".join("%02X" % b for b in data)))
        print("_(xor) key...:{}".format(":".join("%02X" % b for b in key)))
        print("_(xor) xored.:{}".format(xored))

    return xored


def cmac_div(key, UID, Sector_number):
    """CMAC diversification"""

    ## Init vector for AES (16 byte)
    _IV = hexdecode("00000000000000000000000000000000")
    ## AES in Cipher block Chaining mode,
    ## Init Vector = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    _key = hexdecode(key)
    cipher = AES.new(_key, AES.MODE_CBC, _IV)
    K1, K2 = gen_subkeys(key, cipher)

    if DEBUG:
        print("IV.........:{}".format(":".join("%02X" % b for b in _IV)))
        print("key........:{}".format(":".join("%02X" % b for b in _key)))
        print("K1.........:{}".format(":".join("%02X" % b for b in K1)))
        print("K2.........:{}".format(":".join("%02X" % b for b in K2)))

    xorkey = K1

    M = "01" + UID + Sector_number
    padding = "8000000000000000000000000000000000000000000000000000"
    if DEBUG:
        print("M(1).......:{}".format(M))

    # if padding needed:
    # pad message and change xorkey to K2
    if len(M) < 64:
        M = (M + padding)[:64]
        xorkey = K2

    if DEBUG:
        print("M(2).......:{}".format(M))

    if len(M) != 64:
        print("M != 32 byte!")
        exit()

    ## last 16 bytes of M
    xordata = hexdecode(M[-32:])

    ## xor xordata with K1 or K2
    _xoreddata = hexdecode(xor(xordata, xorkey))

    if DEBUG:
        print("xordata....:{}".format(":".join("%02X" % b for b in xordata)))
        print("xorkey.....:{}".format(":".join("%02X" % b for b in xorkey)))
        print("xoreddata..:{}".format(":".join("%02X" % b for b in _xoreddata)))

    ## replace last 16 bytes with xordata
    M = M[:-32] + "".join("%02X" % b for b in _xoreddata)

    if DEBUG:
        print("M(3).......:{}".format(M))

    ## reset cipher
    cipher = AES.new(hexdecode(key), AES.MODE_CBC, _IV)

    ## AES M and slice out the right piece
    aes_M = "".join("%02X" % b for b in cipher.encrypt(hexdecode(M)))
    _divkey = hexdecode(aes_M[-32:-20])

    if DEBUG:
        print("aes_M......:{}".format(aes_M))
        print("divkey.....:{}".format(":".join("%02X" % b for b in _divkey)))

    print("AES version")
    print("Masterkey........: {}".format(key.upper()))
    print("UID..............: {}".format(UID.upper()))
    print("Sector...........: {}".format(Sector_number.upper()))
    print("Subkey 1.........: {}".format("".join("%02X" % b for b in K1)))
    print("Subkey 2.........: {}".format("".join("%02X" % b for b in K2)))
    print("Message..........: {}".format(M.upper()))
    print("Diversified key..: {}".format("".join("%02X" % b for b in _divkey)))
    print("")

    return _divkey


def des3_div(key, UID, Sector_number, MIFkey):
    """DES3 diversification"""

    ## van sector naar trailerblock van sector
    trailerblock = 4 * int(Sector_number) + 3
    trailerblock = "{:02x}".format(trailerblock)

    M = MIFkey[:8]
    M += xor(hexdecode(MIFkey[8:10]), hexdecode(UID[:2]))
    M += xor(hexdecode(MIFkey[10:]), hexdecode(UID[2:4]))
    M += xor(hexdecode(trailerblock), hexdecode(UID[4:6]))
    M += UID[6:]

    if DEBUG:
        print("M(1).......:{}".format(M))

    cipher = DES3.new(hexdecode(key), DES3.MODE_ECB)
    # divkey = cipher.encrypt( hexdecode(M) ).encode( "hex" )[2:14]

    des3_M = "".join("%02X" % b for b in cipher.encrypt(hexdecode(M)))
    _divkey = hexdecode(des3_M[2:14])

    if DEBUG:
        print("des3_M.....:{}".format(des3_M))
        print("divkey.....:{}".format(":".join("%02X" % b for b in _divkey)))

    print("3DES version")
    print("Masterkey........: {}".format(key.upper()))
    print("UID..............: {}".format(UID.upper()))
    print("Sector...........: {}".format(Sector_number.upper()))
    print("Trailer Block....: {}".format(trailerblock.upper()))
    print("Mifare key.......: {}".format(MIFkey))
    print("Message..........: {}".format(M.upper()))
    print("Diversified key..: {}".format("".join("%02X" % b for b in _divkey)))
    print("")

    return _divkey


if __name__ == "__main__":

    # Test data from documentation
    masterkey = "00112233445566778899aabbccddeeff"
    # Only needed for 3DES version(MF RC171)
    MIFkey = "A0A1A2A3A4A5"

    # 4-bytes UID
    UID = "F4EA548E"

    Sector_number = "05"
    # CMAC base key diversification (4-byte UID)
    cmac_div(masterkey, UID, Sector_number)

    Sector_number = "01"
    # 3DES diversification MF RC171
    des3_div(masterkey, UID, Sector_number, MIFkey)

    # 7-byte UID
    UID = "04793D21801D80"

    Sector_number = "05"
    # CMAC base key diversification (7-byte UID)
    cmac_div(masterkey, UID, Sector_number)
