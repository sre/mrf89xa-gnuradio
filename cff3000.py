#!/usr/bin/env python3
import sys, struct, socket, time
from abus_cfa3000_encrypt import message_encrypt
import binascii

def swap_bits(byte):
    revlsb = (byte & 0xf0) >> 4 | (byte & 0xff) << 4
    revlsb = (revlsb & 0xcc) >> 2 | (revlsb & 0x33) << 2
    return (revlsb & 0xaa) >> 1 | (revlsb & 0x55) << 1

def lfsr_ibm_generator(seed = 0x1ff, amount=20):
    for x in range(0, amount):
        yield seed & 0xff
        for i in range(8):
            bit = (seed >> 5) ^ (seed >> 0) & 1
            outword = ((seed >> 1) & 0xFF) | (bit << 8)
            seed = outword & 0x1FF

def lfsr_ccitt_generator(seed = 0x1ff, amount=20):
    return [swap_bits(byte) for byte in lfsr_ibm_generator(seed, amount)]

pn9data = lfsr_ccitt_generator(amount=16+2)

def crc16_ccitt(crc, data):
    msb = crc >> 8
    lsb = crc & 255
    for c in data:
        x = c ^ msb
        x ^= (x >> 4)
        msb = (lsb ^ (x >> 3) ^ (x << 4)) & 0xff
        lsb = (x ^ (x << 5)) & 0xff
    crc = (msb << 8) + lsb

    # MRF89XA uses negated CRC
    return ~crc & 0xffff

def encode(message):
    start = (0xff, 0xff, 0xff, 0xff)
    end = (0xff, 0xff, 0xff, 0xff)

    preamble = (0xaa, 0xaa)
    syncword = (0xf0, 0x0f, 0x12, 0xed)
    crc16 = crc16_ccitt(0x1D0F, message)
    crc = (crc16 >> 8 & 0xff, crc16 & 0xff)

    scrambled_payload = tuple([pair[0] ^ pair[1] for pair in zip(message, pn9data)])
    scrambled_crc = (crc[0] ^ pn9data[16]) , (crc[1] ^ pn9data[17])

    complete_msg = (preamble + syncword + scrambled_payload + scrambled_crc)
    return struct.pack('B'*24, *complete_msg[0:24])

def decode(raw):
    payload = raw[0:16]
    crc = raw[16:18]

    plainpayload = [pair[0] ^ pair[1] for pair in zip(payload, pn9data)]
    plaincrc = ((crc[0] ^ pn9data[16]) << 8) | (crc[1] ^ pn9data[17])

    crcok = crc16_ccitt(0x1D0F, plainpayload) == plaincrc

    return (plainpayload, plaincrc, crcok)

def gen_request_msg(address, command, number):
    return (0xab, address[0], address[1], address[2], address[3], address[4], address[5], command, number, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

def gen_crypto_msg(challenge):
    return message_encrypt(challenge)

def invert_and_swap(a):
    return ((~a & 0x0f) << 4) | ((~a & 0xf0) >> 4)

def check_inverted_swapped_address(addr, msg):
    for i in range(0,6):
        tmp = invert_and_swap(msg[i+1])
        if tmp != addr[i]:
            return False
    return True

def hexstr(data, separator):
    result = binascii.hexlify(bytes(data)).decode('utf-8')
    result = separator.join(result[i:i+2] for i in range(0, len(result), 2))
    return result

def format_addr(addr):
    return hexstr(addr, ':')

def format_pkg(pkg):
    return hexstr(pkg, ' ')

def str2cmd(cmd):
    if cmd == "status" or cmd == "status-door1":
        return 0x01
    elif cmd == "lock" or cmd == "lock-door1":
        return 0x11
    elif cmd == "unlock" or cmd == "unlock-door1":
        return 0x21
    elif cmd == "status-door2":
        return 0x02
    elif cmd == "lock-door2":
        return 0x12
    elif cmd == "unlock-door2":
        return 0x22
    else:
        raise RuntimeError("Invalid command: \"{}\"".format(cmd))

def str2mac(mac):
    mac = mac.replace(':', '')
    if len(mac) != 2*6:
        raise RuntimeError("Invalid MAC length: \"{}\"".format(mac))
    return binascii.unhexlify(mac)

def cff3000(address, command):
    print("Remote Control Address: {}".format(format_addr(address)))
    print("Command Byte: {:02x}".format(command))
    print("")

    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.settimeout(2.0)
    rx.bind(("127.0.0.1", 7000))

    # send initial request
    print("Sending control requests...")
    for pkgnum in range(99, -1, -1):
        pkg = gen_request_msg(address, command, pkgnum)
        if pkgnum == 0:
            print("\t{}".format(format_pkg(pkg)))
        tx.sendto(encode(pkg), ("127.0.0.1", 7001))

    # receive challenge
    print("Receiving challenge...")
    challenge = []
    while len(challenge) == 0:
        (payload, plaincrc, crcok) = decode(rx.recv(18))
        #print("pkg: ", payload, plaincrc, crcok)
        if not crcok:
            continue
        # check if this is a challenge
        if payload[0] != 0xab:
            continue
        if not check_inverted_swapped_address(address, payload):
            continue
        if not payload[7] == command:
            continue
        challenge = payload
        print("\t{}".format(format_pkg(challenge)))

    if command & 0xf0 != 0x00:
        # wait until CFA3000 is ready to receive
        time.sleep(0.2)

        print("Sending encrypted response...")
        pkg = gen_crypto_msg(challenge)
        for pkgnum in range(0, 20):
            if pkgnum == 0:
                print("\t{}".format(format_pkg(pkg)))
            tx.sendto(encode(pkg), ("127.0.0.1", 7001))
    else:
        if challenge[14] == 0x00:
            print("CFA3000 door status: unknown")
        elif challenge[14] == 0x02:
            print("CFA3000 door status: unlocked")
        elif challenge[14] == 0x04:
            print("CFA3000 door status: locked")
        else:
            print("CFA3000 reported status unsupported by this script")

def cff3000help():
    print("{} <MAC> <CMD>".format(sys.argv[0]))
    print("MAC e.g. \"ba:ad:c0:de:da:e5\" or \"ba:aa:ad:c0:00:de\"")
    print("Supported commands:")
    print("\tstatus-door1")
    print("\tlock-door1")
    print("\tunlock-door1")
    print("\tstatus-door2")
    print("\tlock-door2")
    print("\tunlock-door2")

if __name__ == "__main__":
    if len(sys.argv) != 3 or "--help" in sys.argv:
        cff3000help()
        sys.exit(1)
    mac = None
    cmd = None
    try:
        mac = str2mac(sys.argv[1])
        cmd = str2cmd(sys.argv[2])
    except RuntimeError as err:
        print("Invalid parameter: {}".format(err))
        sys.exit(1)
    except binascii.Error as err:
        print("Invalid MAC address: {}".format(err))
        sys.exit(1)
    try:
        cff3000(mac, cmd)
    except socket.timeout:
        print("\tTimeout - Did not receive CFA3000 challenge!")
        sys.exit(1)
