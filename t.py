import os
import struct

import tun


eth_hdr = struct.Struct(">6s6sH")

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_RARP = 0x8035
eth_p_map = {
    ETH_P_IP: "IP",
    ETH_P_ARP: "ARP",
    ETH_P_RARP: "RARP",
}

def pmac(mac):
    return ":".join(["%x" % b for b in mac])


arp = struct.Struct(">HHBBH6sI6sI")

ARP_HED_ETHER = 1

ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2
arp_cache = {} # ip --> mac



fd = tun.open_tap("tap1")
os.system("ip link set tap1 up")
os.system("ip address add 192.168.1.11/24 dev tap1")

my_netdev = {
    "ipaddr": int.from_bytes(bytes([192, 168, 1, 1]), "big"),
    "hwaddr": b"\x00\x34\x45\x67\x89\xab",
}


def pack_recv():
    pack = os.read(fd, 1500)
    try:
        dmac, smac, eth_type = eth_hdr.unpack(pack[:eth_hdr.size])
        print("dmac:%s smac:%s type:%X(%s) len:%d" % (
            pmac(dmac), pmac(smac),
            eth_type,
            eth_p_map.get(eth_type),
            len(pack)))
        _type = eth_p_map.get(eth_type)
        if _type == "ARP":
            arp_in(pack[eth_hdr.size:])
        elif _type == "IP":
            ip_in(pack[eth_hdr.size:])
        else:
            print("no support packet, drop")
    except struct.error as e:
        print("unpack eth_hdr error %s" % e)
    return pack[eth_hdr.size:]


def arp_in(pk):
    print("process arp")
    try:
        hwtype, protype, _, _, opcode, smac, sip, dmac, dip = arp.unpack(pk)
    except struct.error as e:
        print("unpack apr error %s. drop" % e)
        return

    if hwtype != ARP_HED_ETHER or protype != ETH_P_IP:
        print("unsupport l2/l3 protocol. drop")
        return

    if opcode != ARP_OP_REQUEST and opcode != ARP_OP_REPLY:
        print("unsupport arp operation %d. drop" % opcode)
        return

    if dip != my_netdev["ipaddr"]:
        print("arp not for us %s. drop", dip)
        return

    print("update arp_cache")
    arp_cache[sip] = smac

    if opcode == ARP_OP_REQUEST:
        pk = arp.pack(hwtype, protype, 6, 4, ARP_OP_REPLY,
                my_netdev["hwaddr"], my_netdev["ipaddr"],
                smac, sip)
        netdev_tx(pk, ETH_P_ARP, smac)


def netdev_tx(pk, proto, dmac):
    hdr = eth_hdr.pack(dmac, my_netdev["hwaddr"], proto)
    pk = hdr + pk
    size = len(pk)
    r = os.write(fd, pk)
    if r != size:
        print("netdev_tx write error %d != %d" % (r, size))


def ip_in(pk):
   print("process ip")


if __name__ ==  '__main__':

    import asyncio
    loop = asyncio.get_event_loop()
    loop.add_reader(fd, pack_recv)

    try:
        loop.run_forever()
    finally:
        loop.close()
