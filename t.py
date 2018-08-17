import os
import struct
import logging

import tun

class PK:

    def __init__(self, b):
        self.data = memoryview(b)
        self.len = len(b)

    def eth(self):
        return eth_hdr.unpack(self.data[:eth_hdr.size])

    def arpp(self):
        return arp.unpack(self.data[eth_hdr.size:eth_hdr.size+arp.size])

    def ip(self):
        return IP.parse(self.data[eth_hdr.size:])

    def icmp(self):
        return ICMP.parse(self.ip().data)



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


def ip2s(ip):
    return ".".join(str(b) for b in ip.to_bytes(4, "big"))

class IP:

    hdr = struct.Struct(">BBHHHBBHII")
    IP_P_ICMP = 1
    IP_P_TCP = 6
    IP_P_UDP = 17
    IP_P_RAW = 255

    ID = [0]
  
    def __init__(self):
        self.ver = 4
        self.hlen = 5
        self.tos = 0
        self.len = 0
        self.id = self.ID[0]; self.ID[0] += 1
        self.fragoff = 0
        self.ttl = 64
        self.pro = 0
        self.cksum = 0
        self.src = 0
        self.dst = 0
        self.data = b''

    @classmethod
    def parse(cls, pk):
        self = cls()
        self.ver = pk[0] >> 4
        self.hlen = pk[0] & 0x0f
        if self.ver != 4:
            raise Exception("only handle IPv4 %s (%d %d)", bin(pk[0]),self.hlen, self.ver)
        self.tos, self.len, self.id, self.fragoff, \
        self.ttl, self.pro, self.cksum, self.src, \
        self.dst = cls.hdr.unpack(pk[:cls.hdr.size])[1:]
        self.data = pk[cls.hdr.size:]
        return self

    def pack(self):
        hdr = self.hdr.pack(self.ver<<4|self.hlen, self.tos, self.len, self.id, self.fragoff,
                self.ttl, self.pro, self.cksum, self.src, self.dst)
        return hdr + self.data


    def __str__(self):
        temp = """\
------------------------------------------
| %d  | %d  |         |       %d         |
------------------------------------------
|                     |                  |
------------------------------------------
|    %d     |    %d   |                  |
------------------------------------------
|                   %s              |
------------------------------------------
|                   %s              |
------------------------------------------
"""
        return temp % (self.ver, self.hlen, self.len, self.ttl, self.pro,
            ip2s(self.src), ip2s(self.dst))


class ICMP:

    hdl = struct.Struct(">BBH")
    ping = struct.Struct(">HH")
  
    ICMP_T_ECHORLY = 0
    ICMP_T_ECHOREQ = 8

    def __init__(self):
        self.type = 0
        self.code = 0
        self.chksum = 0
        self.id = 0
        self.seq = 0
        self.data = 0

    @classmethod
    def parse(cls, pk):
        self = cls()
        hs = cls.hdl.size
        self.type, self.code, self.cksum = cls.hdl.unpack(pk[:hs])
        if self.type != cls.ICMP_T_ECHOREQ:
            raise Exception("Only support echo request. %s", self.type)
        self.id, self.seq = cls.ping.unpack(pk[hs:hs+cls.ping.size])
        self.data = pk[hs+cls.ping.size:]
        return self

    def reply_pk(self):
        pk = self.hdl.pack(self.ICMP_T_ECHORLY, 0, 0)
        pk += self.ping.pack(self.id, self.seq)
        pk += bytes(self.data)
        return pk

    def __str__(self):
        return "id:%d  seq:%d" % (self.id, self.seq)
      

fd = tun.open_tap("tap1")
os.system("ip link set tap1 up")
os.system("ip address add 192.168.1.11/24 dev tap1")

my_netdev = {
    "ipaddr": int.from_bytes(bytes([192, 168, 1, 2]), "big"),
    "hwaddr": b"\x00\x34\x45\x67\x89\xab",
}


def pack_recv():
    pk = PK(os.read(fd, 1500))
    try:
        dmac, smac, eth_type = pk.eth()
        print("dmac:%s smac:%s type:%X(%s) len:%d" % (
            pmac(dmac), pmac(smac),
            eth_type,
            eth_p_map.get(eth_type),
            pk.len))
        _type = eth_p_map.get(eth_type)
        if _type == "ARP":
            arp_in(pk)
        elif _type == "IP":
            ip_in(pk)
        else:
            "no support packet, drop"
    except struct.error as e:
        print("unpack eth_hdr error %s" % e)


def arp_in(pk):
    print("process arp")
    try:
        hwtype, protype, _, _, opcode, smac, sip, dmac, dip = pk.arpp()
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

    print("update arp_cache", ip2s(sip), pmac(smac))
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
    try:
        ip = pk.ip()
    except Exception as e:
        print("parse ip packet error %s" % e)
        return
    if ip.dst != my_netdev["ipaddr"]:
        print("ip not for us %s. drop" % ip2s(ip.dst))
        return
    if ip.pro == IP.IP_P_ICMP:
        icmp_in(pk)


def icmp_in(pk):
    print("process icmp")
    ip = pk.ip()
    icmp = pk.icmp()
    print(icmp)
    data = icmp.reply_pk()
    dst = ip.src
    ip_out(ip, data, dst)


def ip_out(orig_ip, data, dst):
    print("send ip out")
    ip = orig_ip
    ip.src = my_netdev["ipaddr"]
    ip.dst = dst
    ip.data = data
    dmac = arp_cache.get(ip.dst)
    if not dmac:
        print("can find dmac", ip.dst, arp_cache)
        return
    netdev_tx(ip.pack(), ETH_P_IP, dmac)


if __name__ ==  '__main__':

    import asyncio
    loop = asyncio.get_event_loop()
    loop.add_reader(fd, pack_recv)

    try:
        loop.run_forever()
    finally:
        loop.close()
