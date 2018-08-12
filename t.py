import os
import tun
fd = tun.open_tap("tap1")

os.system("ip link set tap1 up")
os.system("ip address add 192.169.1.11/24 dev tap1")

while True:
    pack = os.read(fd, 1500)
    print("recv pack %d" % len(pack))
