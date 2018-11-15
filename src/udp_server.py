# !/usr/bin/python
# -*-coding:utf-8-*-
# bugreport:lyq19961011@gmail.com
import sys
import socket
import struct
import hashlib
import threading
import time


def check_md5(md5, md5_recv):
    for i in range(16):
        if md5[i] != md5_recv[i]:
            print "MD5校验失败..."
            return False
    return True


def encrypt(packet):
    return_packet = []
    for i in packet:
        i = (i & 0x80) >> 6 | (i & 0x40) >> 4 | (i & 0x20) >> 2 | (i & 0x10) << 2 | (
            i & 0x08) << 2 | (i & 0x04) << 2 | (i & 0x02) >> 1 | (i & 0x01) << 7
        return_packet.append(i)
    return return_packet


def decrypt(packet):
    return_packet = []
    for i in packet:
        i = (i & 0x80) >> 7 | (i & 0x40) >> 2 | (i & 0x20) >> 2 | (i & 0x10) >> 2 | (
            i & 0x08) << 2 | (i & 0x04) << 4 | (i & 0x02) << 6 | (i & 0x01) << 1
        return_packet.append(i)
    return return_packet


def generate_ip_ret():
    packet = []
    packet.append(0x0D)
    pack_len = 2 + 16 + 2 + 4
    packet.append(pack_len)
    packet.extend([i * 0 for i in range(16)])
    packet.append(0x0c)
    packet.append(0x06)
    packet.append(127)
    packet.append(0)
    packet.append(0)
    packet.append(1)
    md5 = hashlib.md5(b''.join([struct.pack('B', i) for i in packet])).digest()
    packet[2:18] = struct.unpack('16B', md5)
    packet = encrypt(packet)
    packet = b''.join([struct.pack('B', i) for i in packet])
    return packet


def generate_ser_ret():
    packet = []
    packet.append(0x08)
    service = [ord("l"), ord("y"), ord("q"), ord("6"), ord("6"), ord("6")]
    pack_len = 2 + 16 + 2 + len(service)
    packet.append(pack_len)
    packet.extend([i * 0 for i in range(16)])
    packet.append(0xa)
    packet.append(len(service) + 2)
    packet.extend(service)
    md5 = hashlib.md5(b''.join([struct.pack('B', i) for i in packet])).digest()
    packet[2:18] = struct.unpack('16B', md5)
    packet = encrypt(packet)
    packet = b''.join([struct.pack('B', i) for i in packet])
    return packet


def generate_login_ret():
    session = [ord("1"), ord("2"), ord("1"), ord("2"), ord("1"), ord("2"), ord("1"), ord(
        "2"), ord("1"), ord("2"), ord("1"), ord("2"), ord("1"), ord("2"), ord("1"), ord("2")]
    message = u"Hello,这个程序用于第三方蝴蝶的测试稳定性!!".encode('gbk')
    packet = []
    packet.append(0x02)
    pack_len = 2 + 16 + 2 + len(session) + 2 + 1 + 2 + len(message)
    packet.append(pack_len)
    packet.extend([i * 0 for i in range(16)])
    packet.append(0x03)
    packet.append(0x03)
    packet.append(0x01)  # 是否登录成功
    packet.append(0x08)
    packet.append(len(session))
    packet.extend(session)
    packet.append(0x0b)
    packet.append(len(message) + 2)
    packet.extend(ord(message[i]) for i in range(len(message)))
    md5 = hashlib.md5(b''.join([struct.pack('B', i) for i in packet])).digest()
    packet[2:18] = struct.unpack('16B', md5)
    packet = encrypt(packet)
    packet = b''.join([struct.pack('B', i) for i in packet])
    return packet


def generate_brea_ret():
    session = [ord("1"), ord("2"), ord("1"), ord("2"), ord("1"), ord("2"), ord("1"), ord(
        "2"), ord("1"), ord("2"), ord("1"), ord("2"), ord("1"), ord("2"), ord("1"), ord("2")]
    packet = []
    packet.append(0x04)
    pack_len = 2 + 16 + 2 + len(session) + 2 + 1
    packet.append(pack_len)
    packet.extend([i * 0 for i in range(16)])
    packet.append(0x03)
    packet.append(0x02)
    packet.append(0x01)  # 是否呼吸成功
    packet.append(0x08)
    packet.append(len(session)+2)
    packet.extend(session)
    md5 = hashlib.md5(b''.join([struct.pack('B', i) for i in packet])).digest()
    packet[2:18] = struct.unpack('16B', md5)
    packet = encrypt(packet)
    packet = b''.join([struct.pack('B', i) for i in packet])
    return packet


def udp_recv(s):
    while not killall:
        try:
            data, addr = s.recvfrom(1024)
        except socket.timeout:
            continue
        print "接收到来自此IP的连接: %s:%s" % addr
        data = [i for i in struct.unpack('B' * len(data), data)]  # 字符串转数组
        data = decrypt(data)
        if data[0] == 0x07:
            print "搜索服务类型",
            md5_recv = data[2:18]
            data[2:18] = [i*0 for i in range(16)]
            md5 = hashlib.md5(b''.join([struct.pack('B', i)
                                        for i in data])).digest()
            md5 = struct.unpack('16B', md5)
            print "检查MD5:",
            if check_md5(md5, md5_recv):
                print "MD5校验通过",
            print "\n包长:",
            print data[1],
            print "实际长度:",
            print len(data),
            print data,
            print "\nMAC地址:",
            for i in data[27:33]:
                print hex(i),
            print "\n"
            raw = generate_ser_ret()
            s.sendto(raw, addr)

        if data[0] == 0x01:
            print "上线",
            md5_recv = data[2:18]
            data[2:18] = [i*0 for i in range(16)]
            md5 = hashlib.md5(b''.join([struct.pack('B', i)
                                        for i in data])).digest()
            md5 = struct.unpack('16B', md5)
            print "检查MD5:",
            if check_md5(md5, md5_recv):
                print "MD5校验通过",
            data[0] = 0
            print "\n包长:",
            print data[1],
            print "实际长度:",
            print len(data),
            print data,
            macindex = data.index(0x07)
            print "\nMAC地址:",
            for i in data[macindex+2:macindex+2+6]:
                print hex(i),
            data[macindex+2:macindex+2+6] = [i *
                                             0 for i in range(macindex+2+6 - macindex-2)]

            userindex = data.index(0x01)
            print "\n用户名:",
            for i in data[userindex+2: userindex + 2 + data[userindex+1] - 2]:
                print chr(i),
            data[userindex: userindex + 2 + data[userindex+1] - 2] = [i *
                                                                      0 for i in range(userindex + 2 + data[userindex+1] - 2 - userindex-2)]

            passindex = data.index(0x02)
            print "\n密码:",
            for i in data[passindex+2: passindex + 2 + data[passindex+1] - 2]:
                print chr(i),
            data[passindex: passindex + 2 + data[passindex+1] - 2] = [i *
                                                                      0 for i in range(passindex + 2 + data[passindex+1] - 2 - passindex-2)]

            ipindex = data.index(0x09)
            print "\nIP地址:",
            for i in data[ipindex + 2: ipindex + 2 + data[ipindex + 1] - 2]:
                print chr(i),
            data[ipindex: ipindex + 2 + data[ipindex + 1] - 2] = [i *
                                                                  0 for i in range(ipindex + 2 + data[ipindex + 1] - 2 - ipindex - 2)]

            serindex = data.index(0x0a)
            print "\nService:",
            for i in data[serindex + 2: serindex + 2 + data[serindex + 1] - 2]:
                print chr(i),
            data[serindex: serindex + 2 + data[serindex + 1] - 2] = [i *
                                                                     0 for i in range(serindex + 2 + data[serindex + 1] - 2 - serindex - 2)]

            dhcpindex = data.index(0xe)
            print "\nDHCP:",
            print data[dhcpindex + 2],
            data[dhcpindex: dhcpindex + 2] = [0, 0, 0]

            print "\nVersion:",
            versionindex = data.index(0x1f)
            for i in data[versionindex + 2: versionindex + 2 + data[versionindex + 1] - 2]:
                print chr(i),
            data[versionindex:versionindex + 2 + data[versionindex + 1] - 2] = [i *
                                                                                0 for i in range(versionindex + 2 + data[versionindex + 1] - 2 - versionindex - 2)]
            print "\n"
            raw = generate_login_ret()
            s.sendto(raw, addr)

        elif data[0] == 0x03:
            print "呼吸",
            md5_recv = data[2:18]
            data[2:18] = [i * 0 for i in range(16)]
            md5 = hashlib.md5(b''.join([struct.pack('B', i)
                                        for i in data])).digest()
            md5 = struct.unpack('16B', md5)
            print "检查MD5:",
            if check_md5(md5, md5_recv):
                print "MD5校验通过",
            data[0] = 0
            print "\n包长:",
            print data[1],
            print "实际长度:",
            print len(data),
            print "应有的长度 session(16) + 88:",
            print 16 + 88,

            sessionindex = data.index(0x08)
            print "\nSession:",
            for i in data[sessionindex + 2: sessionindex + 2 + data[sessionindex + 1] - 2]:
                print chr(i),

            print "\n"
            raw = generate_brea_ret()
            s.sendto(raw, addr)

        else:
            print "其他暂不处理"
    print "thread-0 exit\n"


def udp_recv1(s1):
    while not killall:
        try:
            data, addr = s1.recvfrom(1024)
        except socket.timeout:
            continue
        print "接收到来自此IP的连接: %s:%s" % addr
        data = [i for i in struct.unpack('B' * len(data), data)]  # 字符串转数组
        data = decrypt(data)
        if data[0] == 0x0c:
            print "搜索服务器IP"
            md5_recv = data[2:18]
            data[2:18] = [i*0 for i in range(16)]
            md5 = hashlib.md5(b''.join([struct.pack('B', i)
                                        for i in data])).digest()
            md5 = struct.unpack('16B', md5)
            print "检查MD5:",
            if check_md5(md5, md5_recv):
                print "MD5校验通过",
            print "\n包长:",
            print data[1],
            print "实际长度:",
            print len(data),
            print data,
            ipindex = data.index(0x09)
            print "IP地址:",
            for i in data[ipindex+2:ipindex+2+16]:
                print chr(i),
            print "\nMAC地址:",
            for i in data[45:51]:
                print hex(i),
            print "\n"
            raw = generate_ip_ret()
            s1.sendto(raw, addr)
    print "thread-1 exit\n"


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 3848))
    s.settimeout(1.0)

    s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s1.bind(("127.0.0.1", 3850))
    s1.settimeout(1.0)

    global killall
    t = threading.Thread(target=udp_recv, args=(s, ))
    t1 = threading.Thread(target=udp_recv1, args=(s1, ))

    t.start()
    t1.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        killall = True
        time.sleep(2)
        s.close()
        s1.close()


if __name__ == '__main__':
    killall = False
    main()
