from pwn import *

elf = ELF('./temp/babyof', checksec=False)

for addr in elf.search(b'sh\x00', executable=True):
    print(f'找到 sh: {hex(addr)}')

for addr in elf.search(b'sh\x00'):
    print(hex(addr))

# system('$0')=system('sh')=system('/bin/sh'),找到任意一个即可
for s in [b'/bin/sh\x00', b'sh\x00', b'$0\x00']:
    for addr in elf.search(s):
        print(f'{s!r} -> {hex(addr)}')