#!/usr/bin/env python3
"""Execute emitted 8051 instructions with a simulated ASIC and HTTP ABI.

This is a focused instruction interpreter, not a switch/boot/interrupt emulator.
The original memory-copy helpers execute directly from the stock image. HTTP,
strcmp, and bank-switch trampolines are modeled at their reviewed ABI boundaries.
"""
import random
import unittest
from pathlib import Path
from build_mac_patch import build, checksums, ROOT, SLOT, STATUS, WORDS, LINE
from mcs51 import offset

STOCK=(ROOT / 'original/TL-SG108Ev5.0_en_1.0.0_[20191021-rel.53360]_up.bin').read_bytes()
IMAGE, INFO=build(STOCK)

class CPU:
    def __init__(self,path='/MacTable00.dat',bus_stuck=False,table_stuck=False,fail_at=None,writer_fail=False):
        self.code=IMAGE[20:];self.mem=bytearray(256);self.x=bytearray(65536)
        self.mem[0xa8]=0x82;self.mem[0x81]=0x60;self.pc=0;self.bank=6;self.frames=[]
        self.body=bytearray();self.headers=[];self.http_status=None;self.flushed=False;self.fallback=False
        self.bus_stuck=bus_stuck;self.table_stuck=table_stuck;self.fail_at=fail_at;self.writer_fail=writer_fail
        self.writes=[];self.slots=[];self.current_slot=0;self.has_command=False;self.count=0;self.max_frames=0
        self.x[0x2ccd:0x2cd0]=bytes([1,0x70,0]);p=path.encode()+b'\0';self.x[0x7000:0x7000+len(p)]=p
        self.client=bytes([1,0x71,0]);self.mem[3],self.mem[2],self.mem[1]=self.client
        self.x[0x2cca:0x2ccd]=self.client
        self.rng=random.Random(104)
    @property
    def acc(self):return self.mem[0xe0]
    @acc.setter
    def acc(self,n):self.mem[0xe0]=n&255
    @property
    def dptr(self):return self.mem[0x83]*256+self.mem[0x82]
    @dptr.setter
    def dptr(self,n):self.mem[0x83]=(n>>8)&255;self.mem[0x82]=n&255
    @property
    def carry(self):return self.mem[0xd0]>>7
    @carry.setter
    def carry(self,n):self.mem[0xd0]=(self.mem[0xd0]&127)|(bool(n)<<7)
    def ptr_read(self,kind,addr,n=None):
        if kind==1:data=self.x;start=addr
        elif kind>=0x84:data=self.code;start=offset(kind-0x81,addr)
        else:raise AssertionError(('unsupported pointer',kind,addr))
        if n is None:return bytes(data[start:data.index(0,start)])
        return bytes(data[start:start+n])
    def clobber(self):
        for r in list(range(8))+[0x82,0x83,0xe0,0xf0]:self.mem[r]=self.rng.randrange(256)
        self.carry=self.rng.randrange(2)
    def hook(self,target):
        if target==0x2baf:
            p=self.ptr_read(self.mem[3],self.mem[2]*256+self.mem[1]);q=self.ptr_read(self.mem[5],self.mem[4]*256+self.mem[0])
            self.clobber();self.mem[7]=0 if p==q else 1;return True
        if target==0x3806:
            assert bytes([self.mem[3],self.mem[2],self.mem[1]])==self.client
            self.fallback=True;self.clobber();self.mem[7]=0;return True
        if target not in (0x1955,0x1961,0x1967,0x196d,0x195b):return False
        assert bytes([self.mem[3],self.mem[2],self.mem[1]])==self.client
        if target==0x1955:self.body.clear()
        if target==0x1961:self.http_status=int.from_bytes(self.mem[4:8],'big')
        if target==0x1967:
            kind,hi,lo=self.x[0x2e37:0x2e3a];self.headers.append(self.ptr_read(kind,hi*256+lo))
        if target==0x196d:
            kind,hi,lo=self.x[0x2e68:0x2e6b];n=int.from_bytes(self.x[0x2e6b:0x2e6f],'big')
            self.body.extend(self.ptr_read(kind,hi*256+lo,n))
        if target==0x195b:self.flushed=True
        self.clobber();self.mem[4:8]=bytes(4)
        if target==0x196d and self.writer_fail:self.mem[4:8]=b'\xff'*4
        return True
    def put(self,d,v):
        self.mem[d]=v&255
        if d!=0xa0:return
        assert not self.mem[0xa8]&128,'ASIC access outside critical section'
        reg=self.mem[0xa2]*256+self.mem[0xa3];self.mem[0xa1]=int(self.bus_stuck)
        if v==3:
            value=self.mem[0xa4]*256+self.mem[0xa5];self.writes.append((reg,value))
            if reg==0x501:self.current_slot=value
            elif reg==0x500:
                assert value==0x14,'Attempt to mutate table'
                assert 0<=self.current_slot<0x1040
                self.slots.append(self.current_slot);self.has_command=True
            else:raise AssertionError(('unexpected write',reg,value))
        elif v==1:
            if reg==0x502:
                busy=self.table_stuck or (self.has_command and self.current_slot==self.fail_at)
                value=0x2000 if busy else 0x1000|(self.current_slot&0x7ff)
            elif 0x520<=reg<=0x525:
                # Synthetic unicast records with distinguishable words and slot bits.
                value=[self.current_slot,0x2233,0x0211,0x2001,0x0800|((self.current_slot%8)<<8),0][reg-0x520]
            else:raise AssertionError(('unexpected read',reg))
            self.mem[0xa6]=value>>8;self.mem[0xa7]=value&255
        else:raise AssertionError(('bad bus command',v))
    def ret(self):
        self.pc,self.bank=self.frames.pop()
        return self.pc!=-1
    def run(self,entry=0x20f3,limit=1000000):
        self.pc=entry;self.frames=[(-1,self.bank)]
        while self.count<limit:
            self.count+=1;self.max_frames=max(self.max_frames,len(self.frames))
            p=offset(self.bank,self.pc);op=self.code[p];self.pc+=1
            def get():
                nonlocal p
                p+=1;self.pc+=1;return self.code[p]
            def branch(v):self.pc=(self.pc+(v if v<128 else v-256))&65535
            if op in (0x12,0x02):
                dest=get()*256+get()
                if self.hook(dest):
                    if op==2 and not self.ret():return self
                else:
                    if op==0x12:self.frames.append((self.pc,self.bank))
                    if dest==0x1130:self.bank=7;self.pc=self.dptr
                    else:self.pc=dest
            elif op==0x22:
                if not self.ret():return self
            elif op==0:pass
            elif op==0x90:self.dptr=get()*256+get()
            elif op==0xe0:self.acc=self.x[self.dptr]
            elif op==0xf0:self.x[self.dptr]=self.acc
            elif op==0xa3:self.dptr=(self.dptr+1)&65535
            elif op==0xe4:self.acc=0
            elif op==0x74:self.acc=get()
            elif op==0xe5:self.acc=self.mem[get()]
            elif op==0xf5:self.put(get(),self.acc)
            elif op==0x75:d=get();self.put(d,get())
            elif 0x78<=op<=0x7f:self.mem[op&7]=get()
            elif 0xe8<=op<=0xef:self.acc=self.mem[op&7]
            elif 0xf8<=op<=0xff:self.mem[op&7]=self.acc
            elif 0xa8<=op<=0xaf:self.mem[op&7]=self.mem[get()]
            elif 0x88<=op<=0x8f:self.put(get(),self.mem[op&7])
            elif op in (0x60,0x70,0x40,0x50):
                delta=get();take={0x60:self.acc==0,0x70:self.acc!=0,0x40:self.carry==1,0x50:self.carry==0}[op]
                if take:branch(delta)
            elif op==0xb4:
                value=get();delta=get();self.carry=self.acc<value
                if self.acc!=value:branch(delta)
            elif 0xd8<=op<=0xdf:
                delta=get();r=op&7;self.mem[r]=(self.mem[r]-1)&255
                if self.mem[r]:branch(delta)
            elif op==0x54:self.acc &= get()
            elif op==0x24:
                n=self.acc+get();self.acc=n;self.carry=n>255
            elif op==0x94:
                n=self.acc-get()-self.carry;self.acc=n;self.carry=n<0
            elif 0x48<=op<=0x4f:self.acc |= self.mem[op&7]
            elif op==0xc4:self.acc=(self.acc<<4)|(self.acc>>4)
            elif op==0x03:self.acc=(self.acc>>1)|(self.acc<<7)
            elif op==0x04:self.acc+=1
            elif op==0x14:self.acc-=1
            elif op==0xc3:self.carry=0
            elif op==0xc2:
                bit=get();assert bit==0xaf;self.mem[0xa8]&=127
            elif op==0xc0:
                d=get();self.mem[0x81]+=1;self.mem[self.mem[0x81]]=self.mem[d]
            elif op==0xd0:
                d=get();self.put(d,self.mem[self.mem[0x81]]);self.mem[0x81]-=1
            else:raise AssertionError(('unimplemented instruction',hex(op),self.bank,hex(self.pc-1)))
        raise AssertionError(('execution bound exceeded',self.bank,hex(self.pc)))

class PatchTests(unittest.TestCase):
    def test_container(self):
        checksums(STOCK);checksums(IMAGE);self.assertEqual(len(STOCK),len(IMAGE))
        self.assertEqual(build(STOCK)[0],IMAGE)
        changed={i for i,(a,b) in enumerate(zip(STOCK,IMAGE)) if a!=b}
        allowed=set(range(8,16))
        for item in INFO['changes']:allowed.update(range(20+item['payload_offset'],20+item['payload_offset']+item['length']))
        self.assertLessEqual(changed,allowed)
        bad=bytearray(STOCK);bad[200]^=1
        with self.assertRaises(ValueError):build(bytes(bad))
        bad=bytearray(IMAGE);bad[200]^=1
        with self.assertRaises(ValueError):checksums(bad)
    def test_routes(self):
        for path in ['/PortStatisticsRpm.htm','/MacTableRpm.htm']+[f'/MacTable{i:02x}.dat' for i in range(65)]:
            with self.subTest(path=path):self.assertEqual(CPU(path).run(0x3800).mem[7],0)
        for path in ['','/MacTable41.dat','/MacTableff.dat','/MacTable0.dat','/MacTable000.dat','/MacTable0A.dat','/MacTable00.dat/','/MacTable00.dat?x=1','Unauth','/SystemInfoRpm.htm','/MacTableRpm.htm/']:
            with self.subTest(path=path):self.assertNotEqual(CPU(path).run(0x3800).mem[7],0)
    def test_original_handler(self):
        c=CPU('/PortStatisticsRpm.htm').run();self.assertTrue(c.fallback);self.assertFalse(c.writes)
    def test_html(self):
        c=CPU('/MacTableRpm.htm').run();self.assertEqual(c.body,(ROOT/'patch/mac_table.html').read_bytes());self.assertEqual(c.http_status,200);self.assertTrue(c.flushed);self.assertFalse(c.writes)
    def test_every_block_and_format(self):
        for block in range(65):
            with self.subTest(block=block):
                c=CPU(f'/MacTable{block:02x}.dat').run()
                self.assertEqual(c.slots,list(range(block*64,block*64+64)))
                lines=c.body.decode().splitlines();self.assertEqual(lines[0],'MACT1');self.assertEqual(lines[-1],'END');self.assertEqual(len(lines),66)
                for i,line in enumerate(lines[1:-1]):
                    slot=block*64+i
                    self.assertEqual(line,f'{slot:04x} {0x1000|(slot&0x7ff):04x} {slot:04x} 2233 0211 2001 {0x0800|((slot%8)<<8):04x} 0000')
                self.assertEqual(c.mem[0xa8],0x82);self.assertEqual(c.mem[0x81],0x60)
                self.assertEqual(c.bank,6);self.assertTrue(c.flushed)
    def test_polling_timeouts(self):
        for kw in [dict(bus_stuck=True),dict(table_stuck=True),dict(fail_at=3)]:
            with self.subTest(kw=kw):
                c=CPU(**kw).run();self.assertTrue(c.body.endswith(b'ERR\n'));self.assertFalse(c.body.endswith(b'END\n'));self.assertEqual(c.mem[0xa8],0x82);self.assertEqual(c.mem[0x81],0x60);self.assertLess(c.count,100000)
        c=CPU(bus_stuck=True);c.mem[0xa8]=2;c.run();self.assertEqual(c.mem[0xa8],2)
    def test_writer_failure_stops_scan(self):
        c=CPU(writer_fail=True).run();self.assertLessEqual(len(c.slots),1);self.assertTrue(c.flushed)

if __name__=='__main__':unittest.main(verbosity=2)
