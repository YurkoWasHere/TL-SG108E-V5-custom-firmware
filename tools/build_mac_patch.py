#!/usr/bin/env python3
"""Build the TL-SG108E V5 MAC table patch and its disassembly."""
from pathlib import Path
from hashlib import sha256
import json
import mcs51

ROOT = Path(__file__).resolve().parents[1]
SOURCE_HASH = '65eba08c9270e470dee69331de3e1345c8e5566b7458265fb3d69388b2a1f4db'
CLIENT, SLOT, REMAIN, STATUS, WORDS, KIND, LINE = 0x2cdf, 0x2ce2, 0x2ce4, 0x2ce5, 0x2ce7, 0x2cf3, 0x2cf4
BANK, BASE, STRINGS = 7, 0x6000, 0x9000

class Asm:
    def __init__(self, base):
        self.base=base; self.code=bytearray(); self.labels={}; self.fixups=[]
    @property
    def pc(self): return self.base+len(self.code)
    def label(self,name):
        assert name not in self.labels
        self.labels[name]=self.pc
    def emit(self,*b): self.code.extend(b)
    def word(self,op,target):
        self.emit(op)
        if isinstance(target,str): self.fixups.append((len(self.code),target,False)); self.emit(0,0)
        else: self.emit(target>>8,target&255)
    def call(self,target): self.word(0x12,target)
    def jump(self,target): self.word(0x02,target)
    def dptr(self,n): self.word(0x90,n)
    def branch(self,op,label,*args):
        self.emit(op,*args); self.fixups.append((len(self.code),label,True)); self.emit(0)
    def far_if(self,op,target):
        # Invert simple A/carry condition and skip a long jump.
        self.emit({0x60:0x70,0x70:0x60,0x40:0x50,0x50:0x40}[op],3); self.jump(target)
    def reg(self,r,n): self.emit(0x78+r,n)
    def load(self,x): self.dptr(x); self.emit(0xe0)
    def store(self,x): self.dptr(x); self.emit(0xf0)
    def setx(self,x,n): self.emit(0x74,n); self.store(x)
    def ptr(self,kind,addr): self.reg(3,kind); self.reg(2,addr>>8); self.reg(1,addr&255)
    def client(self): self.dptr(CLIENT); self.call(0x2866)
    def finish(self):
        for pos,name,relative in self.fixups:
            dest=self.labels[name]
            if relative:
                delta=dest-(self.base+pos+1)
                assert -128<=delta<=127,(name,delta)
                self.code[pos]=delta&255
            else: self.code[pos:pos+2]=dest.to_bytes(2,'big')
        return bytes(self.code)

def checksums(image):
    h=image[:20]; p=image[20:]
    if len(h)!=20 or h[:4]!=bytes.fromhex('12341085') or h[16:]!=bytes.fromhex('332255ff'):
        raise ValueError('Wrong image wrapper')
    if int.from_bytes(h[4:8],'big')!=len(p) or p[0x3ffe:0x4012]!=h:
        raise ValueError('Length or embedded header mismatch')
    if sum(h[:8]+h[12:])!=int.from_bytes(h[8:12],'big'):
        raise ValueError('Header checksum mismatch')
    if (sum(p)-sum(h)+20*255)&0xffffffff!=int.from_bytes(h[12:16],'big'):
        raise ValueError('Payload checksum mismatch')

def build(source):
    if sha256(source).hexdigest()!=SOURCE_HASH: raise ValueError('Only the exact reviewed stock image is supported')
    checksums(source)
    pool=bytearray(); strings={}
    def add(name,s):
        b=s.encode() if isinstance(s,str) else s
        strings[name]=(STRINGS+len(pool),len(b));pool.extend(b+b'\0')
    add('old','/PortStatisticsRpm.htm');add('page','/MacTableRpm.htm')
    for i in range(65): add('block'+str(i),f'/MacTable{i:02x}.dat')
    add('html_header','Content-Type: text/html')
    add('data_header','Content-Type: text/plain\r\nCache-Control: no-store')
    add('html',(ROOT/'patch/mac_table.html').read_bytes())
    add('magic','MACT1\n');add('end','END\n');add('error','ERR\n')
    a=Asm(BASE)
    def string_ptr(name): a.ptr(0x81+BANK,strings[name][0])
    def raw(name):
        string_ptr(name);a.dptr(0x2e68);a.call(0x289d)
        n=strings[name][1]
        for r,v in zip(range(4,8),n.to_bytes(4,'big')): a.reg(r,v)
        a.dptr(0x2e6b);a.call(0x284e);a.client();a.call(0x196d)
    def header(name):
        string_ptr(name);a.dptr(0x2e37);a.call(0x289d);a.client();a.call(0x1967)
    a.label('route_compare')
    a.call('classify');a.emit(0xef);a.branch(0xb4,'matched',255)
    a.reg(7,1);a.emit(0x22)
    a.label('matched');a.reg(7,0);a.emit(0x22)

    a.label('handler')
    a.dptr(CLIENT);a.call(0x289d);a.call('classify');a.emit(0xef)
    a.branch(0x70,'new_handler')
    a.client();a.jump(0x3806) # Original Port Statistics bank stub, copied verbatim.
    a.label('new_handler');a.store(KIND)
    # The stock dispatcher only calls this for an exact recognized path.
    a.emit(0xef);a.branch(0xb4,'valid_handler',255);a.reg(7,255);a.emit(0x22)
    a.label('valid_handler');a.client();a.call(0x1955)
    a.client();a.reg(4,0);a.reg(5,0);a.reg(6,0);a.reg(7,200);a.call(0x1961)
    a.load(KIND);a.branch(0xb4,'data_handler',66)
    header('html_header');raw('html');a.jump('finish')
    a.label('data_handler');header('data_header');raw('magic')
    # block=(kind-1); slot=block*64. Accepted block range 0..64.
    a.load(KIND);a.emit(0x14,0xff,0x03,0x03,0x54,0x1f);a.store(SLOT)
    a.emit(0xef,0x03,0x03,0x54,0xc0);a.store(SLOT+1)
    a.setx(REMAIN,64)
    a.label('entry_loop');a.call('read_slot');a.far_if(0x70,'failed')
    a.call('format_line')
    a.ptr(1,LINE);a.dptr(0x2e68);a.call(0x289d)
    a.reg(4,0);a.reg(5,0);a.reg(6,0);a.reg(7,40);a.dptr(0x2e6b);a.call(0x284e)
    a.client();a.call(0x196d)
    # Honor the stock writer's nonzero error return; do not keep scanning.
    a.emit(0xec,0x4d,0x4e,0x4f);a.far_if(0x70,'finish')
    a.load(SLOT+1);a.emit(0x04,0xf0);a.branch(0x70,'slot_incremented')
    a.load(SLOT);a.emit(0x04,0xf0)
    a.label('slot_incremented');a.load(REMAIN);a.emit(0x14,0xf0);a.far_if(0x70,'entry_loop')
    raw('end');a.jump('finish')
    a.label('failed');raw('error')
    a.label('finish');a.client();a.call(0x195b);a.emit(0xe4,0xfc,0xfd,0xfe,0xff,0x22)

    a.label('classify')
    # Exact strcmp on all allowed paths prevents truncation, suffix and range bugs.
    for i,(name,kind) in enumerate([('old',0),('page',66)]+[('block'+str(k),k+1) for k in range(65)]):
        a.dptr(0x2ccd);a.call(0x2866);a.emit(0xa8,1,0xac,2,0xad,3)
        string_ptr(name);a.call(0x2baf);a.emit(0xef);a.branch(0x70,'next'+str(i))
        a.reg(7,kind);a.emit(0x22);a.label('next'+str(i))
    a.reg(7,255);a.emit(0x22)

    a.label('read_slot')
    # Preserve IE and exclude interrupt users of the shared ASIC table engine.
    a.emit(0xc0,0xa8,0xc2,0xaf)
    a.call('table_ready');a.far_if(0x70,'slot_error')
    a.load(SLOT);a.emit(0xfc,0xa3,0xe0,0xfd)
    a.reg(6,5);a.reg(7,1);a.call('reg_write');a.far_if(0x70,'slot_error')
    # Read by address, L2 table = 4, method = 1; write-operation bit 3 stays 0.
    a.reg(6,5);a.reg(7,0);a.reg(4,0);a.reg(5,0x14);a.call('reg_write');a.far_if(0x70,'slot_error')
    a.call('table_ready');a.far_if(0x70,'slot_error')
    a.dptr(STATUS);a.emit(0xee,0xf0,0xa3,0xef,0xf0)
    for i in range(6):
        a.reg(6,5);a.reg(7,0x20+i);a.call('reg_read');a.far_if(0x70,'slot_error')
        a.dptr(WORDS+2*i);a.emit(0xee,0xf0,0xa3,0xef,0xf0)
    a.emit(0xd0,0xa8,0xe4,0x22)
    a.label('slot_error');a.emit(0xd0,0xa8,0x74,1,0x22)
    a.label('table_ready');a.reg(0,32)
    a.label('table_poll');a.reg(6,5);a.reg(7,2);a.call('reg_read');a.branch(0x70,'io_error')
    a.emit(0xee,0x54,0x20);a.branch(0x60,'io_ok');a.branch(0xd8,'table_poll')
    a.label('io_error');a.emit(0x74,1,0x22)
    a.label('io_ok');a.emit(0xe4,0x22)
    a.label('reg_read');a.emit(0x8e,0xa2,0x8f,0xa3,0x75,0xa0,1)
    a.call('bus_ready');a.branch(0x70,'read_return');a.emit(0xae,0xa6,0xaf,0xa7)
    a.label('read_return');a.emit(0x22)
    a.label('reg_write');a.emit(0x8e,0xa2,0x8f,0xa3,0x8c,0xa4,0x8d,0xa5,0x75,0xa0,3)
    a.label('bus_ready');a.reg(1,255)
    a.label('bus_poll');a.emit(*([0]*11));a.emit(0xe5,0xa1);a.branch(0x60,'io_ok');a.branch(0xd9,'bus_poll');a.jump('io_error')

    a.label('format_line')
    # Eight 16-bit hex fields, exactly 40 bytes. No printf or unbounded buffers.
    for i,addr in enumerate([SLOT,STATUS]+[WORDS+2*j for j in range(6)]):
        for j in range(2):
            a.load(addr+j);a.emit(0xff,0xc4);a.call('hex_nibble');a.store(LINE+i*5+j*2)
            a.emit(0xef);a.call('hex_nibble');a.store(LINE+i*5+j*2+1)
        a.setx(LINE+i*5+4,10 if i==7 else 32)
    a.emit(0x22)
    a.label('hex_nibble');a.emit(0x54,15,0xc3,0x94,10);a.branch(0x40,'hex_digit')
    a.emit(0x24,ord('a'),0x22)
    a.label('hex_digit');a.emit(0x24,10+ord('0'),0x22)
    code=a.finish()
    assert BASE+len(code)<STRINGS and STRINGS+len(pool)<0xffff
    payload=bytearray(source[20:]);changes=[]
    def replace(off,expected,new,description):
        if payload[off:off+len(expected)]!=expected: raise ValueError('Unexpected bytes: '+description)
        assert len(new)==len(expected)
        payload[off:off+len(new)]=new
        changes.append({'payload_offset':off,'length':len(new),'purpose':description,'old_sha256':sha256(expected).hexdigest(),'new_sha256':sha256(new).hexdigest()})
    def stub(addr):return b'\x90'+addr.to_bytes(2,'big')+bytes.fromhex('021130')
    replace(0x2800,bytes(12),stub(a.labels['route_compare'])+bytes.fromhex('907f750211a8'),'common route trampoline and original handler trampoline')
    replace(0x10f3,bytes.fromhex('907f750211a8'),stub(a.labels['handler']),'Port Statistics handler multiplexor')
    replace(0x2cf62,bytes.fromhex('122baf'),bytes.fromhex('123800'),'route comparator hook')
    replace(mcs51.offset(BANK,BASE),bytes(len(code)),code,'new 8051 routines in zero code cave')
    replace(mcs51.offset(BANK,STRINGS),bytes(len(pool)),bytes(pool),'new route strings and HTML')
    h=bytearray(source[:20]);h[12:16]=((sum(payload)-sum(payload[0x3ffe:0x4012])+20*255)&0xffffffff).to_bytes(4,'big')
    h[8:12]=sum(h[:8]+h[12:]).to_bytes(4,'big')
    replace(0x3ffe,source[:20],bytes(h),'embedded header checksums')
    candidate=bytes(h+payload);checksums(candidate)
    info = {
        'status': 'Experimental firmware patch; hardware results in REVERSE_ENGINEERING.md',
        'source_sha256': SOURCE_HASH,
        'candidate_sha256': sha256(candidate).hexdigest(),
        'size': len(candidate),
        'bank': BANK,
        'code_start': BASE,
        'code_size': len(code),
        'data_start': STRINGS,
        'data_size': len(pool),
        'labels': a.labels,
        'strings': strings,
        'changes': changes,
        'outer_header_before': source[:20].hex(),
        'outer_header_after': h.hex(),
        'checksums': 'Header and payload sums verified',
    }
    return candidate,info

def main():
    source=(ROOT / 'original/TL-SG108Ev5.0_en_1.0.0_[20191021-rel.53360]_up.bin').read_bytes()
    candidate,info=build(source)
    out=ROOT/'patch/build';out.mkdir(parents=True,exist_ok=True)
    (out/'mac-table-experimental.bin').write_bytes(candidate)
    (out/'patch-report.json').write_text(json.dumps(info,indent=2)+'\n')
    mcs51.DATA=candidate[20:]
    labels={v:k for k,v in info['labels'].items()};addr=BASE;lines=[]
    while addr<BASE+info['code_size']:
        if addr in labels:lines.append('\n'+labels[addr]+':')
        n,txt,_=mcs51.decode(BANK,addr);p=mcs51.offset(BANK,addr)
        lines.append(f'{p:06x} {BANK:02d}:{addr:04x} {mcs51.DATA[p:p+n].hex(" "):10s} {txt}');addr+=n
    (out/'patch-disassembly.txt').write_text('\n'.join(lines)+'\n')
    print(json.dumps({k:info[k] for k in ['status','candidate_sha256','size','code_size','data_size','outer_header_after']},indent=2))

if __name__=='__main__':main()
