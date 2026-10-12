#!/usr/bin/env python3
"""Small 8051 decoder and address mapper for this exact TP-Link image.

Offsets are relative to the extracted payload. Common code is mapped at 0x1000;
bank 3 starts at payload 0x2ffe and each bank occupies 0xc000 bytes.
"""
import argparse
from pathlib import Path

IMAGE = Path(__file__).resolve().parents[1] / 'unpacked/firmware_payload.bin'
DATA = IMAGE.read_bytes()

def offset(bank, address):
    if 0x1000 <= address < 0x4000:
        return address - 0x1000
    if 0x4000 <= address <= 0xffff and bank >= 3:
        return 0x2ffe + (bank-3)*0xc000 + address-0x4000
    raise ValueError((bank, address))

def location(off):
    if off < 0x2ffe:
        return 0, off+0x1000
    bank, within = divmod(off-0x2ffe, 0xc000)
    return bank+3, within+0x4000

def resolve(target):
    if not 0x1000 <= target < 0x4000:
        return None
    p=target-0x1000
    q=DATA[p:p+6]
    if len(q)==6 and q[0]==0x90 and q[3]==2:
        stub=int.from_bytes(q[4:6],'big')
        s=DATA[stub-0x1000:stub-0x1000+12]
        if s[:5]==bytes.fromhex('8596bb7596'):
            return s[5], int.from_bytes(q[1:3],'big')
    return None

def decode(bank, address):
    off=offset(bank,address)
    op=DATA[off]; x=DATA[off+1] if off+1<len(DATA) else 0; y=DATA[off+2] if off+2<len(DATA) else 0
    n=1; target=None
    direct=lambda z:f'0x{z:02x}'
    imm=lambda z:f'#0x{z:02x}'
    rel=lambda z,size:(address+size+(z if z<128 else z-256))&65535
    if op&31 in (1,17):
        n=2;target=((address+2)&0xf800)|((op&0xe0)<<3)|x
        text=('ACALL' if op&31==17 else 'AJMP')+f' 0x{target:04x}'
    elif op in (2,18):
        n=3;target=x*256+y;text=('LCALL' if op==18 else 'LJMP')+f' 0x{target:04x}'
    elif op in (0x10,0x20,0x30):
        n=3;target=rel(y,n);text={0x10:'JBC',0x20:'JB',0x30:'JNB'}[op]+f' {direct(x)},0x{target:04x}'
    elif op in (0x40,0x50,0x60,0x70,0x80):
        n=2;target=rel(x,n);text={0x40:'JC',0x50:'JNC',0x60:'JZ',0x70:'JNZ',0x80:'SJMP'}[op]+f' 0x{target:04x}'
    elif op in (0x04,0x14):text=('INC' if op==4 else 'DEC')+' A'
    elif op in (0x05,0x15):n=2;text=('INC' if op==5 else 'DEC')+' '+direct(x)
    elif op in (0x06,0x07,0x16,0x17):text=('INC' if op<0x10 else 'DEC')+f' @R{op&1}'
    elif 8<=op<=15 or 0x18<=op<=0x1f:text=('INC' if op<0x10 else 'DEC')+f' R{op&7}'
    elif op&0xf0 in (0x20,0x30,0x40,0x50,0x60,0x90) and op&15>=4:
        verb={0x20:'ADD',0x30:'ADDC',0x40:'ORL',0x50:'ANL',0x60:'XRL',0x90:'SUBB'}[op&0xf0]
        k=op&15
        if k==4:n=2;arg=imm(x)
        elif k==5:n=2;arg=direct(x)
        elif k<8:arg=f'@R{k&1}'
        else:arg=f'R{k&7}'
        text=f'{verb} A,{arg}'
    elif op in (0x42,0x43,0x52,0x53,0x62,0x63):
        n=2+(op&1);text={0x40:'ORL',0x50:'ANL',0x60:'XRL'}[op&0xf0]+f' {direct(x)},'+(imm(y) if op&1 else 'A')
    elif op in (0x72,0x82,0xa0,0xb0):
        n=2;text=('ORL' if op in (0x72,0xa0) else 'ANL')+' C,'+('/' if op in (0xa0,0xb0) else '')+direct(x)
    elif op==0x74:n=2;text=f'MOV A,{imm(x)}'
    elif op==0x75:n=3;text=f'MOV {direct(x)},{imm(y)}'
    elif op in (0x76,0x77):n=2;text=f'MOV @R{op&1},{imm(x)}'
    elif 0x78<=op<=0x7f:n=2;text=f'MOV R{op&7},{imm(x)}'
    elif op==0x85:n=3;text=f'MOV {direct(y)},{direct(x)}'
    elif op in (0x86,0x87):n=2;text=f'MOV {direct(x)},@R{op&1}'
    elif 0x88<=op<=0x8f:n=2;text=f'MOV {direct(x)},R{op&7}'
    elif op==0x90:n=3;text=f'MOV DPTR,#0x{x*256+y:04x}'
    elif op==0x92:n=2;text=f'MOV {direct(x)},C'
    elif op==0xa2:n=2;text=f'MOV C,{direct(x)}'
    elif op in (0xa6,0xa7):n=2;text=f'MOV @R{op&1},{direct(x)}'
    elif 0xa8<=op<=0xaf:n=2;text=f'MOV R{op&7},{direct(x)}'
    elif 0xb4<=op<=0xbf:
        n=3;target=rel(y,n)
        lhs='A' if op<0xb6 else (f'@R{op&1}' if op<0xb8 else f'R{op&7}')
        rhs=direct(x) if op==0xb5 else imm(x)
        text=f'CJNE {lhs},{rhs},0x{target:04x}'
    elif op in (0xb2,0xc2,0xd2,0xc0,0xd0):
        n=2;text={0xb2:'CPL',0xc2:'CLR',0xd2:'SETB',0xc0:'PUSH',0xd0:'POP'}[op]+' '+direct(x)
    elif op==0xc5:n=2;text=f'XCH A,{direct(x)}'
    elif op in (0xc6,0xc7,0xd6,0xd7):text=('XCH' if op<0xd0 else 'XCHD')+f' A,@R{op&1}'
    elif 0xc8<=op<=0xcf:text=f'XCH A,R{op&7}'
    elif op==0xd5:n=3;target=rel(y,n);text=f'DJNZ {direct(x)},0x{target:04x}'
    elif 0xd8<=op<=0xdf:n=2;target=rel(x,n);text=f'DJNZ R{op&7},0x{target:04x}'
    elif op in (0xe2,0xe3):text=f'MOVX A,@R{op&1}'
    elif op==0xe5:n=2;text=f'MOV A,{direct(x)}'
    elif op in (0xe6,0xe7):text=f'MOV A,@R{op&1}'
    elif 0xe8<=op<=0xef:text=f'MOV A,R{op&7}'
    elif op in (0xf2,0xf3):text=f'MOVX @R{op&1},A'
    elif op==0xf5:n=2;text=f'MOV {direct(x)},A'
    elif op in (0xf6,0xf7):text=f'MOV @R{op&1},A'
    elif 0xf8<=op<=0xff:text=f'MOV R{op&7},A'
    else:
        text={0:'NOP',3:'RR A',0x13:'RRC A',0x22:'RET',0x23:'RL A',0x32:'RETI',0x33:'RLC A',0x73:'JMP @A+DPTR',0x83:'MOVC A,@A+PC',0x84:'DIV AB',0x93:'MOVC A,@A+DPTR',0xa3:'INC DPTR',0xa4:'MUL AB',0xa5:'RESERVED',0xb3:'CPL C',0xc3:'CLR C',0xc4:'SWAP A',0xd3:'SETB C',0xd4:'DA A',0xe0:'MOVX A,@DPTR',0xe4:'CLR A',0xf0:'MOVX @DPTR,A',0xf4:'CPL A'}[op]
    annotation=''
    if op in (2,18) and target is not None:
        resolved=resolve(target)
        if resolved:
            bk,pc=resolved;annotation=f' ; bank {bk}:0x{pc:04x} file 0x{offset(bk,pc):06x}'
    return n,text+annotation,target

def listing(bank,start,end):
    while start<end:
        off=offset(bank,start);n,text,_=decode(bank,start)
        yield f'{off:06x}  {bank:02d}:{start:04x}  {DATA[off:off+n].hex(" "):8s}  {text}'
        start+=n

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--bank',type=int,default=0)
    p.add_argument('--start',type=lambda s:int(s,0),required=True)
    p.add_argument('--end',type=lambda s:int(s,0),required=True)
    a=p.parse_args()
    print('\n'.join(listing(a.bank,a.start,a.end)))
