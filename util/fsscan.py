#!/usr/bin/python3

from io import BufferedWriter
from pathlib import Path, PurePosixPath
import os
import sys
import argparse
import traceback
from datetime import date

parser = argparse.ArgumentParser(description='Scan Centurion disk images\nImage must be a raw image: 400 B/sect padded to 512 B/sect (CCDP compatible)',add_help=True)
parser.add_argument('-x', action='store_true', help='extract matching file')
parser.add_argument('-d', action='store_true', help='display matching file')
parser.add_argument('-t', action='store_true', help='convert text files')
parser.add_argument('file')
parser.add_argument('search_file', nargs='?')
inargs = parser.parse_args()
IMGSECTSIZE = 0x200 # centurion sectors aligned to 512 bytes in the image file

f = Path(inargs.file)
search = None
if inargs.search_file:
    search = PurePosixPath(inargs.search_file.upper())
    print(search)

fb = bytearray(f.read_bytes())

print('disk file:', f, len(fb),'bytes,',hex(len(fb) // IMGSECTSIZE),'sectors')
def clearhi(v):
    i = 0
    while i < len(v):
        if v[i] < 0x80:
            return False
        v[i] &= 0x7f
        i += 1
    return True

def entstr(bv):
    v = bytearray(bv)
    if not clearhi(v):
        print('invalid entry string')
        exit()
    return str(v, 'ascii').rstrip()

FILETYPES: dict[int, (str, str)] = {0x0:('INDIR','RAW'),0x1:('RECORD','BIN'),0x2:('ATXT','TXT'),0x3:('SYSCF','BIN'),0x4:('RLBIN','BIN'),0x5:('LIB','DSKLIB'),0x6:('INDXD','RAW')}

def filetype(ft:int):
    return FILETYPES.get(ft, (hex(ft),'RAW'))[0]

def extract_text(outfile:BufferedWriter, sector_list:list):
    for x in sector_list:
        sec_base = x * IMGSECTSIZE
        fcvb = bytearray(fb[sec_base:sec_base + 400])
        clearhi(fcvb)
        y = 0
        yl = False
        while y < len(fcvb):
            if fcvb[y] == 0xd:
                if yl:
                    fcvb = fcvb[0:y]
                    break
                fcvb[y] = 10
                yl = True
            elif fcvb[y] == 0:
                yl = False
                del fcvb[y]
                continue
            else:
                yl = False
            y += 1
        outfile.write(fcvb)
    pass

def extract_bin(outfile:BufferedWriter, sector_list:list):
    vofs = 0
    for x in sector_list:
        sec_base = x * IMGSECTSIZE
        secbytes = bytearray(fb[sec_base:sec_base + 400])
        ofs = 0
        while ofs < len(secbytes):
            rectype = secbytes[ofs]
            if rectype > 1:
                break
            reclen = secbytes[ofs+1]
            recbase = secbytes[ofs+2:ofs+4]
            slbuf = secbytes[ofs+4:ofs+4+reclen]
            recsum = rectype + reclen + recbase[0] + recbase[1] + secbytes[ofs + reclen + 4]
            for i in range(reclen):
                recsum += slbuf[i]
                slbuf[i] &= 0x7f
                if slbuf[i] < 9 or slbuf[i] == 11 or slbuf[i] == 12 or slbuf[i] == 127 or (slbuf[i] > 13 and slbuf[i] < 32):
                    slbuf[i] = 0x2e
            #vofs = recbase
            #print(recbase.hex(),rectype,(recsum & 0xff) == 0,':', fcvb[ofs+4:ofs+4+reclen].hex(' '), repr(bytes(slbuf)))
            if rectype == 0:
                print(recbase.hex(),':', repr(bytes(slbuf)))
            ofs += 5+reclen
        outfile.write(secbytes)
    pass

def extract_raw(outfile:BufferedWriter, sector_list:list):
    for x in sector_list:
        sec_base = x * IMGSECTSIZE
        secbytes = bytearray(fb[sec_base:sec_base + 400])
        outfile.write(secbytes)
    pass

def filelist(start:int, use_offset=False, base=''):
    sec = start * IMGSECTSIZE
    volname = fb[sec:sec+0x0a]
    volmap = fb[sec+0xe:sec+0x10]
    mapsec = int.from_bytes(volmap, 'big') * IMGSECTSIZE
    volnamestr = base + entstr(volname)
    if use_offset:
        mapsec += sec
    else:
        print('volume label:',volnamestr)

    # print(start.to_bytes(2,'big').hex(),':',sec.to_bytes(4,'big').hex(),' ',
    #     repr(volnamestr),' ',volmap.hex(),
    #     sep='')
    entry_ofs = 0x10
    ind = 0
    while ind < 100:
        while entry_ofs < 400:
            entry_base = sec + entry_ofs
            fname = fb[entry_base:entry_base+0x0a]
            if fname[0] == 0:
                entry_ofs += 0x10
                continue # skip entry
            if fname[0] == 0x84 and fname[1] == 0x8d:
                return # terminal entry
            fnamestr = entstr(fname)
            fmap = fb[entry_base+0x0a]
            fmapsec = int.from_bytes(fb[entry_base+0x0b:entry_base+0x0d], 'big') * IMGSECTSIZE
            fmapseci = fmapsec
            ftype = fb[entry_base+0x0d] & 0xf
            fattr = fb[entry_base+0x0d] >> 4
            fdatestamp = int.from_bytes(fb[entry_base+0x0e:entry_base+0x10], 'big')
            # date stamp, days since 1900 ?
            fdate = date.fromordinal(693596 + fdatestamp) # 1900 Jan 1 + days
            fdatef = ' <NOT SET>'
            if fdatestamp > 0:
                fdatef = fdate.isoformat()
            fxs = mapsec + fmapseci + fmap * 3
            # length in sectors, minus 1
            # alternately: stop after this many sectors
            try:
                fxlen = int.from_bytes(fb[fxs:fxs+2], 'big')
                fxbuffer = fb[fxs+2:fxs+4]
                fxclshift = fb[fxs+4]
                fx2 = fb[fxs+5:fxs+6]
            except:
                print('invalid or corrupt image, if no data was listed: try arcscan.py')
                exit(1)
            fxsize = 1 << fxclshift
            if fxsize > 0x100000:
                print('invalid or corrupt image, if no data was listed: try arcscan.py')
                exit(1)
            fxs += 6
            msec = []
            msi = 0
            while msi < 155:
                mso = fxs + msi * 3
                if fb[mso] == 0xff:
                    if fb[mso+1] != 0xff:
                        fmapseci = (fb[mso+1] ^ 0xff) * IMGSECTSIZE
                        fxs = mapsec + fmapseci
                        msi = fb[mso+2]
                        continue
                    break
                msent = int.from_bytes(fb[mso+1:mso+3], 'big')
                if use_offset:
                    msent += start
                msec.append(msent)
                msi += 1
            fentfile = PurePosixPath(fnamestr)
            if len(base) == 0:
                fentpath = fnamestr
            else:
                fentpath = base + '.' + fnamestr
            show = True
            match = False
            if search:
                show = False
                if search.is_absolute():
                    if fentpath == search:
                        print('MATCH PATH')
                        match = True
                elif fentfile == search:
                    print('MATCH FILE')
                    match = True
            try:
                if show or match:
                    print(start.to_bytes(2,'big').hex(),':',entry_base.to_bytes(4,'big').hex(),' -> ',
                        str(fentpath).ljust(16),':',hex(fattr)[2:],':',filetype(ftype).ljust(6),':',fdatef,
                        ' (',(mapsec + fmapsec).to_bytes(4,'big').hex(),':',fmap.to_bytes(1,'big').hex(),
                        ')-> l:',fxlen.to_bytes(2,'big').hex(),' ',fxbuffer.hex().upper(),' m:',fx2.hex().upper(),
                        ' sz:',(len(msec) * fxsize).to_bytes(2,'big').hex(),' '
                        ' ',hex(msec[0]) if len(msec) else '','=>',hex(msec[0]*IMGSECTSIZE) if len(msec) else '',
                        '[',','.join([hex(x) for x in msec]),']',
                        sep='')
                if match:
                    msecfull = []
                    for x in msec:
                        msecfull.extend(range(x, x+fxsize))
                    print('[',','.join([hex(y) for y in msecfull]),']',)
                    if inargs.d:
                        if inargs.t and (ftype == 0x02 or ftype == 0x12 or ftype not in FILETYPES):
                            extract_text(sys.stdout.buffer, msecfull)
                        elif ftype == 0x04 or ftype == 0x14:
                            extract_bin(sys.stdout.buffer, msecfull)
                    elif inargs.x:
                        pathparts=fentpath.lstrip('.').split('.')
                        relpath:Path = Path(f.stem)
                        for pp in pathparts:
                            relpath.mkdir(exist_ok=True)
                            relpath = relpath / pp
                        file_exp_ext = FILETYPES.get(ftype, ('','RAW'))[1].lower()
                        relpath = relpath.with_suffix('.' + file_exp_ext)
                        outfile = relpath.open('w+b')
                        if inargs.t and (ftype == 0x2 or ftype not in FILETYPES):
                            extract_text(outfile, msecfull)
                        elif ftype == 0x4:
                            extract_bin(outfile, msecfull)
                        else:
                            extract_raw(outfile, msecfull)
                        outfile.close()
                        print('wrote', relpath)
                
                if (ftype == 0x05 or ftype == 0x15) and len(msec) > 0:
                    if use_offset:
                        filelist(msec[0], True, volnamestr + '.' + fnamestr)
                    else:
                        filelist(msec[0], True, base + '.' + fnamestr)
            except Exception as e:
                print('Error: ' + str(e))
                traceback.print_exc()
            entry_ofs += 0x10
        ind += 1
        entry_ofs = 0
        sec += IMGSECTSIZE

filelist(0x10)
