import idaapi
from idc import *
import ctypes



def read_whole_file(li):
    li.seek(0)
    return li.read(li.size())

# -----------------------------------------------------------------------


def accept_file(li, file_name):
    fh = read_struct(li, file_header_t)

    print(f"Check file_name: {file_name}")
    if fh.sig.decode('ascii') != 'CHNK':
        return 0
    else:
        return {'format': "CHNK Exs", 'processor': fh.cpuname.decode('ascii')}  # accept the file


uint32_t = ctypes.c_uint
char = ctypes.c_char
le_struct = ctypes.LittleEndianStructure

class chunk_t(le_struct):
    _pack = 1
    _fields_ = [
        ("base", uint32_t),
        ("sz", uint32_t),
        ("bytes", char * 0)
    ]

class file_header_t(le_struct):
    _pack_ = 1
    _fields_ = [
        ("sig", char * 4),
        ("cpuname", char * 10),
        ("nchunks", uint32_t),
        ("entrypoint", uint32_t),
        ("chunks", chunk_t * 0)
    ]


def read_struct(li, struct):
    s = struct()
    slen = ctypes.sizeof(s)
    if li.size() >= slen + li.tell():
        hdr = li.read(slen)
        ctypes.memmove(ctypes.addressof(s), hdr, min(len(hdr), slen))
    return s

# def print_neflags(neflags):

def flag_lookup(flag, module, prefix):
    try:
        from inspect import getmembers, isfunction
        find_flags = [s for s, v in getmembers(module, not isfunction) if s.startswith(prefix) and flag & v]
    except Exception as e:
        print('error', e)
    return '|'.join(find_flags)

def load_file(li, neflags, format):
    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """
    flag_str = flag_lookup(neflags, ida_loader, 'NEF_')
    print(f'neflags: 0x{neflags:x}: ({flag_str}, format: {format})')


    fh = read_struct(li, file_header_t)
    print(f"'sig: '{fh.sig}, cpuname: {fh.cpuname}, nchunks: {fh.nchunks}, entry: {fh.entrypoint:x}")

    # read chunk
    while fh.nchunks > 0:
        chk = read_struct(li, chunk_t)
        add_segm_ex(chk.base, chk.base+chk.sz, 0, 1, saRelPara, scPub, ADDSEG_NOSREG)
        print(f'current pos: {li.tell():x}, base: {chk.base:x}, sz: {chk.sz}')
        li.file2base(li.tell(), chk.base, chk.base + chk.sz, False)
        fh.nchunks -= 1

    set_inf_attr(INF_START_EA, fh.entrypoint)
    set_inf_attr(INF_START_IP, fh.entrypoint)
    set_inf_attr(INF_START_CS, 0)
    set_processor_type(fh.cpuname.decode('ascii'), SETPROC_USER)
    add_entry(0, fh.entrypoint, "start", 1)
    return 1
