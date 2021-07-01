import idautils
import ida_hexrays
import idc
import idaapi
import ida_pro
import ctypes
import struct
import socket
def save_code_to_file(ea, ea_len, fname = None):
    if not fname:
        fname = 'inj_' + idc.get_input_file_path().split('\\')[-1] + '_' + hex(ea) + '_' + str(ea_len) + '.bin'
    sc = idaapi.get_bytes(ea, ea_len)
    with open(fname, 'wb+') as fp:
        fp.write(sc)
    print(f'[+] Save shellcode to {fname:s} (from 0x{ea:x} with len {ea_len:d})')


def find_calls(cfunc, callee_ea):
    class finder_t(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.results = []
            return


        def visit_expr(self, expr):
            if expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_obj and expr.x.obj_ea == callee_ea:
                self.results.append(expr)
            return 0

    finder = finder_t()
    finder.apply_to(cfunc.body, None)
    return finder.results


def lookup_hexray_op(op):
    for m in dir(ida_hexrays):
        if m.startswith('cot_') and getattr(ida_hexrays, m) == op:
                return m
    return 'unknown'


get_segment_range = lambda name: (idaapi.get_segm_by_name(name).start_ea, idaapi.get_segm_by_name(name).end_ea)
def get_pdb_string():
    possible_pdb = []

    for s in idautils.Strings():
        try:
            str_value = idaapi.get_strlit_contents(s.ea, s.length, ida_nalt.STRTYPE_C).decode('ascii')
            if 'pdb' in str_value:
                #print('pdb string:', str_value)
                possible_pdb.append(str_value)
        except UnicodeDecodeError:
            pass
    return possible_pdb

def resolve_sockaddr_ip(sockadd_val):

    class sockaddr_in(ctypes.Structure):
        _fields_ = [("sa_family", ctypes.c_ushort),  # sin_family
                    ("sin_port", ctypes.c_ushort),
                    ("sin_addr", ctypes.c_byte * 4),
                    ("__pad", ctypes.c_byte * 8)]  # struct sockaddr_in is 16 bytes

    s = sockaddr_in()
    ctypes.memmove(ctypes.addressof(s), struct.pack('<Q', sockadd_val), ctypes.sizeof(s))
    assert socket.AF_INET == s.sa_family

    print('C2: %s:%d' % (socket.inet_ntoa(s.sin_addr), socket.ntohs(s.sin_port)))

def save_inject_code(write_process_ea = None):
    if not write_process_ea:
        write_process_ea = idaapi.get_name_ea(0, 'WriteProcessMemory')
    done_set = set()
    for xref in idautils.XrefsTo(write_process_ea, idaapi.XREF_DATA):
        if xref.frm in done_set:
            continue
        else:
            done_set.add(xref.frm)

        cfunc = ida_hexrays.decompile(xref.frm)
        for expr in find_calls(cfunc, xref.to):
            arg2 = expr.a[2]
            arg3 = expr.a[3]
            write_ea = None
            if arg2.op == ida_hexrays.cot_obj:
                write_ea = arg2.obj_ea
            elif arg2.op == ida_hexrays.cot_ref:
                write_ea = arg2.x.obj_ea
            else:
                print(f'arg2 op: {lookup_hexray_op(arg2.op):s}')
            assert arg3.op == ida_hexrays.cot_num

            write_len = arg3.n._value

            if write_ea:
                save_code_to_file(write_ea, write_len)


#idaapi.msg_clear()
#print(get_pdb_string())
#resolve_sockaddr_ip()
#save_inject_code()
#ida_pro.qexit(0)