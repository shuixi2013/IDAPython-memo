import idaapi
import idc
import idautils


def get_ref_cnt_in_func(ea):
    ref_dict = {}
    xref_set = set()
    for xref in idautils.XrefsTo(ea):
        xref_set.add(xref.frm)

    for frm in xref_set:
        func = idaapi.get_func(frm)
        if not func:
            continue
        frm_fn_start = func.start_ea
        if frm_fn_start in ref_dict:
            ref_dict[frm_fn_start] = ref_dict[frm_fn_start] + 1
        else:
            ref_dict[frm_fn_start] = 1
    return ref_dict


def find_infect_file():
    create_file_imp = idaapi.get_name_ea(idaapi.BADADDR, 'CreateFileA')
    close_handle_imp = idaapi.get_name_ea(idaapi.BADADDR, 'CloseHandle')
    fopen_imp = idaapi.get_name_ea(idaapi.BADADDR, '_fopen')

    cf_ref_dict = get_ref_cnt_in_func(create_file_imp)
    ch_ref_dict = get_ref_cnt_in_func(close_handle_imp)
    fopen_ref_dict = get_ref_cnt_in_func(fopen_imp)

    for ea, ref in cf_ref_dict.items():
        if ref == 2 and ch_ref_dict[ea] == 2:
            if len(fopen_ref_dict) == 0:
                print('This version maybe malware variant')
            for xref in idautils.XrefsTo(ea):
                print('frm:', hex(xref.frm), ', to infect_file:', hex(xref.to))
                insn = idaapi.insn_t()
                if idaapi.decode_prev_insn(insn, xref.frm):
                    if insn.itype == idaapi.NN_push and insn.Op1.type == idaapi.o_imm:
                        print('key value:', hex(insn.Op1.value))


class find_infect_file_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Exs8: Find infect file"
    wanted_hotkey = "Ctrl-Shift-F8"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg_clear()
        find_infect_file()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return find_infect_file_t()


idaapi.msg_clear()
find_infect_file()
