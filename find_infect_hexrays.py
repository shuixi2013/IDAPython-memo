import idaapi
import idc
import idautils
import ida_hexrays

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


def find_calls(cfunc, callee_ea):
    class finder_t(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.results = []
            return

        #def visit_insn(self, inst):
        #    pass
        #    if inst.op == ida_hexrays.cit_expr and inst.cexpr.op == ida_hexrays.cot_call:
        #        self.results.append(inst)
        #    return 0

        def visit_expr(self, expr):
            if expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_obj and expr.x.obj_ea == callee_ea:
                self.results.append(expr)
            return 0

    finder = finder_t()
    finder.apply_to(cfunc.body, None)
    return finder.results

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
                print('ea: %s' % hex(idaapi.get_func(xref.frm).start_ea))
                cfunc = ida_hexrays.decompile(xref.frm)

                for expr in find_calls(cfunc, xref.to):
                    arg1 = expr.a[0]
                    assert arg1.op == ida_hexrays.cot_num
                    print(f'caller ea: {expr.ea:x}; callee ea: {expr.x.obj_ea:x}, key: {arg1.n._value:x}')




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
