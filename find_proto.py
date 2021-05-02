import idaapi
import idc


def find_funct_by_proto(start = idaapi.get_screen_ea()):
    st = idaapi.get_func(start).start_ea
    ti = idaapi.tinfo_t()

    for fn in range(idaapi.get_func_qty()):
        st = idaapi.getn_func(fn).start_ea
        idaapi.get_tinfo(ti, st)
        func_info = idaapi.func_type_data_t()
        ti.get_func_details(func_info)
        arg_type_list = ','.join([str(func_info[i].type) for i in range(func_info.size())])

        if func_info.empty():
            continue
        if str(func_info.rettype) == 'int' and str(func_info[0].type) == 'int':
            print('0x{:x}: retype: {} \tname: {} \t({})'.format(st, func_info.rettype, idaapi.get_func_name(st), arg_type_list))


class find_funct_by_proto_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Exs6: Find function by prototype"
    wanted_hotkey = "Ctrl-Shift-F6"

    def init(self):
        print("plugin init")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg_clear()
        find_funct_by_proto()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return find_funct_by_proto_t()

#idaapi.msg_clear()
#find_funct_by_proto()
