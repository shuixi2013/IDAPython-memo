import idaapi
import idc
import idautils


def color_caller(current = idaapi.get_screen_ea()):
    for xref in idautils.XrefsTo(idaapi.get_func(current).start_ea):
        print(xref.type, idautils.XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
        idaapi.set_item_color(xref.frm, 606060)

        #print('caller ea:', hex(ea), idc.print_insn_mnem(ea), idc.print_operand(ea, 0), idc.print_operand(ea, 1))


class color_caller_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is  help"
    wanted_name = "Exs5:Color callers"
    wanted_hotkey = "Ctrl-Shift-F5"

    def init(self):
        print("plugin init")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        color_caller()
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return color_caller_t()


#idaapi.msg_clear()
