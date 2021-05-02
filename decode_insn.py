from idaapi import *
import idc
import idautils

def find_ret(start=get_screen_ea()):
    fnct = get_func(start)
    if fnct:
        ea = fnct.start_ea
        while ea < fnct.end_ea:
            insn = insn_t()
            if not decode_insn(insn, ea):
                print('failed to decode instruction at %x', ea)
                continue
            # print(hex(ea), ':', idc.print_insn_mnem(ea), idc.print_operand(ea, 0), idc.print_operand(ea, 1))
            if insn.itype == NN_retn:
                if insn.Op1.type == o_void:
                    print(hex(ea), ':', 'normal return')
                else:
                    print(hex(ea), ':', 'return with stack cleanup of:', insn.Op1.value)
                jumpto(ea)
                break
            else:
                ea = idc.next_head(ea)
        return True

    else:
        print('No function at cursor')
        return False

def print_insn_in_function():
    for ea in idautils.FuncItems(get_screen_ea()):
        print(hex(ea), ':', idc.print_insn_mnem(ea), idc.print_operand(ea, 0), idc.print_operand(ea, 1))

class find_return_t(plugin_t):
    flags = PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Exs4: Find return instruction"
    wanted_hotkey = "Ctrl-Shift-F4"

    def init(self):
        return PLUGIN_OK

    def run(self, arg):

        find_ret()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return find_return_t()

#msg_clear()
print_insn_in_function()
