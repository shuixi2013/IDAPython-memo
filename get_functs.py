import idaapi
import idc

def get_func_frame(start = idaapi.get_screen_ea()):
    func = idaapi.get_func(start)
    frame = idaapi.get_frame(func)

    for i in range(frame.memqty):
        mptr = frame.members[i]
        name = idaapi.get_member_name(mptr.id)
        print('%x: offset %a-%a: %s' % (func.start_ea, mptr.soff, mptr.eoff, name))

class show_frame_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Exs7: Get function frame"
    wanted_hotkey = "Ctrl-Shift-F7"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        get_func_frame()
    def term(self):
        pass

def PLUGIN_ENTRY():
    return show_frame_t()

#idaapi.msg_clear()
#get_func_frame()
