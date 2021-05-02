import idaapi
import idc
class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Exs2: Ask to dump file"
    wanted_hotkey = "Ctrl-Shift-F2"

    def init(self):
        print("plugin init")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        fname = idaapi.ask_file(True, "wahaha.bin", "Specify the output file")
        buf_len = idaapi.ask_long(0x100, "Specify the length")
        addr = idaapi.ask_addr(idc.get_screen_ea(), "Specify the address")
        buf = idaapi.get_bytes(addr, buf_len)
        print ("fname: %s len: %d, addr: %a" % (fname, buf_len, addr))

        with open(fname, 'wb') as fp:
            fp.write(buf)

    def term(self):
        pass

def PLUGIN_ENTRY():

    return myplugin_t()

#idaapi.msg_clear()

