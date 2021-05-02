import ida_kernwin
import idaapi
import pefile


def save_pe(ea=0x40dff0):
    image = idaapi.get_bytes(ea, idaapi.inf_get_max_ea())
    # print (dos_hdr)
    try:
        pe = pefile.PE(data=image)
        if (ea + pe.DOS_HEADER.e_lfanew > idaapi.inf_get_max_ea()):
            return 0
    except pefile.PEFormatError as e:
        print('0x%x: PE format error:%s' % (ea, e))
        return 0
    except Exception as e:
        print(e)
        return 0

    max_off = 0

    for s in pe.sections:
        if (s.SizeOfRawData + s.PointerToRawData > max_off):
            max_off = s.SizeOfRawData + s.PointerToRawData
    dump_fname = 'MZ_%x.pe' % ea
    with open(dump_fname, 'wb') as fp:
        fp.write(idaapi.get_bytes(ea, max_off))
    print("Save 0x%x with length %d to file: %s" % (ea, max_off, dump_fname))
    return max_off


def search_byte_seq(pattern, st=idaapi.inf_get_min_ea(), end=idaapi.inf_get_max_ea()):
    binvec = idaapi.compiled_binpat_vec_t()
    idaapi.parse_binpat_str(binvec, st, pattern, 16)
    return idaapi.bin_search(st, end, binvec,
                             idaapi.BIN_SEARCH_FORWARD | idaapi.BIN_SEARCH_CASE | idaapi.BIN_SEARCH_NOBREAK)


class dump_pe_files_action_handler_t(idaapi.action_handler_t):
    action = None

    def __init__(self, _action):
        super().__init__()

        self.action = _action
        print('register action name: %s' % self.action.actname)

    def activate(self, ctx):
        print("action activate %s" % self.action.actname)
        self.action.run(2)
        return False

    def update(self, ctx):
        print("action update")
        return idaapi.AST_ENABLE_ALWAYS


class action_ctx_t(idaapi.plugmod_t):
    dumped_files = None
    actname = "DumpPE2"

    menu_ok = False

    def __init__(self):
        print("action_ctx_t ctor")
        self.dumped_files = idaapi.netnode()
        self.dumped_files.create("$ dumped files")

        idaapi.register_action(idaapi.action_desc_t(self.actname, 'Dump embedded PE files via IDAPython',
                                                    dump_pe_files_action_handler_t(self), 'Ctrl-F2'))
        self.menu_ok = idaapi.attach_action_to_menu('File/Produce file/', self.actname, idaapi.SETMENU_INS)

    def __del__(self):
        ida_kernwin.msg("unloaded action_ctx\n")

    def dump_pe(self, start=None, end=None):
        if not start:
            start = idaapi.inf_get_min_ea()
        if not end:
            end = idaapi.inf_get_max_ea()
        ea = start
        while ea < end:

            ea = search_byte_seq('4D 5A', st=ea)
            # ea = idc.find_binary(ea, idc.SEARCH_DOWN, '4D 5A') --> deprecated
            if ea != idaapi.BADADDR:
                if self.dumped_files.altval(ea):
                    print('%a: Already dumped' % ea)
                else:
                    dumpe_len = save_pe(ea)
                    if dumpe_len:
                        self.dumped_files.altset(ea, dumpe_len)
                ea = ea + 1
            else:
                break

    def run(self, arg):

        ida_kernwin.msg("run() called with %d!\n" % arg)
        idaapi.msg_clear()
        self.dump_pe()
        return (arg % 2) == 0


class pe_extract_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Exs3:PE Extractor"
    wanted_hotkey = "Ctrl-Shift-F3"

    def init(self):
        idaapi.msg_clear()
        ctx = action_ctx_t()
        if ctx.menu_ok:
            return ctx
        del ctx
        return idaapi.PLUGIN_UNL

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return pe_extract_plugin_t()
