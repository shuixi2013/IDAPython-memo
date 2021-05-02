

import idc
import idaapi



def hide_pattern(pattern):
    nxt = idaapi.inf_get_min_ea()
    end = idaapi.inf_get_max_ea()

    #print(f'{nxt:x}, {end:x}')
    while nxt  < end:
        nxt = idc.find_binary(nxt, idc.SEARCH_DOWN, pattern)
        if nxt == idaapi.BADADDR:
            break
        idc.patch_dword(nxt, 0x90909090)
        idc.patch_byte(nxt+4, 0x90)
        idc.del_items(nxt, 1, 5)
        idaapi.add_hidden_range(nxt, nxt+5, '', '', '', 0xffffffff)
        print (f'hide {nxt:x} - {nxt+5:x}')
        nxt = nxt + 5
        idc.create_insn(nxt)
        print('create instr %x' % nxt)



idaapi.msg_clear()
hide_pattern('79 03 78 01')
hide_pattern('70 03 71 01')
hide_pattern('72 03 73 01')
idaapi.refresh_idaview_anyway()
