"""

Sample File access logger

(based on debughook.py)

Copyright (c) 1990-2009 Hex-Rays
ALL RIGHTS RESERVED.

"""

import ida_idaapi
import ida_name
import ida_dbg
import ida_idd
import ida_bytes
import ida_kernwin
import ida_ida
import idaapi
import idc


def set_breakpoint(addr):
    if addr == idaapi.BADADDR:
        return False

    idaapi.add_bpt(addr, 0, idaapi.BPT_SOFT)
    print("Add Breakpoint : 0x%x" % addr)
    idaapi.enable_bpt(addr, True)
    bpt = idaapi.bpt_t()
    idaapi.get_bpt(addr, bpt)
    bpt.elang = 'Python'
    bpt.condition = """esp = idc.get_reg_value("ESP")
#ida_dbg.invalidate_dbgmem_contents(esp, 1024)
fn_ea = ida_bytes.get_wide_dword(esp + 4)
#if not ida_bytes.is_mapped(fn_ea):
#    ida_dbg.invalidate_dbgmem_config()
fn = idc.get_strlit_contents(fn_ea, -1, idc.STRTYPE_C_16)
print("CreateFile('%s')" % fn)
return False"""
    idaapi.update_bpt(bpt)
    return True


eip_ea = lambda: idaapi.get_reg_val('EIP')


class ApiDbgHook(ida_dbg.DBG_Hooks):
    
    def __init(self):
        #print("constructor")
        self.added_bpts = False
        #return super().__init__()
    
    def dbg_run_to(self, pid, tid=0, ea=0):
        #idaapi.msg_clear()
        print("got run_to: pid: %d tid: %d ea: 0x%x" % (pid, tid, ea))

        self.added_bpts = False

        return 0

    def dbg_suspend_process(self):
        if self.added_bpts:
            return 0
        print("got suspend process: 0x%x" % eip_ea())
        # resolve addresses
        self.createfile = idaapi.get_name_ea(idaapi.BADADDR, "kernel32_CreateFileW")

        print("Resolve CreateFileW: 0x%x" % self.createfile)
        if self.createfile == ida_idaapi.BADADDR:
            print("Failed to resolve API address!")
            ida_dbg.request_exit_process()
            ida_dbg.run_requests()

        set_breakpoint(self.createfile)
        # now resume
        ida_dbg.continue_process()
        self.added_bpts = True
        return 0

    """def dbg_bpt(self, tid, ea):
            # createfile?
            if ea == self.createfile:
                esp = idc.get_reg_value("ESP")
                ida_dbg.invalidate_dbgmem_contents(esp, 1024);
                fn_ea = ida_bytes.get_wide_dword(esp + 4)
                if not ida_bytes.is_mapped(fn_ea):
                    print('0x%x: is_not_mapped' % fn_ea)
                    ida_dbg.invalidate_dbgmem_config()

                fn = idc.get_strlit_contents(fn_ea, -1, idc.STRTYPE_C_16)
                # log the access
                print("CreateFile('%s')" % fn)
                ida_dbg.continue_process()
            return 0"""

    def dbg_process_exit(self, pid, tid, ea, code):
        if self.added_bpts and self.createfile != ida_idaapi.BADADDR:
            idc.del_bpt(self.createfile)
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        return 0


# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
        debughook = None
except:
    pass

# Install the debug hook
debughook = ApiDbgHook()
debughook.hook()
print("Installed debugger hook!")

#idaapi.get_name_ea(idaapi.BADADDR, '_wmain_0')
if ida_kernwin.ask_yn(1, "HIDECANCEL\nrun now?") == 1:
    ida_dbg.load_debugger('win32', False)
    #idaapi.run_to(idaapi.get_name_ea(idaapi.BADADDR, '_wmain_0'))
    ida_dbg.run_to(ida_ida.cvar.inf.start_ea)
