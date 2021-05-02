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


class ApiDbgHook(ida_dbg.DBG_Hooks):

    def dbg_process_start(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
        idaapi.msg_clear()
        print(f"process_start(pid: {pid}, tid: {tid}, ea: {ea:x}, modinfo_name:{modinfo_name}, modeinfo_base:{modinfo_base:x}, modinfo_size:{modinfo_size})")
        idc = get_idc_name()
        if idc:
            print('Executing idc:', idc)
            if idaapi.exec_idc_script(idaapi.idc_value_t(0), idc, 'main', idaapi.idc_value_t(0), 0):
                print('errbuf')
            else:
                print('ok')

        return 0

    def dbg_process_attach(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):

        print(f"process_attach(pid: {pid}, tid: {tid}, ea: {ea:x}, modinfo_name:{modinfo_name}, modeinfo_base:{modinfo_base:x}, modinfo_size:{modinfo_size})")

        #exec_idc_script()
        return 0

    def dbg_run_to(self, pid, tid=0, ea=0):
        print("got run_to: pid: %d tid: %d ea: 0x%x" % (pid, tid, ea))
        idaapi.continue_process()
        #return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        return 0

node_name = "$ debugger idc file"
mynode = idaapi.netnode(node_name)

get_idc_name = lambda: mynode.supstr(0)
set_idc_name = lambda idc_name: mynode.create(node_name) and mynode.supset(0, idc_name)

def ask_idc_name():
    newidc = idaapi.ask_file(False, '*.idc', 'Specify the script to run upon debugger launch')
    if newidc:
        set_idc_name(newidc)
        print(f"Script {newidc} will be run when the debugger is launched")


# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
        debughook = None
except:
    pass

idaapi.msg_clear()
ask_idc_name()


# Install the debug hook
debughook = ApiDbgHook()
debughook.hook()
print("Installed debugger hook!")

#ida_dbg.load_debugger('bochs', False)
ida_dbg.load_debugger('win32', False)
ida_dbg.run_to(ida_ida.cvar.inf.start_ea)
