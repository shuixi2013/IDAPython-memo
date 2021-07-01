from __future__ import print_function

import idautils

import ida_kernwin
import ida_hexrays
import ida_idaapi

import traceback

ACTION_NAME = "hexrays-sample:training-py"

TEST_STANDALONE = True
"""
Standalone mode is ideal when developing the plugin. Just run the script from IDA.
Each time you run it, it cleanly terminates the previous plugin instance.
"""

if TEST_STANDALONE:
    try:
        plg
        plg.term()
        del plg
        print("Terminated previous instance")
    except:
        pass


def find_calls(cfunc):
    class finder_t(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)

            self.results = []
            return

        def visit_insn(self, inst):
            if inst.op == ida_hexrays.cit_expr and inst.cexpr.op == ida_hexrays.cot_call:
                self.results.append(inst)
            return 0

    finder = finder_t()
    finder.apply_to(cfunc.body, None)
    return finder.results


def find_else(cfunc):
    class if_finder_t(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)

            self.results = []
            return

        def visit_insn(self, i):
            if i.op == ida_hexrays.cit_e:
                self.found = i
                return 1  # stop enumeration
            return 0

    iff = if_finder_t(vu.tail.loc.ea)
    if iff.apply_to(vu.cfunc.body, None):
        return iff.found

class findcalls_ah_t(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if vdui:
            self.plugin.print_ifelse_statement(vdui)
        #    self.plugin.print_call_statements(vdui)

        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET



class hexrays_hooks_t(ida_hexrays.Hexrays_Hooks):
    def populating_popup(self, widget, phandle, vu):
        ida_kernwin.attach_action_to_popup(vu.ct, None, ACTION_NAME)
        return 0


class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Hex-Rays IF ELSE statements finder"
    wanted_hotkey = ""
    comment = "Find IF ELSE statements"
    help = ""

    def print_ifelse_statment(self, vu):
        cfunc = vu.cfunc


    def print_call_statements(self, vu):
        cfunc = vu.cfunc
        for stmt in find_calls(cfunc):
            print(f"{stmt.ea:x} call stmt;")


    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_NAME,
                "Find call statements",
                findcalls_ah_t(self),
                "I"))
        self.hr_hooks = hexrays_hooks_t()
        self.hr_hooks.hook()
        return ida_idaapi.PLUGIN_KEEP
            
    def term(self):
        self.hr_hooks.unhook()

    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return my_plugin_t()


if TEST_STANDALONE:
    print("Initializing the plugin")
    PLUGIN_ENTRY().init()
