from idaapi import *
from idc import *
if sys.modules.has_key("idajmm"):
    del sys.modules["idajmm"]
from idajmm import *


def rdt_name_entries(ea):
    return Word(ea+0xC)

def rdt_id_entries(ea):
    return Word(ea+0xE)

# FIXME: Shall I add a thing to idajmm for looking up entries in the directory table of
# the PE file?
rsrc_base = LocByName("rsrc_base")
print "rsrc_base: {:#x}".format(rsrc_base)

todo_list = [[rsrc_base, "base"]]

resource_types = {
    1: "cursor",
    2: "bitmap",
    3: "icon",
    4: "menu",
    5: "dialog",
    6: "string",
    7: "fontdir",
    8: "font",
    9: "accelerator",
    10: "rcdata",
    11: "messagetable",
    12: "groupcursor",
    14: "groupicon",
    16: "version",
    17: "dlginclude",
    19: "plugplay",
    20: "vxd",
    21: "anicursor",
    22: "anticon",
    23: "html",
    24: "manifest"
    }

while todo_list:
    todo_item = todo_list[0]
    todo_list = todo_list[1:]

    table_ea = todo_item[0]

    MakeStructHard(table_ea, "resource_dir_table")
    if todo_item[1] != "base":
        MakeNameHarder(table_ea, todo_item[1] + "_table")

    print "Name entries: {}".format(rdt_name_entries(table_ea))
    print "ID entries: {}".format(rdt_id_entries(table_ea))

    entry_ea = table_ea + 0x10
    def handle_entry(entry_ea, table_name, is_named):
        MakeDword(entry_ea)
        MakeDword(entry_ea + 4)
        
        name_raw = Dword(entry_ea)
        if is_named:
            name_effective = name_raw + rsrc_base - 0x80000000
            OpOffEx(entry_ea, 0, REF_OFF32, -1, rsrc_base, 0x80000000)
            name = MakeAndGetString(name_effective, ASCSTR_ULEN2)
        else:
            if todo_item[1] == "base" and name_raw in resource_types:
                name = resource_types[name_raw]
            else:
                name = "{:x}".format(name_raw)
                
        
        if todo_item[1] == "base": 
           child_name = "rsrc_" + name
        else:
            child_name = table_name + "_" + name

        payload = Dword(entry_ea + 4)
        payload_effective = payload + rsrc_base
        if payload & 0x80000000:
            payload_effective = payload_effective - 0x80000000
            OpOffEx(entry_ea + 4, 0, REF_OFF64, -1, rsrc_base, 0x80000000)
            todo_list.append([payload_effective, child_name])
        else:
            OpOffEx(entry_ea + 4, 0, REF_OFF64, -1, rsrc_base, 0)
            MakeNameHarder(payload_effective, "{}_almost".format(child_name))
            MakeNameHarder(RVAAt(payload_effective, True), "{}_data".format(child_name))
    
    for i in range(0, rdt_name_entries(table_ea)):
        handle_entry(entry_ea, todo_item[1], True)
        entry_ea = entry_ea + 8

    for i in range(0, rdt_id_entries(table_ea)):
        handle_entry(entry_ea, todo_item[1], False)
        entry_ea = entry_ea + 8

# Some slightly random notes on dialog resources
"""
http://www.csn.ul.ie/~caolan/pub/winresdump/winresdump/doc/resfmt.txt
 - very out of date, but best I've found...

https://github.com/CyberGrandChallenge/binutils/blob/master/binutils/resbin.c#L423


 
"""
