from idaapi import *
from idc import *
if sys.modules.has_key("idajmm"):
    del sys.modules["idajmm"]
from idajmm import *

# FIXME: Why does this not get imported from idajmm?
__ImageBase = LocByName("__ImageBase")



root_todo_item = [ScreenEA(), "CRuntimeClass", "(ScreenEA at start)"]
todo_list = [root_todo_item]

def get_names(ea):
    ret = atoa(ea)
    fo = GetFuncOffset(ea)
    if (fo):
        ret = ret + " = " + fo
    return ret

overall_find_i = 0
while todo_list:
    todo_item = todo_list[0]
    todo_list = todo_list[1:]

    todo_addr = todo_item[0]
    todo_kind = todo_item[1]
    todo_path = todo_item[2]

    print "{:#x}: {} # {}".format(todo_addr, todo_kind, todo_path)

    name = MakeAndGetString(Mw(todo_addr))
    print " ", name
    crc_name = name + "_CRuntimeClass"
    MakeNameHarder(todo_addr, crc_name)
    # FIXME: Define this struct!
    MakeStructHard(todo_addr, "CRuntimeClass")
    size = Mw(todo_addr + mwbytes)

    this_sid = GetStrucIdByName(name)
    if this_sid == 0xffffffffffffffff:
        this_sid = AddStrucEx(-1, name, 0)
    print "sid for {} is {:#x}".format(name, this_sid)
    
    endmember = GetMemberName(this_sid, size-1)
    if not endmember:
        print "End member does not already exist, adding"
        AddStrucMember(this_sid, "end_marker", size-1, FF_DATA|FF_BYTE, -1, 1)

    # FIXME: Tell the difference between parent-is-function (dynamically linked) and parent-is-struct (staticly linked)
    parent = Mw(todo_addr + mwbytes * 4)
    if parent:
        parent_name = MakeAndGetString(Mw(parent))
        parent_size = Mw(parent + mwbytes)
        parent_sid  = GetStrucIdByName(parent_name)
        print "Adding parent to struct, {} {:#x} len {}".format(parent_name, parent_sid, parent_size)

        # no need to add a parent if there's something already at offset 0
        if not GetMemberName(this_sid, 0):
            # If the size of this is the same as the size of the parent, then the end marker will conflict with
            # the parent, so get rid of it.
            if size == parent_size:
                DelStrucMember(this_sid, size-1)
            
            ret = AddStrucMember(this_sid, "parent", 0, FF_DATA|FF_STRU, parent_sid, parent_size)
            print "addstrucmember returned {} = {:#x}".format(ret, ret)
            if ret:
                break


    # Search for references to this.  (The hard way, not via xrefs, so we catch even if it's in currently-undefined space.)
    search_start = __ImageBase
    while True:
        search_ret = FindBinary(search_start, SEARCH_DOWN|SEARCH_NEXT, "{:x}".format(todo_addr), 16)
        if search_ret == 0xffffffffffffffff:
            break

        search_start = search_ret
        
        align = (search_ret % mwbytes)
        overall_find_i += 1
        
        print "Search ofi {} returned {:#x} = {}, align={}".format(overall_find_i, search_ret, get_names(search_ret), align)
        if align != 0:
            print " Misaligned, skipping"
            continue

        if SegName(search_ret) == ".rsrc":
            print "In resource, skipping"
            continue

        flags = GetFlags(PrevNotTail(search_ret))
        #print " Flags: {:#x}".format(flags)
        global left
        left = flags

        # Bad: 0x4003ec
        def phex(tag, val):
            print "  {}: {:#x}".format(tag, val)
        def domask(tag, maskval):
            global left
            phex(tag, left & maskval)
            left = left & ~maskval

        if (False):
            domask("MS_VAL", MS_VAL)
            domask("FF_IVL", FF_IVL)
            domask("MS_CLS", MS_CLS)
            domask("MS_COMM", MS_COMM)
            domask("MS_0TYPE", MS_0TYPE)
            domask("MS_1TYPE", MS_0TYPE)
            phex("left", left)

        cls = flags & MS_CLS
        if cls != 0x400 and cls != 0:
            print " Not data, skipping (MS_CLS is {:#x})".format(flags & MS_CLS)
            continue
        
        todo_list.append([search_ret - mwbytes*4, "CRuntimeClass", "ofi {}, ref to {}, flags={:#x}".format(overall_find_i, name, flags)])
