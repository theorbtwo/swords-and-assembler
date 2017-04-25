from idaapi import *
from idc import *

addr_size = 8


def MachineSized(ea, index):
    addr = ea + addr_size * index
    if addr_size == 4:
        return Dword(addr)
    else:
        return Qword(addr)

bar_count = 0
wanted_vft = MachineSized(ScreenEA(), 0)

while MachineSized(ScreenEA(), 0) == wanted_vft:
    bar_count = bar_count+1
    bar_address = ScreenEA()
    vft = MachineSized(bar_address, 0)
    payload = MachineSized(bar_address, 1)
    name_addr = MachineSized(bar_address, 2)
    name = GetString(name_addr)
    type_byte = Byte(name_addr)
    
    struc_name = ""
    if type_byte == 115:
        # "s", (pointer to a) string.
        struc_name = "bar_string"
    elif type_byte == 98:
        # b for bool
        struc_name = "bar_bool"
    elif type_byte == 102:
        struc_name = "bar_float"
    elif type_byte == 105:
        struc_name = "bar_int"
    elif type_byte == 114:
        # r for ... color?
        struc_name = "bar_int"
    elif type_byte == 117:
        # u for unsigned -- ui for unsigned int, do we need the 2nd char?
        struc_name = "bar_int"
    else:
        print "FIXME: name has type_byte {} at {".format(type_byte)
        break
    
    struc_id = GetStrucIdByName(struc_name)
    if (struc_id==BADADDR):
        Message("Can't get struc id for {}\n".format(struc_name))

    MakeUnknown(bar_address, 3*addr_size-1, 0)

    ret = MakeStructEx(bar_address, -1, struc_name)
    if (ret != True):
        print("MakeStructEx ret {} at {:#x}".format(ret, bar_address))
        break
    MakeNameEx(bar_address, name, SN_AUTO);
    Jump(ScreenEA() + 3*addr_size);

Message("Found {} bar structures".format(bar_count))
