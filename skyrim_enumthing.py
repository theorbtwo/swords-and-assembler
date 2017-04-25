from idaapi import *
from idc import *

addr_size = 8


def Pointer(ea):
    if addr_size == 4:
        return Dword(ea)
    else:
        return Qword(ea)

enum_thing = ScreenEA();
enum_name_addr = Pointer(enum_thing);
make_ascii_string(enum_name_addr, 0, ASCSTR_C);
enum_name = GetString(enum_name_addr);
MakeNameEx(enum_thing, "enum_thing_{}".format(enum_name), 0);
Message("enum {}\n".format(enum_name));
# Find or create the enum -- find with GetEnum(name), create with AddEnum(idx, name, flag)

values_addr  = Pointer(enum_thing + 1*addr_size);
MakeNameEx(values_addr, "{}_enum_values".format(enum_name), 0);
values_count = Pointer(enum_thing + 2*addr_size);

enum_id = AddEnum(-1, enum_name, 0);
if enum_id==BADADDR:
    Message("Cannot create enum?\n");

current_value_addr = values_addr;
while True:
    value_value = Pointer(current_value_addr);
    value_name = GetString(Pointer(current_value_addr + 1*addr_size));
    Message(" {}: {}\n".format(value_value, value_name));
    current_value_addr = current_value_addr + 2*addr_size;
    
    AddConstEx(enum_id, value_name, value_value, -1)

    values_count = values_count-1;
    
    if not(values_count):
        break;
Message("\n");
