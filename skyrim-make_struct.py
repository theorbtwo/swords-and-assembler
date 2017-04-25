
from idaapi import *
from idc import *
if sys.modules.has_key("idajmm"):
    del sys.modules["idajmm"]
from idajmm import *

addr_size = 8

__ImageBase = LocByName("__ImageBase")

make_struct = LocByName("make_struct")

# https://msdn.microsoft.com/en-us/library/windows/hardware/ff561499(v=vs.85).aspx
# [abcd]
reg_re_abcd = r"[re]?[abcd][xhl]"
# si,di
reg_re_sidi = r"[re]?[sd]il?"
# r9-r15
reg_re_rn = r"r\d+[dwb]?"
reg_re = "(?:" + reg_re_abcd + "|" + reg_re_sidi + "|" + reg_re_rn + ")"

def reg_to_64(i):
    m = re.match(r"[re]?([abcd])[xhl]", i)
    if m:
        return "r{}x".format(m.group(1))
    m = re.match(r"[re]?([sd])il?", i)
    if m:
        return "r{}i".format(m.group(1))
    m = re.match(r"r(\d+)[dwb]?", i)
    if m:
        return "r{}".format(m.group(1))
    1/0

def reg_to_32(i):
    m = re.match(r"[re]?([abcd])[xhl]", i)
    if m:
        return "e{}x".format(m.group(1))
    m = re.match(r"[re]?([sd])il?", i)
    if m:
        return "e{}i".format(m.group(1))
    m = re.match(r"r(\d+)[dwb]?", i)
    if m:
        return "r{}d".format(m.group(1))
    1/0

def intel_to_num(i):
    if re.match(r"\d+$", i):
        return int(i)
    
    m = re.match(r"([0-9A-F]+)h$", i)
    if m:
        return int(m.group(1), 16)

    1/0

def process_func(f):
    line_num = 0
    line_ea = f
    end = FindFuncEnd(f)
    stored_values = {}
    while line_ea < end:
        done=0
        text = GetDisasmEx(line_ea, GENDSM_FORCE_CODE)
        line_num += 1
        
        text = re.sub(r';.*$', r'', text)
        text = re.sub(r'^\s+', r'', text)
        text = re.sub(r'\s+$', r'', text)
        text = re.sub(r'\s{2,}', r' ', text)
        #print "line {} at {:#x}: {}".format(line_num, line_ea, text)

        if re.match(r"mov rax, rsp", text):
            print "Cannot process this function: {:#x}: rax-based-frame?\n"
            return

        m = re.match(r"sub rsp, (?P<rspoff>.*)", text)
        if m:
            done=1
            stored_values["rspoff"] = m.group("rspoff")

        m = re.match(r"xor (?P<reg>"+reg_re+"), (?P=reg)", text)
        if not done and m:
            done=1
            reg = m.group("reg")
            reg32 = reg_to_64(reg)
            reg64 = reg_to_32(reg)
            #print "xor-self: {} {} {}".format(reg, reg32, reg64)
            stored_values[reg32] = 0
            stored_values[reg64] = 0

        m = re.match(r"lea (?P<reg>"+reg_re+"), (?P<src>.*)", text)
        if not done and m:
            # FAILURE MODE: lea r9d, [rcx+20h], hkAabb_make_struct+29
            done=1
            stored_values[m.group("reg")] = LocByNameEx(line_ea, m.group("src"))

        m = re.match(r"mov (dword ptr )?\[rsp\+"+stored_values["rspoff"]+"\+(?P<stackvar>.*)], (?P<val>.*)", text)
        if not done and m:
            done=1
            val = m.group("val")
            if re.match(r"[0-9A-F]+h?$", val):
                stored_values[m.group("stackvar")] = intel_to_num(val)
            else:
                stored_values[m.group("stackvar")] = stored_values[val]

        # FIXME: This is very similar to the one directly above it. Merge?
        m = re.match(r"mov (?P<dest>"+reg_re+"), (?P<val>.*)", text)
        if not done and m:
            done=1
            val = m.group("val")
            if re.match(r"[0-9A-F]+h?$", val):
                stored_values[m.group("dest")] = intel_to_num(val)
            else:
                stored_values[m.group("dest")] = stored_values[val]
            
    

        if text == "call make_struct":
            # rcx rdx r8 r9
            #print stored_values
            name = GetString(stored_values["rdx"], -1, ASCSTR_C)
            MakeNameHarder(f, "{}_make_struct".format(name))
            
            # serializable_type_info *being_created
            being_created = stored_values["rcx"]
            #print "rcx: being_created {:#x}".format(stored_values["rcx"])
            MakeNameHarder(being_created, "{}_sti".format(name))
            MakeStructHard(being_created, "serializable_type_info")
            
            # char *name, 
            name = GetString(stored_values["rdx"], -1, ASCSTR_C)
            #print "rdx: name          {:#x} {}".format(stored_values["rdx"], name)
            MakeNameHarder(stored_values["rdx"], "a"+name)
            
            # struct serializable_type_info *inner_type, 
            #print "r8 : inner_type    {:#x}".format(stored_values["r8"])
            
            # int the10, 
            #print "r9d: the10         {:#x}".format(stored_values["r9d"])
            
            # void *a5,
            #print "a5:          {:#x}".format(stored_values["a5"])
            
            # int the14,
            #print "the14:       {:#x}".format(stored_values["the14"])
            
            # enum_thing *enum_info,
            #print "enum_info:   {:#x}".format(stored_values["the18"])
            
            # int enum_count,
            #print "enum_count:  {:#x}".format(stored_values["the20"])

            if stored_values["the20"]:
                enum_info = stored_values["the18"]
                enum_count = stored_values["the20"]
                # There seem to be only 1 enum_thing struct here, even when enum_count > 1,
                # which makes me wonder what this refers to.
                MakeStructHard(enum_info, "enum_thing", 1)
                MakeNameHarder(enum_info, "{}_enum_info".format(name))

            # struct_4 *field_info,
            #print "field_info:  {:#x}".format(stored_values["the28"])

            # int field_count,
            #print "field_count: {:#x}".format(stored_values["the30"])

            if stored_values["the30"]:
                # Very basic initial setup thingimies.
                field_info = stored_values["the28"]
                field_count = stored_values["the30"]
                MakeStructHard(field_info, "hkClassMember", field_count)
                MakeArray(field_info, field_count)
                MakeNameHarder(field_info, "{}_field_info".format(name))

                print "field info: {:#x} * {}".format(field_info, field_count)

                for field_i in range(0, field_count):
                    this_field_info = field_info + field_i * 0x28
                    name   = GetString(Qword(this_field_info), -1, ASCSTR_C)
                    offset = Word(this_field_info + 0x1E)
                    print "{:#x}: {}".format(offset, name)

                #raise StandardError, "more to come"
                

            # __int64 the38,
            #print "the38:       {:#x}".format(stored_values["the38"])

            # __int64 the40,
            #print "the40:       {:#x}".format(stored_values["the40"])
            # int the48,
            #print "the48:       {:#x}".format(stored_values["the48"])
            # int the4c
            #print "the4c:       {:#x}".format(stored_values["the4c"])

            return

        if not done:
            raise StandardError, "No thingimy matched for line {} at {:#x}".format(text, line_ea)
        
        line_ea = NextHead(line_ea, line_ea+1024)


xref = RfirstB(make_struct)
while xref and xref != -1:
    print "xref: {:#x}".format(xref)

    f = GetFunctionAttr(xref, FUNCATTR_START)
    process_func(f)
    
    xref = RnextB(make_struct, xref)
    if xref == 0xffffffffffffffff:
        xref = -1

