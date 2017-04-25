# IDA Python RTTI parser ~pod2g 06/2013
# http://blog.quarkslab.com/visual-c-rtti-inspection.html

from idaapi import *
from idc import *
if sys.modules.has_key("idajmm"):
    del sys.modules["idajmm"]
from idajmm import *

__ImageBase = LocByName("__ImageBase")

if is32bit:
    porr_reftype = REF_OFF32
    porr_base    = 0
if is64bit:
    porr_reftype = REFINFO_RVA | REF_OFF64
    porr_base    = __ImageBase

# _s__RTTICompleteObjectLocator2 29522 [29523, 29524, 29525, 29526, 29527, 29528, ]
#  public signature        at  0 type 58898 [unsigned long len 4]
#  public offset           at  4 type 58898 [unsigned long len 4]
#  public cdOffset         at  8 type 58898 [unsigned long len 4]
#  public pTypeDescriptor  at  c type 29515 [8 byte pointer to 28
#  public pClassDescriptor at 14 type 29521
rcol_sid = MakeStruct("_s__RTTICompleteObjectLocator")
AddStrucMember_checked(rcol_sid, "signature",	           0x00,    FF_DATA | FF_DWRD,	-1,	4);
AddStrucMember_checked(rcol_sid, "offset",	           0x04,    FF_DATA | FF_DWRD,	-1,	4);
AddStrucMember_checked(rcol_sid, "cdOffset",	           0x08,    FF_DATA | FF_DWRD,	-1,	4);
AddStrucMember_checked(rcol_sid, "pTypeDescriptor",	   0x0C,    FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA, porr_base, 4, 0xFFFFFFFFFFFFFFFF, 0, porr_reftype);
AddStrucMember_checked(rcol_sid, "pClassDescriptor",	   0x10,    FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA, porr_base, 4, 0xFFFFFFFFFFFFFFFF, 0, porr_reftype);
AddStrucMember_checked(rcol_sid, "pCompleteObjectLocator", 0x14,    FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA, porr_base, 4, 0xFFFFFFFFFFFFFFFF, 0, porr_reftype);

rchd_sid = MakeStruct("_s__RTTIClassHierarchyDescriptor")
AddStrucMember_checked(rchd_sid, "signature",                 0,    FF_DATA | FF_DWRD, -1, 4)
AddStrucMember_checked(rchd_sid, "attributes",                4,    FF_DATA | FF_DWRD, -1, 4)
AddStrucMember_checked(rchd_sid, "numBaseClasses",            8,    FF_DATA | FF_DWRD, -1, 4)
AddStrucMember_checked(rchd_sid, "pBaseClassArray",         0xC,    FF_DATA | FF_DWRD | FF_0OFF | FF_1OFF, porr_base, 4, 0xFFFFFFFFFFFFFFFF, 0, porr_reftype);

rbcd_sid = MakeStruct("_s__RTTIBaseClassDescriptor")
# FIXME: change to the "offical" names?
AddStrucMember_checked(rbcd_sid, "pTypeDescriptor",           0, FF_DATA | FF_DWRD | FF_0OFF | FF_1OFF, porr_base, 4, 0xFFFFFFFFFFFFFFFF, 0, porr_reftype);
AddStrucMember_checked(rbcd_sid, "count_subclasses",          4, FF_DATA | FF_DWRD, -1, 4)
AddStrucMember_checked(rbcd_sid, "mdisp",                     8, FF_DATA | FF_DWRD, -1, 4)
AddStrucMember_checked(rbcd_sid, "pdisp",                   0xc, FF_DATA | FF_DWRD, -1, 4)
AddStrucMember_checked(rbcd_sid, "vdisp",                  0x10, FF_DATA | FF_DWRD, -1, 4)
AddStrucMember_checked(rbcd_sid, "attrs",                  0x14, FF_DATA | FF_DWRD, -1, 4)

first_seg = FirstSeg()
last_seg = FirstSeg()
for seg in Segments():
    if seg > last_seg:
        last_seg = seg
    if seg < first_seg:
        first_seg = seg

def in_image(ea):
    return ea >= first_seg and ea <= SegEnd(last_seg)

def get_class_name(name_addr, prefixlen=4):
    s = Demangle('??_7' + GetString(name_addr + prefixlen) + '6B@', 8)
    if s != None:
        return s[0:len(s)-11]
    else:
        return GetString(name_addr)




# start: Where we should start searching from, next time.
start = first_seg
print "Starting at {:#x}".format(start)
while True:
    f = BADADDR
    prefixlen = 0
    poss = FindBinary(start, SEARCH_DOWN, "2E 3F 41 55") # .?AU
    if (poss < f):
        prefixlen = 4
        f = poss
    poss = FindBinary(start, SEARCH_DOWN, "2E 3F 41 56") # .?AV
    if (poss < f):
        prefixlen = 4
        f = poss
    poss = FindBinary(start, SEARCH_DOWN, "2E 50 41 56") # .PAV
    if (poss < f):
        prefixlen = 5
        f = poss
        
    if f == BADADDR:
        break
    class_name = get_class_name(f)
    start = f + prefixlen
    # http://www.geoffchappell.com/studies/msvc/language/predefined/index.htm?tx=12 -- _TypeDescriptor
    rtd = f - 2*mwbytes
    MakeNameHarder(rtd, "{}_rtd".format(class_name))
    MakeRptCmt(rtd, "{} (std::type_info)".format(class_name));
    
    MakeUnknown(rtd, mwbytes*2, 0)
    MakeMw(rtd)
    OpOff(rtd, 0, 0)
    
    MakeName(rtd+mwbytes, "")
    MakeMw(rtd+mwbytes)

    make_ascii_string(rtd+mwbytes*2, 0, ASCSTR_C)

# Looking for cross-references turns out to not be as useful as you might hope, because the 32-bit rva pointers
# that are used for referencing on this level don't get picked up as such by the autoanalysis.
# Instead, it seems we must search every four-byte boundry for it's own address minus 6*4?
# For the moment, just the .rdata section, hardcoded?

seg = SegByName(".rdata")
start = SegByBase(seg)
image_base = first_seg

last_report = 0
report_freq = 1024*1024
while True:
    # The "signature" field is always 1, which is a bit like signing "X", but it's somewhere to start.
    if is32bit:
        f = FindBinary(start, SEARCH_DOWN, "00 00 00 00")
    else:
        f = FindBinary(start, SEARCH_DOWN, "01 00 00 00")
    if f == BADADDR:
        break
    start = f+4

    if f > last_report+report_freq:
        print "F now {:#x}".format(f)
        last_report = f

    if image_base+Dword(f+0x14) != f:
        continue


    # The pTypeDescriptor points to a typedescriptor, which we have hopefully already given a name above,
    # but go ahead and get the name again, so we can use it to rename everything else.
    rtd = image_base + Dword(f + 3*4)
    class_name = get_class_name(rtd + 0x10)
    print "Class name {}".format(class_name)

    MakeStructHard(f, "_s__RTTICompleteObjectLocator")
    MakeNameHarder(f, "{}_rcol".format(class_name))
    print " CompleteObjectLocator at {:#x}".format(f)

    rchd = image_base + Dword(f + 4*4)
    print " class heierarchy descriptor: {:#x}".format(rchd)
    MakeStructHard(rchd, "_s__RTTIClassHierarchyDescriptor")
    MakeNameHarder(rchd, "{}_rchd".format(class_name))
    numBaseClasses = Dword(rchd + 0x8)
    rbca = image_base + Dword(rchd + 3*4)

    print " rtti base class array {:#x}".format(rbca)
    MakeNameHarder(rbca, "{}_rbca".format(class_name))
    MakeUnknown(rbca, numBaseClasses * 4, 0)
    MakeDword(rbca)
    OpOffEx(rbca, 0, REF_OFF64 | REFINFO_RVA, -1, image_base, 0)
    MakeArray(rbca, numBaseClasses)

    # The number of classes for whom this is the last base class, by index in the rbca.
    foo = {}
    summary_string = ""
    depth = 0
    for i in range(numBaseClasses):
        rbcd = image_base + Dword(rbca + i * 4)
        MakeStructHard(rbcd, "_s__RTTIBaseClassDescriptor")
        base_rta = RVAAt(rbcd)
        base_rta_name = GetTrueName(base_rta)
        subclasses = Dword(rbcd + 1*4)
        mdisp = Dword(rbcd + 2*4)
        pdisp = Dword(rbcd + 3*4)
        if pdisp == 0xFFFFFFFF:
            pdisp = -1
        vdisp = Dword(rbcd + 4*4)
        attrs = Dword(rbcd + 5*4)

        print " rbcd #{} at {:#x}: {} subs {}, mpvdisp {} {} {} attr {:#x}".format(
            i, rbcd, base_rta_name, subclasses, mdisp, pdisp, vdisp, attrs)

        summary_string += "[{:4x}] {} {}\n".format(mdisp, " " * depth, base_rta_name)

        #if mdisp != 0:
        #    1/0
        if pdisp != -1:
            2/0
        if vdisp != 0:
            3/0

        if depth == 0:
            print " Make two structs: members and vtables"
        elif depth == 1:
            print " Make an element of the members struct at {} which is {}".format(mdisp, base_rta_name)
        else:
            pass


        if subclasses > 0:
            end_at = i + subclasses
            foo[end_at] = foo.get(end_at, 0) + 1
            #summary_string += "["
            depth += 1

        end_brackets = foo.get(i, 0)
        if end_brackets > 0:
            #summary_string += "]" * end_brackets
            depth -= end_brackets

        # depth is now the depth of the next thing!

    print summary_string, "\n"

# It is possible, IE AlchemyItem, for a single _rtd to have multiple _rcol structures.
# They have different _rcol.offset, but all point to the same rchd, and thus the same
# list of RBCDs.  They will, however, each have their own vtable.
