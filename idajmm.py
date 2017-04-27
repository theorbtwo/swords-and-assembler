from idaapi import *
from idc import *

__ImageBase = LocByName("__ImageBase")

def RVAAt(ea, make=False, pastend=False):
 if make:
     MakeDword(ea)
     reftype = REF_OFF64 | REFINFO_RVA
     if pastend:
         reftype = reftype | REFINFO_PASTEND
     OpOffEx(ea, 0, reftype, -1, __ImageBase, 0)
 return __ImageBase + Dword(ea)

# FIXME: Find a good method of interrogating ida, rather then looking inside
# the PE header, so this can be nicely general.
PE_header = RVAAt(__ImageBase + 0x3C, True)
# MakeNameHarder(PE_header, "PE_header")

PE_machine = Word(PE_header + 4)

if PE_machine == 0x014C:
    mwbits = 32 # i386
elif PE_machine == 0x200:
    mwbits = 64 # itanium
elif PE_machine == 0x8664:
    mwbits = 64 # amd64
else:
    # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx
    print "Unknown PE machine {:#x}".format(PE_machine)
    1/0

mwbytes = mwbits / 8

is8bit  = (mwbits == 8)
is16bit = (mwbits == 16)
is32bit = (mwbits == 32)
is64bit = (mwbits == 64)

if is8bit:
    MakeMw = MakeByte
    Mw = Byte
if is16bit:
    MakeMw = MakeWord
    Mw = Word
if is32bit:
    MakeMw = MakeDword
    Mw = Dword
if is64bit:
    MakeMw = MakeQword
    Mw = Qword

print "mwbits: {}".format(mwbits)

def MakeAndGetString(ea, strtype=ASCSTR_C):
 if (ea == 0):
  return ""
 make_ascii_string(ea, 0, strtype)
 return GetString(ea, -1, strtype)

#def MakeAndGet_builder(make, plain):
#    tempnamne_really = def tempname_sorry_about_that(ea):
#        make(ea)
#        return plain(ea)
#    return tempname_really
           

#MaGByte = MakeAndGet_builder(MakeByte, Byte)
#MaGWord = MakeAndGet_builder(MakeWord, Word)
#MaGDword = MakeAndGet_builder(MakeDword, Dword)
#MaGQword = MakeAndGet_builder(MakeQword, Qword)
#MaGMw = MakeAndGet_builder(MakeMw, Mw)

def MakeNameHarder(ea, name):
 if ea == 0:
  return
 print " {:#x}: {}".format(ea, name)
 ok = MakeNameEx(ea, name, 0)
 i=0
 while not ok:
  ok = MakeNameEx(ea, "{}_{}".format(name, i), 0)
  i = i + 1
  if i > 1000:
    print "Giving up renaming {:#x} to {}_...".format(ea, name)
    break


def MakeStructHard(ea, struc_name, count=1):
    sid = GetStrucIdByName(struc_name)
    if sid == 0xffffffffffffffff:
        print "Couldn't get struct id of {}".format(struc_name)
        1/0

    len = GetStrucSize(sid)
    MakeUnknown(ea, len*count, 0)
    ret = MakeStructEx(ea, len, struc_name)
    if ret != True:
        raise StandardError, "MakeStructEx of {} ({} = {:#x}) at {:#x} len {} ret {}".format(struc_name, sid, sid, ea, len, ret)
    if count > 1:
        ret = MakeArray(ea, count)
        if ret != True:
            raise StandardError, "MakeArray {} at {:#x} len {} each returned {}".format(count, ea, len, ret)
    return ret

def MakeStruct(name):
    print "Making struct {}".format(name)
    if GetStrucIdByName(name) != 0xffffffffffffffff:
        id = GetStrucIdByName(name)
        print "Already exists, id={:#x} {}".format(id, id)
        return id
    else:
        id = AddStrucEx(-1, name, 0)
        print "Created, id={:#x} {}".format(id, id)
        return AddStrucEx(-1, name, 0)

# AddStrucMember(strucid, name, offset, flag, typeid,  nbytes , target, tdelta, reftype
# flag: FF_* constants
#    0000_0400 = FF_DATA should always be set
#    s000_0000 = "size"
#     0..3: BYTE WORD DWORD QWRD
#     4:    TBYT
#     5:    ASCI (used for all strings, typeid is ASCSTR_ constant)
#     6:    STRU (an actual struct instance is here?, typeid is struct id)
#     7:    OWRD (128 bits)
#     8..9: FLOAT, DOUBLE
#     A: PACKREAL
#     B: ALIGN
#     C: 3BYTE
#     D: CUSTOM
#    0aa0_0000 = "argument" -- both nybbles seem to be the same in these?
#     0: void, unknown type or nothing special?
#     1: hexadecimal
#     2: decimal
#     3: char ('x')
#     4: segment
#     5: offset -- things past typeid are valid, typeid is base
#     6: binary
#     7: octal
#     8: enum -- typeid is enum id
#     9: forced operand
#     a: struct offset
#     b: stack variable
#     c: floating point number?
#     d: custom format type
# typeid: definition depends on flags, -1 if N/A
# target, tdelta, reftype only for when you want a complex offset expression.
# target: -1 to let ida calculate
# tdelta: normally 0
# reftype: REF_* constant
#  define REF_OFF64   9 // 64bit full offset
#  define REFINFO_RVA     0x10 // based reference (rva)

# FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA = FF_DWRD | FF_0FF | FF_1OFF | FF_DATA


def AddStrucMember_checked(sid, name, offset, flag, typeid, nbytes, target=None, tdelta=None, reftype=None):
    ret = None
    if (target is None):
        ret = AddStrucMember(sid, name, offset, flag, typeid, nbytes)
    else:
        ret = AddStrucMember(sid, name, offset, flag, typeid, nbytes, target, tdelta, reftype)
    print "AddStrucMember {} returned {:#x}".format(name, ret)
