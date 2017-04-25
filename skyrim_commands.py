from idaapi import *
from idc import *

current_addr = ScreenEA()

def DwordIn(base, n):
 return Dword(base+4*n)

def QwordIn(base, n):
 return Qword(base+8*n)

def MakeAndGetString(ea):
 if (ea == 0):
  return ""
 make_ascii_string(ea, 0, ASCSTR_C)
 return GetString(ea)

def MakeStructHard(ea, struc_name):
 sid = GetStrucIdByName(struc_name)
 len = GetStrucSize(sid)
 MakeUnknown(ea, len, 0)
 MakeStructEx(ea, len, struc_name)

def MakeNameHarder(ea, name):
 if ea == 0:
  return
 print " {:#x}: {}".format(ea, name)
 ok = MakeNameEx(ea, name, 0)
 i=0
 while not ok:
  ok = MakeNameEx(ea, "{}_{}".format(name, i), 0)
  i = i + 1
  if i > 100:
    print "Giving up renaming {:#x} to {}_...".format(ea, name)
    break

repeats=0
parse_wanted = 0
while 1:
 
 name        = MakeAndGetString(qword_in(current_addr, 0))
 short_name  = MakeAndGetString(qword_in(current_addr, 1))
 id          = qword_in(current_addr, 2)
 help_text   = MakeAndGetString(qword_in(current_addr, 3))
 arg_count   = Word(current_addr + 0x22)
 arg_info_base = qword_in(current_addr, 5)
 execute     = qword_in(current_addr, 6)
 parse       = qword_in(current_addr, 7)
 compile_q   = qword_in(current_addr, 8)
 mostly_zero = qword_in(current_addr, 9)
 
 if parse_wanted == 0:
  parse_wanted = parse
 if parse != parse_wanted:
  break

 MakeStructHard(current_addr, "console_command")

 print "<td>{:#x}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>".format(id, name, short_name, help_text, arg_count)
 if mostly_zero:
  print " mostly zero is {}".format(mostly_zero)

 for i in range(arg_count):
  arg_info = arg_info_base + i*0x10
  MakeStructHard(arg_info, "command_arg")
  arg_text = MakeAndGetString(Qword(arg_info))
  arg_type_n = Dword(arg_info + 8)
  arg_is_optional = Dword(arg_info + 0xC)
  if arg_is_optional:
   arg_text = "[{}]".format(arg_text)
  print " arg #{} at {:#x}: {}".format(i, arg_info, arg_text)

 MakeNameHarder(execute, "{}_exec".format(name))

 current_addr = current_addr + 10*8
 repeats = repeats + 1