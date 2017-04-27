from idaapi import *
from idc import *
from idajmm import *

__ImageBase = LocByName("__ImageBase")

# http://llvm.org/docs/doxygen/html/WinException_8cpp_source.html, around line 657, defines these
ehflag_eid = AddEnum(0, "EHFlag", FF_DATA | FF_DWRD);
if ehflag_eid == 0xFFFFFFFFFFFFFFFF:
    ehflag_eid = GetEnum("EHFlag")
SetEnumBf(ehflag_eid, 1)
AddConstEx(ehflag_eid, "EHFLAG_NOASYNC", 1, 1)
# Set: no exceptions are allowed to unwind to the caller of this function
AddConstEx(ehflag_eid, "EHFLAG_NOEXCEPT", 4, 4)

# Oddly, the first time I run this, only the structs themselves appear.
# It requires another run before they have actual members...
# Only place I've seen this structure given correctly is http://www.hexblog.com/wp-content/uploads/2012/06/Recon-2012-Skochinsky-Compiler-Internals.pdf page 21
funcinfo_sid = MakeStruct("_s_FuncInfo")
AddStrucMember_checked(funcinfo_sid,"magicNumber",	0x00,	FF_DATA | FF_DWRD,	-1,	4);
AddStrucMember_checked(funcinfo_sid,"maxState",		0x04,	FF_DATA | FF_DWRD,	-1,	4);
AddStrucMember_checked(funcinfo_sid,"dispUnwindMap",	0x08,	FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA, __ImageBase, 4, 0xFFFFFFFFFFFFFFFF, 0, REFINFO_RVA | REF_OFF64);
AddStrucMember_checked(funcinfo_sid,"nTryBlocks",	0x0C,	FF_DATA | FF_DWRD,	-1,	4);
AddStrucMember_checked(funcinfo_sid,"dispTryBlockMap",	0x10,	FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA, __ImageBase, 4, 0xFFFFFFFFFFFFFFFF, 0, REFINFO_RVA | REF_OFF64);
AddStrucMember_checked(funcinfo_sid,"nIPMapEntries",	0x14,	FF_DATA | FF_DWRD,	-1,	4);
AddStrucMember_checked(funcinfo_sid,"dispIPtoStateMap",	0x18,	FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA, __ImageBase, 4, 0xFFFFFFFFFFFFFFFF, 0, REFINFO_RVA | REF_OFF64);
AddStrucMember_checked(funcinfo_sid,"dispUwindHelp",	0x1C,	FF_DATA | FF_DWRD,	-1,	4);
AddStrucMember_checked(funcinfo_sid,"dispESTypeList",	0x20,	FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA, __ImageBase, 4, 0xFFFFFFFFFFFFFFFF, 0, REFINFO_RVA | REF_OFF64);
AddStrucMember_checked(funcinfo_sid,"EHFlags",		0x24,	FF_DWRD | FF_0ENUM | FF_1ENUM | FF_DATA,  ehflag_eid,	4);

ume_sid = MakeStruct("_s_UnwindMapEntry")
AddStrucMember_checked(ume_sid, "ToState",    0, FF_DATA | FF_DWRD, -1, 4);
AddStrucMember_checked(ume_sid, "Action",     4, FF_DATA | FF_DWRD | FF_0OFF | FF_1OFF, __ImageBase, 4, 0xFFFFFFFFFFFFFFFF, 0, REFINFO_RVA | REF_OFF64);

id = MakeStruct("IptoStateMapEntry")
# "ip" is a reserved word in ida/x64.
AddStrucMember_checked(id, "_Ip",   0, FF_DATA | FF_DWRD | FF_0OFF | FF_1OFF, __ImageBase, 4, 0xFFFFFFFFFFFFFFFF, 0, REFINFO_RVA | REF_OFF64);
AddStrucMember_checked(id, "State", 4, FF_DATA | FF_DWRD, -1, 4)

id = MakeStruct("RUNTIME_FUNCTION");
print "id, from get: {}".format(id)
mid = AddStrucMember(id,"FunctionStart",      0,    FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA,	__ImageBase,	4,	0xFFFFFFFFFFFFFFFF,	0,	REFINFO_RVA | REF_OFF64);
mid = AddStrucMember(id,"FunctionEnd",	    0x4,    FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA,	__ImageBase,	4,	0xFFFFFFFFFFFFFFFF,	0,	REFINFO_PASTEND | REFINFO_RVA | REF_OFF64);
mid = AddStrucMember(id,"UnwindData",       0x8,    FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA,	__ImageBase,	4,	0xFFFFFFFFFFFFFFFF,	0,	REFINFO_RVA | REF_OFF64);

id = MakeStruct("UNWIND_INFO");
mid = AddStrucMember(id,"Ver3_Flags",	    0,	    FF_BYTE | FF_DATA,	-1,	1);
mid = AddStrucMember(id,"PrologSize",	    0X1,    FF_BYTE | FF_DATA,	-1,	1);
mid = AddStrucMember(id,"CntUnwindCodes",   0X2,    FF_BYTE | FF_DATA,	-1,	1);
mid = AddStrucMember(id,"FrReg_FrRegOff",   0X3,    FF_BYTE | FF_DATA,	-1,	1);

id = MakeStruct("UNWIND_CODE");
mid = AddStrucMember(id,"PrologOff",	    0,	    FF_BYTE | FF_DATA,	-1,	1);
mid = AddStrucMember(id,"OpCode_OpInfo",    0X1,    FF_BYTE | FF_DATA,	-1,	1);

id = MakeStruct("UNWIND_CODE_2SLOT");
mid = AddStrucMember(id,"PrologOff",	    0,	    FF_BYTE | FF_DATA,	-1,	1);
mid = AddStrucMember(id,"OpCode_OpInfo",    0X1,    FF_BYTE | FF_DATA,	-1,	1);
mid = AddStrucMember(id,"Extra",            0X2,    FF_WORD | FF_DATA,	-1,	2);

id = MakeStruct("UNWIND_CODE_3SLOT");
mid = AddStrucMember(id,"PrologOff",	    0,	    FF_BYTE | FF_DATA,	-1,	1);
mid = AddStrucMember(id,"OpCode_OpInfo",    0X1,    FF_BYTE | FF_DATA,	-1,	1);
mid = AddStrucMember(id,"Extra",            0X2,    FF_DWRD | FF_DATA,	-1,	4);

id = MakeStruct("C_SCOPE_TABLE");
mid = AddStrucMember(id,"Begin",	0,	FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA,	__ImageBase,	4,	0XFFFFFFFFFFFFFFFF,	0,	REFINFO_RVA | REF_OFF64);
mid = AddStrucMember(id,"End",	        0X4,	FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA,	__ImageBase,	4,	0XFFFFFFFFFFFFFFFF,	0,	REFINFO_PASTEND | REFINFO_RVA | REF_OFF64);
mid = AddStrucMember(id,"Handler",	0X8,	FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA,	__ImageBase,	4,	0XFFFFFFFFFFFFFFFF,	0,	REFINFO_RVA | REF_OFF64);
mid = AddStrucMember(id,"Target",	0XC,	FF_DWRD | FF_0OFF | FF_1OFF | FF_DATA,	__ImageBase,	4,	0XFFFFFFFFFFFFFFFF,	0,	REFINFO_RVA | REF_OFF64);

# https://github.com/DFHack/dfhack/blob/master/reversing/ms_ehseh.idc
id = MakeStruct("_s_HandlerType")
mid = AddStrucMember(id, "tryLow",           0, FF_DATA | FF_DWRD, -1, 4)
mid = AddStrucMember(id, "tryHigh",          4, FF_DATA | FF_DWRD, -1, 4)
mid = AddStrucMember(id, "catchHigh",        8, FF_DATA | FF_DWRD, -1, 4)
mid = AddStrucMember(id, "nCatches",       0xC, FF_DATA | FF_DWRD, -1, 4)
mid = AddStrucMember(id, "pHandlerArray", 0x10, FF_DATA | FF_DWRD | FF_0OFF | FF_1OFF, __ImageBase, 4, 0XFFFFFFFFFFFFFFFF,	0,	REFINFO_RVA | REF_OFF64);

# https://msdn.microsoft.com/en-us/library/ck9asaa9.aspx, at the bottom
def RegNumberToName(n):
 # FIXME: in perl, I'd write [qw<rax rcx ...>]->[n].  Learn python better.
 if n==0:
  return "rax"
 elif n==1:
  return "rcx"
 elif n==2:
  return "rdx"
 elif n==3:
  return "rbx"
 elif n==4:
  return "rsp"
 elif n==5:
  return "rbp"
 elif n==6:
  return "rsi"
 elif n==7:
  return "rdi"
 elif n>=8 and n<=15:
  return "r{}".format(n)
 else:
  return n

def DwordIn(base, n):
 return Dword(base+4*n)

def QwordIn(base, n):
 return Qword(base+8*n)

def RVAAt(ea, make=False, pastend=False):
 if make:
     MakeDword(ea)
     reftype = REF_OFF64 | REFINFO_RVA
     if pastend:
         reftype = reftype | REFINFO_PASTEND
     OpOffEx(ea, 0, reftype, -1, __ImageBase, 0)
 return __ImageBase + Dword(ea)

def MakeAndGetString(ea):
 if (ea == 0):
  return ""
 make_ascii_string(ea, 0, ASCSTR_C)
 return GetString(ea)

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

# FIXME: We will blow away any comments that exist where we want to make
# one, even ones we did not add.
made_comments = {}
def AddComm(ea, text):
 if made_comments.get(ea, 0) == 0:
     MakeComm(ea, "")
     made_comments[ea] = 1
 old_comment = CommentEx(ea, 0)
 if old_comment and len(old_comment) >= 1023:
  MakeComm(ea, text)
 elif text == old_comment:
  # Don't add a second copy of something that is already there
  return
 elif old_comment:
  MakeComm(ea, old_comment + "\n" + text)
 else:
  MakeComm(ea, text)

def handle__s_FuncInfo(funcinfo_addr):
    print "_s_FuncInfo at {:#x}".format(funcinfo_addr)
    
    MakeStructHard(funcinfo_addr, "_s_FuncInfo")
    magicNumber      = Dword(funcinfo_addr)
    maxState         = Dword(funcinfo_addr +    4)
    dispUnwindMap    = RVAAt(funcinfo_addr +    8)
    nTryBlocks       = Dword(funcinfo_addr + 0x0c)
    dispTryBlockMap  = RVAAt(funcinfo_addr + 0x10)
    nIPMapEntries    = Dword(funcinfo_addr + 0x14)
    dispIPtoStateMap = RVAAt(funcinfo_addr + 0x18)
    dispUwindHelp    = Dword(funcinfo_addr + 0x1C)
    dispESTypeList   = RVAAt(funcinfo_addr + 0x20)
    EHFlags          = Dword(funcinfo_addr + 0x24)

    if magicNumber != 0x19930522:
        print "Interesting magicNumber: {:#x}".format(magicNumber)
        1/0
    if EHFlags & ~5 != 0:
        print "Interesting EHFlags: {}".format(EHFlags)
        2/0

    stateinfo = []

    if maxState > 0:
        #print "maxState is {}".format(maxState)
        for i in range(0, maxState):
            start = dispUnwindMap + i * 8
            #print "UnwindMapEntry {} at {:#x}".format(i, start)
            MakeStructHard(start, "_s_UnwindMapEntry")
            tostate = Dword(start)
            if tostate == 0xFFFFFFFF:
                tostate = -1
            action = RVAAt(start + 4)
            stateinfo.append((tostate, action))
            
    if nTryBlocks > 0:
        # win10 explorer.exe, web'n'walk manager
        print "warning: try blocks not supported yet nTryBlocks is {}".format(nTryBlocks)
        #1/0

    if nIPMapEntries > 0:
        #print "nIPMapEntries is {}".format(nIPMapEntries)
        for i in range(0, nIPMapEntries):
            start = dispIPtoStateMap + i * 8
            #print "IPtoStateMapEntry {} at {:#x}".format(i, start)
            MakeStructHard(start, "IptoStateMapEntry")
            ip = RVAAt(start)
            state = Dword(start + 4)
            if state == 0xFFFFFFFF:
                state = -1
            startcomment = "error/unwind state {}".format(state)
            handlercomment = ""
            while state != -1:
                action = stateinfo[state][1]
                state = stateinfo[state][0]
                if len(handlercomment) > 0:
                    handlercomment = "{}, {:#x} -> {}".format(handlercomment, action, state)
                else:
                    handlercomment = "{:#x} -> {}".format(action, state)
            if handlercomment == "":
                AddComm(ip, startcomment)
            else:
                AddComm(ip, "{}\nHandlers: {}".format(startcomment, handlercomment))

    if dispESTypeList != __ImageBase:
        5/0

PE_header = RVAAt(__ImageBase + 0x3C, True)
MakeNameHarder(PE_header, "PE_header")
ExceptionDir = RVAAt(PE_header + 0xA0, True)
MakeNameHarder(ExceptionDir, "ExceptionDir")
ExceptionDirSize = Dword(PE_header + 0xA4)

print "-----"

# https://msdn.microsoft.com/en-us/library/7kcdt6fy(v=vs.140).aspx
runtime_function_addr = ExceptionDir
runtime_functions_processed = 0
error_out = 0
while 1:
 if error_out:
  break

 if (runtime_function_addr - ExceptionDir >= ExceptionDirSize):
  break

 MakeStructHard(runtime_function_addr, "RUNTIME_FUNCTION")
 begin = RVAAt(runtime_function_addr)
 end   = RVAAt(runtime_function_addr + 4)
 unwind_info = RVAAt(runtime_function_addr + 8)
 MakeComm(unwind_info, "")
 MakeComm(begin, "")
 #print "Exception info for {:#x} ... {:#x} is at {:#x}: ".format(begin, end, unwind_info)
 AddComm(unwind_info, "for {:#x} ... {:#x}".format(begin, end))
 AddComm(begin, "unwind info at {:#x}".format(unwind_info))
 
 MakeStructHard(unwind_info, "UNWIND_INFO")
 ver_flags = Byte(unwind_info)
 flags = ver_flags >> 3
 ver = ver_flags & 0b111
 prolog_size = Byte(unwind_info + 1)
 # Number of used word-sized entries, not number of ops.
 # May be one word of padding after this.
 unwind_count = Byte(unwind_info + 2)
 fr_froffset = Byte(unwind_info + 3)
 fr = fr_froffset & 0b1111
 if fr == 0:
  fr = "(none)"
 else:
  fr = RegNumberToName(fr)   
 froffset = 16 * (fr_froffset >> 4)
 AddComm(unwind_info, " ver {} flags {} prolog {} unwinds {} fr {} froff {}".format(ver, flags, prolog_size, unwind_count, fr, froffset))

 if ver != 1 and ver != 2:
  print "unknown version"
  error_out = 1
  break

 # Actual numeric values are in https://msdn.microsoft.com/en-us/library/ssa62fwe.aspx
 ehandler = flags & 1
 uhandler = flags & 2
 chaininfo = flags & 4
 unkflags = flags & 0b11000
 if unkflags != 0:
  print "Unknown flags"
  error_out = 1
  break
 
 if fr != "(none)":
  print " Frame register {}".format(RegNumberToName(fr))
 
 if froffset != 0:
  print "Frame register offset {}".format(froffset)
 
 if (prolog_size > 0):
   prolog_end = begin + prolog_size
   # The prolog end given is the first byte that is not part of the prolog.  What we want is the last byte that is.
   AddComm(PrevHead(prolog_end), "end of prolog")
 else:
     AddComm(begin, "no prolog")
 
 # https://msdn.microsoft.com/en-us/library/ck9asaa9.aspx gives most of the information on unwind codes, except
 # for UWOP_EPILOG, which seems to be un/under documented.  https://github.com/dotnet/coreclr/blob/master/src/unwinder/amd64/unwinder_amd64.cpp handles it, which suggests it may be designed for CLR use,
 # but it appears in windows 10's explorer.exe, which is native code.
 # The code for UWOP_EPILOG is apparently also UWOP_SAVE_XMM, but the instructions for the function
 # don't seem to actually do anything with xmm registers at all, and the UNWIND_CODE PrologOff field would
 # otherwise be out of order.
 # The relevant bits of code seem to be:
 #  https://github.com/dotnet/coreclr/commit/5720457962860915e42b8ee0fd9fb52904b21423#diff-6b22cf1a082c2c59fec61a022b690fcdL826
 #  https://github.com/dotnet/coreclr/blob/master/src/unwinder/amd64/unwinder_amd64.cpp#L1533
 unwind_start = unwind_info + 4
 unwind_i = 0
 found_epilog = False
 while unwind_i < unwind_count:
  code_addr = unwind_start + unwind_i*2
  MakeStructHard(code_addr, "UNWIND_CODE")
  code_offset = Byte(code_addr)
  instruction = PrevHead(begin + code_offset)
  op_inf = Byte(code_addr+1)
  op = op_inf & 0b1111
  inf = op_inf >> 4
  #print " {:#x} op {} inf {}".format(instruction, op, inf)
  
  text = ""
  # Do not make a comment against the instruction (but do comment the UNWIND_CODE struct itself).
  no_comment = False
  if op == 0:
   # FIXME: Give register name instead of number
   text = "UWOP_PUSH_NONVOL({})".format(RegNumberToName(inf))
  elif op == 1:
   size=0
   if inf == 0:
    MakeStructHard(code_addr, "UNWIND_CODE_2SLOT")
    size = 8 * Word(code_addr+2)
    unwind_i += 1
   elif inf == 1:
    MakeStructHard(code_addr, "UNWIND_CODE_3SLOT")
    size = Dword(code_addr_2)
    unwind_i += 2
   else:
    print "FIXME: Unhandled UWOP_ALLOC_LARGE inf {}".format(inf)
    error_out = 1
    break
   text = "UWOP_ALLOC_LARGE({:#x})".format(size)
   
  elif op == 2:
   size = inf * 8 + 8
   text = "UWOP_ALLOC_SMALL({})".format(size)
  elif op == 3:
   # What register is playing FP here, and what the offset is is given in UNWIND_INFO.  The doc "note[s] that
   # the operation info field is reserved and should not be used".
   text = "UWOP_SET_FPREG"
  elif op == 4:
   reg = inf
   MakeStructHard(code_addr, "UNWIND_CODE_2SLOT")
   offset = 8 * Word(code_addr+2)
   unwind_i = unwind_i + 1
   text = "UWOP_SAVE_NONVOL(reg={}, offset={:#x})".format(RegNumberToName(reg), offset)
   
  elif op == 6 and ver == 2:
   print "*** undocumented UWOP_EPILOG"
   # https://github.com/dotnet/coreclr/blob/master/src/unwinder/amd64/unwinder_amd64.cpp#L1533
   # Note that the clr code uses a union, but it's really just a simple renaming.
   # CodeOffset = OffsetLow  = code_offset
   # UnwindOp   = UnwindOp   = op = 6, or we wouldn't be here
   # OpInfo     = OffsetHigh = inf

   print "offset {} op {} info {} first-already-found {}".format(code_offset, op, inf, found_epilog)
   
   if not found_epilog:
    found_epilog = True
    # Because this whole thing was apparently not alraedy confusing enough, the first OP_EPILOG code
    # is special ... but only if it has the flag set?
    flag = ((inf & 1) == 1)
    if flag:
     epilogue_size = code_offset
     instruction = end - epilogue_size
     text = "only epilogue"
     
   if inf == 0 and code_offset == 0:
    text = "UWOP_EPILOG (padding?)"
    no_comment = True

   if not text:
    epilogue_offset = code_offset + inf * 255
    instruction = end - epilogue_offset
    text = "epilogue"

   print "epilogue code, UWOP_EPILOG at {:#x} text {}".format(instruction, text)
  elif op == 8:
   reg = inf
   MakeStructHard(code_addr, "UNWIND_CODE_2SLOT")
   offset = 16 * Word(code_addr+2)
   unwind_i = unwind_i + 1
   text = "UWOP_SAVE_XMM128(reg={}, offset={:#x})".format(RegNumberToName(reg), offset)
  else:
   print "FIXME: Unknown op {}".format(op)
   error_out = 1
   break

  if (not no_comment):
   AddComm (instruction, "{:#x}: {}".format(code_addr,   text))
  MakeComm(code_addr,   "{:#x}: {}".format(instruction, text))

  unwind_i = unwind_i + 1
 
  after_unwinds = unwind_start + unwind_i*2
  if unwind_count & 1:
   # If unwind_count is odd, there is an extra two bytes of padding.
   MakeAlign(after_unwinds, 2, 3)
   after_unwinds = after_unwinds + 2
 
 if ehandler or uhandler:
  MakeComm(after_unwinds, "e|u handler func")
  MakeComm(after_unwinds+4, "e|u handler data")

  handler = RVAAt(after_unwinds, True)
  handler_data_addr = after_unwinds+4

  # __CxxFrameHandler3: Data is an RVA to a _s_FuncInfo
  # __C_specific_handler: Data is the count of C_SCOPE_TABLE structs, which immediately follow the data field.
  # __GSHandlerCheck_SEH: Data is as __C_specific_handler
  # __GSHandlerCheck: Data seems to be some smallish number?  0x140..0x1030 noted, always mul of 0x10?

  handler_name = GetTrueName(handler)
  if handler_name == "__GSHandlerCheck":
   MakeComm(handler_data_addr, "stack cookie")
  elif handler_name == "__CxxFrameHandler3" or handler_name == "__CxxFrameHandler3_0":
   # FIXME: Make the above a regex, or a prefix check?
   data = RVAAt(handler_data_addr, True)
   # Only place I've seen this structure given correctly is http://www.hexblog.com/wp-content/uploads/2012/06/Recon-2012-Skochinsky-Compiler-Internals.pdf page 21
   MakeStructHard(data, "_s_FuncInfo")
   handle__s_FuncInfo(data)

  else:
   print("SEH e|u handler for function starting at {:#x} is named {} with data {:#x} at {:#x}".format(begin, handler_name, Dword(handler_data_addr), handler_data_addr))

 runtime_function_addr = runtime_function_addr + 0xC
 
 runtime_functions_processed = runtime_functions_processed + 1
 if error_out:
  break
