# ....
id = AddStrucEx(-1,"pagedu64_header",0);
id = AddStrucEx(-1,"TRIAGE_DUMP64",0);
id = AddStrucEx(-1,"DataBlock",0);
id = AddStrucEx(-1,"unloaded_driver",0);
id = AddStrucEx(-1,"loaded_driver",0);

id = GetStrucIdByName("pagedu64_header");
mid = AddStrucMember(id,"signature",	0,	0x50000400,	0,	8);
SetMemberComment(id,	0,	"PAGEDU64",	0);
mid = AddStrucMember(id,"majorversion",	0X8,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"minorversion",	0XC,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"DirectoryTableBase",	0X10,	0x30500400,	0,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"PfnDataBase",	0X18,	0x30500400,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"PsLoadedModuleList",	0X20,	0x30500400,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"PsActiveProcessHead",	0X28,	0x30500400,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"MachineImageType",	0X30,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"NumberProcessors",	0X34,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"BugCheckCode",	0X38,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"pad",	0X3C,	0x20300400,	-1,	4);
mid = AddStrucMember(id,"BugCheckParameter1",	0X40,	0x30000400,	-1,	8);
mid = AddStrucMember(id,"BugCheckParameter2",	0X48,	0x30500400,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"BugCheckParameter3",	0X50,	0x30500400,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"BugCheckParameter4",	0X58,	0x30100400,	-1,	8);
mid = AddStrucMember(id,"field_60",	0X60,	0x20300400,	-1,	32);
mid = AddStrucMember(id,"KdDebuggerDataBlock",	0X80,	0x30500400,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"field_88",	0X88,	0x20300400,	-1,	704);

id = GetStrucIdByName("TRIAGE_DUMP64");
mid = AddStrucMember(id,"ServicePackBuild",	0,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"SizeOfDump",	0X4,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"ValidOffset",	0X8,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"ContextOffset",	0XC,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"ExceptionOffset",	0X10,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"MmOffset",	0X14,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"UnloadedDriversOffset",	0X18,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"PrbcOffset",	0X1C,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"ProcessOffset",	0X20,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"ThreadOffset",	0X24,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"CallStackOffset",	0X28,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"SizeOfCallStack",	0X2C,	0x20100400,	-1,	4);
mid = AddStrucMember(id,"DriverListOffset",	0X30,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"DriverCount",	0X34,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"StringPoolOffset",	0X38,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"StringPoolSize",	0X3C,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"BrokenDriverOffset",	0X40,	0x20500400,	0XFFFFFFFFFFFFFFFF,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000002);
mid = AddStrucMember(id,"TriageOptions",	0X44,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"TopOfStack",	0X48,	0x30500400,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"BStoreOffset",	0X50,	0x20500400,	0XFFFFFFFFFFFFFFFF,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000002);
mid = AddStrucMember(id,"SizeOfBStore",	0X54,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"LimitOfBStore",	0X58,	0x30000400,	-1,	8);
mid = AddStrucMember(id,"field_60",	0X60,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"field_64",	0X64,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"field_68",	0X68,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"field_6C",	0X6C,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"DebuggerDataOffset",	0X70,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"DebuggerDataSize",	0X74,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"DataBlocksOffset",	0X78,	0x20500400,	0,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"DataBlocksCount",	0X7C,	0x20000400,	-1,	4);

id = GetStrucIdByName("DataBlock");
mid = AddStrucMember(id,"start",	0,	0x30509500,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"offset",	0X8,	0x20500500,	0XFFFFFFFFFFFFFFFF,	4,	0XFFFFFFFFFFFFFFFF,	0,	0x000002);
mid = AddStrucMember(id,"size",	0XC,	0x20000500,	-1,	4);

id = GetStrucIdByName("unloaded_driver");
mid = AddStrucMember(id,"field_0",	0,	0x10000400,	-1,	2);
mid = AddStrucMember(id,"field_2",	0X2,	0x10000400,	-1,	2);
mid = AddStrucMember(id,"field_4",	0X4,	0x20000400,	-1,	4);
mid = AddStrucMember(id,"anonymous_1",	0X8,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"name",	0X10,	0x5000c500,	0x3,	24);
mid = AddStrucMember(id,"start",	0X28,	0x30500500,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"stop",	0X30,	0x30000500,	-1,	8);

id = GetStrucIdByName("loaded_driver");
mid = AddStrucMember(id,"name",	0,	0x30505500,	0,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"anonymous_0",	0X8,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_1",	0X10,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_2",	0X18,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_3",	0X20,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_4",	0X28,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_5",	0X30,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"start",	0X38,	0x30504500,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
mid = AddStrucMember(id,"anonymous_6",	0X40,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"length",	0X48,	0x20000500,	-1,	4);
mid = AddStrucMember(id,"anonymous_8",	0X4C,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_9",	0X54,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_10",	0X5C,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_11",	0X64,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_12",	0X6C,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_13",	0X74,	0x30000500,	-1,	8);
mid = AddStrucMember(id,"anonymous_14",	0X7C,	0x20100500,	-1,	4);
mid = AddStrucMember(id,"anonymous_15",	0X80,	0x30100500,	-1,	8);
mid = AddStrucMember(id,"filetime",	0X88,	0x30000500,	-1,	8);

data_blocks_start = 0x17580

data_blocks_count = 0x443

for db_i in range(0x443):
    db_start = data_blocks_start + 0x10 * db_i

    address = Qword(db_start + 0)
    offset  = Dword(db_start + 8)
    length  = Dword(db_start + 0xC)

    print "addr, off, len: {:>16x} {:>8x} {:>8x}".format(address, offset, length)

    if (address-offset) & 1 != 0:
        print "odd address-offset paring, skipping {:#x}".format(address-offset)
        continue

    if SegStart(address) == address:
        print "Segment already exists, skipping"
        continue

    # align=1
    # comb=2
    # perm=0
    # flags=0
    # sel=1
    # type=0
    # startea, endea, sel, use32, align comb flags
    ret = AddSegEx(offset, offset+length, 1, 2, 1, 2, 0)
    print "AddSeg returned: {}".format(ret)
    if not ret:
        break
    
    ret = RenameSeg(offset, "offset_{:x}h".format(offset))
    print "RenameSeg returned: {}".format(ret)
    if ret != 1:
        break
    
    ret = MoveSegm(offset, address, MSF_NOFIX)
    print "MoveSegm to {:#x} returned: {}".format(address, ret)
    if ret != 0:
        break


