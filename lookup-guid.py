from idajmm import *
from _winreg import *

def get_reg(root, key, subkey):
    try:
        keyhandle = OpenKey(root, key, 0, KEY_READ)
        (value, type) = QueryValueEx(keyhandle, subkey)
        return value
    except OSError as e:
        if e.winerror == 2:
            return None
        else:
            raise

start = ScreenEA()
formatted = "{:0>8x}-{:0>4x}-{:0>4x}-{:0>2x}{:0>2x}-".format(Dword(start), Word(start+4), Word(start+6), Byte(start+8), Byte(start+9))

for i in range(10, 16):
    formatted = "{}{:0>2x}".format(formatted, Byte(start + i))

formatted = "{" + formatted + "}"

print formatted

name = None

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Media Device Manager\{KnownDeviceClasses,KnownDevices}\(name)\DeviceInterface
#  maybe

interface = get_reg(HKEY_CLASSES_ROOT, "Interface\\"+formatted, None)
if interface:
    name = "IID_{}".format(interface)

devclass = get_reg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\"+formatted, "Class")
if devclass:
    name = "DevClass_{}".format(devclass)

klass = get_reg(HKEY_CLASSES_ROOT, "CLSID\\"+formatted, None)
if klass:
    name = "CLSID_{}".format(klass)

if name:
    MakeStructHard(start, "GUID")
    MakeNameHarder(start, name)

