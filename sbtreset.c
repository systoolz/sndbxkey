/*

Sandboxie trial period reset tool.
Tested only with Sandboxie 5.22.
Use it on your own risk.

Compile and make this tool to autorun with Windows startup.
Note that if you're registered Sandboxie user you may need to reset 400 characters activation key
or the Sandboxie will ask everyday for activation since all activation servers are closed now.
You can save the following text as "reset.reg" file and run it or manually change the following
keys in your registry.



REGEDIT4

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{98E6BD24-2D93-41A5-BC6D-CB7C1507318B}]
"N"=""
"K"=""
"K0"=hex(0):
"K1"=hex(0):
"K2"=hex(0):
"K3"=hex(0):
"K4"=hex(0):
"K5"=hex(0):
"K6"=hex(0):
"K7"=hex(0):
"K8"=hex(0):
"K9"=hex(0):

*/

#include <windows.h>

static TCHAR stSBName[] = TEXT("I\0SOFTWARE\\Classes\\CLSID\\{98E6BD24-2D93-41A5-BC6D-CB7C1507318B}");

int main(void) {
ULARGE_INTEGER ui;
FILETIME ft;
HKEY hReg;
  if (
    RegOpenKeyEx(
      HKEY_LOCAL_MACHINE,
      &stSBName[2],
      0, KEY_SET_VALUE, &hReg
    ) == ERROR_SUCCESS
  ) {
    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    RegSetValueEx(hReg, stSBName, 0, REG_BINARY, (BYTE *) &ui.QuadPart, sizeof(ui.QuadPart));
    RegCloseKey(hReg);
  }
  return(0);
}
