#include <windows.h>
#include <stdio.h>

__declspec(dllexport) int malicious_function() {
    MessageBoxA(NULL, "DLL Injection Successful!", "Vulnerability Demo", MB_OK);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded
            break;
        case DLL_PROCESS_DETACH:
            // DLL is being unloaded
            break;
    }
    return TRUE;
} 