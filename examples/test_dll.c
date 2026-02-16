// Test DLL for Manual Mapping
// Compile: gcc test_dll.c -shared -o test_dll.dll -mwindows

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL,
                       "Manual Mapping Test\n\n"
                       "DLL이 수동으로 매핑되어 로드되었습니다!\n\n"
                       "DllMain이 성공적으로 호출되었습니다.",
                       "Manual Mapping Success",
                       MB_OK | MB_ICONINFORMATION);
            break;
        
        case DLL_PROCESS_DETACH:
            // Cleanup code here
            break;
        
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

// Export a test function
__declspec(dllexport) void TestFunction() {
    MessageBoxA(NULL, 
                "TestFunction이 호출되었습니다!",
                "Test Function",
                MB_OK | MB_ICONINFORMATION);
}
