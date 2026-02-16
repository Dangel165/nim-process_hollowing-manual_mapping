// Test Payload for Process Hollowing
// Compile: gcc test_payload.c -o test_payload.exe -mwindows

#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    MessageBoxA(NULL, 
                "Process Hollowing Test\n\n"
                "이 프로그램이 다른 프로세스 내에서 실행되었습니다!\n\n"
                "성공적으로 Process Hollowing이 완료되었습니다.",
                "Process Hollowing Success",
                MB_OK | MB_ICONINFORMATION);
    return 0;
}
