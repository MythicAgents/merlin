#ifdef __WIN32

// Test DLL execution
// rundll32 merlin.dll,Magic

#include <windows.h>
#include <stdio.h>

void Run();

// https://docs.microsoft.com/en-us/windows/desktop/dlls/dynamic-link-library-entry-point-function

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH:
            // Initialize once for each new process.
            // Return FALSE to fail DLL load.
            // printf("[+] Hello from DllMain-PROCESS_ATTACH in Merlin\n");
            // MessageBoxA( NULL, "Hello from DllMain-PROCESS_ATTACH in Merlin!", "Reflective Dll Injection", MB_OK );
            break;

        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization.
            // MessageBoxA( NULL, "Hello from DllMain-PROCESS_ATTACH in Merlin!", "Reflective Dll Injection", MB_OK );
            break;

        case DLL_THREAD_DETACH:
            // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
            // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

#elif __linux__

// Test SO execution
// LD_PRELOAD=/home/rastley/Downloads/merlin.so /usr/bin/whoami

#include <stdlib.h>

void Magic();

static void __attribute__ ((constructor)) init(void);

static void init(void) {
   // Thanks to the Sliver team for the unsetenv reminder
    unsetenv("LD_PRELOAD");
    unsetenv("LD_PARAMS");
  // Magic is the exported function from shared.go
  Magic();
  return;
}

#elif __APPLE__

// Test Dylib execution with python3
// python3
// import ctypes
// ctypes.CDLL("./melrin.dylib")

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <assert.h>
#include <pthread.h>

void Magic();

__attribute__ ((constructor)) void initializer()
{
    // Thanks to the Sliver team for the unsetenv reminder
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("LD_PARAMS");

	pthread_attr_t  attr;
    pthread_t       posixThreadID;
    int             returnVal;

    returnVal = pthread_attr_init(&attr);
    assert(!returnVal);
    returnVal = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    assert(!returnVal);
    pthread_create(&posixThreadID, &attr, &RunMain, NULL);
}

#endif