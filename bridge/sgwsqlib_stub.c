/* Stub sgwsqlib.dll - provides the 3 exports that sgfplib.dll imports */
/* No windows.h needed - minimal stub */

__declspec(dllexport) int __stdcall SGWSQ_Free(void *ptr) {
    (void)ptr;
    return 0;
}

__declspec(dllexport) int __stdcall SGWSQ_Encode(
    int a, int b, int c, int d, int e, int f, int g, int h, int i) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; (void)h; (void)i;
    return -1;
}

__declspec(dllexport) int __stdcall SGWSQ_Decode(
    int a, int b, int c, int d, int e, int f, int g, int h) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; (void)h;
    return -1;
}

int __stdcall _DllMainCRTStartup(void *hinstDLL, unsigned int fdwReason, void *lpReserved) {
    (void)hinstDLL; (void)fdwReason; (void)lpReserved;
    return 1;
}
