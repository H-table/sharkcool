/* libusb_proxy2.c - Win32-only MITM proxy (no CRT at all).
 * Forward 17 libusb imports used by the app; log via CreateFileA/WriteFile.
 * Compile: tcc -shared -o libusb-1.0.dll libusb_proxy2.c
 */
#include <windows.h>

static HMODULE real_dll = NULL;
static HANDLE g_log = INVALID_HANDLE_VALUE;

static void ensure_real(void) {
    if (real_dll) return;
    char path[MAX_PATH];
    /* prefer host exe dir, fallback to our own module dir */
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *slash = strrchr(path, '\\');
    if (slash) slash[1] = 0;
    lstrcatA(path, "libusb-1.0_real.dll");
    real_dll = LoadLibraryA(path);
    if (!real_dll) {
        HMODULE self = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           (LPCSTR)&ensure_real, &self);
        GetModuleFileNameA(self, path, MAX_PATH);
        slash = strrchr(path, '\\');
        if (slash) slash[1] = 0;
        lstrcatA(path, "libusb-1.0_real.dll");
        real_dll = LoadLibraryA(path);
    }
}

static void log_open(void) {
    if (g_log != INVALID_HANDLE_VALUE) return;
    char path[MAX_PATH];
    DWORD n = GetTempPathA(MAX_PATH, path);
    if (n == 0 || n >= MAX_PATH - 16) return;
    lstrcatA(path, "libusb_proxy2.log");
    g_log = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void log_hex(const char *dir, unsigned char ep, int length, int r, const unsigned char *data, int dlen) {
    char hdr[64];
    int hn = wsprintfA(hdr, "ep=0x%02X %s len=%d r=%d: ", ep, dir, length, r);
    if (hn > 0 && hn < 64) {
        log_open();
        if (g_log != INVALID_HANDLE_VALUE) {
            DWORD w;
            WriteFile(g_log, hdr, hn, &w, NULL);
            if (data && dlen > 0) WriteFile(g_log, data, dlen, &w, NULL);
            WriteFile(g_log, "\r\n", 2, &w, NULL);
        }
    }
}

#define GET(fn) \
    static int (__cdecl *p_##fn)(void); \
    if (!p_##fn) { ensure_real(); p_##fn = (int (__cdecl *)(void))GetProcAddress(real_dll, #fn); } \
    if (!p_##fn) return 0;

/* ---- 17 forwarders (all cdecl) ---- */

__declspec(dllexport) int __cdecl libusb_init(void **ctx) {
    static int (__cdecl *f)(void **);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void **))GetProcAddress(real_dll, "libusb_init"); }
    {
        char msg[128];
        int n = wsprintfA(msg, "[proxy] init real=%p f=%p\n", real_dll, f);
        log_open();
        if (g_log != INVALID_HANDLE_VALUE && n > 0) { DWORD w; WriteFile(g_log, msg, n, &w, NULL); }
    }
    {
        int rc = f ? f(ctx) : -4;
        char msg[64];
        int n = wsprintfA(msg, "[proxy] init rc=%d ctx=%p\n", rc, ctx ? ctx[0] : 0);
        log_open();
        if (g_log != INVALID_HANDLE_VALUE && n > 0) { DWORD w; WriteFile(g_log, msg, n, &w, NULL); }
        return rc;
    }
}
__declspec(dllexport) void __cdecl libusb_exit(void *ctx) {
    static void (__cdecl *f)(void *);
    if (!f) { ensure_real(); f = (void (__cdecl *)(void *))GetProcAddress(real_dll, "libusb_exit"); }
    if (f) f(ctx);
}
__declspec(dllexport) const char *__cdecl libusb_error_name(int e) {
    static const char *(__cdecl *f)(int);
    if (!f) { ensure_real(); f = (const char *(__cdecl *)(int))GetProcAddress(real_dll, "libusb_error_name"); }
    return f ? f(e) : "unknown";
}
static void plog(const char *tag, int a, int b) {
    char msg[96];
    int n = wsprintfA(msg, "[proxy] %s a=%d b=%d\n", tag, a, b);
    log_open();
    if (g_log != INVALID_HANDLE_VALUE && n > 0) { DWORD w; WriteFile(g_log, msg, n, &w, NULL); }
}

__declspec(dllexport) int __cdecl libusb_get_device_list(void *ctx, void ***list) {
    static int (__cdecl *f)(void *, void ***);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, void ***))GetProcAddress(real_dll, "libusb_get_device_list"); }
    plog("get_device_list", 0, 0);
    return f ? f(ctx, list) : -1;
}
__declspec(dllexport) void __cdecl libusb_free_device_list(void *list, int unref) {
    static void (__cdecl *f)(void *, int);
    if (!f) { ensure_real(); f = (void (__cdecl *)(void *, int))GetProcAddress(real_dll, "libusb_free_device_list"); }
    if (f) f(list, unref);
}
__declspec(dllexport) int __cdecl libusb_get_device_descriptor(void *dev, void *desc) {
    static int (__cdecl *f)(void *, void *);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, void *))GetProcAddress(real_dll, "libusb_get_device_descriptor"); }
    return f ? f(dev, desc) : -1;
}
__declspec(dllexport) int __cdecl libusb_claim_interface(void *dev, int iface) {
    static int (__cdecl *f)(void *, int);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, int))GetProcAddress(real_dll, "libusb_claim_interface"); }
    return f ? f(dev, iface) : -1;
}
__declspec(dllexport) void *__cdecl libusb_open_device_with_vid_pid(void *ctx, unsigned short v, unsigned short p) {
    static void *(__cdecl *f)(void *, unsigned short, unsigned short);
    if (!f) { ensure_real(); f = (void *(__cdecl *)(void *, unsigned short, unsigned short))GetProcAddress(real_dll, "libusb_open_device_with_vid_pid"); }
    plog("open_vidpid", v, p);
    void *r = f ? f(ctx, v, p) : NULL;
    {
        char msg[96];
        int n = wsprintfA(msg, "[proxy] open_vidpid -> %p\n", r);
        log_open();
        if (g_log != INVALID_HANDLE_VALUE && n > 0) { DWORD w; WriteFile(g_log, msg, n, &w, NULL); }
    }
    return r;
}
__declspec(dllexport) int __cdecl libusb_get_active_config_descriptor(void *dev, void **desc) {
    static int (__cdecl *f)(void *, void **);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, void **))GetProcAddress(real_dll, "libusb_get_active_config_descriptor"); }
    return f ? f(dev, desc) : -1;
}
__declspec(dllexport) void __cdecl libusb_free_config_descriptor(void *desc) {
    static void (__cdecl *f)(void *);
    if (!f) { ensure_real(); f = (void (__cdecl *)(void *))GetProcAddress(real_dll, "libusb_free_config_descriptor"); }
    if (f) f(desc);
}
__declspec(dllexport) void __cdecl libusb_close(void *dev) {
    static void (__cdecl *f)(void *);
    if (!f) { ensure_real(); f = (void (__cdecl *)(void *))GetProcAddress(real_dll, "libusb_close"); }
    if (f) f(dev);
}
__declspec(dllexport) void *__cdecl libusb_get_device(void *handle) {
    static void *(__cdecl *f)(void *);
    if (!f) { ensure_real(); f = (void *(__cdecl *)(void *))GetProcAddress(real_dll, "libusb_get_device"); }
    return f ? f(handle) : NULL;
}
__declspec(dllexport) int __cdecl libusb_release_interface(void *dev, int iface) {
    static int (__cdecl *f)(void *, int);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, int))GetProcAddress(real_dll, "libusb_release_interface"); }
    return f ? f(dev, iface) : -1;
}
__declspec(dllexport) int __cdecl libusb_hotplug_register_callback(void *ctx, int events, int flags,
        int vendor_id, int product_id, int dev_class, void *callback, void *user_data, void **handle) {
    static int (__cdecl *f)(void *, int, int, int, int, int, void *, void *, void **);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, int, int, int, int, int, void *, void *, void **))GetProcAddress(real_dll, "libusb_hotplug_register_callback"); }
    return f ? f(ctx, events, flags, vendor_id, product_id, dev_class, callback, user_data, handle) : -12;
}
__declspec(dllexport) void __cdecl libusb_hotplug_deregister_callback(void *ctx, void *handle) {
    static void (__cdecl *f)(void *, void *);
    if (!f) { ensure_real(); f = (void (__cdecl *)(void *, void *))GetProcAddress(real_dll, "libusb_hotplug_deregister_callback"); }
    if (f) f(ctx, handle);
}
__declspec(dllexport) int __cdecl libusb_handle_events_timeout_completed(void *ctx, void *tv, int *completed) {
    static int (__cdecl *f)(void *, void *, int *);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, void *, int *))GetProcAddress(real_dll, "libusb_handle_events_timeout_completed"); }
    return f ? f(ctx, tv, completed) : -2;
}
/* runtime GetProcAddress targets commonly used by clients */
__declspec(dllexport) void *__cdecl libusb_get_version(void) {
    static void *(__cdecl *f)(void);
    if (!f) { ensure_real(); f = (void *(__cdecl *)(void))GetProcAddress(real_dll, "libusb_get_version"); }
    return f ? f() : NULL;
}
__declspec(dllexport) int __cdecl libusb_set_option(void *ctx, int option, ...) {
    static int (__cdecl *f)(void *, int);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, int))GetProcAddress(real_dll, "libusb_set_option"); }
    return f ? f(ctx, option) : -6;
}
__declspec(dllexport) int __cdecl libusb_has_capability(unsigned int capability) {
    static int (__cdecl *f)(unsigned int);
    if (!f) { ensure_real(); f = (int (__cdecl *)(unsigned int))GetProcAddress(real_dll, "libusb_has_capability"); }
    return f ? f(capability) : 0;
}

/* the interception point */
__declspec(dllexport) int __cdecl libusb_interrupt_transfer(void *dev, unsigned char ep,
                                                            unsigned char *data, int length,
                                                            int *transferred, unsigned int timeout) {
    static int (__cdecl *f)(void *, unsigned char, unsigned char *, int, int *, unsigned int);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, unsigned char, unsigned char *, int, int *, unsigned int))GetProcAddress(real_dll, "libusb_interrupt_transfer"); }
    int r = f ? f(dev, ep, data, length, transferred, timeout) : -4;
    if (data && length > 0) {
        log_hex((ep & 0x80) ? "IN " : "OUT", ep, length, r, data, length < 96 ? length : 96);
    }
    return r;
}
