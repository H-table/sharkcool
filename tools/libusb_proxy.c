/* libusb_proxy.c - MITM proxy for libusb-1.0.dll used by Brb02CoolerComm.dll
 *
 * Forwards all 14 imports of Brb02CoolerComm.dll to the real DLL
 * (renamed to libusb-1.0_real.dll) and logs EVERY libusb_interrupt_transfer
 * payload (both directions) to %TEMP%\libusb_proxy.log.
 *
 * Compile (TinyCC 0.9.27, 32-bit):
 *   tcc.exe -shared -o libusb-1.0.dll libusb_proxy.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static HMODULE real_dll = NULL;
static FILE *g_log = NULL;

static void ensure_real(void) {
    if (real_dll) return;
    /* the real DLL sits next to us with a different name */
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *slash = strrchr(path, '\\');
    if (slash) slash[1] = 0; else path[0] = 0;
    strcat(path, "libusb-1.0_real.dll");
    real_dll = LoadLibraryA(path);
    /* fallback: same directory as our own module */
    if (!real_dll) {
        HMODULE self = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           (LPCSTR)&ensure_real, &self);
        GetModuleFileNameA(self, path, MAX_PATH);
        slash = strrchr(path, '\\');
        if (slash) slash[1] = 0;
        strcat(path, "libusb-1.0_real.dll");
        real_dll = LoadLibraryA(path);
    }
    if (!real_dll) {
        MessageBoxA(NULL, "libusb proxy: real DLL not found", "SharkCool", MB_OK);
    }
}

typedef void *(*fp_void_p)(const char *n);

static void log_open(void) {
    if (g_log) return;
    const char *tmp = getenv("TEMP");
    if (!tmp) tmp = "C:\\Windows\\Temp";
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\libusb_proxy.log", tmp);
    g_log = fopen(path, "a");
}

/* ---- forwarders ---- */

__declspec(dllexport) int __cdecl libusb_init(void **ctx) {
    static int (__cdecl *f)(void **);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void **))GetProcAddress(real_dll, "libusb_init"); }
    return f ? f(ctx) : -4;
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

__declspec(dllexport) int __cdecl libusb_get_device_list(void *ctx, void ***list) {
    static int (__cdecl *f)(void *, void ***);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, void ***))GetProcAddress(real_dll, "libusb_get_device_list"); }
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
    return f ? f(ctx, v, p) : NULL;
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

/* extra import set used by BlackSharkEquipmentBox.exe itself */
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

/* the interception point */
__declspec(dllexport) int __cdecl libusb_interrupt_transfer(void *dev, unsigned char ep,
                                                            unsigned char *data, int length,
                                                            int *transferred, unsigned int timeout) {
    static int (__cdecl *f)(void *, unsigned char, unsigned char *, int, int *, unsigned int);
    if (!f) { ensure_real(); f = (int (__cdecl *)(void *, unsigned char, unsigned char *, int, int *, unsigned int))GetProcAddress(real_dll, "libusb_interrupt_transfer"); }
    int r = f ? f(dev, ep, data, length, transferred, timeout) : -4;
    if (data && length > 0) {
        log_open();
        if (g_log) {
            fprintf(g_log, "ep=0x%02X %s len=%d r=%d: ", ep, (ep & 0x80) ? "IN " : "OUT", length, r);
            int n = length < 96 ? length : 96;
            fwrite(data, 1, n, g_log);
            fprintf(g_log, "\n");
            fflush(g_log);
        }
    }
    return r;
}
