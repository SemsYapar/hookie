/*
 * hookie_stub.c — Windows CPython bootstrap for hookie.
 *
 * Runtime policy:
 *   - If the target already owns the same CPython minor version (same
 *     python3XY.dll), reuse that main interpreter under PyGILState_Ensure.
 *   - If only a different CPython minor version is loaded, use Hookie's
 *     bundled versioned DLL; Windows resolves the C API through that HMODULE.
 *   - No subinterpreters are created.
 *
 * A Hookie-owned bundled interpreter is process-lifetime because installed
 * ctypes.CFUNCTYPE detours can execute later on arbitrary native threads.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

typedef void           (*Py_InitializeEx_t)(int);
typedef int            (*Py_IsInitialized_t)(void);
typedef const char *   (*Py_GetVersion_t)(void);
typedef int            (*PyRun_SimpleString_t)(const char *);
typedef void           (*PyErr_Print_t)(void);
typedef void *         (*PyEval_SaveThread_t)(void);
typedef int            (*PyGILState_Ensure_t)(void);
typedef void           (*PyGILState_Release_t)(int);

static HMODULE g_self = NULL;
static HMODULE g_py = NULL;

static Py_InitializeEx_t             pPy_InitializeEx;
static Py_IsInitialized_t            pPy_IsInitialized;
static Py_GetVersion_t               pPy_GetVersion;
static PyRun_SimpleString_t          pPyRun_SimpleString;
static PyErr_Print_t                 pPyErr_Print;
static PyEval_SaveThread_t           pPyEval_SaveThread;
static PyGILState_Ensure_t           pPyGILState_Ensure;
static PyGILState_Release_t          pPyGILState_Release;

#define HK_RESOURCE_MAGIC "HOOKIE_PAYLOAD_V1"
#define HK_RESOURCE_PATH 1
#define HK_RESOURCE_PACKED 2
#define HK_MAX_IDENT 64            /* sanity cap on the payload id length */
#define HK_MAX_RAW (1ull << 31)    /* 2 GiB cap on decompressed payload size */

/* Injected DLLs usually have no console, so printf/stderr are invisible.
 * Build with -DHK_DEBUG and watch DebugView to trace where the worker stops. */
#ifdef HK_DEBUG
#define HK_TRACE(msg)   OutputDebugStringW(L"[hookie] " msg L"\n")
#define HK_TRACEW(wstr) do { OutputDebugStringW(L"[hookie] "); \
                             OutputDebugStringW(wstr); OutputDebugStringW(L"\n"); } while (0)
#else
#define HK_TRACE(msg)   ((void)0)
#define HK_TRACEW(wstr) ((void)0)
#endif

#pragma pack(push, 1)
typedef struct {
    char magic[17];
    uint8_t mode;
    uint8_t ident_len;      /* id byte count (packed mode); 0 in path mode */
    uint8_t reserved[5];
    uint64_t raw_size;
    uint64_t data_size;
} HookieFooter;
#pragma pack(pop)
typedef char HookieFooterSizeMustBe40[(sizeof(HookieFooter) == 40) ? 1 : -1];

static BOOL make_parents(const wchar_t *path)
{
    wchar_t tmp[MAX_PATH * 4];
    wchar_t *p;
    wcsncpy(tmp, path, (sizeof(tmp) / sizeof(tmp[0])) - 1);
    tmp[(sizeof(tmp) / sizeof(tmp[0])) - 1] = 0;
    for (p = tmp + 3; *p; ++p) {
        if (*p == L'\\' || *p == L'/') { wchar_t c = *p; *p = 0; CreateDirectoryW(tmp, NULL); *p = c; }
    }
    return TRUE;
}

static BOOL lzss_decompress(const uint8_t *src, size_t src_n, uint8_t *dst, size_t dst_n)
{
    size_t si = 0, di = 0;
    while (si < src_n && di < dst_n) {
        uint8_t flags = src[si++]; int bit;
        for (bit = 0; bit < 8 && di < dst_n; ++bit) {
            if (flags & (1u << bit)) {
                if (si >= src_n) return FALSE;
                dst[di++] = src[si++];
            } else {
                uint16_t t; size_t dist, len, j;
                if (si + 2 > src_n) return FALSE;
                t = (uint16_t)(src[si] | ((uint16_t)src[si + 1] << 8)); si += 2;
                dist = t & 0x0fff; len = ((t >> 12) & 0x0f) + 3;
                if (!dist || dist > di || di + len > dst_n) return FALSE;
                for (j = 0; j < len; ++j) { dst[di] = dst[di - dist]; ++di; }
            }
        }
    }
    return di == dst_n;
}

static BOOL extract_archive(const uint8_t *raw, size_t n, const wchar_t *root)
{
    size_t at = 0;
    while (at + 4 <= n) {
        uint32_t plen; uint64_t size; char rel8[MAX_PATH * 4]; wchar_t rel[MAX_PATH * 2], full[MAX_PATH * 4]; HANDLE h; DWORD wrote;
        memcpy(&plen, raw + at, 4); at += 4;
        if (!plen) return TRUE;
        if (at + 8 + plen > n || plen >= sizeof(rel8)) return FALSE;
        memcpy(&size, raw + at, 8); at += 8;
        memcpy(rel8, raw + at, plen); rel8[plen] = 0; at += plen;
        if (rel8[0] == '/' || strstr(rel8, "../") || strstr(rel8, "..\\")) return FALSE;
        if (size > n - at || size > 0xffffffffu) return FALSE;
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, rel8, -1, rel, (int)(sizeof(rel)/sizeof(rel[0])))) return FALSE;
        _snwprintf(full, (sizeof(full)/sizeof(full[0])) - 1, L"%s\\%s", root, rel); full[(sizeof(full)/sizeof(full[0])) - 1] = 0;
        make_parents(full);
        h = CreateFileW(full, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return FALSE;
        if (size && (!WriteFile(h, raw + at, (DWORD)size, &wrote, NULL) || wrote != (DWORD)size)) { CloseHandle(h); return FALSE; }
        CloseHandle(h); at += (size_t)size;
    }
    return FALSE;
}

static BOOL resolve_payload_dir(wchar_t *out, size_t cap)
{
    wchar_t module[MAX_PATH * 4], tempbase[MAX_PATH * 2], tempdir[MAX_PATH * 4], wid[HK_MAX_IDENT + 1];
    char ident[HK_MAX_IDENT + 1];
    HANDLE h; LARGE_INTEGER sz, pos; HookieFooter ft; DWORD got; uint8_t *blob = NULL, *raw = NULL;
    if (!GetModuleFileNameW(g_self, module, (DWORD)(sizeof(module)/sizeof(module[0])))) return FALSE;
    h = CreateFileW(module, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE || !GetFileSizeEx(h, &sz) || sz.QuadPart < (LONGLONG)sizeof(ft)) { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); return FALSE; }
    pos.QuadPart = sz.QuadPart - (LONGLONG)sizeof(ft); SetFilePointerEx(h, pos, NULL, FILE_BEGIN);
    if (!ReadFile(h, &ft, sizeof(ft), &got, NULL) || got != sizeof(ft) || memcmp(ft.magic, HK_RESOURCE_MAGIC, 17) != 0 || ft.data_size > (uint64_t)(sz.QuadPart - sizeof(ft))) { CloseHandle(h); return FALSE; }
    pos.QuadPart = sz.QuadPart - (LONGLONG)sizeof(ft) - (LONGLONG)ft.data_size; SetFilePointerEx(h, pos, NULL, FILE_BEGIN);
    blob = (uint8_t *)malloc((size_t)ft.data_size + 1); if (!blob) { CloseHandle(h); return FALSE; }
    if (ft.data_size > 0xffffffffu || !ReadFile(h, blob, (DWORD)ft.data_size, &got, NULL) || got != (DWORD)ft.data_size) { free(blob); CloseHandle(h); return FALSE; }
    CloseHandle(h);
    if (ft.mode == HK_RESOURCE_PATH) {
        blob[ft.data_size] = 0;
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *)blob, -1, out, (int)cap)) { free(blob); return FALSE; }
        free(blob); return TRUE;
    }
    if (ft.mode != HK_RESOURCE_PACKED || ft.raw_size > SIZE_MAX || ft.raw_size > HK_MAX_RAW ||
        ft.ident_len == 0 || ft.ident_len > HK_MAX_IDENT || ft.data_size < ft.ident_len) { free(blob); return FALSE; }
    memcpy(ident, blob, ft.ident_len); ident[ft.ident_len] = 0;
    if (strspn(ident, "0123456789abcdefABCDEF") != ft.ident_len) { free(blob); return FALSE; }
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, ident, -1, wid, (int)(sizeof(wid)/sizeof(wid[0])))) { free(blob); return FALSE; }
    raw = (uint8_t *)malloc((size_t)ft.raw_size); if (!raw) { free(blob); return FALSE; }
    if (!lzss_decompress(blob + ft.ident_len, (size_t)ft.data_size - ft.ident_len, raw, (size_t)ft.raw_size)) { free(raw); free(blob); return FALSE; }
    free(blob);
    if (!GetTempPathW((DWORD)(sizeof(tempbase)/sizeof(tempbase[0])), tempbase)) { free(raw); return FALSE; }
    _snwprintf(tempdir, (sizeof(tempdir)/sizeof(tempdir[0])) - 1, L"%s%s", tempbase, wid);
    tempdir[(sizeof(tempdir)/sizeof(tempdir[0])) - 1] = 0;
    if (!CreateDirectoryW(tempdir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) { free(raw); return FALSE; }
    if (!extract_archive(raw, (size_t)ft.raw_size, tempdir)) { free(raw); return FALSE; }
    free(raw); wcsncpy(out, tempdir, cap - 1); out[cap - 1] = 0; return TRUE;
}

/* Return the full path of the bundled versioned CPython DLL. */
static BOOL find_python_dll(const wchar_t *dir, wchar_t *full, size_t full_cap,
                            wchar_t *base, size_t base_cap)
{
    wchar_t pattern[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    BOOL found = FALSE;

    _snwprintf(pattern, MAX_PATH, L"%spython3*.dll", dir);
    pattern[MAX_PATH - 1] = 0;

    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    do {
        if (_wcsicmp(fd.cFileName, L"python3.dll") == 0) continue;
        _snwprintf(full, full_cap, L"%s%s", dir, fd.cFileName);
        full[full_cap - 1] = 0;
        wcsncpy(base, fd.cFileName, base_cap - 1);
        base[base_cap - 1] = 0;
        found = TRUE;
        break;
    } while (FindNextFileW(h, &fd));

    FindClose(h);
    return found;
}

static BOOL bind_common_python(void)
{
    pPy_InitializeEx       = (Py_InitializeEx_t)GetProcAddress(g_py, "Py_InitializeEx");
    pPy_IsInitialized      = (Py_IsInitialized_t)GetProcAddress(g_py, "Py_IsInitialized");
    pPy_GetVersion         = (Py_GetVersion_t)GetProcAddress(g_py, "Py_GetVersion");
    pPyRun_SimpleString    = (PyRun_SimpleString_t)GetProcAddress(g_py, "PyRun_SimpleString");
    pPyErr_Print           = (PyErr_Print_t)GetProcAddress(g_py, "PyErr_Print");
    pPyEval_SaveThread     = (PyEval_SaveThread_t)GetProcAddress(g_py, "PyEval_SaveThread");
    pPyGILState_Ensure     = (PyGILState_Ensure_t)GetProcAddress(g_py, "PyGILState_Ensure");
    pPyGILState_Release    = (PyGILState_Release_t)GetProcAddress(g_py, "PyGILState_Release");

    return pPy_InitializeEx && pPy_IsInitialized && pPy_GetVersion &&
           pPyRun_SimpleString && pPyErr_Print && pPyEval_SaveThread &&
           pPyGILState_Ensure && pPyGILState_Release;
}


/* Convert payload dir to UTF-8 and escape it for a Python single-quoted literal. */
static BOOL python_quote_dir(const wchar_t *dir, char *out, size_t cap)
{
    char utf8[MAX_PATH * 4];
    int n = WideCharToMultiByte(CP_UTF8, 0, dir, -1,
                                utf8, (int)sizeof(utf8), NULL, NULL);
    size_t i, j = 0;
    if (!n) return FALSE;

    for (i = 0; utf8[i]; ++i) {
        unsigned char c = (unsigned char)utf8[i];
        if (c == '\\' || c == '\'') {
            if (j + 2 >= cap) return FALSE;
            out[j++] = '\\';
            out[j++] = (char)c;
        } else {
            if (j + 1 >= cap) return FALSE;
            out[j++] = (char)c;
        }
    }
    if (j >= cap) return FALSE;
    out[j] = 0;
    return TRUE;
}

static int execute_payload(const wchar_t *dir)
{
    char qdir[MAX_PATH * 8];
    char code[MAX_PATH * 20 + 4096];

    if (!python_quote_dir(dir, qdir, sizeof(qdir))) return -1;

    _snprintf(code, sizeof(code),
        "import sys, os, importlib.util\n"
        "_hookie_dir = '%s'\n"
        "_hookie_id = os.path.basename(os.path.normpath(_hookie_dir))\n"
        "_hookie_site = os.path.join(_hookie_dir, 'Lib', 'site-packages')\n"
        "if _hookie_site not in sys.path: sys.path.insert(0, _hookie_site)\n"
        "if _hookie_dir not in sys.path: sys.path.insert(0, _hookie_dir)\n"
        "# Keep the returned handle alive: closing/GC'ing it removes this DLL search path.\n"
        "if hasattr(os, 'add_dll_directory'):\n"
        "    if not hasattr(sys, '_hookie_dll_dirs'): sys._hookie_dll_dirs = []\n"
        "    sys._hookie_dll_dirs.append(os.add_dll_directory(_hookie_dir))\n"
        "_hookie_name = 'hookie_' + _hookie_id\n"
        "_hookie_file = os.path.join(_hookie_dir, 'hook.py')\n"
        "_hookie_mod = sys.modules.get(_hookie_name)\n"
        "if _hookie_mod is None:\n"
        "    _hookie_spec = importlib.util.spec_from_file_location(_hookie_name, _hookie_file)\n"
        "    if _hookie_spec is None or _hookie_spec.loader is None: raise ImportError('cannot load hookie payload')\n"
        "    _hookie_mod = importlib.util.module_from_spec(_hookie_spec)\n"
        "    _hookie_mod.__hookie_loaded__ = False\n"
        "    sys.modules[_hookie_name] = _hookie_mod\n"
        "    _hookie_spec.loader.exec_module(_hookie_mod)\n"
        "    _hookie_mod.__hookie_loaded__ = True\n"
        "elif not getattr(_hookie_mod, '__hookie_loaded__', False):\n"
        "    raise RuntimeError('previous hookie payload execution failed; refusing to execute it twice')\n",
        qdir);
    code[sizeof(code) - 1] = 0;

    {
        int rc = pPyRun_SimpleString(code);
        if (rc != 0) pPyErr_Print();
        return rc;
    }
}

static DWORD run_existing_runtime(HMODULE existing, const wchar_t *dir)
{
    int gil;
    int rc;
    g_py = existing;
    if (!bind_common_python()) {
        HK_TRACE(L"run_existing: required CPython API missing");
        return 30;
    }
    if (!pPy_IsInitialized()) {
        HK_TRACE(L"run_existing: matching CPython DLL is not initialized");
        return 31;
    }

    HK_TRACE(L"run_existing: acquiring target interpreter GIL");
    gil = pPyGILState_Ensure();
    rc = execute_payload(dir);
    pPyGILState_Release(gil);
    if (rc != 0) {
        HK_TRACE(L"run_existing: payload execution FAILED");
        return 32;
    }
    HK_TRACE(L"run_existing: payload executed in target main interpreter");
    return 0;
}

/* No matching initialized runtime exists: own the bundled runtime. */
static DWORD run_bundled_runtime(const wchar_t *dir, const wchar_t *pydll)
{
    HK_TRACE(L"run_bundled: LoadLibraryExW ->"); HK_TRACEW(pydll);
    g_py = LoadLibraryExW(pydll, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!g_py) { HK_TRACE(L"run_bundled: LoadLibraryExW FAILED"); return 20; }
    if (!bind_common_python()) { HK_TRACE(L"run_bundled: bind_common_python FAILED"); return 21; }

    /* The python3XX._pth beside the embeddable runtime defines its stdlib
     * search path.  We deliberately do not mutate PYTHONHOME/PYTHONPATH. */
    HK_TRACE(L"run_bundled: Py_InitializeEx");
    pPy_InitializeEx(0);
    if (!pPy_IsInitialized()) { HK_TRACE(L"run_bundled: not initialized"); return 22; }

    HK_TRACE(L"run_bundled: execute payload entrypoint");
    if (execute_payload(dir) != 0) {
        HK_TRACE(L"run_bundled: payload FAILED (idle)");
        /* Same process-lifetime rule: a partially installed hook must not be
         * left pointing at a finalized interpreter. */
        pPyEval_SaveThread();
        Sleep(INFINITE);
        return 23;
    }

    HK_TRACE(L"run_bundled: payload OK (idle)");
    pPyEval_SaveThread();
    Sleep(INFINITE);
    return 0;
}

static DWORD WINAPI worker(LPVOID param)
{
    wchar_t dir[MAX_PATH];
    wchar_t pydll[MAX_PATH];
    wchar_t pybase[MAX_PATH];
    HMODULE existing;
    (void)param;

    HK_TRACE(L"worker: begin");
    if (!resolve_payload_dir(dir, MAX_PATH)) { HK_TRACE(L"worker: resolve FAILED"); return 1; }
    HK_TRACE(L"worker: resolve OK, dir ->"); HK_TRACEW(dir);

    /* resolve_payload_dir yields a bare directory with no trailing separator,
     * while find_python_dll concatenates the directory and filename. */
    {
        size_t dl = wcslen(dir);
        if (dl && dir[dl - 1] != L'\\' && dir[dl - 1] != L'/' && dl + 2 < MAX_PATH) {
            dir[dl] = L'\\';
            dir[dl + 1] = 0;
        }
    }

    if (!find_python_dll(dir, pydll, MAX_PATH, pybase, MAX_PATH)) {
        HK_TRACE(L"worker: find_python_dll FAILED");
        return 1;
    }
    HK_TRACE(L"worker: bundled runtime ->"); HK_TRACEW(pydll);

    /* Same-version reuse is safe without a subinterpreter: bind the already
     * initialized main interpreter and enter it with PyGILState_Ensure. A
     * different python3XY.dll does not block the separately named bundled DLL. */
    existing = GetModuleHandleW(pybase);
    if (existing) {
        HK_TRACE(L"worker: matching target CPython found; reusing main interpreter ->");
        HK_TRACEW(pybase);
        return run_existing_runtime(existing, dir);
    }

    HK_TRACE(L"worker: no matching CPython; using bundled runtime");
    return run_bundled_runtime(dir, pydll);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE thread;
        g_self = (HMODULE)hinst;
        DisableThreadLibraryCalls(hinst);
        HK_TRACE(L"DllMain: PROCESS_ATTACH; starting worker");
        thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (thread) { HK_TRACE(L"DllMain: worker created"); CloseHandle(thread); }
        else HK_TRACE(L"DllMain: CreateThread FAILED");
    }

    /* Never call Python during DLL_PROCESS_DETACH. */
    return TRUE;
}
