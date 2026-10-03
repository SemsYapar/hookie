/*
 * hookie_stub_linux.c — Linux CPython bootstrap for hookie.
 *
 * Runtime policy:
 *   - If the target already owns the same CPython major.minor, reuse that
 *     main interpreter under PyGILState_Ensure.
 *   - If a different CPython runtime is present, do nothing: loading another
 *     libpython into the ELF process risks symbol interposition.
 *   - No subinterpreters are created.
 *
 * A Hookie-owned bundled interpreter is process-lifetime because installed
 * ctypes.CFUNCTYPE detours can execute later on arbitrary native threads.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <wchar.h>

typedef void           (*Py_InitializeEx_t)(int);
typedef int            (*Py_IsInitialized_t)(void);
typedef const char *   (*Py_GetVersion_t)(void);
typedef void           (*Py_SetPythonHome_t)(const wchar_t *);
typedef int            (*PyRun_SimpleString_t)(const char *);
typedef void           (*PyErr_Print_t)(void);
typedef void *         (*PyEval_SaveThread_t)(void);
typedef int            (*PyGILState_Ensure_t)(void);
typedef void           (*PyGILState_Release_t)(int);

static void *g_py;
static wchar_t g_python_home[PATH_MAX];

static Py_InitializeEx_t             pPy_InitializeEx;
static Py_IsInitialized_t            pPy_IsInitialized;
static Py_GetVersion_t               pPy_GetVersion;
static Py_SetPythonHome_t            pPy_SetPythonHome;
static PyRun_SimpleString_t          pPyRun_SimpleString;
static PyErr_Print_t                  pPyErr_Print;
static PyEval_SaveThread_t           pPyEval_SaveThread;
static PyGILState_Ensure_t           pPyGILState_Ensure;
static PyGILState_Release_t          pPyGILState_Release;

static void *sym(const char *name)
{
    return dlsym(g_py ? g_py : RTLD_DEFAULT, name);
}

#define HK_RESOURCE_MAGIC "HOOKIE_PAYLOAD_V1"
#define HK_RESOURCE_PATH 1
#define HK_RESOURCE_PACKED 2
#define HK_MAX_IDENT 64            /* sanity cap on the payload id length */
#define HK_MAX_RAW (1ull << 31)    /* 2 GiB cap on decompressed payload size */

#ifdef HK_DEBUG
#define HK_TRACE(msg) do { fprintf(stderr, "[hookie] %s\n", (msg)); fflush(stderr); } while (0)
#define HK_TRACEF(...) do { fprintf(stderr, "[hookie] "); fprintf(stderr, __VA_ARGS__); \
                            fputc('\n', stderr); fflush(stderr); } while (0)
#else
#define HK_TRACE(msg) ((void)0)
#define HK_TRACEF(...) ((void)0)
#endif

typedef struct __attribute__((packed)) {
    char magic[17];
    uint8_t mode;
    uint8_t ident_len;      /* id byte count (packed mode); 0 in path mode */
    uint8_t reserved[5];
    uint64_t raw_size;
    uint64_t data_size;
} HookieFooter;
typedef char HookieFooterSizeMustBe40[(sizeof(HookieFooter) == 40) ? 1 : -1];

static int self_path(char *out, size_t cap)
{
    Dl_info info;
    (void)cap;
    if (!dladdr((void *)&self_path, &info) || !info.dli_fname) return 0;
    return realpath(info.dli_fname, out) != NULL;
}

static int mkdir_parents(const char *path)
{
    char tmp[PATH_MAX];
    char *p;
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) return 0;
    for (p = tmp + 1; *p; ++p) {
        if (*p == '/') { *p = 0; mkdir(tmp, 0700); *p = '/'; }
    }
    return 1;
}

static int lzss_decompress(const uint8_t *src, size_t src_n, uint8_t *dst, size_t dst_n)
{
    size_t si = 0, di = 0;
    while (si < src_n && di < dst_n) {
        uint8_t flags = src[si++];
        int bit;
        for (bit = 0; bit < 8 && di < dst_n; ++bit) {
            if (flags & (1u << bit)) {
                if (si >= src_n) return 0;
                dst[di++] = src[si++];
            } else {
                uint16_t t; size_t dist, len, j;
                if (si + 2 > src_n) return 0;
                t = (uint16_t)(src[si] | ((uint16_t)src[si + 1] << 8)); si += 2;
                dist = t & 0x0fff; len = ((t >> 12) & 0x0f) + 3;
                if (!dist || dist > di || di + len > dst_n) return 0;
                for (j = 0; j < len; ++j) { dst[di] = dst[di - dist]; ++di; }
            }
        }
    }
    return di == dst_n;
}

static int extract_archive(const uint8_t *raw, size_t n, const char *root)
{
    size_t at = 0;
    while (at + 4 <= n) {
        uint32_t plen; uint64_t size; char rel[PATH_MAX], full[PATH_MAX]; FILE *f;
        memcpy(&plen, raw + at, 4); at += 4;
        if (!plen) return 1;
        if (at + 8 + plen > n || plen >= sizeof(rel)) return 0;
        memcpy(&size, raw + at, 8); at += 8;
        memcpy(rel, raw + at, plen); rel[plen] = 0; at += plen;
        if (rel[0] == '/' || strstr(rel, "../") || strstr(rel, "\\")) return 0;
        if (size > n - at) return 0;
        if (snprintf(full, sizeof(full), "%s/%s", root, rel) >= (int)sizeof(full)) return 0;
        if (!mkdir_parents(full)) return 0;
        f = fopen(full, "wb"); if (!f) return 0;
        if (size && fwrite(raw + at, 1, (size_t)size, f) != (size_t)size) { fclose(f); return 0; }
        fclose(f); at += (size_t)size;
    }
    return 0;
}

static int resolve_payload_dir(char *out, size_t cap)
{
    char module[PATH_MAX], temp[PATH_MAX], ident[HK_MAX_IDENT + 1], *tmpbase;
    FILE *f; long end; HookieFooter ft; uint8_t *blob = NULL, *raw = NULL;
    if (!self_path(module, sizeof(module))) return 0;
    f = fopen(module, "rb"); if (!f) return 0;
    if (fseek(f, 0, SEEK_END) || (end = ftell(f)) < (long)sizeof(ft)) { fclose(f); return 0; }
    if (fseek(f, end - (long)sizeof(ft), SEEK_SET) || fread(&ft, 1, sizeof(ft), f) != sizeof(ft)) { fclose(f); return 0; }
    if (memcmp(ft.magic, HK_RESOURCE_MAGIC, 17) != 0 || ft.data_size > (uint64_t)(end - (long)sizeof(ft))) { fclose(f); return 0; }
    if (fseek(f, end - (long)sizeof(ft) - (long)ft.data_size, SEEK_SET)) { fclose(f); return 0; }
    blob = (uint8_t *)malloc((size_t)ft.data_size + 1); if (!blob) { fclose(f); return 0; }
    if (fread(blob, 1, (size_t)ft.data_size, f) != (size_t)ft.data_size) { free(blob); fclose(f); return 0; }
    fclose(f);
    if (ft.mode == HK_RESOURCE_PATH) {
        if (ft.data_size + 1 > cap) { free(blob); return 0; }
        memcpy(out, blob, (size_t)ft.data_size); out[ft.data_size] = 0; free(blob); return 1;
    }
    if (ft.mode != HK_RESOURCE_PACKED || ft.raw_size > SIZE_MAX || ft.raw_size > HK_MAX_RAW ||
        ft.ident_len == 0 || ft.ident_len > HK_MAX_IDENT || ft.data_size < ft.ident_len) { free(blob); return 0; }
    memcpy(ident, blob, ft.ident_len); ident[ft.ident_len] = 0;
    if (strspn(ident, "0123456789abcdefABCDEF") != ft.ident_len) { free(blob); return 0; }
    raw = (uint8_t *)malloc((size_t)ft.raw_size); if (!raw) { free(blob); return 0; }
    if (!lzss_decompress(blob + ft.ident_len, (size_t)ft.data_size - ft.ident_len, raw, (size_t)ft.raw_size)) { free(raw); free(blob); return 0; }
    free(blob);
    tmpbase = getenv("TMPDIR"); if (!tmpbase || !*tmpbase) tmpbase = "/tmp";
    if (snprintf(temp, sizeof(temp), "%s/%s", tmpbase, ident) >= (int)sizeof(temp)) { free(raw); return 0; }
    if (mkdir(temp, 0700) != 0 && errno != EEXIST) { free(raw); return 0; }
    if (!extract_archive(raw, (size_t)ft.raw_size, temp)) { free(raw); return 0; }
    free(raw);
    return snprintf(out, cap, "%s", temp) < (int)cap;
}

static int find_python(const char *dir, char *out, size_t cap,
                       char *version, size_t version_cap)
{
    char marker[PATH_MAX];
    char rel[PATH_MAX];
    const char *name;
    const char *p;
    FILE *f;
    int major = 0, minor = 0;
    int digits = 0;

    if (snprintf(marker, sizeof(marker), "%s/.hookie-libpython", dir) >= (int)sizeof(marker))
        return 0;
    f = fopen(marker, "r");
    if (!f) return 0;
    if (!fgets(rel, sizeof(rel), f)) { fclose(f); return 0; }
    fclose(f);
    rel[strcspn(rel, "\r\n")] = '\0';
    if (!rel[0] || rel[0] == '/') return 0;
    if (snprintf(out, cap, "%s/%s", dir, rel) >= (int)cap) return 0;

    name = strrchr(rel, '/');
    name = name ? name + 1 : rel;
    p = strstr(name, "libpython");
    if (!p) return 0;
    p += strlen("libpython");
    while (*p >= '0' && *p <= '9') {
        major = major * 10 + (*p - '0');
        if (major > 99) return 0;
        ++p; ++digits;
    }
    if (!digits || *p != '.') return 0;
    ++p; digits = 0;
    while (*p >= '0' && *p <= '9') {
        minor = minor * 10 + (*p - '0');
        if (minor > 99) return 0;
        ++p; ++digits;
    }
    if (!digits) return 0;
    return snprintf(version, version_cap, "%d.%d", major, minor) < (int)version_cap;
}

static int version_matches(const char *actual, const char *expected)
{
    size_t n;
    if (!actual || !expected) return 0;
    n = strlen(expected);
    if (strncmp(actual, expected, n) != 0) return 0;
    return actual[n] == '\0' || actual[n] == '.' || actual[n] == ' ';
}

/* Detect an interpreter whose C API is process-global (normal Python and many
 * embedding applications). Returns 1 when Py_IsInitialized is visible. */
static int visible_python_runtime(const char **actual_out, int *initialized_out)
{
    Py_IsInitialized_t is_init =
        (Py_IsInitialized_t)dlsym(RTLD_DEFAULT, "Py_IsInitialized");
    Py_GetVersion_t get_version =
        (Py_GetVersion_t)dlsym(RTLD_DEFAULT, "Py_GetVersion");
    if (actual_out) *actual_out = NULL;
    if (initialized_out) *initialized_out = 0;
    if (!is_init) return 0;
    if (actual_out && get_version) *actual_out = get_version();
    if (initialized_out) *initialized_out = is_init();
    return 1;
}

/* Some embedders dlopen libpython with RTLD_LOCAL, so its symbols are absent
 * from RTLD_DEFAULT. /proc/self/maps lets us find the already loaded object and
 * RTLD_NOLOAD obtains a handle without introducing another runtime.\n
 * Return: 1=same version found, 0=no libpython mapping, -1=different version
 * present, -2=maps unavailable/ambiguous. */
static int mapped_python_runtime(const char *expected, char *same_path, size_t cap)
{
    FILE *f;
    char line[PATH_MAX * 2];
    int saw_different = 0;
    int saw_same = 0;

    f = fopen("/proc/self/maps", "r");
    if (!f) return -2;
    while (fgets(line, sizeof(line), f)) {
        char *path = strchr(line, '/');
        char *name;
        char ver[32];
        const char *p;
        int major = 0, minor = 0, digits = 0;
        if (!path) continue;
        path[strcspn(path, "\r\n")] = '\0';
        name = strrchr(path, '/');
        name = name ? name + 1 : path;
        p = strstr(name, "libpython");
        if (!p) continue;
        p += strlen("libpython");
        while (*p >= '0' && *p <= '9') { major = major * 10 + (*p++ - '0'); ++digits; }
        if (!digits || *p != '.') continue;
        ++p; digits = 0;
        while (*p >= '0' && *p <= '9') { minor = minor * 10 + (*p++ - '0'); ++digits; }
        if (!digits) continue;
        if (snprintf(ver, sizeof(ver), "%d.%d", major, minor) >= (int)sizeof(ver)) continue;
        if (strcmp(ver, expected) == 0) {
            if (!saw_same) {
                if (snprintf(same_path, cap, "%s", path) >= (int)cap) {
                    fclose(f); return -2;
                }
                saw_same = 1;
            }
        } else {
            saw_different = 1;
        }
    }
    fclose(f);
    if (saw_different) return -1; /* multiple runtimes on Linux: refuse */
    return saw_same ? 1 : 0;
}


static int bind_common_python(void)
{
    pPy_InitializeEx = (Py_InitializeEx_t)sym("Py_InitializeEx");
    pPy_IsInitialized = (Py_IsInitialized_t)sym("Py_IsInitialized");
    pPy_GetVersion = (Py_GetVersion_t)sym("Py_GetVersion");
    pPyRun_SimpleString = (PyRun_SimpleString_t)sym("PyRun_SimpleString");
    pPyErr_Print = (PyErr_Print_t)sym("PyErr_Print");
    pPyEval_SaveThread = (PyEval_SaveThread_t)sym("PyEval_SaveThread");
    pPyGILState_Ensure = (PyGILState_Ensure_t)sym("PyGILState_Ensure");
    pPyGILState_Release = (PyGILState_Release_t)sym("PyGILState_Release");
    return pPy_InitializeEx && pPy_IsInitialized && pPy_GetVersion &&
           pPyRun_SimpleString && pPyErr_Print && pPyEval_SaveThread &&
           pPyGILState_Ensure && pPyGILState_Release;
}


static int python_quote(const char *src, char *out, size_t cap)
{
    size_t i, j = 0;
    for (i = 0; src[i]; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\\' || c == '\'') {
            if (j + 2 >= cap) return 0;
            out[j++] = '\\';
            out[j++] = (char)c;
        } else {
            if (j + 1 >= cap) return 0;
            out[j++] = (char)c;
        }
    }
    if (j >= cap) return 0;
    out[j] = '\0';
    return 1;
}

static int execute_payload(const char *dir, const char *version)
{
    char qdir[PATH_MAX * 2];
    char code[PATH_MAX * 6 + 4096];

    if (!python_quote(dir, qdir, sizeof(qdir))) return -1;
    if (snprintf(code, sizeof(code),
        "import sys, os, importlib.util\n"
        "_hookie_dir = '%s'\n"
        "_hookie_id = os.path.basename(os.path.normpath(_hookie_dir))\n"
        "_hookie_site = os.path.join(_hookie_dir, 'lib', 'python%s', 'site-packages')\n"
        "if _hookie_site not in sys.path: sys.path.insert(0, _hookie_site)\n"
        "if _hookie_dir not in sys.path: sys.path.insert(0, _hookie_dir)\n"
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
        qdir, version) >= (int)sizeof(code)) return -1;

    {
        int rc = pPyRun_SimpleString(code);
        if (rc != 0) pPyErr_Print();
        return rc;
    }
}

static void *run_existing_runtime(void *handle, const char *dir, const char *version)
{
    int gil;
    int rc;
    g_py = handle; /* NULL means RTLD_DEFAULT. */
    if (!bind_common_python()) {
        fprintf(stderr, "hookie: existing CPython lacks required API\n");
        return NULL;
    }
    if (!pPy_IsInitialized()) {
        fprintf(stderr, "hookie: matching CPython is loaded but not initialized\n");
        return NULL;
    }

    HK_TRACEF("run_existing: reusing CPython %s main interpreter", pPy_GetVersion());
    gil = pPyGILState_Ensure();
    rc = execute_payload(dir, version);
    pPyGILState_Release(gil);
    if (rc != 0)
        fprintf(stderr, "hookie: payload execution failed in existing interpreter\n");
    else
        HK_TRACE("run_existing: payload executed successfully");
    return NULL;
}


static void park_interpreter(void)
{
    pPyEval_SaveThread();
    for (;;) pause();
}

static int set_bundled_home(const char *dir)
{
    size_t n;
    pPy_SetPythonHome = (Py_SetPythonHome_t)sym("Py_SetPythonHome");
    if (!pPy_SetPythonHome) return 0;
    n = mbstowcs(g_python_home, dir, PATH_MAX - 1);
    if (n == (size_t)-1 || n >= PATH_MAX) return 0;
    g_python_home[n] = L'\0';
    pPy_SetPythonHome(g_python_home);
    return 1;
}

static void *run_bundled_runtime(const char *dir, const char *pydll,
                                 const char *version)
{
    HK_TRACEF("run_bundled: dlopen(%s)", pydll);
    g_py = dlopen(pydll, RTLD_NOW | RTLD_GLOBAL);
    if (!g_py) {
        fprintf(stderr, "hookie: dlopen(%s) failed: %s\n", pydll, dlerror());
        return NULL;
    }
    if (!bind_common_python()) {
        HK_TRACE("run_bundled: bind_common_python failed");
        fprintf(stderr, "hookie: bundled CPython lacks required API\n");
        return NULL;
    }

    /* Configure the runtime directly instead of changing PYTHONHOME in the
     * process environment.  The buffer is static because CPython requires the
     * home string to remain valid through initialization. */
    HK_TRACE("run_bundled: configuring Python home");
    if (!set_bundled_home(dir)) {
        fprintf(stderr, "hookie: Py_SetPythonHome unavailable/failed\n");
        return NULL;
    }

    HK_TRACE("run_bundled: Py_InitializeEx");
    pPy_InitializeEx(0);
    if (!pPy_IsInitialized()) {
        fprintf(stderr, "hookie: bundled CPython initialization failed\n");
        return NULL;
    }

    HK_TRACE("run_bundled: execute payload entrypoint");
    if (execute_payload(dir, version) != 0)
        fprintf(stderr, "hookie: payload execution failed; keeping runtime alive\n");
    else
        HK_TRACE("run_bundled: payload OK; parking interpreter");

    park_interpreter();
    return NULL;
}

static void *worker(void *unused)
{
    char dir[PATH_MAX];
    char pydll[PATH_MAX];
    char version[32];
    (void)unused;
    HK_TRACE("worker: begin");

    if (!resolve_payload_dir(dir, sizeof(dir))) {
        fprintf(stderr, "hookie: cannot resolve payload resource\n");
        return NULL;
    }
    HK_TRACEF("worker: payload dir = %s", dir);
    if (!find_python(dir, pydll, sizeof(pydll), version, sizeof(version))) {
        fprintf(stderr, "hookie: cannot resolve bundled libpython/version\n");
        return NULL;
    }
    HK_TRACEF("worker: bundled libpython = %s (CPython %s)", pydll, version);

    /* First handle normal Python/embedders whose C API is globally visible. */
    {
        const char *actual = NULL;
        int initialized = 0;
        if (visible_python_runtime(&actual, &initialized)) {
            char mapped_check[PATH_MAX];
            int mapped_rc;
            if (!actual || !version_matches(actual, version)) {
                fprintf(stderr,
                    "hookie: target exposes CPython %s but payload needs %s; "
                    "Linux will not load a second libpython\n",
                    actual ? actual : "<unknown>", version);
                return NULL;
            }
            if (!initialized) {
                fprintf(stderr, "hookie: matching target CPython is not initialized\n");
                return NULL;
            }
            mapped_rc = mapped_python_runtime(version, mapped_check, sizeof(mapped_check));
            if (mapped_rc == -1) {
                fprintf(stderr,
                    "hookie: multiple CPython versions are already mapped; refusing reuse on Linux\n");
                return NULL;
            }
            if (mapped_rc == -2) {
                fprintf(stderr,
                    "hookie: cannot verify Linux libpython mappings; refusing existing-runtime reuse\n");
                return NULL;
            }
            HK_TRACEF("worker: reusing visible target CPython %s", actual);
            return run_existing_runtime(NULL, dir, version);
        }
    }

    /* Then catch RTLD_LOCAL libpython instances. Reuse only the same version;
     * the presence of any different libpython is a hard stop on Linux. */
    {
        char mapped[PATH_MAX];
        int mapped_rc = mapped_python_runtime(version, mapped, sizeof(mapped));
        if (mapped_rc == 1) {
            void *existing = dlopen(mapped, RTLD_NOW | RTLD_NOLOAD);
            if (!existing) {
                fprintf(stderr, "hookie: matching libpython is mapped but RTLD_NOLOAD failed\n");
                return NULL;
            }
            HK_TRACEF("worker: reusing mapped target CPython -> %s", mapped);
            return run_existing_runtime(existing, dir, version);
        }
        if (mapped_rc == -1) {
            fprintf(stderr,
                "hookie: a different libpython is already mapped; Linux will not load a second runtime\n");
            return NULL;
        }
        if (mapped_rc == -2) {
            fprintf(stderr,
                "hookie: cannot safely determine loaded libpython state; refusing bundled runtime\n");
            return NULL;
        }
    }

    HK_TRACEF("worker: no target CPython found; using bundled CPython %s", version);
    return run_bundled_runtime(dir, pydll, version);
}

__attribute__((constructor))
static void hookie_start(void)
{
    pthread_t t;
    HK_TRACE("constructor: starting worker");
    if (pthread_create(&t, NULL, worker, NULL) == 0) {
        HK_TRACE("constructor: worker created");
        pthread_detach(t);
    } else {
        HK_TRACE("constructor: pthread_create failed");
    }
}
