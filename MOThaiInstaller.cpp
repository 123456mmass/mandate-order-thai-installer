/* ---------------------------------------------------------------------------
 * MOThaiInstaller -- standalone GUI installer for the Mandate Order
 * Thai-translation mod.
 *
 * Why C++ and not Python: the people who install mods do not have a Python
 * environment.  One .exe, no runtime, nothing to install first -- and the pak
 * it installs is appended to the exe itself, so there is no loose .pak to
 * download, unpack or misplace either.
 *
 * The mod takes over an EMPTY pak slot the game already ships and never uses:
 * `pakchunk5000_s3-Windows.pak`, 365 bytes with no files in it.  Chosen because
 * pak files mount in descending filename order and this name sorts above
 * pakchunk0 and its _s1/_s2/_s3 siblings, so ours wins every path it carries --
 * and because a matching `.utoc` already exists beside it, which is what lets
 * a pak mount at all.  The game's own .pak/.ucas/.utoc for that chunk are never
 * touched.
 *
 * What it does, in order:
 *   1. locates the game (Steam library scan -> registry -> browse dialog)
 *   2. backs up the 365-byte original of that slot into
 *        <game>\MOProject\Content\Paks\_ThaiMod_Backup\
 *      plus manifest.txt, which records the original bytes of the exe edit, so
 *      restoring does not need a 215 MB copy of the exe
 *   3. patches one 6-byte site in MOProject-Win64-Shipping.exe: the `jne` in
 *      FPakFile::CreatePakReader that routes a modified pak into signature
 *      verification -- NOP it, or every pak we rebuild is rejected as unsigned
 *   4. writes the pak out of the payload appended to this exe
 *   5. verifies what it wrote against the expected SHA-256
 *
 * Uninstall reverses exactly those steps from the backup folder.
 *
 * Build (MinGW-w64), then append the payload:
 *   g++ -O2 -std=c++17 -mwindows -static -static-libgcc -static-libstdc++ \
 *       MOThaiInstaller.cpp -o MOThaiInstaller.exe \
 *       -lcomctl32 -lshell32 -lole32 -luuid
 *   python installer/make_payload.py MOThaiInstaller.exe <mod pak>
 *
 * The exe patch site was reverse-engineered from the shipped build and is
 * re-located at run time by pattern scan rather than trusted blindly, so a
 * Steam update fails loudly instead of silently patching the wrong bytes.
 * ------------------------------------------------------------------------- */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

/* ------------------------------------------------------------------ consts */

/* The empty slot the mod takes over.  Its original content is nothing but a
 * 365-byte header, so the backup of it is free. */
static const wchar_t* SLOT_NAME = L"pakchunk5000_s3-Windows.pak";
static const wchar_t* PAKS_REL = L"MOProject\\Content\\Paks";
static const wchar_t* EXE_REL = L"MOProject\\Binaries\\Win64\\MOProject-Win64-Shipping.exe";
static const wchar_t* BACKUP_DIR = L"_ThaiMod_Backup";
/* a leftover .pak from the first generation of this mod, which the game would
 * mount ahead of everything and which must not be left behind */
static const wchar_t* STALE_P = L"MOProject_ThaiMod_P.pak";
static const wchar_t* MOD_VERSION = L"1.0";

/* The build this mod was created against.  Size plus the six bytes at the patch
 * site is the check -- not a whole-file hash, because the exe legitimately has
 * those six bytes changed once we have run, and a second install must not be
 * mistaken for an unknown build. */
static const uint64_t REF_EXE_SIZE = 215169944ull;

/* --- exe patch site ------------------------------------------------------- */
/* `jne 0x142648CD0` directly after `cmp byte ptr [rcx+0x2f0], bpl` in
 * FPakFile::CreatePakReader -- NOP it so a rebuilt pak is not sent to the
 * signature verifier.  See the docstring of tools/patch_exe_nosig.py for the
 * disassembly trail. */
static const uint64_t SIG_VA = 0x142648B7Eull;
static const uint64_t SIG_OFF_DIRECT = 0x264817Eull;   /* SIG_VA - image base */
static const uint64_t SIG_TARGET_VA = 0x142648CD0ull;
static const uint8_t  SIG_EXPECT[6] = {0x0f, 0x85, 0x4c, 0x01, 0x00, 0x00};
static const uint8_t  SIG_PATCH[6]  = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

/* --- the pak we install --------------------------------------------------- */
/* Kept so a truncated or tampered payload is caught here rather than blamed on
 * the game afterwards.  Regenerate this line whenever the pak is rebuilt. */
static const wchar_t* MOD_SHA = L"99acfffdbe64e226e3923c790ce47863e9521f979ab0bbabe8a4fe43519c8e02";
static const uint64_t MOD_SIZE = 56786833ull;

/* --- payload trailer ------------------------------------------------------ */
/* The pak is appended to this exe after a 24-byte footer: magic, offset, size.
 * Appending rather than embedding as a resource keeps the build a plain g++
 * invocation with no windres step over a 54 MB blob. */
static const char PAYLOAD_MAGIC[8] = {'M','O','T','H','A','I','P','K'};
static const int  PAYLOAD_FOOTER = 24;

/* ------------------------------------------------------------------ globals */

static HINSTANCE g_inst;
static HWND g_main, g_path, g_status, g_chk_backup, g_prog, g_action, g_log;
static HWND g_b_install, g_b_uninstall, g_b_close, g_b_browse;
static HFONT g_font, g_font_bold;
static std::wstring g_exedir;
static bool g_busy;
static bool g_cli;        /* --install/--uninstall: no window, log to stdout */
static volatile int g_pb_base, g_pb_span;   /* current phase's slice of the bar */

#define WM_LOG      (WM_APP + 1)
#define WM_PROGRESS (WM_APP + 2)
#define WM_DONE     (WM_APP + 3)

/* -------------------------------------------------------------------- utils */

static std::wstring fmt(const wchar_t* f, ...) {
    wchar_t buf[2048];
    va_list ap;
    va_start(ap, f);
    _vsnwprintf(buf, 2047, f, ap);
    va_end(ap);
    buf[2047] = 0;
    return buf;
}

static std::wstring narrow(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::string widen(const std::wstring& s) {
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string o((size_t)n, 0);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &o[0], n, nullptr, nullptr);
    return o;
}

static std::wstring join(const std::wstring& a, const wchar_t* b) {
    if (a.empty()) return b;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L'\\' + b;
}

static std::wstring join(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L'\\' + b;
}

static bool seek64(HANDLE h, uint64_t off) {
    LONG hi = (LONG)(off >> 32);
    return SetFilePointer(h, (LONG)(off & 0xFFFFFFFFull), &hi, FILE_BEGIN)
           != INVALID_SET_FILE_POINTER;
}

static std::wstring dirname_of(const std::wstring& p) {
    size_t k = p.find_last_of(L"\\/");
    return k == std::wstring::npos ? std::wstring(L".") : p.substr(0, k);
}

static bool is_dir(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool is_file(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static uint64_t file_size(const std::wstring& p) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &d)) return 0;
    return ((uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow;
}

static std::wstring trim_end(std::wstring s) {
    while (!s.empty() && (s.back() == L'\\' || s.back() == L'/' || s.back() == L' ')) s.pop_back();
    return s;
}

static std::wstring fmt_mb(uint64_t b) {
    return fmt(L"%.1f MB", (double)b / 1048576.0);
}

/* ------------------------------------------------------------------ sha-256 */

namespace sha256impl {
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static inline uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

struct Ctx {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t n;
    void init() {
        static const uint32_t I[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        memcpy(h, I, sizeof I);
        len = 0; n = 0;
    }
    void block(const uint8_t* p) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
                   ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void update(const uint8_t* p, size_t n) {
        len += n;
        while (n) {
            size_t take = 64 - this->n;
            if (take > n) take = n;
            memcpy(buf + this->n, p, take);
            this->n += take; p += take; n -= take;
            if (this->n == 64) { block(buf); this->n = 0; }
        }
    }
    void final(uint8_t out[32]) {
        uint64_t bits = len * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t z = 0;
        while (n != 56) update(&z, 1);
        uint8_t L[8];
        for (int i = 0; i < 8; i++) L[i] = (uint8_t)(bits >> (56 - 8*i));
        update(L, 8);
        for (int i = 0; i < 8; i++) {
            out[i*4]   = (uint8_t)(h[i] >> 24);
            out[i*4+1] = (uint8_t)(h[i] >> 16);
            out[i*4+2] = (uint8_t)(h[i] >> 8);
            out[i*4+3] = (uint8_t)h[i];
        }
    }
};
} // namespace sha256impl

static void hex32(const uint8_t in[32], wchar_t out[65]) {
    static const wchar_t* D = L"0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i*2]   = D[in[i] >> 4];
        out[i*2+1] = D[in[i] & 15];
    }
    out[64] = 0;
}

static bool sha_file(const std::wstring& path, wchar_t out[65], uint64_t* size) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    sha256impl::Ctx c;
    c.init();
    uint8_t buf[1 << 16];
    DWORD got;
    uint64_t total = 0;
    while (ReadFile(h, buf, sizeof buf, &got, nullptr) && got) { c.update(buf, got); total += got; }
    CloseHandle(h);
    uint8_t d[32];
    c.final(d);
    hex32(d, out);
    if (size) *size = total;
    return true;
}

/* ------------------------------------------------------------- PE section map */

struct Pe {
    bool ok;
    uint64_t image_base;
    struct Sec { uint32_t va, vsz, raw, rsz; };
    std::vector<Sec> secs;

    /* Only the headers and the section table are needed, so read a fixed window
     * instead of loading 215 MB into RAM just to look up one offset. */
    bool load(const std::wstring& path) {
        ok = false;
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        uint8_t d[4096];
        DWORD got = 0;
        if (!ReadFile(h, d, sizeof d, &got, nullptr) || got < 512) { CloseHandle(h); return false; }
        CloseHandle(h);
        if (d[0] != 'M' || d[1] != 'Z') return false;
        uint32_t e = *(uint32_t*)(d + 0x3c);
        if (e + 24 > got || memcmp(d + e, "PE\0\0", 4)) return false;
        uint16_t magic = *(uint16_t*)(d + e + 24);
        uint16_t nsec  = *(uint16_t*)(d + e + 6);
        if (magic != 0x20b) return false;              // PE32+ only
        image_base = *(uint64_t*)(d + e + 24 + 24);
        uint32_t so = e + 24 + 240;
        if (so + (uint32_t)nsec * 40 > got) return false;
        for (uint16_t i = 0; i < nsec; i++) {
            /* IMAGE_SECTION_HEADER order, which is not the order the names
             * suggest: Misc (VirtualSize) comes FIRST, then VirtualAddress,
             * then SizeOfRawData, then PointerToRawData.  Reading VirtualSize
             * as VirtualAddress made every section look like it spanned the
             * whole image, so rva_to_off() matched the wrong section for every
             * address it was asked about. */
            const uint8_t* s = d + so + i * 40;
            Sec x;
            x.vsz = *(uint32_t*)(s + 8);    /* Misc.VirtualSize    */
            x.va  = *(uint32_t*)(s + 12);   /* VirtualAddress      */
            x.rsz = *(uint32_t*)(s + 16);   /* SizeOfRawData       */
            x.raw = *(uint32_t*)(s + 20);   /* PointerToRawData    */
            secs.push_back(x);
        }
        ok = true;
        return true;
    }
    int64_t off_to_rva(int64_t off) const {
        for (size_t i = 0; i < secs.size(); i++)
            if (off >= (int64_t)secs[i].raw && off < (int64_t)secs[i].raw + (int64_t)secs[i].rsz)
                return (int64_t)secs[i].va + (off - (int64_t)secs[i].raw);
        return -1;
    }
    int64_t rva_to_off(uint32_t rva) const {
        for (size_t i = 0; i < secs.size(); i++)
            if (rva >= secs[i].va && rva < secs[i].va + std::max(secs[i].vsz, secs[i].rsz))
                return (int64_t)secs[i].raw + (rva - secs[i].va);
        return -1;
    }
    uint64_t va_of(int64_t off) const {
        long r = off_to_rva(off);
        return r < 0 ? 0 : image_base + (uint64_t)r;
    }
};

/* -------------------------------------------------------------- job plumbing */

/* The pak riding inside this exe, located by its trailer.  Declared here rather
 * than with the rest of the payload code because Job below carries one. */
struct Payload {
    bool ok;
    uint64_t off, size;
    Payload() : ok(false), off(0), size(0) {}
};

struct Job {
    bool install;
    bool do_backup;
    std::wstring root, paks, exe, self;
    Payload payload;
};

/* Where the run log goes.  Beside the exe is the obvious place, but an exe run
 * straight out of the download zip lives in a temp folder that is deleted on
 * exit, so fall back to %LOCALAPPDATA% when the exe's own folder is not
 * writable.  Resolved once, on first use. */
static std::wstring& log_path() {
    static std::wstring cached;
    if (!cached.empty()) return cached;

    std::wstring candidate = g_exedir.empty()
        ? std::wstring() : join(g_exedir, L"MOThaiInstaller.log");
    if (!candidate.empty()) {
        HANDLE h = CreateFileW(candidate.c_str(), FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); cached = candidate; return cached; }
    }
    wchar_t buf[MAX_PATH] = L"";
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH)) {
        std::wstring dir = join(std::wstring(buf), L"MOThaiMod");
        CreateDirectoryW(dir.c_str(), nullptr);
        cached = join(dir, L"install.log");
    }
    return cached;
}

/* One line per open, one open per line: the volume here is a few dozen lines
 * and a long-lived handle would hold the file open if the process is killed. */
static void log_to_file(const std::wstring& s) {
    const std::wstring& p = log_path();
    if (p.empty()) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t stamp[16];
    _snwprintf(stamp, 15, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    stamp[15] = 0;
    HANDLE h = CreateFileW(p.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string u = widen(fmt(L"[%s] %s", stamp, s.c_str())) + "\r\n";
    DWORD put = 0;
    WriteFile(h, u.data(), (DWORD)u.size(), &put, nullptr);
    CloseHandle(h);
}

struct Backend {
    HWND hwnd;
    explicit Backend(HWND h) : hwnd(h) {}

    void log(const std::wstring& s) const {
        /* Every line goes to the file as well as to the window.  A user who
         * hits a problem should be able to send one file, not retype what they
         * saw; and in CLI mode it is the only record that survives, because
         * attaching to the parent console re-points stdout at CONOUT$ and a
         * redirect from the caller then captures nothing. */
        log_to_file(s);
        if (g_cli) { _putws(s.c_str()); return; }
        PostMessageW(hwnd, WM_LOG, 0, (LPARAM)new std::wstring(s));
    }
    void logf(const wchar_t* f, ...) const {
        wchar_t buf[2048];
        va_list ap; va_start(ap, f);
        _vsnwprintf(buf, 2047, f, ap);
        va_end(ap); buf[2047] = 0;
        log(buf);
    }
    /* announce the start of stage `i` of `n`; the bar jumps there and the next
     * file copy fills the remaining slice */
    void stage(int i, int n, const wchar_t* what) const {
        if (g_cli) return;
        int base = i * 100 / n;
        g_pb_base = base;
        g_pb_span = 100 / n;
        PostMessageW(hwnd, WM_PROGRESS, (WPARAM)((unsigned short)base),
                     (LPARAM)new std::wstring(what));
    }
};

/* CopyFileEx progress callback.  It must only PostMessage -- calling into the
 * UI thread from here deadlocks against the busy state. */
static DWORD WINAPI copy_cb(LARGE_INTEGER total, LARGE_INTEGER done,
                            LARGE_INTEGER, LARGE_INTEGER, DWORD, DWORD,
                            HANDLE, HANDLE, LPVOID) {
    if (total.QuadPart <= 0) return PROGRESS_CONTINUE;
    static int last = -1;
    int pct = (int)(done.QuadPart * 100 / total.QuadPart);
    if (pct == last) return PROGRESS_CONTINUE;
    last = pct;
    int overall = g_pb_base + (int)((__int64)pct * g_pb_span / 100);
    if (overall > 100) overall = 100;
    PostMessageW(g_main, WM_PROGRESS, (WPARAM)((unsigned short)overall),
                 (LPARAM)new std::wstring(fmt(L"กำลังคัดลอกไฟล์... %d%%", pct)));
    return PROGRESS_CONTINUE;
}

static bool copy_pak(Backend& be, const std::wstring& src, const std::wstring& dst,
                     const wchar_t* label) {
    be.logf(L"  คัดลอก %s  (%s)", label, fmt_mb(file_size(src)).c_str());
    if (!CopyFileExW(src.c_str(), dst.c_str(), copy_cb, nullptr, nullptr, 0)) {
        be.logf(L"  !! คัดลอกไม่สำเร็จ (โค้ด %lu) -> %s", GetLastError(), dst.c_str());
        return false;
    }
    return true;
}

static void remove_tree(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(join(dir, L"*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) { RemoveDirectoryW(dir.c_str()); return; }
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        std::wstring p = join(dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) remove_tree(p);
        else SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_NORMAL), DeleteFileW(p.c_str());
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    RemoveDirectoryW(dir.c_str());
}

/* -------------------------------------------------------------------- payload */

/* The pak rides along inside this exe.  Reading our own image is a plain file
 * read; nothing is extracted to disk in between, and the destination is written
 * once, under its final name, straight from the payload. */
static Payload find_payload(const std::wstring& self) {
    Payload p;
    uint64_t total = file_size(self);
    if (total < PAYLOAD_FOOTER) return p;
    HANDLE h = CreateFileW(self.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return p;
    uint8_t f[PAYLOAD_FOOTER];
    DWORD got = 0;
    if (seek64(h, total - PAYLOAD_FOOTER) && ReadFile(h, f, PAYLOAD_FOOTER, &got, nullptr) &&
        got == PAYLOAD_FOOTER && !memcmp(f, PAYLOAD_MAGIC, 8)) {
        p.off  = *(uint64_t*)(f + 8);
        p.size = *(uint64_t*)(f + 16);
        p.ok   = p.off >= 512 && p.size > 0 && p.off + p.size <= total - PAYLOAD_FOOTER;
    }
    CloseHandle(h);
    return p;
}

/* Stream the payload out in 1 MB blocks so a 54 MB pak never sits in memory. */
static bool extract_payload(Backend& be, const std::wstring& self, const Payload& p,
                            const std::wstring& dst, const wchar_t* label) {
    be.logf(L"  เขียน %s  (%s)", label, fmt_mb(p.size).c_str());
    HANDLE in = CreateFileW(self.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (in == INVALID_HANDLE_VALUE) { be.logf(L"  !! อ่านไฟล์ตัวเองไม่ได้ (%lu)", GetLastError()); return false; }
    if (!seek64(in, p.off)) { CloseHandle(in); be.log(L"  !! seek ในไฟล์ตัวเองไม่สำเร็จ"); return false; }
    HANDLE out = CreateFileW(dst.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (out == INVALID_HANDLE_VALUE) {
        CloseHandle(in);
        be.logf(L"  !! เขียน %s ไม่ได้ (โค้ด %lu)", dst.c_str(), GetLastError());
        return false;
    }
    std::vector<uint8_t> buf(1u << 20);
    uint64_t left = p.size, done = 0;
    int last = -1;
    bool okw = true;
    while (left) {
        DWORD want = (DWORD)std::min<uint64_t>(buf.size(), left), got = 0, put = 0;
        if (!ReadFile(in, buf.data(), want, &got, nullptr) || got == 0) { okw = false; break; }
        if (!WriteFile(out, buf.data(), got, &put, nullptr) || put != got) { okw = false; break; }
        left -= got;
        done += got;
        int pct = (int)(done * 100 / p.size);
        if (pct != last && !g_cli) {
            last = pct;
            int overall = g_pb_base + (int)((__int64)pct * g_pb_span / 100);
            if (overall > 100) overall = 100;
            PostMessageW(g_main, WM_PROGRESS, (WPARAM)((unsigned short)overall),
                         (LPARAM)new std::wstring(fmt(L"กำลังติดตั้ง pak... %d%%", pct)));
        }
    }
    if (!okw) be.logf(L"  !! คัดลอก payload ไม่สำเร็จ (โค้ด %lu)", GetLastError());
    FlushFileBuffers(out);
    CloseHandle(out);
    CloseHandle(in);
    if (!okw) DeleteFileW(dst.c_str());
    return okw;
}

/* -------------------------------------------------------------------- patching */

/* Returns the file offset of the `jne` to NOP, -1 when it cannot be pinned down
 * safely, -2 when the exe already carries our patch. */
static int64_t find_sig_site(const std::wstring& exe, const Pe& pe, bool* already) {
    *already = false;
    uint64_t sz = file_size(exe);
    int64_t by_va = pe.rva_to_off((uint32_t)(SIG_VA - pe.image_base));

    HANDLE h = CreateFileW(exe.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;

    auto read_at = [&](uint64_t off, void* buf, DWORD n) -> bool {
        if (!seek64(h, off)) return false;
        DWORD got = 0;
        return ReadFile(h, buf, n, &got, nullptr) && got == n;
    };

    /* 1. the offset documented for this build -- fast path, but verified */
    if (by_va >= 0) {
        uint8_t six[6];
        if (read_at((uint64_t)by_va, six, 6)) {
            if (!memcmp(six, SIG_EXPECT, 6)) { CloseHandle(h); return by_va; }
            /* Already ours.  Still report the offset: a reinstall over an
             * existing install must leave a manifest that can undo it, and the
             * bytes to put back are known (they are SIG_EXPECT by definition). */
            if (!memcmp(six, SIG_PATCH, 6))  { CloseHandle(h); *already = true; return by_va; }
        }
    }

    /* 2. whole-file pattern scan.  Chunks overlap by 5 bytes so a pattern that
     *    straddles a boundary is still found; duplicates are skipped. */
    std::vector<int64_t> hits;
    const DWORD CHUNK = 8u << 20;
    std::vector<uint8_t> buf(CHUNK);
    uint64_t pos = 0;
    while (pos < sz) {
        DWORD want = (DWORD)std::min((uint64_t)CHUNK, sz - pos);
        if (!seek64(h, pos)) break;
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), want, &got, nullptr) || got < 6) break;
        want = got;
        size_t i = 0;
        while (i + 6 <= want) {
            uint8_t* q = (uint8_t*)memchr(buf.data() + i, SIG_EXPECT[0], want - i - 5);
            if (!q) break;
            if (!memcmp(q, SIG_EXPECT, 6)) {
                int64_t at = (int64_t)(pos + (q - buf.data()));
                if (hits.empty() || hits.back() != at) hits.push_back(at);
            }
            i = (size_t)(q - buf.data()) + 1;
        }
        if (want < 6) break;
        pos += want - 5;
    }
    CloseHandle(h);
    if (hits.size() == 1) return hits[0];

    /* More than one candidate: keep only those that are a real `jne` landing on
     * the signature-verification block.  Six bytes that merely look alike will
     * not carry the right relative displacement. */
    if (hits.size() > 1) {
        std::vector<int64_t> good;
        for (size_t i = 0; i < hits.size(); i++) {
            uint8_t six[6];
            HANDLE r = CreateFileW(exe.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (r == INVALID_HANDLE_VALUE) break;
            DWORD got = 0;
            bool okr = seek64(r, (uint64_t)hits[i]) &&
                       ReadFile(r, six, 6, &got, nullptr) && got == 6;
            CloseHandle(r);
            if (!okr) continue;
            uint64_t va = pe.va_of(hits[i]);
            if (!va) continue;
            int32_t rel = *(int32_t*)(six + 2);
            if (va + 6 + (uint64_t)rel == SIG_TARGET_VA) good.push_back(hits[i]);
        }
        if (good.size() == 1) return good[0];
    }
    return -1;                       /* 0, or still ambiguous: refuse rather than guess */
}

static bool patch_exe(Backend& be, const std::wstring& exe, bool* touched,
                      int64_t* sig_off_out, uint8_t orig6[6]) {
    *touched = false;
    *sig_off_out = -1;
    memcpy(orig6, SIG_EXPECT, 6);

    Pe pe;
    if (!pe.load(exe)) { be.log(L"!! อ่าน PE header ของ exe ไม่ได้"); return false; }
    be.logf(L"  PE image base 0x%llX, %d sections", (unsigned long long)pe.image_base,
            (int)pe.secs.size());

    /* (a) signature check */
    bool already = false;
    long off = find_sig_site(exe, pe, &already);
    if (already) {
        be.log(L"  [1] จุดตรวจ signature ของ pak: ถูก NOP ไว้แล้ว");
        *sig_off_out = off;
    } else if (off < 0) {
        be.log(L"!! ไม่สามารถหาจุดแก้ signature check ใน exe นี้ได้แบบมั่นใจ");
        be.log(L"   มอดนี้ทำมาสำหรับ exe เวอร์ชันที่ระบุไว้ ถ้าเกมอัปเดตผ่าน Steam");
        be.log(L"   จุดแก้ต้องหาที่ใหม่ก่อน — จึงไม่แตะไฟล์ใดๆ");
        return false;
    } else {
        uint8_t six[6];
        {
            HANDLE h = CreateFileW(exe.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            DWORD got = 0;
            if (h == INVALID_HANDLE_VALUE || !seek64(h, (uint64_t)off) ||
                !ReadFile(h, six, 6, &got, nullptr) || got != 6) {
                if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
                be.log(L"!! อ่านไบต์ที่จุดแก้ไม่ได้");
                return false;
            }
            CloseHandle(h);
        }
        int32_t rel = *(int32_t*)(six + 2);
        uint64_t va = pe.va_of(off);
        uint64_t tgt = va + 6 + (uint64_t)rel;
        if (!va) {
            be.log(L"!! จุดแก้อยู่นอก section ที่รู้จัก ไม่แก้");
            return false;
        }
        if (tgt != SIG_TARGET_VA) {
            be.logf(L"!! คำสั่งกระโดดไปที่ 0x%llX (ควรเป็น 0x%llX) — exe เปลี่ยนไป จึงไม่แก้",
                    (unsigned long long)tgt, (unsigned long long)SIG_TARGET_VA);
            return false;
        }
        HANDLE w = CreateFileW(exe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD put = 0;
        bool okw = w != INVALID_HANDLE_VALUE && seek64(w, (uint64_t)off) &&
                   WriteFile(w, SIG_PATCH, 6, &put, nullptr) && put == 6 &&
                   FlushFileBuffers(w);
        if (w != INVALID_HANDLE_VALUE) CloseHandle(w);
        if (!okw) {
            be.logf(L"  !! เขียน exe ไม่สำเร็จ (โค้ด %lu) — เกมกำลังเปิดอยู่?", GetLastError());
            return false;
        }
        be.logf(L"  [1] NOP การตรวจ signature ของ pak @ file offset 0x%X (VA 0x%llX)",
                off, (unsigned long long)va);
        *sig_off_out = off;
        *touched = true;
    }

    /* Nothing else needs patching.  The old build also had to clear
     * bMountFailOnMissingUtoc because it installed a pak with no .utoc beside
     * it; this one takes over a slot that already has a matching .utoc, which
     * is the whole reason that slot was chosen. */
    return true;
}

static void unpatch_exe(Backend& be, const std::wstring& exe, int64_t sig_off,
                        const uint8_t orig6[6]) {
    if (sig_off >= 0) {
        HANDLE w = CreateFileW(exe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD put = 0;
        bool okw = w != INVALID_HANDLE_VALUE && seek64(w, (uint64_t)sig_off) &&
                   WriteFile(w, orig6, 6, &put, nullptr) && put == 6 &&
                   FlushFileBuffers(w);
        if (w != INVALID_HANDLE_VALUE) CloseHandle(w);
        be.logf(okw ? L"  คืนโค้ดต้นทางของ signature check @ file offset 0x%X"
                    : L"  !! คืน signature check ไม่ได้ (โค้ด %lu)",
                okw ? (unsigned long)sig_off : GetLastError());
    }
    if (sig_off < 0)
        be.log(L"  ไม่มีอะไรต้องคืนใน exe");
}

/* ------------------------------------------------------------------- manifest */

static void write_manifest(Backend& be, const std::wstring& dir, const Job& j,
                           long sig_off, const uint8_t orig6[6],
                           const wchar_t* exe_sha, uint64_t exe_size) {
    std::wstring p = join(dir, L"manifest.txt");
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { be.log(L"  !! เขียน manifest ไม่ได้"); return; }
    std::string s;
    char tmp[160];
    s += "Mandate Order Thai mod -- backup manifest\r\n";
    s += "version=" + widen(MOD_VERSION) + "\r\n";
    s += "exe=" + widen(j.exe) + "\r\n";
    s += "exe_sha256=" + widen(std::wstring(exe_sha)) + "\r\n";
    sprintf(tmp, "exe_size=%llu\r\n", (unsigned long long)exe_size); s += tmp;
    sprintf(tmp, "sig_site_file_offset=0x%llX\r\n", (unsigned long long)sig_off); s += tmp;
    s += "sig_site_original=";
    for (int i = 0; i < 6; i++) sprintf(tmp + i * 2, "%02x", orig6[i]);
    tmp[12] = 0; s += tmp; s += "\r\n";
    s += "slot=" + widen(std::wstring(SLOT_NAME)) + "\r\n";
    DWORD put = 0;
    WriteFile(h, s.data(), (DWORD)s.size(), &put, nullptr);
    CloseHandle(h);
    be.log(L"  เขียน manifest.txt (ใช้คืน exe ตอนถอนการติดตั้ง)");
}

struct Mani {
    bool ok;
    std::wstring exe, exe_sha;
    uint64_t exe_size;
    int64_t sig_off;
    uint8_t orig6[6];
};

static bool read_manifest(Backend& be, const std::wstring& dir, Mani& m) {
    std::wstring p = join(dir, L"manifest.txt");
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        be.log(L"!! ไม่พบ manifest.txt ในโฟลเดอร์สำรอง");
        return false;
    }
    std::string all;
    char b[4096]; DWORD got;
    while (ReadFile(h, b, sizeof b, &got, nullptr) && got) all.append(b, got);
    CloseHandle(h);
    m = Mani();
    size_t pos = 0;
    while (pos < all.size()) {
        size_t e = all.find("\r\n", pos);
        if (e == std::string::npos) e = all.size();
        std::string ln = all.substr(pos, e - pos);
        pos = e + 2;
        size_t eq = ln.find('=');
        if (eq == std::string::npos) continue;
        std::string k = ln.substr(0, eq), v = ln.substr(eq + 1);
        if (k == "exe") m.exe = narrow(v);
        else if (k == "exe_sha256") m.exe_sha = narrow(v);
        else if (k == "exe_size") m.exe_size = strtoull(v.c_str(), nullptr, 10);
        else if (k == "sig_site_file_offset") m.sig_off = strtoll(v.c_str(), nullptr, 16);
        else if (k == "sig_site_original") {
            for (int i = 0; i < 6; i++) { unsigned x; sscanf(v.c_str() + i * 2, "%2x", &x); m.orig6[i] = (uint8_t)x; }
        }
    }
    m.ok = !m.exe.empty();
    return m.ok;
}

/* --------------------------------------------------------------- game checks */

static bool game_running(Backend& be) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W e;
    e.dwSize = sizeof e;
    bool found = false;
    static const wchar_t* names[] = { L"MOProject-Win64-Shipping.exe", L"MOProject.exe", nullptr };
    for (int i = 0; names[i] && !found; i++) {
        if (Process32FirstW(s, &e)) {
            do {
                if (!_wcsicmp(e.szExeFile, names[i])) { found = true; break; }
            } while (Process32NextW(s, &e));
        }
    }
    CloseHandle(s);
    if (found) be.log(L"!! เกมกำลังทำงานอยู่ — กรุณาปิดเกมก่อน");
    return found;
}

static bool looks_like_game(const std::wstring& root) {
    if (root.empty()) return false;
    if (!is_dir(join(root, L"MOProject\\Content\\Paks"))) return false;
    if (!is_file(join(root, EXE_REL))) return false;
    return true;
}

static bool verify_same(Backend& be, const std::wstring& a, const std::wstring& b) {
    wchar_t ha[65], hb[65];
    uint64_t sa, sb;
    if (!sha_file(a, ha, &sa)) { be.logf(L"  !! อ่านไม่ได้ %s", a.c_str()); return false; }
    if (!sha_file(b, hb, &sb)) { be.logf(L"  !! อ่านไม่ได้ %s", b.c_str()); return false; }
    if (sa != sb || wcscmp(ha, hb)) {
        be.logf(L"  !! ตรวจสอบไม่ตรงกัน: %s != %s", ha, hb);
        return false;
    }
    be.logf(L"  ตรวจ SHA-256 ตรงกัน (%s...)", std::wstring(ha, 12).c_str());
    return true;
}

/* ------------------------------------------------------------------- worker */

/* Both the windowed path and the CLI path funnel through here, so there is
   exactly one implementation of "what installing means". */
static bool worker(Job& j) {
    Backend be(g_main);
    bool ok = true;

    be.log(L"");
    if (!log_path().empty()) be.logf(L"log ของรอบนี้: %s", log_path().c_str());

    if (game_running(be)) return false;

    const std::wstring slot = join(j.paks, SLOT_NAME);
    const std::wstring backup = join(j.paks, BACKUP_DIR);
    const std::wstring bak_slot = join(backup, std::wstring(SLOT_NAME) + L".orig");
    wchar_t exe_sha[65]; uint64_t exe_sz = 0;
    bool have_exe_sha = sha_file(j.exe, exe_sha, &exe_sz);

    if (j.install) {
        be.log(L"===== ติดตั้งมอดแปลภาษาไทย =====");
        be.logf(L"โฟลเดอร์เกม : %s", j.root.c_str());
        be.logf(L"pak ที่จะติดตั้ง : %s  (%s)", SLOT_NAME, fmt_mb(MOD_SIZE).c_str());

        /* --- 0. the pak riding inside this exe must be intact */
        be.stage(0, 6, L"ตรวจไฟล์มอดที่แนบมากับตัวติดตั้ง");
        be.log(L"[0/6] ตรวจไฟล์มอดที่แนบมากับตัวติดตั้ง");
        if (!j.payload.ok) {
            be.log(L"!! ตัวติดตั้งนี้ไม่มี pak แนบอยู่ข้างใน (ไฟล์ถูกตัดหรือไม่ครบ)");
            be.log(L"   ดาวน์โหลดตัวติดตั้งใหม่ทั้งไฟล์");
            ok = false;
        } else if (j.payload.size != MOD_SIZE) {
            be.logf(L"!! ขนาด pak ในตัวติดตั้งไม่ตรง (ได้ %llu ควรเป็น %llu)",
                    (unsigned long long)j.payload.size, (unsigned long long)MOD_SIZE);
            ok = false;
        } else {
            be.logf(L"  payload %s — ขนาดตรง", fmt_mb(j.payload.size).c_str());
        }
        if (!ok) { be.log(L"ยกเลิก — ไม่มีอะไรถูกเปลี่ยนแปลง"); return false; }

        /* --- 1. is the player's build the one this mod was made for? */
        be.stage(1, 6, L"ตรวจเวอร์ชันเกม");
        be.log(L"[1/6] ตรวจเวอร์ชันเกม");
        if (!have_exe_sha) {
            be.log(L"!! อ่าน exe ของเกมไม่ได้");
            ok = false;
        } else if (exe_sz != REF_EXE_SIZE) {
            be.log(L"!! exe ของคุณไม่ตรงกับเวอร์ชันที่มอดนี้ทำมาด้วย (เกมอัปเดต?)");
            be.logf(L"   ขนาด %llu ไบต์ ควรเป็น %llu", (unsigned long long)exe_sz,
                    (unsigned long long)REF_EXE_SIZE);
            be.log(L"   จุดแก้ในโปรแกรมอาจเละ จึงหยุดก่อนแตะไฟล์ใดๆ");
            ok = false;
        } else {
            be.logf(L"  exe ตรงกับเวอร์ชันที่ทำมอดไว้ (%llu ไบต์)", (unsigned long long)exe_sz);
        }

        /* --- 2. back up the slot's original, all 365 bytes of it */
        if (ok) {
            be.stage(2, 6, j.do_backup ? L"สำรองไฟล์ดั้งเดิม" : L"ข้ามการสำรอง");
            if (j.do_backup) {
                be.log(L"[2/6] สำรอง pak ช่องเดิม");
                if (!is_dir(backup) && !CreateDirectoryW(backup.c_str(), nullptr) &&
                    GetLastError() != ERROR_ALREADY_EXISTS) {
                    be.logf(L"!! สร้างโฟลเดอร์สำรองไม่ได้ (โค้ด %lu)", GetLastError());
                    ok = false;
                } else if (is_file(bak_slot)) {
                    be.log(L"  มีสำรองไว้แล้ว (ไม่เขียนทับ)");
                } else if (file_size(slot) == MOD_SIZE) {
                    /* The mod is already in place and the backup is gone.  That
                     * file is ours, not the game's -- copying it aside would
                     * capture the mod as its own "original" and make uninstall
                     * restore the mod over the mod. */
                    be.log(L"  !! ช่องนี้เป็นมอดอยู่แล้วแต่ไม่มีไฟล์สำรอง");
                    be.log(L"     ข้ามการสำรอง (ไม่เอาไฟล์มอดมาเป็นต้นฉบับ)");
                } else if (!is_file(slot)) {
                    be.logf(L"!! ไม่พบ %s ในเกม", SLOT_NAME);
                    ok = false;
                } else if (!copy_pak(be, slot, bak_slot, SLOT_NAME)) {
                    ok = false;
                }
            } else {
                be.log(L"[2/6] ไม่สำรอง (ไม่ได้เลือก) — ถ้าอยากคืนเกมต้นทาง");
                be.log(L"      กด Verify integrity of game files ผ่าน Steam");
            }
        }

        /* --- 3. patch the exe */
        int64_t sig_off = -1;
        uint8_t orig6[6];
        memcpy(orig6, SIG_EXPECT, 6);
        if (ok) {
            be.stage(3, 6, L"แก้ MOProject-Win64-Shipping.exe");
            be.log(L"[3/6] แก้ MOProject-Win64-Shipping.exe");
            bool touched = false;
            if (!patch_exe(be, j.exe, &touched, &sig_off, orig6)) ok = false;
            else if (!touched) be.log(L"  exe ถูกแก้อยู่แล้ว ไม่ต้องทำอะไร");
        }

        /* --- 4. manifest (tiny; written even when the pak backup is skipped,
                so uninstall can still put the exe back) */
        if (ok) {
            be.stage(4, 6, L"บันทึก manifest");
            be.log(L"[4/6] บันทึก manifest");
            if (!is_dir(backup) && !CreateDirectoryW(backup.c_str(), nullptr) &&
                GetLastError() != ERROR_ALREADY_EXISTS)
                be.log(L"  !! สร้างโฟลเดอร์สำรองไม่ได้ (ข้าม manifest)");
            else if (have_exe_sha)
                write_manifest(be, backup, j, sig_off, orig6, exe_sha, exe_sz);
        }

        /* --- 5. write the pak out of the payload */
        if (ok) {
            be.stage(5, 6, L"ติดตั้ง pak ของมอด");
            be.log(L"[5/6] ติดตั้ง pak ของมอด");
            if (!extract_payload(be, j.self, j.payload, slot, SLOT_NAME)) ok = false;
        }

        /* --- 6. verify */
        if (ok) {
            be.stage(6, 6, L"ตรวจสอบไฟล์ที่เขียน");
            be.log(L"[6/6] ตรวจสอบไฟล์ที่เขียน");
            wchar_t hx[65]; uint64_t sz = 0;
            if (!sha_file(slot, hx, &sz)) { be.log(L"  !! อ่าน pak ที่เขียนไม่ได้"); ok = false; }
            else if (wcscmp(hx, MOD_SHA)) {
                be.logf(L"  !! SHA-256 ไม่ตรง — ที่คาด %s ที่ได้ %s", MOD_SHA, hx);
                ok = false;
            } else {
                be.logf(L"  SHA-256 ตรงกัน (%s...)", std::wstring(hx, 12).c_str());
            }
        }

        if (ok) {
            std::wstring stale = join(j.paks, STALE_P);
            if (is_file(stale)) { DeleteFileW(stale.c_str()); be.log(L"ลบ MOProject_ThaiMod_P.pak ที่ค้างอยู่ออก"); }
            be.log(L"");
            be.log(L"เสร็จสิ้น — เปิดเกมได้เลย ภาษาไทยใช้ได้ทันที");
        } else {
            be.log(L"");
            be.log(L"ติดตั้งไม่สมบูรณ์ — อ่านรายการด้านบนเพื่อดูสาเหตุ (เกมต้นทางคาดว่าปลอดภัย)");
        }
    } else {
        be.log(L"===== ถอนการติดตั้งมอด =====");
        Mani m;
        bool have = read_manifest(be, backup, m);
        if (have) {
            wchar_t hx[65]; uint64_t sz = 0;
            sha_file(m.exe, hx, &sz);
            if (sz != m.exe_size) {
                be.log(L"!! exe เปลี่ยนไปจากตอนสำรอง (อาจเกมอัปเดต) — ข้ามขั้นตอนคืน exe");
                have = false;
            } else {
                be.log(L"[1/3] คืน exe เป็นต้นทาง");
                unpatch_exe(be, m.exe, m.sig_off, m.orig6);
            }
        } else {
            be.log(L"[1/3] ไม่มี manifest — คืนแค่ pak");
        }

        bool pak_ok = true;
        be.stage(1, 3, L"คืน pak ช่องเดิม");
        if (!is_file(bak_slot)) {
            be.logf(L"!! ไม่มีสำรองของ %s — ถอนไม่ครบ กด Verify ผ่าน Steam แทนได้", SLOT_NAME);
            pak_ok = false;
        } else {
            be.logf(L"คืน %s", SLOT_NAME);
            if (!copy_pak(be, bak_slot, slot, SLOT_NAME)) pak_ok = false;
            else if (!verify_same(be, bak_slot, slot)) pak_ok = false;
        }

        if (pak_ok) {
            std::wstring stale = join(j.paks, STALE_P);
            if (is_file(stale)) DeleteFileW(stale.c_str());
            remove_tree(backup);
            if (!is_dir(backup)) be.log(L"ลบโฟลเดอร์สำรองแล้ว");
            be.log(L"");
            be.log(L"ถอนการติดตั้งแล้ว — เกมกลับเป็นเหมือนต้น");
            ok = true;
        } else {
            ok = false;
            be.log(L"");
            be.log(L"ถอนไม่สมบูรณ์ — เกมอาจยังเหลือมอดอยู่ ถ้าติดปัญหากด Verify ผ่าน Steam");
        }
    }

    return ok;
}

static DWORD WINAPI worker_thread(LPVOID param) {
    Job* jp = (Job*)param;
    Job j = *jp;
    bool ok = worker(j);
    delete jp;
    PostMessageW(g_main, WM_DONE, ok ? 1 : 0, 0);
    return 0;
}

/* -------------------------------------------------------------------- status */

/* The mod is "installed" when the pak in place is the one we ship.  Deliberately
 * does not look at the backup folder: skipping backups is a legal choice. */
static bool mod_installed(const std::wstring& paks) {
    wchar_t a[65];
    if (!sha_file(join(paks, SLOT_NAME), a, nullptr)) return false;
    return wcscmp(a, MOD_SHA) == 0;
}

/* The slot is "free" when it still holds the game's own empty pak.  Matched by
 * size rather than hash so a slightly different game build is not reported as
 * someone else's mod. */
static std::wstring describe_slot(const std::wstring& p) {
    uint64_t sz = file_size(p);
    if (!sz) return L"ช่อง pak: ไม่พบไฟล์";
    if (sz == MOD_SIZE) return L"ช่อง pak: เป็นมอดไทย";
    if (sz < 4096)     return L"ช่อง pak: ยังว่างอยู่";
    return L"ช่อง pak: มีมอดอื่นอยู่";
}

static bool exe_patched(const std::wstring& exe) {
    HANDLE h = CreateFileW(exe.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint8_t six[6] = {0};
    DWORD got = 0;
    bool ok = seek64(h, SIG_OFF_DIRECT) && ReadFile(h, six, 6, &got, nullptr) &&
              got == 6 && !memcmp(six, SIG_PATCH, 6);
    CloseHandle(h);
    return ok;
}

static void refresh_state() {
    wchar_t root[MAX_PATH];
    GetWindowTextW(g_path, root, MAX_PATH);
    std::wstring r = trim_end(root);
    std::wstring paks = r.empty() ? L"" : join(r, PAKS_REL);
    std::wstring exe  = r.empty() ? L"" : join(r, EXE_REL);

    if (r.empty()) { SetWindowTextW(g_status, L"ยังไม่ได้เลือกโฟลเดอร์เกม"); return; }
    if (!is_dir(join(r, L"MOProject"))) {
        SetWindowTextW(g_status, L"ไม่พบโฟลเดอร์ MOProject — โฟลเดอร์นี้ไม่ใช่ตัวเกม");
        return;
    }
    if (!is_dir(paks)) {
        SetWindowTextW(g_status, L"ไม่พบ MOProject\\Content\\Paks — โฟลเดอร์นี้ไม่ใช่ตัวเกม");
        return;
    }
    if (!is_file(exe)) {
        SetWindowTextW(g_status, L"ไม่พบ MOProject\\Binaries\\Win64\\MOProject-Win64-Shipping.exe");
        return;
    }

    std::wstring what = describe_slot(join(paks, SLOT_NAME));
    what += L"  |  exe: ";
    what += exe_patched(exe) ? L"แก้แล้ว" : L"ยังไม่แก้";
    std::wstring state = mod_installed(paks) ? L"ติดตั้งมอดอยู่: ใช่" : L"พร้อมติดตั้ง";
    if (is_file(join(paks, std::wstring(BACKUP_DIR) + L"\\" + SLOT_NAME + L".orig")))
        state += L"  |  มีสำรอง";

    SetWindowTextW(g_status, fmt(L"%s  |  %s", state.c_str(), what.c_str()).c_str());
}

static void start_job(bool install) {
    if (g_busy) return;
    wchar_t root[MAX_PATH];
    GetWindowTextW(g_path, root, MAX_PATH);
    std::wstring r = trim_end(root);
    if (r.empty() || !looks_like_game(r)) {
        MessageBoxW(g_main,
            L"กรุณาเลือกโฟลเดอร์ที่ติดตั้งเกม Mandate Order ก่อน\n"
            L"(โฟลเดอร์ที่มี MOProject อยู่ข้างใน)",
            L"ยังไม่พร้อม", MB_OK | MB_ICONWARNING);
        return;
    }
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    Payload pl = find_payload(self);
    if (install && !pl.ok) {
        MessageBoxW(g_main,
            L"ตัวติดตั้งนี้ไม่มี pak แนบอยู่ข้างใน\n\n"
            L"ไฟล์อาจถูกตัดตอนคัดลอกหรือดาวน์โหลดไม่ครบ "
            L"ให้โหลดตัวติดตั้งใหม่ทั้งไฟล์",
            L"ไฟล์มอดไม่ครบ", MB_OK | MB_ICONWARNING);
        return;
    }
    Job* j = new Job();
    j->install = install;
    j->do_backup = (SendMessageW(g_chk_backup, BM_GETCHECK, 0, 0) == BST_CHECKED);
    j->root = r;
    j->paks = join(r, PAKS_REL);
    j->exe = join(r, EXE_REL);
    j->self = self;
    j->payload = pl;

    SetWindowTextW(g_log, L"");
    g_pb_base = 0; g_pb_span = 100;
    g_busy = true;
    EnableWindow(g_b_install, false);
    EnableWindow(g_b_uninstall, false);
    EnableWindow(g_b_browse, false);
    EnableWindow(g_path, false);
    EnableWindow(g_chk_backup, false);
    SetWindowTextW(g_b_close, L"กำลังทำงาน...");
    EnableWindow(g_b_close, false);
    SetWindowTextW(g_action, install ? L"กำลังติดตั้ง..." : L"กำลังถอนการติดตั้ง...");
    SendMessageW(g_prog, PBM_SETMARQUEE, 1, 30);
    g_busy = true;

    HANDLE th = CreateThread(nullptr, 0, worker_thread, j, 0, nullptr);
    if (!th) {
        MessageBoxW(g_main, L"เริ่มงานไม่ได้", L"ผิดพลาด", MB_OK | MB_ICONERROR);
        g_busy = false;
        EnableWindow(g_b_install, true);
        EnableWindow(g_b_uninstall, true);
        EnableWindow(g_b_browse, true);
        EnableWindow(g_path, true);
        EnableWindow(g_chk_backup, true);
        EnableWindow(g_b_close, true);
        SetWindowTextW(g_b_close, L"ปิด");
        SendMessageW(g_prog, PBM_SETMARQUEE, 0, 0);
        delete j;
    }
}

static void ui_log(const std::wstring& s) {
    if (!g_log) return;
    int len = GetWindowTextLengthW(g_log);
    if (len > (1 << 20) - 4096) SetWindowTextW(g_log, L"");
    SendMessageW(g_log, EM_SETSEL, (WPARAM)GetWindowTextLengthW(g_log),
                 (LPARAM)GetWindowTextLengthW(g_log));
    SendMessageW(g_log, EM_REPLACESEL, 0, (LPARAM)s.c_str());
    SendMessageW(g_log, EM_REPLACESEL, 0, (LPARAM)L"\r\n");
    SendMessageW(g_log, WM_VSCROLL, SB_BOTTOM, 0);
}

/* -------------------------------------------------------------------- window */

#define M 14

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        RECT rc; GetClientRect(h, &rc);
        int W = rc.right;
        int y = M;

        g_font = CreateFontW(-15, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
            OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_font_bold = CreateFontW(-18, 0,0,0, FW_SEMIBOLD, 0,0,0, DEFAULT_CHARSET,
            OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        HWND t;
        t = CreateWindowW(L"STATIC", L"มอดแปลภาษาไทย — Mandate Order",
            WS_CHILD | WS_VISIBLE, M, y, W - 2*M, 26, h, nullptr, g_inst, nullptr);
        SendMessageW(t, WM_SETFONT, (WPARAM)g_font_bold, 1); y += 28;
        t = CreateWindowW(L"STATIC",
            L"ตัวติดตั้งนี้ไม่ต้องมี Python — เลือกโฟลเดอร์เกมแล้วกดติดตั้ง",
            WS_CHILD | WS_VISIBLE, M, y, W - 2*M, 18, h, nullptr, g_inst, nullptr);
        SendMessageW(t, WM_SETFONT, (WPARAM)g_font, 1); y += 24;

        t = CreateWindowW(L"BUTTON", L"โฟลเดอร์ติดตั้งเกม",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX, M, y, W - 2*M, 80, h, nullptr, g_inst, nullptr);
        SendMessageW(t, WM_SETFONT, (WPARAM)g_font, 1);
        g_path = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
            M + 10, y + 22, W - 2*M - 126, 24, h, nullptr, g_inst, nullptr);
        SendMessageW(g_path, WM_SETFONT, (WPARAM)g_font, 1);
        g_b_browse = CreateWindowW(L"BUTTON", L"เรียกดู…",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            W - M - 106, y + 22, 96, 24, h, (HMENU)1001, g_inst, nullptr);
        SendMessageW(g_b_browse, WM_SETFONT, (WPARAM)g_font, 1);
        g_status = CreateWindowW(L"STATIC", L"กำลังหาเกม...",
            WS_CHILD | WS_VISIBLE, M + 10, y + 52, W - 2*M - 20, 18, h, nullptr, g_inst, nullptr);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, 1);
        y += 90;

        t = CreateWindowW(L"BUTTON", L"ตัวเลือก",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX, M, y, W - 2*M, 54, h, nullptr, g_inst, nullptr);
        SendMessageW(t, WM_SETFONT, (WPARAM)g_font, 1);
        g_chk_backup = CreateWindowW(L"BUTTON",
            L"สำรองไฟล์ดั้งก่อนเก็บไว้ในเกม (แนะนำ — ใช้คืนได้ทุกเมื่อ)",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP,
            M + 10, y + 20, W - 2*M - 20, 22, h, (HMENU)1002, g_inst, nullptr);
        SendMessageW(g_chk_backup, WM_SETFONT, (WPARAM)g_font, 1);
        SendMessageW(g_chk_backup, BM_SETCHECK, BST_CHECKED, 0);
        y += 64;

        t = CreateWindowW(L"BUTTON", L"ความคืบหน้า",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX, M, y, W - 2*M, 70, h, nullptr, g_inst, nullptr);
        SendMessageW(t, WM_SETFONT, (WPARAM)g_font, 1);
        g_action = CreateWindowW(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE, M + 10, y + 19, W - 2*M - 20, 16, h, nullptr, g_inst, nullptr);
        SendMessageW(g_action, WM_SETFONT, (WPARAM)g_font, 1);
        g_prog = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE,
            M + 10, y + 38, W - 2*M - 20, 18, h, (HMENU)1003, g_inst, nullptr);
        SendMessageW(g_prog, PBM_SETRANGE32, 0, 100);
        y += 80;

        int bw = 150, bh = 30, gap = 10;
        int log_bottom = rc.bottom - M - bh - 12;
        g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            M, y, W - 2*M, std::max(60, log_bottom - y), h, nullptr, g_inst, nullptr);
        SendMessageW(g_log, WM_SETFONT, (WPARAM)g_font, 1);

        int by = rc.bottom - M - bh;
        g_b_install = CreateWindowW(L"BUTTON", L"ติดตั้งมอด",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
            M, by, bw, bh, h, (HMENU)1004, g_inst, nullptr);
        g_b_uninstall = CreateWindowW(L"BUTTON", L"ถอนการติดตั้ง",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            M + bw + gap, by, bw + 20, bh, h, (HMENU)1005, g_inst, nullptr);
        g_b_close = CreateWindowW(L"BUTTON", L"ปิด",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            W - M - 90, by, 90, bh, h, (HMENU)1006, g_inst, nullptr);
        HWND btns[3] = {g_b_install, g_b_uninstall, g_b_close};
        for (int i = 0; i < 3; i++) SendMessageW(btns[i], WM_SETFONT, (WPARAM)g_font, 1);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(w)) {
        case 1001: {
            BROWSEINFOW bi;
            memset(&bi, 0, sizeof bi);
            bi.hwndOwner = h;
            bi.lpszTitle = L"เลือกโฟลเดอร์ที่ติดตั้งเกม Mandate Order "
                           L"(โฟลเดอร์ที่มี MOProject อยู่ข้างใน)";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX;
            LPITEMIDLIST id = SHBrowseForFolderW(&bi);
            if (id) {
                wchar_t p[MAX_PATH] = L"";
                SHGetPathFromIDListW(id, p);
                CoTaskMemFree(id);
                if (p[0]) {
                    SetWindowTextW(g_path, trim_end(p).c_str());
                    refresh_state();
                }
            }
            return 0;
        }
        case 1004: start_job(true); return 0;
        case 1005: start_job(false); return 0;
        case 1006:
            if (!g_busy) DestroyWindow(h);
            return 0;
        }
        return 0;

    case WM_CTLCOLORSTATIC:
        SetBkColor((HDC)w, GetSysColor(COLOR_BTNFACE));
        SetTextColor((HDC)w, GetSysColor(COLOR_BTNTEXT));
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);

    case WM_CTLCOLORBTN:
        SetBkColor((HDC)w, GetSysColor(COLOR_BTNFACE));
        SetTextColor((HDC)w, GetSysColor(COLOR_BTNTEXT));
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);

    case WM_LOG:
        if (l) { ui_log(*(std::wstring*)l); delete (std::wstring*)l; }
        return 0;

    case WM_PROGRESS: {
        std::wstring* s = (std::wstring*)l;
        int pct = (int)(w & 0xFFFF);
        if (s) {
            if (!s->empty()) SetWindowTextW(g_action, s->c_str());
            delete s;
        }
        if (pct >= 0 && pct <= 100) SendMessageW(g_prog, PBM_SETPOS, pct, 0);
        return 0;
    }

    case WM_DONE: {
        SendMessageW(g_prog, PBM_SETMARQUEE, 0, 0);
        SendMessageW(g_prog, PBM_SETPOS, 0, 0);
        g_busy = false;
        EnableWindow(g_b_install, true);
        EnableWindow(g_b_uninstall, true);
        EnableWindow(g_b_browse, true);
        EnableWindow(g_path, true);
        EnableWindow(g_chk_backup, true);
        EnableWindow(g_b_close, true);
        SetWindowTextW(g_b_close, L"ปิด");
        SetWindowTextW(g_action, L"");
        wchar_t root[MAX_PATH]; GetWindowTextW(g_path, root, MAX_PATH);
        std::wstring paks = join(trim_end(root), PAKS_REL);
        std::wstring lp = log_path();
        std::wstring tail = lp.empty() ? L"" : L"\n\nlog อยู่ที่:\n" + lp;
        bool backup = is_file(join(paks, std::wstring(BACKUP_DIR) + L"\\" +
                                  SLOT_NAME + L".orig"));
        SetForegroundWindow(h);
        std::wstring msg;
        const wchar_t* caption;
        UINT icon = MB_OK | MB_ICONINFORMATION;
        if (w && mod_installed(paks)) {
            caption = L"ติดตั้งสำเร็จ";
            msg = L"ติดตั้งมอดเรียบร้อย\n\n"
                  L"• สำรอง pak เดิมของเกมไว้แล้ว\n"
                  L"• แก้ exe 6 ไบต์ เพื่อให้เกมยอมโหลด pak ที่ไม่มีลายเซ็น\n"
                  L"• ติดตั้ง pak ของมอด และตรวจ SHA-256 ผ่าน\n\n"
                  L"เปิดเกมได้เลย — ภาษาไทยใช้ได้ทันที\n"
                  L"ถอนคืนได้ทุกเมื่อจากปุ่ม \"ถอนการติดตั้ง\"";
            if (!backup)
                msg += L"\n\n(ไม่ได้เลือกสำรองไฟล์ — ถ้าต้องการคืนเกม\n"
                       L"ให้กด Verify integrity of game files ผ่าน Steam)";
        } else if (w) {
            caption = L"ถอนการติดตั้งสำเร็จ";
            msg = L"ถอนการติดตั้งเรียบร้อย\n\n"
                  L"• คืน pak เดิมของเกมแล้ว (365 ไบต์)\n"
                  L"• คืนไบต์ใน exe แล้ว\n"
                  L"• ลบโฟลเดอร์สำรองแล้ว\n\n"
                  L"เกมกลับเป็นเหมือนก่อนลงมอด";
        } else {
            caption = L"ไม่สำเร็จ";
            icon = MB_OK | MB_ICONWARNING;
            msg = L"ทำงานไม่สมบูรณ์\n\n"
                  L"อ่านรายการด้านบนในหน้าต่างนี้เพื่อดูสาเหตุ\n"
                  L"เกมต้นทางคาดว่ายังปลอดภัย — ไม่มีไฟล์ใดถูกแก้ครึ่ง ๆ กลาง ๆ";
        }
        if (!tail.empty()) msg += tail;
        MessageBoxW(h, msg.c_str(), caption, icon);
        refresh_state();
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

/* ------------------------------------------------------------------ detection */

static std::wstring read_reg(HKEY hive, const wchar_t* sub, const wchar_t* val) {
    wchar_t buf[1024] = L"";
    DWORD n = sizeof buf, t = 0;
    if (RegGetValueW(hive, sub, val, RRF_RT_REG_SZ, &t, buf, &n) != ERROR_SUCCESS)
        return std::wstring();
    buf[n / sizeof(wchar_t) ? (n / sizeof(wchar_t) - 1) : 0] = 0;
    return trim_end(buf);
}

/* libraryfolders.vdf is loose key/value text; pulling the quoted strings after
 * "path" is enough and avoids writing a real VDF parser. */
static std::vector<std::wstring> steam_libraries() {
    std::vector<std::wstring> out;
    std::wstring steam = read_reg(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Valve\\Steam", L"InstallPath");
    if (steam.empty()) steam = read_reg(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Valve\\Steam", L"InstallPath");
    if (steam.empty()) steam = read_reg(HKEY_CURRENT_USER, L"SOFTWARE\\Valve\\Steam", L"SteamPath");
    if (steam.empty()) return out;
    out.push_back(trim_end(steam));

    /* Read libraryfolders.vdf from the Steam root(s) and collect what they list.
     *
     * This must walk a fixed snapshot, not `out` while appending to it.  A
     * library's own copy of libraryfolders.vdf lists every library -- including
     * itself and including the Steam root it was just read from -- so a loop
     * bounded by a vector it is also pushing to appends at least one new entry
     * every pass and never ends.  That is exactly what it did: the window came
     * up, never painted, and the process sat at 100% of a core until killed.
     *
     * Only the roots are read; whatever the libraries' copies contain is the
     * same list again. */
    std::vector<std::wstring> roots = out;
    for (size_t i = 0; i < roots.size(); i++) {
        std::wstring vdf = join(roots[i], L"steamapps\\libraryfolders.vdf");
        HANDLE h = CreateFileW(vdf.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        std::string all;
        char b[4096]; DWORD got;
        while (ReadFile(h, b, sizeof b, &got, nullptr) && got) all.append(b, got);
        CloseHandle(h);
        size_t p = 0;
        while ((p = all.find("\"path\"", p)) != std::string::npos) {
            size_t q = all.find('"', p + 6);
            size_t r = q == std::string::npos ? q : all.find('"', q + 1);
            if (q != std::string::npos && r != std::string::npos && r > q + 1) {
                std::wstring lib = trim_end(narrow(all.substr(q + 1, r - q - 1)));
                if (!lib.empty() &&
                    std::find(out.begin(), out.end(), lib) == out.end())
                    out.push_back(lib);
            }
            p += 6;
        }
    }
    return out;
}

static std::vector<std::wstring> guess_roots() {
    std::vector<std::wstring> cands;
    std::vector<std::wstring> libs = steam_libraries();
    for (size_t i = 0; i < libs.size(); i++)
        cands.push_back(join(trim_end(libs[i]), L"steamapps\\common\\mo"));

    /* common hand-made library names on every fixed drive */
    for (wchar_t d = L'C'; d <= L'Z'; d++) {
        wchar_t dr[4] = {d, L':', L'\\', 0};
        UINT t = GetDriveTypeW(dr);
        if (t != DRIVE_FIXED && t != DRIVE_REMOVABLE) continue;
        const wchar_t* tails[] = {
            L"Steam\\steamapps\\common\\mo",
            L"SteamLibrary\\steamapps\\common\\mo",
            L"SteamLibrary2\\steamapps\\common\\mo",
            L"SteamLibrary3\\steamapps\\common\\mo",
            L"Games\\Steam\\steamapps\\common\\mo",
            L"Games\\mo",
            L"mo",
            nullptr};
        for (int i = 0; tails[i]; i++) cands.push_back(join(std::wstring(dr), tails[i]));
    }
    const wchar_t* extra[] = {
        L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\mo",
        L"C:\\Program Files\\Steam\\steamapps\\common\\mo",
        nullptr};
    for (int i = 0; extra[i]; i++) cands.push_back(extra[i]);

    std::vector<std::wstring> good;
    for (size_t i = 0; i < cands.size(); i++)
        if (looks_like_game(cands[i]) &&
            std::find(good.begin(), good.end(), cands[i]) == good.end())
            good.push_back(cands[i]);
    return good;
}

/* ---------------------------------------------------------------------- main */

int WINAPI WinMain(HINSTANCE inst, HINSTANCE, LPSTR, int show) {
    g_inst = inst;
    INITCOMMONCONTROLSEX ic;
    ic.dwSize = sizeof ic;
    ic.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&ic);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    wchar_t me[MAX_PATH];
    GetModuleFileNameW(nullptr, me, MAX_PATH);
    g_exedir = dirname_of(std::wstring(me));

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hIcon = LoadIconW(nullptr, (LPCWSTR)IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"MOThaiInstallerWnd";
    wc.hIconSm = LoadIconW(nullptr, (LPCWSTR)IDI_APPLICATION);
    RegisterClassExW(&wc);

    g_main = CreateWindowExW(WS_EX_CONTROLPARENT, L"MOThaiInstallerWnd",
        L"ติดตั้งมอดแปลภาษาไทย — Mandate Order",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 660, 640, nullptr, nullptr, inst, nullptr);
    if (!g_main) return 1;
    ShowWindow(g_main, show);
    UpdateWindow(g_main);

    /* Auto-detect first; the Browse button is only there for the case where
     * detection fails. */
    /* ---- command line: MOThaiInstaller.exe --install|--uninstall <game dir> ----
       Handy for scripted installs and for testing the exact same code path the
       window drives. */
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool want_install = false, want_uninstall = false;
    std::wstring cli_root;
    for (int i = 1; i < argc; i++) {
        if (!_wcsicmp(argv[i], L"--install") || !_wcsicmp(argv[i], L"-i")) want_install = true;
        else if (!_wcsicmp(argv[i], L"--uninstall") || !_wcsicmp(argv[i], L"-u")) want_uninstall = true;
        else if (!_wcsicmp(argv[i], L"--no-backup")) { /* handled below */ }
        else if (argv[i][0] != L'-') cli_root = trim_end(argv[i]);
    }
    if (want_install || want_uninstall) {
        g_cli = true;
        if (cli_root.empty()) cli_root = L"";
        if (cli_root.empty() || !looks_like_game(cli_root)) {
            _putws(L"!! ต้องระบุโฟลเดอร์เกม:  MOThaiInstaller.exe --install <โฟลเดอร์เกม>");
            _putws(L"   folder must contain MOProject\\Content\\Paks and MOProject\\Binaries\\Win64\\MOProject-Win64-Shipping.exe");
            return 2;
        }
        if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            if (freopen("CONOUT$", "w", stdout)) { /* stdout now reaches the caller */ }
        }
        Job j;
        j.install = want_install;
        j.do_backup = true;
        j.root = cli_root;
        j.paks = join(cli_root, PAKS_REL);
        j.exe = join(cli_root, EXE_REL);
        j.self = me;
        j.payload = find_payload(me);
        bool ok = worker(j);
        _putws(ok ? L"\n[OK] done" : L"\n[FAIL] not finished");
        fflush(stdout);
        FreeConsole();
        LocalFree(argv);
        return ok ? 0 : 1;
    }

    std::vector<std::wstring> roots = guess_roots();
    if (!roots.empty()) {
        SetWindowTextW(g_path, roots[0].c_str());
        if (roots.size() > 1)
            ui_log(fmt(L"พบเกม %d ที่ — ใช้ที่แรก ถ้าไม่ใช่กด \"เรียกดู…\"",
                       (int)roots.size()));
    } else {
        SetWindowTextW(g_status,
            L"หาเกมไม่เจออัตโนมัติ — กด \"เรียกดู…\" แล้วเลือกโฟลเดอร์ที่มี MOProject");
    }
    refresh_state();
    /* Same two lines to the window and to the file, so a log sent in by a user
     * says when the program was opened even if they never pressed a button. */
    std::wstring hello = L"พร้อมใช้งาน — ตรวจสอบโฟลเดอร์เกมด้านบน แล้วกด \"ติดตั้งมอด\"";
    ui_log(hello);
    log_to_file(hello);
    if (!log_path().empty()) {
        std::wstring where = L"บันทึกการทำงานไว้ที่: " + log_path();
        ui_log(where);
        log_to_file(where);
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(g_main, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    CoUninitialize();
    return (int)msg.wParam;
}
