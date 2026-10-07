//
// 运行时内存 dump 实现
//

#include "mem_dump.h"
#include "log.h"

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <elf.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string>
#include <vector>

#include "xdl.h"

static constexpr uint32_t kMetadataMagic = 0xFAB11BAF;
static constexpr size_t kMaxMetadataSize = 0x40000000;   // 1GB 上限，防误判
static constexpr size_t kMaxBackSearch = 256u << 20;     // 回溯搜索上限 256MB

void make_dirs(const std::string &path) {
    if (path.empty()) {
        return;
    }
    std::string cur;
    for (char c: path) {
        cur += c;
        if (c == '/' && cur.size() > 1) {
            mkdir(cur.c_str(), 0755);
        }
    }
    mkdir(path.c_str(), 0755);
}

std::string pick_writable_dir(const char *appDataDir) {
    std::vector<std::string> candidates;
    std::string base(appDataDir ? appDataDir : "");
    if (!base.empty()) {
        candidates.emplace_back(base + "/files");
        candidates.emplace_back(base);
        auto slash = base.rfind('/');
        if (slash != std::string::npos && slash + 1 < base.size()) {
            candidates.emplace_back("/sdcard/Android/data/" + base.substr(slash + 1) + "/files");
        }
    }
    for (const auto &dir: candidates) {
        make_dirs(dir);
        if (access(dir.c_str(), W_OK) == 0) {
            return dir;
        }
    }
    return {};
}

static bool write_all(int fd, const void *data, size_t len) {
    auto p = static_cast<const char *>(data);
    while (len > 0) {
        auto n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

static bool read_u32(const void *p, uint32_t *out) {
    memcpy(out, p, sizeof(uint32_t));
    return true;
}

// ---------------------------------------------------------------------------
// libil2cpp.so
// ---------------------------------------------------------------------------

struct LoadSegment {
    uint64_t vaddr;
    uint64_t offset;
    uint64_t filesz;
    uint64_t memsz;
};

static bool offsets_are_sane(std::vector<LoadSegment> segs) {
    std::sort(segs.begin(), segs.end(),
              [](const LoadSegment &a, const LoadSegment &b) { return a.offset < b.offset; });
    uint64_t prevEnd = 0;
    for (const auto &s: segs) {
        if (s.offset < prevEnd) {
            return false;
        }
        prevEnd = s.offset + s.filesz;
    }
    return true;
}

bool dump_libil2cpp(const std::string &path, DumpInfo *dumpInfo) {
    auto handle = xdl_open("libil2cpp.so", XDL_DEFAULT);
    if (!handle) {
        LOGE("libil2cpp.so not loaded, skip so dump");
        return false;
    }
    xdl_info_t info{};
    if (xdl_info(handle, XDL_DI_DLINFO, &info) != 0 || info.dli_fbase == nullptr) {
        LOGE("xdl_info(libil2cpp.so) failed");
        // 故意不 close：避免影响后续运行时状态
        return false;
    }
    auto base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    auto ehdr = reinterpret_cast<ElfW(Ehdr) *>(base);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("bad ELF header at %p", reinterpret_cast<void *>(base));
        // 故意不 close：避免影响后续运行时状态
        return false;
    }
    if (ehdr->e_phoff > 0x10000 || ehdr->e_phnum == 0 || ehdr->e_phnum > 128) {
        LOGE("suspicious ELF header (e_phoff=0x%llx e_phnum=%d), skip so dump",
             static_cast<unsigned long long>(ehdr->e_phoff), ehdr->e_phnum);
        return false;
    }
    auto phdr = reinterpret_cast<ElfW(Phdr) *>(base + ehdr->e_phoff);

    std::vector<LoadSegment> segs;
    uint64_t minVaddr = UINT64_MAX;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type != PT_LOAD || phdr[i].p_filesz == 0) {
            continue;
        }
        segs.push_back({phdr[i].p_vaddr, phdr[i].p_offset, phdr[i].p_filesz, phdr[i].p_memsz});
        if (phdr[i].p_vaddr < minVaddr) {
            minVaddr = phdr[i].p_vaddr;
        }
    }
    if (segs.empty()) {
        LOGE("no PT_LOAD segment in libil2cpp.so");
        // 故意不 close：避免影响后续运行时状态
        return false;
    }

    std::vector<ElfW(Phdr)> phdrCopy(phdr, phdr + ehdr->e_phnum);
    bool byVaddr = false;
    if (!offsets_are_sane(segs)) {
        LOGW("program header offsets overlap, rebuild file layout by vaddr");
        byVaddr = true;
        uint64_t cursor = 0;
        for (auto &s: segs) {
            auto vaddr = s.vaddr;
            s.offset = cursor;
            cursor += s.filesz;
            for (int i = 0; i < ehdr->e_phnum; ++i) {
                if (phdrCopy[i].p_type == PT_LOAD && phdrCopy[i].p_vaddr == vaddr) {
                    phdrCopy[i].p_offset = s.offset;
                }
            }
        }
    }

    auto fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOGE("open %s failed: %s", path.c_str(), strerror(errno));
        // 故意不 close：避免影响后续运行时状态
        return false;
    }
    // 按 p_memsz 落盘（把 .bss 也带上），并把程序头的 p_filesz 同步改成 p_memsz，
    // 这样文件就是一个完整的"内存镜像"，Il2CppDumper 等工具以 dumped 模式处理时能拿到运行时数据
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrCopy[i].p_type == PT_LOAD) {
            phdrCopy[i].p_filesz = phdrCopy[i].p_memsz;
        }
    }
    bool ok = true;
    size_t written = 0;
    for (const auto &s: segs) {
        auto size = s.memsz > s.filesz ? s.memsz : s.filesz;
        ok = lseek(fd, static_cast<off_t>(s.offset), SEEK_SET) != (off_t) -1 &&
             write_all(fd, reinterpret_cast<const void *>(base + s.vaddr), size);
        if (!ok) {
            break;
        }
        written += size;
    }
    if (ok) {
        ok = lseek(fd, 0, SEEK_SET) != (off_t) -1 &&
             write_all(fd, ehdr, sizeof(ElfW(Ehdr))) &&
             lseek(fd, static_cast<off_t>(ehdr->e_phoff), SEEK_SET) != (off_t) -1 &&
             write_all(fd, phdrCopy.data(), phdrCopy.size() * sizeof(ElfW(Phdr)));
    }
    close(fd);
    // 故意不 close：避免影响后续运行时状态
    if (!ok) {
        LOGE("dump %s failed: %s", path.c_str(), strerror(errno));
        unlink(path.c_str());
        return false;
    }
    if (dumpInfo) {
        dumpInfo->soBase = base;
        dumpInfo->soSize = written;
    }
    LOGI("dump libil2cpp.so ok: %s (%zu bytes, %d segments%s, base %p)", path.c_str(), written,
         static_cast<int>(segs.size()), byVaddr ? ", vaddr layout" : "",
         reinterpret_cast<void *>(base));
    return true;
}

// ---------------------------------------------------------------------------
// global-metadata.dat
// ---------------------------------------------------------------------------

struct MemRegion {
    uintptr_t start;
    uintptr_t end;
    bool readable;
    std::string path;
};

// 安全内存读取：优先走 /proc/self/mem（越界/空洞只会返回错误，不会让进程崩掉）
static ssize_t read_via_process_vm(uintptr_t addr, void *buf, size_t len) {
    struct iovec local{};
    struct iovec remote{};
    local.iov_base = buf;
    local.iov_len = len;
    remote.iov_base = reinterpret_cast<void *>(addr);
    remote.iov_len = len;
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
}

// 安全内存读取：优先 /proc/self/mem，其次 process_vm_readv —— 两者都只会返回错误，
// 不会因为访问到"已失效的映射"而把进程打死
class MemReader {
public:
    MemReader() {
        fd_ = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
        uint32_t probe = 0;
        pvmOk_ = read_via_process_vm(reinterpret_cast<uintptr_t>(&probe), &probe, sizeof(probe)) > 0;
        if (fd_ < 0 && !pvmOk_) {
            LOGW("no safe memory reader available (mem fd=%d, process_vm_readv=%d), direct read will be used",
                 fd_, static_cast<int>(pvmOk_));
        }
    }

    ~MemReader() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    const char *name() const {
        if (fd_ >= 0) return "/proc/self/mem";
        if (pvmOk_) return "process_vm_readv";
        return "direct";
    }

    ssize_t read_at(uintptr_t addr, void *buf, size_t len) const {
        if (fd_ >= 0) {
            auto n = pread(fd_, buf, len, static_cast<off_t>(addr));
            if (n > 0) {
                return n;
            }
        }
        if (pvmOk_) {
            auto n = read_via_process_vm(addr, buf, len);
            if (n > 0) {
                return n;
            }
        }
        if (fd_ < 0 && !pvmOk_) {
            // 实在没有安全通道才直接读（有崩溃风险）
            memcpy(buf, reinterpret_cast<const void *>(addr), len);
            return static_cast<ssize_t>(len);
        }
        return -1;
    }

private:
    int fd_ = -1;
    bool pvmOk_ = false;
};

static bool collect_regions(std::vector<MemRegion> &regions) {
    auto fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("open /proc/self/maps failed: %s", strerror(errno));
        return false;
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start = 0;
        uintptr_t end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s", &start, &end, perms) != 3) {
            continue;
        }
        if (end <= start) {
            continue;
        }
        MemRegion r{};
        r.start = start;
        r.end = end;
        r.readable = perms[0] == 'r';
        int fields = 0;
        char *p = line;
        while (*p && fields < 5) {
            while (*p == ' ') p++;
            while (*p && *p != ' ' && *p != '\n') p++;
            fields++;
        }
        while (*p == ' ') p++;
        size_t len = strlen(p);
        while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == '\r')) p[--len] = 0;
        r.path.assign(p);
        regions.push_back(r);
    }
    fclose(fp);
    return true;
}

static const uint8_t *find_magic(const uint8_t *p, size_t len, uint32_t magic) {
    if (len < sizeof(magic)) {
        return nullptr;
    }
    auto b0 = static_cast<uint8_t>(magic & 0xFF);
    auto b1 = static_cast<uint8_t>((magic >> 8) & 0xFF);
    auto b2 = static_cast<uint8_t>((magic >> 16) & 0xFF);
    auto b3 = static_cast<uint8_t>((magic >> 24) & 0xFF);
    const uint8_t *end = p + len - sizeof(magic) + 1;
    while (p < end) {
        auto hit = static_cast<const uint8_t *>(memchr(p, b0, static_cast<size_t>(end - p)));
        if (!hit) {
            return nullptr;
        }
        if (hit[1] == b1 && hit[2] == b2 && hit[3] == b3) {
            return hit;
        }
        p = hit + 1;
    }
    return nullptr;
}

static size_t read_some(const MemReader &reader, uintptr_t addr, void *buf, size_t len) {
    if (len == 0) {
        return 0;
    }
    auto n = reader.read_at(addr, buf, len);
    return n > 0 ? static_cast<size_t>(n) : 0;
}

// 分块扫描一段内存里的 4 字节魔数（安全读取），命中返回绝对地址，否则返回 0
static uintptr_t scan_magic(const MemReader &reader, uintptr_t start, uintptr_t end, uint32_t magic,
                            std::vector<uint8_t> &buf, size_t chunk) {
    uintptr_t cur = start;
    while (cur + 4 <= end) {
        size_t want = static_cast<size_t>(cur + chunk <= end ? chunk : end - cur);
        size_t got = read_some(reader, cur, buf.data(), want);
        if (got < 4) {
            break;
        }
        auto hit = find_magic(buf.data(), got, magic);
        if (hit) {
            return cur + static_cast<uintptr_t>(hit - buf.data());
        }
        if (got < want) {
            break;
        }
        cur += got - 3;   // 保留 3 字节重叠，避免跨块漏掉
    }
    return 0;
}

struct HeaderInfo {
    uint32_t sanity = 0;
    int32_t version = 0;
    size_t size = 0;
    bool structural = false;
};

// 校验 addr 处是否是 metadata 头部。requireMagic=false 时用纯结构判定（应对魔数被改）
static bool inspect_header(const MemReader &reader, uintptr_t addr, uintptr_t limit,
                           bool requireMagic, HeaderInfo *out) {
    if (limit <= addr) {
        return false;
    }
    size_t avail = static_cast<size_t>(limit - addr);
    if (avail < 0x40) {
        return false;
    }
    uint8_t hdr[8 + 64 * 8];
    size_t want = avail < sizeof(hdr) ? avail : sizeof(hdr);
    if (read_some(reader, addr, hdr, want) < want) {
        return false;
    }
    auto raw = reinterpret_cast<const int32_t *>(hdr);
    uint32_t sanity = 0;
    memcpy(&sanity, hdr, 4);
    int32_t version = raw[1];
    if (version < 16 || version > 64) {
        return false;
    }
    if (requireMagic && sanity != kMetadataMagic) {
        return false;
    }
    auto pairs = (want - 8) / 8;
    if (pairs > 64) {
        pairs = 64;
    }
    size_t valid = 0;
    size_t maxEnd = 0;
    for (size_t i = 0; i < pairs; ++i) {
        int64_t offset = raw[2 + i * 2];
        int64_t size = raw[3 + i * 2];
        if (offset <= 0 || size <= 0 || offset >= static_cast<int64_t>(kMaxMetadataSize) ||
            size >= static_cast<int64_t>(kMaxMetadataSize)) {
            continue;
        }
        valid++;
        auto end2 = static_cast<size_t>(offset + size);
        if (end2 > maxEnd && end2 <= avail) {
            maxEnd = end2;
        }
    }
    if (requireMagic) {
        if (valid == 0 || maxEnd < 0x1000) {
            return false;
        }
    } else {
        if (valid < 20 || maxEnd < (1u << 20)) {
            return false;
        }
    }
    if (out) {
        out->sanity = sanity;
        out->version = version;
        out->size = maxEnd;
        out->structural = !requireMagic;
    }
    return true;
}

// 分块把内存写到文件；magicPatch 非空时把文件头 4 字节改成标准魔数
static bool stream_to_file(const MemReader &reader, const std::string &path, uintptr_t addr,
                           size_t size, const uint8_t *magicPatch) {
    auto fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOGE("open %s failed: %s", path.c_str(), strerror(errno));
        return false;
    }
    std::vector<uint8_t> buf(1u << 20);
    size_t done = 0;
    bool ok = true;
    while (done < size) {
        size_t want = size - done < buf.size() ? size - done : buf.size();
        size_t got = read_some(reader, addr + done, buf.data(), want);
        if (got == 0) {
            break;
        }
        if (!write_all(fd, buf.data(), got)) {
            ok = false;
            break;
        }
        done += got;
    }
    if (ok && done == 0) {
        ok = false;
    }
    if (ok && magicPatch) {
        if (pwrite(fd, magicPatch, 4, 0) != 4) {
            LOGW("patch magic failed");
        }
    }
    close(fd);
    if (!ok) {
        LOGE("write %s failed: %s", path.c_str(), strerror(errno));
        unlink(path.c_str());
        return false;
    }
    return true;
}

// 写出 metadata；如果魔数被改过会顺手改回标准值方便工具读取
static bool emit_metadata(const MemReader &reader, const std::string &path, uintptr_t addr,
                          const HeaderInfo &info, DumpInfo *out) {
    uint8_t patch[4];
    const uint8_t *patchPtr = nullptr;
    if (info.sanity != kMetadataMagic) {
        uint32_t std = kMetadataMagic;
        memcpy(patch, &std, 4);
        patchPtr = patch;
    }
    if (!stream_to_file(reader, path, addr, info.size, patchPtr)) {
        return false;
    }
    if (out) {
        out->metadataAddr = addr;
        out->metadataSize = info.size;
        out->metadataVersion = info.version;
        out->metadataMagic = info.sanity;
        out->metadataStructural = info.structural ? 1 : 0;
    }
    LOGI("dump global-metadata.dat ok: %s (v%d, %zu bytes, addr 0x%" PRIxPTR ", magic 0x%08x%s)",
         path.c_str(), info.version, info.size, addr, info.sanity,
         info.structural ? ", structural match" : "");
    if (patchPtr) {
        LOGW("metadata magic 0x%08x -> 0xFAB11BAF (patched)", info.sanity);
    }
    return true;
}

bool dump_global_metadata(const std::string &path, const std::vector<uintptr_t> &hints, DumpInfo *out) {
    std::vector<MemRegion> regions;
    if (!collect_regions(regions)) {
        return false;
    }
    MemReader reader;
    size_t readableBytes = 0, readableCount = 0;
    for (const auto &r: regions) {
        if (r.readable) {
            readableBytes += r.end - r.start;
            readableCount++;
        }
    }
    LOGI("metadata scan: %zu regions (%zu readable, %zu MB), reader=%s", regions.size(),
         readableCount, readableBytes >> 20, reader.name());

    const size_t chunk = 1u << 20;
    std::vector<uint8_t> buf(chunk + 64);
    HeaderInfo info{};

    // ---- 策略 1：全内存搜标准魔数 ----
    LOGI("metadata: strategy 1 (magic scan) start");
    size_t scanned = 0;
    for (const auto &r: regions) {
        if (!r.readable) {
            continue;
        }
        uintptr_t cur = r.start;
        while (cur + 4 <= r.end) {
            uintptr_t hit = scan_magic(reader, cur, r.end, kMetadataMagic, buf, chunk);
            if (!hit) {
                break;
            }
            if (inspect_header(reader, hit, r.end, true, &info)) {
                return emit_metadata(reader, path, hit, info, out);
            }
            cur = hit + 4;
        }
        scanned += r.end - r.start;
        if ((scanned >> 20) % 512 < (r.end - r.start) / (1u << 20)) {
            LOGI("metadata: scanned %zu MB", scanned >> 20);
        }
    }
    LOGW("metadata magic not found, fallback to pointer guided search");

    // ---- 策略 2：用运行时指针往回找头部（不要求魔数）----
    LOGI("metadata: strategy 2 (pointer guided) with %zu hints", hints.size());
    for (auto hint: hints) {
        const MemRegion *home = nullptr;
        for (const auto &r: regions) {
            if (r.readable && hint >= r.start && hint < r.end) {
                home = &r;
                break;
            }
        }
        if (!home) {
            LOGW("hint 0x%" PRIxPTR " not in readable region", hint);
            continue;
        }
        LOGI("hint 0x%" PRIxPTR " in 0x%" PRIxPTR "-0x%" PRIxPTR " (%s), searching backwards",
             hint, home->start, home->end, home->path.empty() ? "anon" : home->path.c_str());

        // 2a) 往回 1MB 密集找魔数
        uintptr_t denseStart = hint > (1u << 20) ? hint - (1u << 20) : home->start;
        if (denseStart < home->start) {
            denseStart = home->start;
        }
        uintptr_t hitCur = denseStart;
        while (hitCur + 4 <= hint) {
            uintptr_t hit = scan_magic(reader, hitCur, hint, kMetadataMagic, buf, chunk);
            if (!hit) {
                break;
            }
            if (inspect_header(reader, hit, home->end, true, &info)) {
                return emit_metadata(reader, path, hit, info, out);
            }
            hitCur = hit + 4;
        }

        // 2b) 按页往回做结构判定
        uintptr_t lower = home->start;
        if (hint > lower + kMaxBackSearch) {
            lower = hint - kMaxBackSearch;
        }
        uintptr_t page = hint & ~static_cast<uintptr_t>(0xFFF);
        size_t steps = 0;
        for (; page > lower && steps < (kMaxBackSearch / 0x1000); page -= 0x1000, ++steps) {
            if (inspect_header(reader, page, home->end, false, &info)) {
                return emit_metadata(reader, path, page, info, out);
            }
        }
        LOGW("hint 0x%" PRIxPTR ": no header found in %zu pages", hint, steps);
    }

    // ---- 策略 3：兜底，找名字带 metadata 的文件映射整块 dump ----
    for (const auto &r: regions) {
        if (!r.readable || r.path.empty() || r.path.find("metadata") == std::string::npos) {
            continue;
        }
        LOGW("fallback: mapping %s 0x%" PRIxPTR "-0x%" PRIxPTR, r.path.c_str(), r.start, r.end);
        HeaderInfo fallback{};
        fallback.size = static_cast<size_t>(r.end - r.start);
        if (emit_metadata(reader, path, r.start, fallback, out)) {
            return true;
        }
    }

    LOGE("global-metadata.dat not found in memory");
    return false;
}

void write_dump_info(const std::string &dir, const DumpInfo &info) {
    if (dir.empty()) {
        return;
    }
    auto path = dir + "/dump_info.txt";
    auto fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOGE("write %s failed: %s", path.c_str(), strerror(errno));
        return;
    }
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
                     "so_base=0x%" PRIxPTR "\n"
                     "so_size=%zu\n"
                     "metadata_addr=0x%" PRIxPTR "\n"
                     "metadata_size=%zu\n"
                     "metadata_version=%d\n"
                     "metadata_magic=0x%08x\n"
                     "metadata_structural_match=%d\n"
                     "dump_dir=%s\n",
                     info.soBase, info.soSize, info.metadataAddr, info.metadataSize,
                     info.metadataVersion, info.metadataMagic, info.metadataStructural, dir.c_str());
    if (n > 0) {
        write_all(fd, buf, static_cast<size_t>(n));
    }
    close(fd);
    LOGI("dump info written: %s", path.c_str());
}
