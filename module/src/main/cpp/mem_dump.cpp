//
// 运行时内存 dump 实现
//

#include "mem_dump.h"
#include "log.h"

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
#include <unistd.h>
#include <string>
#include <algorithm>
#include <vector>

#include "xdl.h"

// global-metadata.dat 头部魔数 (Il2CppGlobalMetadataHeader::sanity)
static constexpr uint32_t kMetadataMagic = 0xFAB11BAF;
// 元数据大小上限，用于过滤误判
static constexpr size_t kMaxMetadataSize = 0x20000000;

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
            // 外部存储里的应用专属目录，不用 root 也方便取出来
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

struct LoadSegment {
    uint64_t vaddr;
    uint64_t offset;
    uint64_t filesz;
};

// p_offset 是否还可用：各段在文件里不能互相重叠
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

bool dump_libil2cpp(const std::string &path) {
    auto handle = xdl_open("libil2cpp.so", XDL_DEFAULT);
    if (!handle) {
        LOGE("libil2cpp.so not loaded, skip so dump");
        return false;
    }
    xdl_info_t info{};
    if (xdl_info(handle, XDL_DI_DLINFO, &info) != 0 || info.dli_fbase == nullptr) {
        LOGE("xdl_info(libil2cpp.so) failed");
        xdl_close(handle);
        return false;
    }
    auto base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    auto ehdr = reinterpret_cast<ElfW(Ehdr) *>(base);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("bad ELF header at %p", reinterpret_cast<void *>(base));
        xdl_close(handle);
        return false;
    }
    auto phdr = reinterpret_cast<ElfW(Phdr) *>(base + ehdr->e_phoff);

    // 收集需要落盘的 PT_LOAD
    std::vector<LoadSegment> segs;
    uint64_t minVaddr = UINT64_MAX;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type != PT_LOAD || phdr[i].p_filesz == 0) {
            continue;
        }
        segs.push_back({phdr[i].p_vaddr, phdr[i].p_offset, phdr[i].p_filesz});
        if (phdr[i].p_vaddr < minVaddr) {
            minVaddr = phdr[i].p_vaddr;
        }
    }
    if (segs.empty()) {
        LOGE("no PT_LOAD segment in libil2cpp.so");
        xdl_close(handle);
        return false;
    }

    // 程序头表副本：必要时会修正 p_offset 后写回文件
    std::vector<ElfW(Phdr)> phdrCopy(phdr, phdr + ehdr->e_phnum);
    bool byVaddr = false;
    if (!offsets_are_sane(segs)) {
        // 加固把 p_offset 改坏了，按 vaddr 紧凑重排，并同步修正程序头
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
        xdl_close(handle);
        return false;
    }
    bool ok = true;
    size_t written = 0;
    for (const auto &s: segs) {
        ok = lseek(fd, static_cast<off_t>(s.offset), SEEK_SET) != (off_t) -1 &&
             write_all(fd, reinterpret_cast<const void *>(base + s.vaddr), s.filesz);
        if (!ok) {
            break;
        }
        written += s.filesz;
    }
    // ELF 头与程序头表一定写进文件（有的加固会把首个 PT_LOAD 的 p_offset 挪开）
    if (ok) {
        ok = lseek(fd, 0, SEEK_SET) != (off_t) -1 &&
             write_all(fd, ehdr, sizeof(ElfW(Ehdr))) &&
             lseek(fd, static_cast<off_t>(ehdr->e_phoff), SEEK_SET) != (off_t) -1 &&
             write_all(fd, phdrCopy.data(), phdrCopy.size() * sizeof(ElfW(Phdr)));
    }
    close(fd);
    xdl_close(handle);
    if (!ok) {
        LOGE("dump %s failed: %s", path.c_str(), strerror(errno));
        unlink(path.c_str());
        return false;
    }
    LOGI("dump libil2cpp.so ok: %s (%zu bytes, %d segments%s, base %p)", path.c_str(), written,
         static_cast<int>(segs.size()), byVaddr ? ", vaddr layout" : "",
         reinterpret_cast<void *>(base));
    return true;
}

// 在内存块里找 4 字节魔数（memmem 在部分 Android 版本不一定可用，这里自己实现）
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

struct MemRegion {
    uintptr_t start;
    uintptr_t end;
};

static bool collect_readable_regions(std::vector<MemRegion> &regions) {
    auto fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("open /proc/self/maps failed: %s", strerror(errno));
        return false;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start = 0;
        uintptr_t end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s", &start, &end, perms) != 3) {
            continue;
        }
        if (perms[0] != 'r' || end <= start) {
            continue;
        }
        regions.push_back({start, end});
    }
    fclose(fp);
    return true;
}

// 头部布局：sanity(int32) version(int32) 之后是成对的 (offset, size)
static bool is_metadata_header(const uint8_t *addr, size_t avail) {
    if (avail < 0x40) {
        return false;
    }
    auto raw = reinterpret_cast<const int32_t *>(addr);
    if (static_cast<uint32_t>(raw[0]) != kMetadataMagic) {
        return false;
    }
    auto version = raw[1];
    if (version < 16 || version > 32) {
        return false;
    }
    auto pairs = (avail - 8) / 8;
    if (pairs > 64) {
        pairs = 64;
    }
    for (size_t i = 0; i < pairs; ++i) {
        int64_t offset = raw[2 + i * 2];
        int64_t size = raw[3 + i * 2];
        if (offset > 0x1000 && size > 0 && offset + size > 0x1000 &&
            static_cast<size_t>(offset + size) <= avail) {
            return true;
        }
    }
    return false;
}

// 用头部的 (offset, size) 对估算整块元数据的大小
static size_t estimate_metadata_size(const uint8_t *addr, size_t avail) {
    auto raw = reinterpret_cast<const int32_t *>(addr);
    size_t maxEnd = 0;
    for (size_t i = 0; i < 64; ++i) {
        int64_t offset = raw[2 + i * 2];
        int64_t size = raw[3 + i * 2];
        if (offset <= 0 || size <= 0 ||
            static_cast<size_t>(offset) > kMaxMetadataSize ||
            static_cast<size_t>(size) > kMaxMetadataSize) {
            continue;
        }
        auto end = static_cast<size_t>(offset + size);
        if (end > maxEnd && end <= kMaxMetadataSize) {
            maxEnd = end;
        }
    }
    if (maxEnd < 0x1000 || maxEnd > avail) {
        // 老版本布局或数据被裁剪时估算不可信，尽量多拿一点（不会越过映射边界）
        maxEnd = avail < (16u << 20) ? avail : (16u << 20);
    }
    return maxEnd;
}

bool dump_global_metadata(const std::string &path) {
    std::vector<MemRegion> regions;
    if (!collect_readable_regions(regions)) {
        return false;
    }
    auto magic = kMetadataMagic;
    for (const auto &region: regions) {
        auto start = reinterpret_cast<const uint8_t *>(region.start);
        size_t remaining = static_cast<size_t>(region.end - region.start);
        while (remaining >= sizeof(magic)) {
            auto found = find_magic(start, remaining, magic);
            if (!found) {
                break;
            }
            auto avail = static_cast<size_t>(region.end - reinterpret_cast<uintptr_t>(found));
            if (is_metadata_header(found, avail)) {
                auto size = estimate_metadata_size(found, avail);
                auto fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd < 0) {
                    LOGE("open %s failed: %s", path.c_str(), strerror(errno));
                    return false;
                }
                bool ok = write_all(fd, found, size);
                close(fd);
                if (!ok) {
                    LOGE("write %s failed: %s", path.c_str(), strerror(errno));
                    unlink(path.c_str());
                    return false;
                }
                LOGI("dump global-metadata.dat ok: %s (v%d, %zu bytes, %p)", path.c_str(),
                     reinterpret_cast<const int32_t *>(found)[1], size, found);
                return true;
            }
            size_t advance = static_cast<size_t>(found - start) + sizeof(magic);
            if (advance >= remaining) {
                break;
            }
            start += advance;
            remaining -= advance;
        }
    }
    LOGE("global-metadata.dat not found in memory");
    return false;
}
