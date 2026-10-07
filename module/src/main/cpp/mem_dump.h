//
// 运行时内存 dump：libil2cpp.so / global-metadata.dat
//

#ifndef ZYGISK_IL2CPPDUMPER_MEM_DUMP_H
#define ZYGISK_IL2CPPDUMPER_MEM_DUMP_H

#include <cstdint>
#include <string>
#include <vector>

// 逐级创建目录（等价于 mkdir -p）
void make_dirs(const std::string &path);

// 依次尝试：应用私有 files 目录 -> 应用私有数据目录 -> 外部存储的应用专属目录，
// 返回第一个可写目录（不存在会自动创建）；全部失败返回空字符串
std::string pick_writable_dir(const char *appDataDir);

// dump 过程中的关键信息，会写进 dump_info.txt
struct DumpInfo {
    uintptr_t soBase = 0;
    size_t soSize = 0;
    uintptr_t metadataAddr = 0;
    size_t metadataSize = 0;
    int32_t metadataVersion = 0;
    uint32_t metadataMagic = 0;
    int metadataStructural = 0;
};

// 从内存中 dump 出 libil2cpp.so（完整内存镜像，含 .bss）
bool dump_libil2cpp(const std::string &path, DumpInfo *info);

// 在进程内存里定位并 dump global-metadata.dat
// hints: 若干"指向 metadata 内部"的地址（例如 il2cpp_class_get_name 返回的字符串指针），可为空
bool dump_global_metadata(const std::string &path, const std::vector<uintptr_t> &hints, DumpInfo *info);

// 把 DumpInfo 写成 <dir>/dump_info.txt，方便直接 cat 出来
void write_dump_info(const std::string &dir, const DumpInfo &info);

#endif //ZYGISK_IL2CPPDUMPER_MEM_DUMP_H
