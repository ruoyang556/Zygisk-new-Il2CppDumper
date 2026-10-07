//
// 运行时内存 dump：libil2cpp.so / global-metadata.dat
//

#ifndef ZYGISK_IL2CPPDUMPER_MEM_DUMP_H
#define ZYGISK_IL2CPPDUMPER_MEM_DUMP_H

#include <string>

// 逐级创建目录（等价于 mkdir -p）
void make_dirs(const std::string &path);

// 依次尝试：应用私有 files 目录 -> 应用私有数据目录 -> 外部存储的应用专属目录，
// 返回第一个可写目录（不存在会自动创建）；全部失败返回空字符串
std::string pick_writable_dir(const char *appDataDir);

// 从内存中 dump 出 libil2cpp.so（按 ELF program header 还原文件布局）
bool dump_libil2cpp(const std::string &path);

// 在进程内存里扫描 global-metadata.dat 的 magic 并 dump 出来
bool dump_global_metadata(const std::string &path);

#endif //ZYGISK_IL2CPPDUMPER_MEM_DUMP_H
