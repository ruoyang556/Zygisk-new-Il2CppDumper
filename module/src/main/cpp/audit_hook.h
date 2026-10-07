#pragma once

#include <cstdint>

// 安装“只打日志、不改行为”的审计钩子（训练营 GM 面板链路）
// 说明：通过改写 IL2CPP 的“方法指针槽”（数据段）来拦截调用，
//       调用方原本就是 ldr 槽 + blr，因此数据槽改写即可命中，且不需要改代码段。
void install_audit_hooks(uintptr_t soBase);
