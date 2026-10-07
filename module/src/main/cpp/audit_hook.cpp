//
// 审计钩子：训练营 GM 面板（只打日志，不改变任何行为）
//
// 槽位/方法 RVA 来自对 libil2cpp.so 重定位表的静态分析（本 build）：
//   CTrainingHelperPnlType1View.ShowGMPanel   槽 0xd615590  方法 0x6601898
//   CNewHeroPracticeGMPnlPartLogic.OnCheat    槽 0xd62a640  方法 0x6a03a28
//   ...ExcutePlayerCheatCmd                   槽 0xd62a660  方法 0x6a04268
//   ...RecoveryCD                             槽 0xd62a658  方法 0x6a04190
//   CTrainingHelper.OpenPanel                 槽 0xd629e48  方法 0x69ed440
//   ...SetPanelOpen                           槽 0xd62a638  方法 0x6a03988
//
#include "audit_hook.h"
#include "log.h"

#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace {

constexpr uintptr_t kSlotShowGMPanel = 0xd615590;
constexpr uintptr_t kRvaShowGMPanel = 0x6601898;

constexpr uintptr_t kSlotOnCheat = 0xd62a640;
constexpr uintptr_t kRvaOnCheat = 0x6a03a28;

constexpr uintptr_t kSlotExcuteCheat = 0xd62a660;
constexpr uintptr_t kRvaExcuteCheat = 0x6a04268;

constexpr uintptr_t kSlotRecoveryCd = 0xd62a658;
constexpr uintptr_t kRvaRecoveryCd = 0x6a04190;

constexpr uintptr_t kSlotTrainingOpenPanel = 0xd629e48;
constexpr uintptr_t kRvaTrainingOpenPanel = 0x69ed440;

constexpr uintptr_t kSlotSetPanelOpen = 0xd62a638;
constexpr uintptr_t kRvaSetPanelOpen = 0x6a03988;

void (*orig_ShowGMPanel)(void *, int32_t);
void (*orig_OnCheat)(void *, void *);
void (*orig_ExcuteCheat)(void *, int32_t, int32_t);
void (*orig_RecoveryCd)(void *);
void (*orig_TrainingOpenPanel)(void *);
void (*orig_SetPanelOpen)(void *, int32_t);

void my_ShowGMPanel(void *self, int32_t show) {
    LOGI("[audit] ShowGMPanel(show=%d) self=%p", show, self);
    if (orig_ShowGMPanel != nullptr) {
        orig_ShowGMPanel(self, show);
    }
}

void my_OnCheat(void *self, void *evt) {
    LOGI("[audit] GM panel button clicked (OnCheat) self=%p evt=%p", self, evt);
    if (orig_OnCheat != nullptr) {
        orig_OnCheat(self, evt);
    }
}

void my_ExcuteCheat(void *self, int32_t param, int32_t cheatType) {
    LOGI("[audit] ExcutePlayerCheatCmd(param=%d, cheatType=%d) self=%p", param, cheatType, self);
    if (orig_ExcuteCheat != nullptr) {
        orig_ExcuteCheat(self, param, cheatType);
    }
}

void my_RecoveryCd(void *self) {
    LOGI("[audit] RecoveryCD called self=%p", self);
    if (orig_RecoveryCd != nullptr) {
        orig_RecoveryCd(self);
    }
}

void my_TrainingOpenPanel(void *self) {
    LOGI("[audit] CTrainingHelper.OpenPanel self=%p", self);
    if (orig_TrainingOpenPanel != nullptr) {
        orig_TrainingOpenPanel(self);
    }
}

void my_SetPanelOpen(void *self, int32_t open) {
    LOGI("[audit] SetPanelOpen(open=%d) self=%p", open, self);
    if (orig_SetPanelOpen != nullptr) {
        orig_SetPanelOpen(self, open);
    }
}

template<typename T>
bool patch_slot(uintptr_t soBase, uintptr_t slotOffset, uintptr_t methodRva, T replacement, T *original,
                const char *name) {
    auto slotAddr = soBase + slotOffset;
    auto expect = soBase + methodRva;
    auto current = *reinterpret_cast<uintptr_t *>(slotAddr);
    if (current != expect) {
        LOGW("[audit] slot mismatch, skip %s: slot=0x%" PRIxPTR " value=0x%" PRIxPTR " expect=0x%" PRIxPTR,
             name, slotAddr, current, expect);
        return false;
    }
    auto pageSize = static_cast<uintptr_t>(getpagesize());
    auto page = slotAddr & ~(pageSize - 1);
    if (mprotect(reinterpret_cast<void *>(page), pageSize, PROT_READ | PROT_WRITE) != 0) {
        LOGE("[audit] mprotect failed for %s: %s", name, strerror(errno));
        return false;
    }
    *original = reinterpret_cast<T>(current);
    *reinterpret_cast<T *>(slotAddr) = replacement;
    __sync_synchronize();
    LOGI("[audit] hooked %s: slot=0x%" PRIxPTR " original=0x%" PRIxPTR, name, slotAddr, current);
    return true;
}

}  // namespace

void install_audit_hooks(uintptr_t soBase) {
    if (soBase == 0) {
        LOGE("[audit] soBase is 0, skip installing audit hooks");
        return;
    }
    LOGI("[audit] installing audit hooks on libil2cpp base 0x%" PRIxPTR " (log only, no behavior change)", soBase);
    int installed = 0;
    installed += patch_slot(soBase, kSlotShowGMPanel, kRvaShowGMPanel, &my_ShowGMPanel, &orig_ShowGMPanel,
                            "ShowGMPanel") ? 1 : 0;
    installed += patch_slot(soBase, kSlotOnCheat, kRvaOnCheat, &my_OnCheat, &orig_OnCheat, "OnCheat") ? 1 : 0;
    installed += patch_slot(soBase, kSlotExcuteCheat, kRvaExcuteCheat, &my_ExcuteCheat, &orig_ExcuteCheat,
                            "ExcutePlayerCheatCmd") ? 1 : 0;
    installed += patch_slot(soBase, kSlotRecoveryCd, kRvaRecoveryCd, &my_RecoveryCd, &orig_RecoveryCd,
                            "RecoveryCD") ? 1 : 0;
    installed += patch_slot(soBase, kSlotTrainingOpenPanel, kRvaTrainingOpenPanel, &my_TrainingOpenPanel,
                            &orig_TrainingOpenPanel, "CTrainingHelper.OpenPanel") ? 1 : 0;
    installed += patch_slot(soBase, kSlotSetPanelOpen, kRvaSetPanelOpen, &my_SetPanelOpen, &orig_SetPanelOpen,
                            "SetPanelOpen") ? 1 : 0;
    LOGI("[audit] %d/%d audit hooks installed (only logging; press the training panel in a SINGLE-PLAYER training match)",
         installed, 6);
}
