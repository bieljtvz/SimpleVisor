#pragma once
#include "shv_backend.h"
void RenderTabMemory(ShvBackend& backend);

// Called from other tabs to pre-fill the VA/PID fields and switch to this tab
void TabMemoryNavigateTo(uint64_t addr, uint64_t pid);
extern bool g_memTabSelectPending;
