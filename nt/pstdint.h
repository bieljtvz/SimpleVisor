#pragma once
// Substituto de pstdint.h para ambiente kernel (WDK).
// Os tipos stdint sao fornecidos pelo WDK via <ntdef.h> / <wdm.h>.
#include <ntdef.h>
typedef UINT8   uint8_t;
typedef UINT16  uint16_t;
typedef UINT32  uint32_t;
typedef UINT64  uint64_t;
typedef INT8    int8_t;
typedef INT16   int16_t;
typedef INT32   int32_t;
typedef INT64   int64_t;
