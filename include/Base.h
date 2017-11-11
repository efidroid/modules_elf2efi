#ifndef BASE_H
#define BASE_H

#include <stdint.h>
#include <stdbool.h>

typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uintptr_t UINTN;
typedef int8_t INT8;
typedef int16_t INT16;
typedef int32_t INT32;
typedef int64_t INT64;
typedef intptr_t INTN;
typedef uint8_t CHAR8;
typedef uint16_t CHAR16;
typedef void* EFI_HANDLE;
typedef bool BOOLEAN;
typedef INTN RETURN_STATUS;
typedef RETURN_STATUS EFI_STATUS;

typedef struct {
  UINT32  Data1;
  UINT16  Data2;
  UINT16  Data3;
  UINT8   Data4[8];
} EFI_GUID;

#define EFIAPI
#define IN
#define OUT

#endif
