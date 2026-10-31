/*++

Module Name:

    shvos_log.c

Abstract:

    Log para arquivo (C:\SimpleVisor.txt), usado por qualquer modulo NT do
    SimpleVisor que precise registrar eventos em PASSIVE_LEVEL (IOCTLs,
    hooks de politica, etc.). Extraido de shvos.c para isolar essa
    responsabilidade.

Environment:

    Kernel mode only.

--*/

#include <ntifs.h>
#include <ntstrsafe.h>
#include "shvos_internal.h"

//
// Log para arquivo. Abre, escreve e fecha a cada chamada para permitir
// leitura concorrente. So funciona em PASSIVE_LEVEL.
//
VOID
ShvLog (
    _In_z_ _Printf_format_string_ const char* Fmt,
    ...
    )
{
    UNICODE_STRING      filePath;
    OBJECT_ATTRIBUTES   objAttr;
    IO_STATUS_BLOCK     ioStatus;
    HANDLE              hFile;
    NTSTATUS            status;
    char                buf[512];
    va_list             ap;
    int                 len;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return;

    va_start(ap, Fmt);
    RtlStringCchVPrintfA(buf, sizeof(buf) - 1, Fmt, ap);
    len = (int)strlen(buf);
    va_end(ap);
    if (len < 0) len = (int)(sizeof(buf) - 2);

    RtlInitUnicodeString(&filePath, L"\\??\\C:\\ShvL.txt");
    InitializeObjectAttributes(&objAttr, &filePath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    // FILE_OPEN_IF: cria se nao existir, abre se ja existir
    // FILE_APPEND_DATA: sempre escreve no fim
    // FILE_SHARE_READ | FILE_SHARE_WRITE: permite leitura concorrente
    status = ZwCreateFile(&hFile,
                          FILE_APPEND_DATA | SYNCHRONIZE,
                          &objAttr,
                          &ioStatus,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                          NULL, 0);
    if (!NT_SUCCESS(status))
        return;

    ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus,
                buf, (ULONG)len, NULL, NULL);
    ZwClose(hFile);

    // Espelha para o debugger kernel (visivel no WinDbg/DebugView)
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", buf);
}
