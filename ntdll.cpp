#include "ntdll.h"

#include "pe.h"

unsigned char* NTDLL::FileData = 0;
ULONG NTDLL::FileSize = 0;

NTSTATUS NTDLL::Initialize()
{
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    RtlInitUnicodeString(&FileName, L"\\SystemRoot\\system32\\ntdll.dll");
    InitializeObjectAttributes(&ObjectAttributes, &FileName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    if(KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
#ifdef _DEBUG
        DPRINT("[DeugMessage] KeGetCurrentIrql != PASSIVE_LEVEL!\n");
#endif
        return STATUS_UNSUCCESSFUL;
    }

    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
                                     GENERIC_READ,
                                     &ObjectAttributes,
                                     &IoStatusBlock, NULL,
                                     FILE_ATTRIBUTE_NORMAL,
                                     FILE_SHARE_READ,
                                     FILE_OPEN,
                                     FILE_SYNCHRONOUS_IO_NONALERT,
                                     NULL, 0);
    if(NT_SUCCESS(NtStatus))
    {
        FILE_STANDARD_INFORMATION StandardInformation = { 0 };
        NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
        if(NT_SUCCESS(NtStatus))
        {
            FileSize = StandardInformation.EndOfFile.LowPart;
            DPRINT("[DeugMessage] FileSize of ntdll.dll is %08X!\r\n", StandardInformation.EndOfFile.LowPart);
            FileData = (unsigned char*)RtlAllocateMemory(true, FileSize);

            LARGE_INTEGER ByteOffset;
            ByteOffset.LowPart = ByteOffset.HighPart = 0;
            NtStatus = ZwReadFile(FileHandle,
                                  NULL, NULL, NULL,
                                  &IoStatusBlock,
                                  FileData,
                                  FileSize,
                                  &ByteOffset, NULL);

            if(!NT_SUCCESS(NtStatus))
            {
                RtlFreeMemory(FileData);
                DPRINT("[DeugMessage] ZwReadFile failed with status %08X...\r\n", NtStatus);
            }
        }
        else
            DPRINT("[DeugMessage] ZwQueryInformationFile failed with status %08X...\r\n", NtStatus);
        ZwClose(FileHandle);
    }
    else
        DPRINT("[DeugMessage] ZwCreateFile failed with status %08X...\r\n", NtStatus);
    return NtStatus;
}

void NTDLL::Deinitialize()
{
    RtlFreeMemory(FileData);
}

int NTDLL::GetExportSsdtIndex(const char* ExportName)
{
    ULONG_PTR ExportOffset = PE::GetExportOffset(FileData, FileSize, ExportName);
    if(ExportOffset == PE_ERROR_VALUE)
        return -1;

    int SsdtOffset = -1;
    unsigned char* ExportData = FileData + ExportOffset;
    for(int i = 0; i < 32 && ExportOffset + i < FileSize; i++)
    {
        if(ExportData[i] == 0xC2 || ExportData[i] == 0xC3)  //RET
            break;
        if(ExportData[i] == 0xB8)  //mov eax,X
        {
            SsdtOffset = *(int*)(ExportData + i + 1);
            break;
        }
    }

    if(SsdtOffset == -1)
    {
        DPRINT("[DeugMessage] SSDT Offset for %s not found...\r\n", ExportName);
    }

    return SsdtOffset;
}