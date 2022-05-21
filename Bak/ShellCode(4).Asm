.586
.model flat,stdcall
option casemap:none

   include windows.inc
   include user32.inc
   include kernel32.inc
   
   includelib user32.lib
   includelib kernel32.lib



.data
   ClassName db "MainWinClass",0
   AppName  db "Main Window",0

.data?
   hInstance HINSTANCE ?
   CommandLine LPSTR ?


GetKernelBase proto

MyGetProcAddress proto  hDll:HINSTANCE,pName:LPCTSTR
mystrcmp  proto
mymemset proto
mymemcmp proto
LoadDll proto  lpMapAddr:LPBYTE,hInst:HANDLE,pEnv:ptr Environment

Environment struc
	m_pfnLoadLibraryA dd 0
	m_pfnGetProcAddress dd 0
	m_pfnCreateDecompressor dd 0 
	m_pfnDecompress dd 0 
	m_pfnVirtualAlloc dd 0
	m_pfnRtlMoveMemory dd 0
	m_pfnVirtualProtect dd 0
Environment ends


ComInfo struc
	m_dwOff dd 0
	m_dwComSize dd 0   ;压缩后大小1232
	m_dwDecomSize dd 0 ;解压大小
ComInfo ends


.code
CODE_START:
    jmp start	
	g_szLoadLibraryA db "LoadLibraryA",0
	g_szGetProcAddress db "GetProcAddress",0
	g_szCabinet db "Cabinet",0
	g_szCreateDecompressor db "CreateDecompressor",0
	g_szDecompress db "Decompress",0
	g_szVirtualAlloc db "VirtualAlloc",0
	g_szRtlMoveMemory db "RtlMoveMemory",0
	g_szNtDll db "ntdll",0
	g_szVirtualProtect db "VirtualProtect",0
	g_env Environment <>
	

Init proc uses ebx esi
	LOCAL hKernel:HMODULE
	LOCAL hCabinet:HMODULE
	LOCAL hNtdll:HMODULE
	
	;重定位
	;指向pop ebx 
	call NEXT
NEXT:
	pop ebx	
	sub ebx,offset NEXT;偏移
	
	;定位Environment
	mov eax,offset g_env
	add eax,ebx
	mov esi,eax
	assume esi:ptr Environment
	
	
	invoke GetKernelBase
	mov hKernel,eax
	
	
	;kernel32相关
	mov eax,offset g_szGetProcAddress
	add eax,ebx
	invoke MyGetProcAddress,hKernel,eax
	mov [esi].m_pfnGetProcAddress,eax
	
	mov eax,offset g_szLoadLibraryA
	add eax,ebx
	push eax
	push hKernel
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnLoadLibraryA,eax
	
	mov eax,offset g_szVirtualAlloc
	add eax,ebx
	push eax
	push hKernel
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnVirtualAlloc,eax
	
	
	
	mov eax,offset g_szVirtualProtect
	add eax,ebx
	push eax
	push hKernel
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnVirtualProtect,eax
	
	
	;压缩相关
	mov eax,offset g_szCabinet
	add eax,ebx
	push eax
	call [esi].m_pfnLoadLibraryA
	mov hCabinet,eax
	
	
	
	
	mov eax,offset g_szCreateDecompressor
	add eax,ebx
	push eax
	push hCabinet
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnCreateDecompressor,eax  
	
	
	
	mov eax,offset g_szDecompress
	add eax,ebx
	push eax
	push hCabinet
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnDecompress,eax  
	
	
	
	
	;g_szRtlMoveMemory db "RtlMoveMemory",0
	;g_szNtDll db "ntdll"
	
	;ntdll相关
	mov eax,offset g_szNtDll
	add eax,ebx
	push eax
	call [esi].m_pfnLoadLibraryA
	mov hNtdll,eax
	
	
	
	
	mov eax,offset g_szRtlMoveMemory
	add eax,ebx
	push eax
	push hNtdll
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnRtlMoveMemory,eax  
	
	
	
	 mov eax,esi
	ret

Init endp	

GetKernelBase proc

	assume fs:nothing
		mov  eax, dword ptr fs : [030h]
		mov  eax, dword ptr      [eax +  0Ch]
		mov  eax, dword ptr      [eax + 0Ch]
		mov  eax, dword ptr      [eax]
		mov  eax, dword ptr  	 [eax]
		mov  eax, dword ptr  	 [eax + 18h]
		ret
GetKernelBase endp


MyGetProcAddress proc  uses esi ebx edi  hDll:HINSTANCE,pName:LPCTSTR
	LOCAL @dwAddressOfNames:DWORD
	LOCAL @dwCnt:DWORD

	mov esi,hDll
	assume esi:ptr IMAGE_DOS_HEADER
	mov esi,[esi].e_lfanew
	add esi,hDll
	
	assume esi:ptr IMAGE_NT_HEADERS
	;得到导出表位置
	mov esi,[esi].OptionalHeader.DataDirectory[0].VirtualAddress
	add esi,hDll
	
	assume esi:ptr IMAGE_EXPORT_DIRECTORY
	
	.if pName > 0ffffh ;名称
		;导出名称表地址
		mov eax,[esi].AddressOfNames
		add eax,hDll
		mov @dwAddressOfNames,eax
	
		;遍历导出名称表，查找对应函数
		mov eax,[esi].NumberOfNames
		mov @dwCnt,eax
		dec @dwCnt
 		.while @dwCnt> 0
			;数组首地址
			mov ebx,@dwAddressOfNames
			mov eax,@dwCnt
			mov eax,[ebx+ eax * sizeof DWORD]
			add eax,hDll 

			;对比字符串
			push eax
			push pName
			call mystrcmp
			add esp,8
			
			
			;invoke crt_strcmp,pName,eax
			.if eax == 0
			
				mov eax,@dwCnt
				mov ebx,[esi].AddressOfNameOrdinals
				add ebx,hDll
				movzx eax,word ptr [ebx+eax*sizeof WORD]
				
				;获取地址
				mov ebx,[esi].AddressOfFunctions
				add ebx,hDll
				mov eax,[ebx+eax*sizeof DWORD]
				
				add eax,hDll
				ret
			.endif
		
			dec @dwCnt
		.endw
	
	.else
		;获取导出地址表中的下标索引
		
		ret	
	.endif
	

	xor eax,eax	
	ret

MyGetProcAddress endp 
; ---------------------------------------------------------------------------




Entry proc
	LOCAL @dwComSize:DWORD
	LOCAL @dwDecomSize:DWORD
	LOCAL @pComData:LPBYTE
	LOCAL @hDecom:HANDLE
	LOCAL @pDecomBuf:LPBYTE
	LOCAL @dwDecomSizeRet:DWORD
	
	;初始化,获取所属的API地址
	invoke Init
	mov esi,eax
	assume esi:ptr Environment
	
	;获取偏移
	call NEXT
NEXT:
	pop ebx	
	sub ebx,offset NEXT;偏移
	
	
	;定位到压缩数据
	mov eax,offset CODE_START
	add eax,ebx
	sub eax,size ComInfo
	mov edi,eax
	assume edi:ptr ComInfo
	
	push [edi].m_dwComSize
	pop @dwComSize
	
	push [edi].m_dwDecomSize
	pop @dwDecomSize
	
	
	
	add edi,[edi].m_dwOff
 	mov @pComData,edi
	assume  edi:nothing
	
	;解压缩
	
	lea eax,@hDecom
	push eax
	push NULL
	push 4
	call [esi].m_pfnCreateDecompressor
	 
	
	push PAGE_EXECUTE_READWRITE
	push MEM_COMMIT
	push @dwDecomSize
	push NULL
	call [esi].m_pfnVirtualAlloc
	mov @pDecomBuf,eax
	
	lea eax,@dwDecomSizeRet
	push eax
	push @dwDecomSize
	push @pDecomBuf
	push @dwComSize
	push @pComData
	push @hDecom
	call [esi].m_pfnDecompress
	
	
	
	;LOADPE
	
	assume fs:nothing
	mov eax,fs:[30h]
	mov eax,[eax+8]

	invoke LoadDll,@pDecomBuf,eax,esi
	ret

Entry endp


mystrcmp  proc

        .FPO    ( 0, 2, 0, 0, 0, 0 )

        mov     edx,[esp + 4]   ; edx = src
        mov     ecx,[esp + 8]   ; ecx = dst

        test    edx,3
        jnz     short dopartial

        align   4
dodwords:
        mov     eax,[edx]

        cmp     al,[ecx]
        jne     short donene
        or      al,al
        jz      short doneeq
        cmp     ah,[ecx + 1]
        jne     short donene
        or      ah,ah
        jz      short doneeq

        shr     eax,16

        cmp     al,[ecx + 2]
        jne     short donene
        or      al,al
        jz      short doneeq
        cmp     ah,[ecx + 3]
        jne     short donene
        add     ecx,4
        add     edx,4
        or      ah,ah
        jnz     short dodwords

        align   4
doneeq:
        xor     eax,eax
        ret

        align   4
donene:
        ; The instructions below should place -1 in eax if src < dst,
        ; and 1 in eax if src > dst.

        sbb     eax,eax
        sal     eax,1
        inc     eax
        ret

        align   4
dopartial:
        test    edx,1
        jz      short doword

        mov     al,[edx]
        inc     edx
        cmp     al,[ecx]
        jne     short donene
        inc     ecx
        or      al,al
        jz      short doneeq

        test    edx,2
        jz      short dodwords


        align   4
doword:
        mov     ax,[edx]
        add     edx,2
        cmp     al,[ecx]
        jne     short donene
        or      al,al
        jz      short doneeq
        cmp     ah,[ecx + 1]
        jne     short donene
        or      ah,ah
        jz      short doneeq
        add     ecx,2
        jmp     short dodwords

mystrcmp  endp

mymemset proc

        .FPO    ( 0, 3, 0, 0, 0, 0 )

        mov     edx,[esp + 0ch] ; edx = "count"
        mov     ecx,[esp + 4]   ; ecx points to "dst"

        test    edx,edx         ; 0?
        jz      short toend     ; if so, nothing to do

        xor     eax,eax
        mov     al,[esp + 8]    ; the byte "value" to be stored


; Align address on dword boundary

        push    edi             ; preserve edi
        mov     edi,ecx         ; edi = dest pointer

        cmp     edx,4           ; if it's less then 4 bytes
        jb      tail            ; tail needs edi and edx to be initialized

        neg     ecx
        and     ecx,3           ; ecx = # bytes before dword boundary
        jz      short dwords    ; jump if address already aligned

        sub     edx,ecx         ; edx = adjusted count (for later)
adjust_loop:
        mov     [edi],al
        inc     edi
        dec     ecx
        jnz     adjust_loop

dwords:
; set all 4 bytes of eax to [value]
        mov     ecx,eax         ; ecx=0/0/0/value
        shl     eax,8           ; eax=0/0/value/0

        add     eax,ecx         ; eax=0/0val/val

        mov     ecx,eax         ; ecx=0/0/val/val

        shl     eax,10h         ; eax=val/val/0/0

        add     eax,ecx         ; eax = all 4 bytes = [value]

; Set dword-sized blocks
        mov     ecx,edx         ; move original count to ecx
        and     edx,3           ; prepare in edx byte count (for tail loop)
        shr     ecx,2           ; adjust ecx to be dword count
        jz      tail            ; jump if it was less then 4 bytes

        rep     stosd
main_loop_tail:
        test    edx,edx         ; if there is no tail bytes,
        jz      finish          ; we finish, and it's time to leave
; Set remaining bytes

tail:
        mov     [edi],al        ; set remaining bytes
        inc     edi

        dec     edx             ; if there is some more bytes
        jnz     tail            ; continue to fill them

; Done
finish:
        mov     eax,[esp + 8]   ; return dest pointer
        pop     edi             ; restore edi

        ret

toend:
        mov     eax,[esp + 4]   ; return dest pointer

        ret

mymemset  endp

mymemcmp  proc

        .FPO    ( 0, 3, 0, 0, 0, 0 )

        mov     eax,[esp+0ch]   ; eax = counter
        test    eax,eax         ; test if counter is zero
        jz      short retnull   ; return 0

        mov     edx,[esp+4]     ; edx = buf1
        push    esi
        push    edi
        mov     esi,edx         ; esi = buf1
        mov     edi,[esp+10h]   ; edi = buf2

; Check for dword (32 bit) alignment
        or      edx,edi
        and     edx,3           ; edx=0 iff buf1 are buf2 are aligned
        jz      short dwords

; Strings are not aligned. If the caller knows the strings (buf1 and buf2) are
; different, the function may be called with length like -1. The difference
; may be found in the last dword of aligned string, and because the other
; string is misaligned it may cause page fault. So, to be safe. the comparison
; must be done byte by byte.
        test    eax,1
        jz      short main_loop

        mov     cl,[esi]
        cmp     cl,[edi]
        jne     short not_equal
        inc     esi
        inc     edi
        dec     eax
        jz      short done      ; eax is already 0

main_loop:
        mov     cl,[esi]
        mov     dl,[edi]
        cmp     cl,dl
        jne     short not_equal

        mov     cl,[esi+1]
        mov     dl,[edi+1]
        cmp     cl,dl
        jne     short not_equal

        add     edi,2
        add     esi,2

        sub     eax,2
        jnz     short main_loop
done:
        pop     edi
        pop     esi
retnull:
        ret                     ; _cdecl return


dwords:
        mov     ecx,eax
        and     eax,3           ; eax= counter for tail loop

        shr     ecx,2
        jz      short tail_loop_start
                                ; counter was >=4 so may check one dword
        repe     cmpsd

        jz      short tail_loop_start

; in last dword was difference
        mov     ecx,dword ptr[esi-4]     ; load last dword from buf1 to ecx
        mov     edx,[edi-4]     ; load last dword from buf2 to edx
        cmp     cl,dl           ; test first bytes
        jne     short difference_in_tail
        cmp     ch,dh           ; test seconds bytes
        jne     short difference_in_tail
        shr     ecx,10h
        shr     edx,10h
        cmp     cl,dl           ; test third bytes
        jne     short difference_in_tail
        cmp     ch,dh           ; they are different, but each one is bigger?
;       jmp     short difference_in_tail

difference_in_tail:
        mov     eax,0
                                ; buf1 < buf2 buf1 > buf2
not_equal:
        sbb     eax,eax         ; AX=-1, CY=1 AX=0, CY=0
        pop     edi             ; counter
        sbb     eax,-1          ; AX=-1 AX=1
        pop     esi
        ret                     ; _cdecl return

; in tail loop we test last three bytes (esi and edi are aligned on dword
; boundary)
tail_loop_start:

        test    eax,eax         ; eax is counter%4 (number of bytes for tail
                                ; loop)
        jz      short done      ; taken if there is no tail bytes
        mov     edx,dword ptr[esi]       ; load dword from buf1
        mov     ecx,dword ptr[edi]       ; load dword from buf2
        cmp     dl,cl           ; test first bytes
        jne     short difference_in_tail
        dec     eax             ; counter--
        jz      short tail_done
        cmp     dh,ch           ; test second bytes
        jne     short difference_in_tail
        dec     eax             ; counter--
        jz      short tail_done
        and     ecx,00ff0000h   ; test third bytes
        and     edx,00ff0000h
        cmp     edx,ecx
        jne     short difference_in_tail
        dec     eax
tail_done:
        pop     edi
        pop     esi
        ret                     ; _cdecl return

mymemcmp  endp

LoadDll proc uses esi edi ebx ecx lpMapAddr:LPBYTE,hInst:HANDLE,pEnv:ptr Environment

	LOCAL @lpMapAddr:LPVOID
	LOCAL @dwFileSize:DWORD
	LOCAL @dwNumberOfsection:DWORD
	LOCAL @dwNumOfHeaders:DWORD
	LOCAL @pSecHdr:ptr IMAGE_SECTION_HEADER
	LOCAL @hInst:HANDLE
	LOCAL @dwOldProc:DWORD
	LOCAL @pImpHdr:ptr IMAGE_IMPORT_DESCRIPTOR
	LOCAL @zeroImp:IMAGE_IMPORT_DESCRIPTOR
	LOCAL @hDll:HANDLE
	LOCAL @pTempThunk: ptr IMAGE_DATA_THUNK
	LOCAL @dwPFNAddr:dword
	LOCAL @dwIAT:DWORD
	LOCAL @dwOep:DWORD
	LOCAL @dwSizeOfImag:DWORD
	LOCAL @pBaseReloc:ptr IMAGE_BASE_RELOCATION
	LOCAL @dwSizeOfReloc:DWORD
	LOCAL @dwOffReloc:DWORD
	LOCAL @dwCntOfReloc:DWORD
	
	
	
	push sizeof IMAGE_IMPORT_DESCRIPTOR
	push 0
	lea  eax,@zeroImp
	push eax
	call mymemset
	add esp,0ch
	
	
	push lpMapAddr
	pop @lpMapAddr
	
	
	
	push hInst
	pop @hInst
	
	
	
	
	
	;保存映射得到的地址
	assume esi:nothing
	
	;拷贝PE
	mov esi,@lpMapAddr
	assume esi:ptr IMAGE_DOS_HEADER
	;指向新的NT头地址
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	
	
	mov eax,[esi].OptionalHeader.SizeOfHeaders
	mov @dwNumOfHeaders,eax
	
	;节表数量
	movzx eax,[esi].FileHeader.NumberOfSections
	mov @dwNumberOfsection,eax
	
	;存储的是节表头地址
	movzx eax,[esi].FileHeader.SizeOfOptionalHeader
	lea ebx,[esi].OptionalHeader
	add eax,ebx
	mov @pSecHdr,eax
	
	mov eax,[esi].OptionalHeader.SizeOfImage
	mov @dwSizeOfImag,eax
	 
	
	
	
	;@dwOffReloc存储的是首选基地址和实际加载地址的偏差
	sub eax,[esi].OptionalHeader.ImageBase
	mov @dwOffReloc,eax
	
	;存储的是dll 的dllmain
	push [esi].OptionalHeader.AddressOfEntryPoint
	pop @dwOep
	mov eax,@hInst
	add @dwOep,eax
	
	;得到导入表的地址
	lea eax,[esi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof IMAGE_DATA_DIRECTORY ]
	assume eax:ptr IMAGE_DATA_DIRECTORY
	mov eax,[eax].VirtualAddress 
	add eax,@hInst
	mov @pImpHdr,eax
	assume eax:nothing	
	

	;得到重定位表
	lea ebx,[esi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC * sizeof IMAGE_DATA_DIRECTORY ]
	assume ebx:ptr IMAGE_DATA_DIRECTORY
	mov eax,[ebx].VirtualAddress
	.if @pBaseReloc!=NULL
		add eax,@hInst
		;存储的重定位表地址
		mov @pBaseReloc,eax
		;存储的重定位表大小
		mov eax,[ebx].isize
		;保存重定位表大小
		mov @dwSizeOfReloc,eax
	.else
		
		mov	@pBaseReloc,NULL
		mov @dwSizeOfReloc,0
	.endif

	
	assume ebx:nothing
	
	assume esi:nothing
	
	assume eax:ptr IMAGE_DATA_DIRECTORY
	
	
	;拷贝dll节头到内存中
	;拷贝PE头
	
	lea eax,@dwOldProc
	push eax
	push PAGE_EXECUTE_READWRITE
	push @dwNumOfHeaders
	push @hInst
	mov eax,pEnv
	assume eax:ptr Environment
	call [eax].m_pfnVirtualProtect
	assume ecx:nothing
	
	;invoke crt_memcpy,@hInst,@lpMapAddr,@dwNumOfHeaders
	push @dwNumOfHeaders
	push @lpMapAddr
	push @hInst
	mov eax,pEnv
	assume eax:ptr Environment
	
	call [eax].m_pfnRtlMoveMemory
	assume ecx:nothing
	
	xor ebx,ebx
	
	 ;拷贝节
	.while ebx < @dwNumberOfsection
		mov ecx,@pSecHdr
		assume ecx:ptr IMAGE_SECTION_HEADER
		;源
		mov esi,[ecx].PointerToRawData
		add esi,@lpMapAddr
		
		;目的
		mov edi,[ecx].VirtualAddress
		add edi,@hInst
		
		
		;invoke crt_memcpy,edi,esi,[ecx].SizeOfRawData
		push [ecx].SizeOfRawData
		push esi
		push edi
		mov eax,pEnv
		assume eax:ptr Environment
		call [eax].m_pfnRtlMoveMemory
		assume ecx:nothing
		
		
		add @pSecHdr,sizeof IMAGE_SECTION_HEADER
		inc ebx
	.endw
	
	
	;处理导入表
	.while TRUE
	;遇到全0项目，遍历结束
		push sizeof  IMAGE_IMPORT_DESCRIPTOR
		lea  eax,@zeroImp
		push eax
		push @pImpHdr
		call mymemcmp
	 	;invoke crt_memcmp,@pImpHdr,addr @zeroImp,sizeof IMAGE_IMPORT_DESCRIPTOR
	 	add esp,0ch
	 	.if eax == 0
	  		.break
	  	.endif
	  
	 	mov esi,@pImpHdr
	 	assume esi:ptr IMAGE_IMPORT_DESCRIPTOR
		
		;获取dll的名称
	
		mov eax,[esi].Name1
		add eax,@hInst
		
		;invoke LoadLibrary,eax
		push eax
		mov eax,pEnv
		assume eax:ptr Environment
		call [eax].m_pfnLoadLibraryA
		assume ecx:nothing
		.if eax==NULL
		 	;
		 	;invoke MessageBox,NULL,offset g_szLoadError,offset g_szLoadError,MB_OK
			.break
		.endif
		
		mov @hDll,eax
		
		
		.if [esi].FirstThunk ==NULL
			.break
		.endif
		mov eax,[esi].FirstThunk
		add eax,@hInst
		mov @dwIAT,eax
		
		
		
		mov eax,[esi].OriginalFirstThunk
		mov @pTempThunk,eax
		
		.if @pTempThunk ==NULL
			mov eax,[esi].FirstThunk
			mov @pTempThunk,eax	
		.endif
		
		mov eax,@hInst
		add @pTempThunk,eax
		
		
		
		
		mov ebx,@pTempThunk
		.while dword ptr [ebx]!=NULL
		
			.if (dword ptr[ebx] >=  8000000h)
				;序号导入
				movzx eax,word ptr [ebx] ;低字为序号
				;invoke GetProcAddress,@hDll,eax
				push eax
				push @hDll
				mov eax,pEnv
				assume eax:ptr Environment
				call [eax].m_pfnGetProcAddress
				assume eax:nothing
				;check
				mov @dwPFNAddr,eax
			
			.else
				;名称导入
			
				mov eax,[ebx]
				add eax,@hInst ;ptr IMAGE_IMPORT_BY_NAME 前面有一个word
				add eax,sizeof word;导入函数地址
				;invoke GetProcAddress,@hDll,eax
				push eax
				push @hDll
				mov eax,pEnv
				assume eax:ptr Environment
			
				call [eax].m_pfnGetProcAddress
				assume eax:nothing
				mov @dwPFNAddr,eax
				
			.endif  
			
			
			;填充IAT
			mov eax,@dwIAT
			push @dwPFNAddr
			pop dword ptr [eax]
			
			
			add ebx,4
			add @dwIAT,4
		.endw
		
		 
		
		
		
	 	assume esi:nothing
	 	add @pImpHdr,sizeof IMAGE_IMPORT_DESCRIPTOR;下一项
	.endw
	
	int 3
	.if @pBaseReloc==NULL
		jmp EXIT
	.endif
	;处理重定位
	.while TRUE
		;@pBaseReloc存储的是重定位表初始化地址
		mov esi,@pBaseReloc
		assume esi:ptr IMAGE_BASE_RELOCATION
		
		
		;获取页内偏移数组地址,IMAGE_BASE_RELOCATION结构不包偏移数组含
		lea ebx,[esi+sizeof IMAGE_BASE_RELOCATION]
		
		;这里的得到是是偏移数组和IMAGE_BASE_RELOCATION总大小
		mov ecx,[esi].SizeOfBlock
		;减去结构体可以偏移数组的大小
		sub ecx,sizeof IMAGE_BASE_RELOCATION
		;右移动除以2，可以得到数组个数（因为每个item大小为2）
		shr ecx,1
		;存储数组的大小
		mov @dwCntOfReloc,ecx
		
		
		xor ecx,ecx
		;遍历偏移数组每一项
		.while ecx < @dwCntOfReloc
			;ecx表示正在遍历第几个
			movzx eax,word ptr[ebx + ecx*sizeof word]
			;只处理30类别 
			.if eax  & 0f000h
				;需要重定位
				and eax,0fffh
				add eax,[esi].VirtualAddress
				;获取需要重定位的地址
				add eax,@hInst
			
				;重定位
				mov edi,@dwOffReloc
				add dword ptr [eax],edi 
					
			.endif
			
			inc ecx

		.endw
		
		;;处理下一个分页 重定位表的下一个item
		add esi,[esi].SizeOfBlock
		;判断是否处理完所有重定位
		mov edi,esi
		;如果下一项的地址减去初始地址大于重定位初始地址证明遍历完成
		sub edi,@pBaseReloc
		.if edi >= @dwSizeOfReloc
			.break
		.endif
	.endw
	

	
	;清理
EXIT:	

	;返回模块的  句柄
	mov eax,@dwOep
	ret

LoadDll endp



start:

	invoke Entry
	jmp eax



end start
