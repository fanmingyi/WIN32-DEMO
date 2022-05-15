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


Environment struc
	m_pfnLoadLibraryA dd 0
	m_pfnGetProcAddress dd 0
	m_pfnCreateDecompressor dd 0 
	m_pfnDecompress dd 0 
	m_pfnVirtualAlloc dd 0
	m_pfnRtlMoveMemory dd 0
Environment ends


ComInfo struc
	m_dwOff dd 0
	m_dwComSize dd 0   ;压缩后大小
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
	g_szNtDll2 db "ntdll",0
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
				;int 3;
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
	mov eax,offset g_szLoadLibraryA
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
start:

	invoke Entry
	jmp eax



end start
