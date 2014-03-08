
// suppose all path var lengths are MAX_PATH

#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>


#include "pework.h"
#pragma comment( lib, "pework.lib" )

extern "C"{
#include "disasm.h"
#pragma comment( lib, "disasm2.lib" )
}


#include <stack>
using namespace std;


#define eg( msg ) do { puts( msg ); return 0; } while( FALSE )







BOOL SetPrivilege(
				  HANDLE hToken,          // access token handle
				  LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
				  BOOL bEnablePrivilege   // to enable or disable privilege
				  ) 
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	
	if ( !LookupPrivilegeValue( 
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid ) )        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
		return FALSE; 
	}
	
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	
	// Enable the privilege or disable all privileges.
	
	if ( !AdjustTokenPrivileges(
		hToken, 
		FALSE, 
		&tp, 
		sizeof(TOKEN_PRIVILEGES), 
		(PTOKEN_PRIVILEGES) NULL, 
		(PDWORD) NULL) )
	{ 
		printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
		return FALSE; 
	} 
	
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	} 
	
	return TRUE;
}

void RisePriv()
{
	HANDLE hToken;
	if( !OpenThreadToken( GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken ) )
	{
		if( GetLastError() == ERROR_NO_TOKEN )
		{
			if( !ImpersonateSelf( SecurityImpersonation) )
			{
				puts( "ImpersonateSelf failure" );
				return;
			}
			if( !OpenThreadToken( GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken ) )
			{
				puts( "OpenThreadToken failure" );
				return;
			}
		}
		else
		{
			puts( "OpenThreadToken failure" );
			return;
		}
	}

	SetPrivilege( hToken, "SeDebugPrivilege", TRUE );

}





BOOL rread( HANDLE hproc, DWORD addr, OUT void *buf, int size )
{
	DWORD tmp;
	DWORD rw;
	MEMORY_BASIC_INFORMATION mbi = {0,};

	if( VirtualQueryEx( hproc, (LPVOID)addr, &mbi, sizeof(mbi) ) == 0 )
	{
		if( GetLastError() == 5 )
		{
			VirtualProtectEx( hproc, (LPVOID)addr, size, PROCESS_VM_READ, &tmp );
			if( ReadProcessMemory( hproc, (LPVOID)addr, buf, size, &rw ) == FALSE )
				return FALSE;
			VirtualProtectEx( hproc, (LPVOID)addr, size, tmp, &tmp );
			return TRUE;
		}
		return FALSE;
	}

	if( VirtualProtectEx( hproc, (LPVOID)addr, size, PAGE_READWRITE, &tmp ) == FALSE )
		return FALSE;
	if( ReadProcessMemory( hproc, (LPVOID)addr, buf, size, &rw ) == FALSE )
		return FALSE;
	VirtualProtectEx( hproc, (LPVOID)addr, size, tmp, &tmp );


	return TRUE;
}


BOOL rwrite( HANDLE hproc, DWORD addr, OUT void *buf, int size )
{
	DWORD tmp;
	DWORD rw;
	if( VirtualProtectEx( hproc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &tmp ) == FALSE )
		return FALSE;
	if( WriteProcessMemory( hproc, (LPVOID)addr, buf, size, &rw ) == FALSE )
		return FALSE;
	VirtualProtectEx( hproc, (LPVOID)addr, size, tmp, &tmp );


	return TRUE;
}


BOOL rread2( DWORD pid, DWORD addr, OUT void *buf, int size )
{
	HANDLE hproc = NULL;
	BOOL result = TRUE;

	hproc = OpenProcess( PROCESS_VM_READ|PROCESS_VM_OPERATION, FALSE, pid );
	if( hproc == NULL )
	{
		if( GetLastError() == 5 )
		{
			// access denied
			hproc = OpenProcess( PROCESS_VM_READ, FALSE, pid );
			if( hproc == NULL )
			{
				result = FALSE;
				goto _END;
			}
		}
	}

	result = rread( hproc, addr, buf, size );


_END:

	if( hproc != NULL )
		CloseHandle( hproc );

	return result;

}



BOOL rwrite2( DWORD pid, DWORD addr, OUT void *buf, int size )
{
	HANDLE hproc = NULL;
	DWORD tmp;
	DWORD rw;
	BOOL result = TRUE;

	hproc = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
	if( hproc == NULL )
	{
		result = FALSE;
		goto _END;
	}

	if( VirtualProtectEx( hproc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &tmp ) == FALSE )
	{
		result = FALSE;
		goto _END;
	}
	if( WriteProcessMemory( hproc, (LPVOID)addr, buf, size, &rw ) == FALSE )
	{
		result = FALSE;
		goto _END;
	}

	VirtualProtectEx( hproc, (LPVOID)addr, size, tmp, &tmp );


_END:

	if( hproc != NULL )
		CloseHandle( hproc );

	return result;

}



BOOL rread2autosize( DWORD pid, DWORD addr, BYTE* buf )
{
	int i;
	for( i = 15; i > 0; i -- )
	{
		if( rread2( pid, addr, buf, i ) == TRUE )
			return TRUE;
	}
	return FALSE;
}

void mylog( char *filename, char *format, ... )
{
	FILE *fp = NULL;
	va_list a;
	char tmp[1024];

	fp = fopen( filename, "at" );
	if( fp == NULL )
		goto _END;

	va_start( a, format );

	vsprintf( tmp, format, a );
	fprintf( fp, "%s\n", tmp );


_END:

	if( fp != NULL )
		fclose( fp );

	return;
}




BOOL Deobfuscate( BYTE *orgcode, int len, OUT BYTE *deobbed, OUT int *outlen )
{
	int index = 0;
	BYTE *code;
	code = (BYTE*)calloc( len, 1 );
	memcpy( code, orgcode, len );
	int linelen;
	t_disasm line;

	while( index < len )
	{
		linelen = Disasm( (char*)( code + index ), len - index, 0, &line, DISASM_CODE );

		// xchg eax, ebp
		// push eax
		// xchg eax, ebp		-> push ebp (\x55)
		if( memcmp( code + index, "\x95\x50\x95", 3 ) == 0 )
		{
			// replace these 3 bytes
			int newlen = len - 3 + 1;
			BYTE *newcode = (BYTE*)calloc( newlen, 1 );
			memcpy( newcode, code, index );
			newcode[index] = '\x55';
			memcpy( newcode + index + 1, code + index + 3, newlen - index - 1 );
			free( code );
			code = newcode;
			len = newlen;
			continue;
		}

		// xchg eax, ecx
		// push eax
		// xchg eax, ecx		-> push ecx (\x51)
		if( memcmp( code + index, "\x91\x50\x91", 3 ) == 0 )
		{
			// delete these 3 bytes
			int newlen = len - 3 + 1;
			BYTE *newcode = (BYTE*)calloc( newlen, 1 );
			memcpy( newcode, code, index );
			newcode[index] = '\x51';
			memcpy( newcode + index + 1, code + index + 3, newlen - index - 1 );
			free( code );
			code = newcode;
			len = newlen;
			continue;
		}

		// 96		XCHG EAX,ESI
		// 50		PUSH EAX
		// 96		XCHG EAX,ESI
		// -> 56	PUSH ESI
		if( memcmp( code + index, "\x96\x50\x96", 3 ) == 0 )
		{
			// delete these 3 bytes
			int newlen = len - 3 + 1;
			BYTE *newcode = (BYTE*)calloc( newlen, 1 );
			memcpy( newcode, code, index );
			newcode[index] = '\x56';
			memcpy( newcode + index + 1, code + index + 3, newlen - index - 1 );
			free( code );
			code = newcode;
			len = newlen;
			continue;
		}



		// push 0x11111111
		// add dword ptr[esp], 0x22222222 -> push 0x33333333
		if( index + 12 < len && 
			code[index] == (BYTE)'\x68' &&
			memcmp( code + index + 5, "\x81\x04\x24", 3 ) == 0 )
		{
			DWORD pushed = 0;
			DWORD added = 0;
			DWORD final = 0;
			// get pushed result
			memcpy( &pushed, code + index + 1, 4 );
			memcpy( &added, code + index + 8, 4 );
			final = pushed + added;

			int newlen = len - 12 + 5;
			BYTE *newcode = (BYTE*)calloc( newlen, 1 );
			memcpy( newcode, code, index );
			newcode[index] = '\x68';
			memcpy( newcode + index + 1, &final, 4 );
			memcpy( newcode + index + 1 + 4, code + index + 12, newlen - index - 1 - 4 );
			free( code );
			code = newcode;
			len = newlen;
			continue;
		}

		// push 0x11111111
		// xor dword ptr[esp], 0x22222222 -> push 0x33333333
		if( index + 12 < len && 
			code[index] == (BYTE)'\x68' &&
			memcmp( code + index + 5, "\x81\x34\x24", 3 ) == 0 )
		{
			DWORD pushed = 0;
			DWORD added = 0;
			DWORD final = 0;
			// get pushed result
			memcpy( &pushed, code + index + 1, 4 );
			memcpy( &added, code + index + 8, 4 );
			final = pushed ^ added;

			int newlen = len - 12 + 5;
			BYTE *newcode = (BYTE*)calloc( newlen, 1 );
			memcpy( newcode, code, index );
			newcode[index] = '\x68';
			memcpy( newcode + index + 1, &final, 4 );
			memcpy( newcode + index + 1 + 4, code + index + 12, newlen - index - 1 - 4 );
			free( code );
			code = newcode;
			len = newlen;
			continue;
		}

		// push 0x11111111
		// sub dword ptr[esp], 0x22222222 -> push 0x33333333
		if( index + 12 < len && 
			code[index] == (BYTE)'\x68' &&
			memcmp( code + index + 5, "\x81\x2c\x24", 3 ) == 0 )
		{
			DWORD pushed = 0;
			DWORD added = 0;
			DWORD final = 0;
			// get pushed result
			memcpy( &pushed, code + index + 1, 4 );
			memcpy( &added, code + index + 8, 4 );
			final = pushed - added;

			int newlen = len - 12 + 5;
			BYTE *newcode = (BYTE*)calloc( newlen, 1 );
			memcpy( newcode, code, index );
			newcode[index] = '\x68';
			memcpy( newcode + index + 1, &final, 4 );
			memcpy( newcode + index + 1 + 4, code + index + 12, newlen - index - 1 - 4 );
			free( code );
			code = newcode;
			len = newlen;
			continue;
		}

		// (E8 xxxxxxxx    CALL    XXXXXXXX)
		// 50              PUSH    EAX
		// 8B4424 04       MOV     EAX, DWORD PTR SS:[ESP+4]
		// 8B00            MOV     EAX, DWORD PTR DS:[EAX]
		// 894424 04       MOV     DWORD PTR SS:[ESP+4], EAX
		// 58              POP     EAX
		// -> 68 XXXXXXXX  PUSH    XXXXXXXX
		if( index + 11 < len &&
			memcmp( code + index, "\x50\x8b\x44\x24\x04\x8b\x00\x89\x44\x24\x04", 11 ) == 0 )
		{
			int newlen = len - 11 + 5;
			BYTE *newcode = (BYTE*)calloc( newlen, 1 );
			memcpy( newcode, code, index );
			memcpy( newcode + index, "\x68\x00\x00\x00\x00", 5 );
			memcpy( newcode + index + 5, code + index + 11, newlen - index );
			free( code );
			code = newcode;
			len = newlen;
			continue;
		}


		// push ecx
		// mov [esp], esi
		// -> push esi		need assembling
		if( memcmp( line.result, "PUSH E", 6 ) == 0 )
		{
			t_disasm next;
			int nextlen = Disasm( (char*)code + index + linelen, len - index, 0, &next, DISASM_CODE );

			if( memcmp( next.result, "MOV [ESP],", 10 ) == 0 )
			{
				// now assemble a new line
				t_asmmodel am;
				char newline[30] = "PUSH ";
				char error[40];
				strcat( newline, next.result + 10 );
				if( Assemble( newline, 0, &am, 0, 0, error ) == 0 )
				{
					printf( "Assemble failed..abort\n" );
					return FALSE;
				}

				// replace
				int newlen = len - ( linelen + nextlen ) + am.length;
				BYTE *newcode = (BYTE*)calloc( newlen, 1 );
				memcpy( newcode, code, index );
				memcpy( newcode + index, am.code, am.length );
				memcpy( newcode + index + am.length, code + index + linelen + nextlen, newlen - index );
				free( code );
				code = newcode;
				len = newlen;
				continue;
			}
		}


		index += linelen;
	}

	memcpy( deobbed, code, len );
	*outlen = len;

	return TRUE;

}


BOOL IsSameFunc( BYTE *orgfunc, BYTE *func2, int len1, int len2 )
{
	BOOL result = FALSE;
	t_disasm dd;
	t_disasm dd2;
	int linelen1;
	int linelen2;

	int index1 = 0;
	int index2 = 0;
	while( index1 < len1 && index2 < len2 )
	{
		linelen1 = Disasm( (char*)orgfunc + index1, len1 - index1, -5, &dd, DISASM_CODE );
		linelen2 = Disasm( (char*)func2 + index2, len2 - index2, -5, &dd2, DISASM_CODE );
		if( orgfunc[index1] == (BYTE)'\x90' )	// nop
		{
			index1 ++;
			continue;
		}
		else if( func2[index2] == (BYTE)'\x90' )	// nop
		{
			index2 ++;
			continue;
		}
		else if( orgfunc[index1] == (BYTE)'\xe8' )
		{
			if( func2[index2] != (BYTE)'\xe8' )
				return FALSE;

//			DWORD dst;
//			memcpy( &dst, func2 + index2 + 1, 4 );
//			if( dd.jmpconst != dst )
			if( dd.jmpconst != dd2.jmpconst )
				return FALSE;
		}
		else if( orgfunc[index1] == (BYTE)'\xe9' )
		{
			if( func2[index2] != (BYTE)'\xe9' )
				return FALSE;
		}
		else if( dd.cmdtype == C_JMC )
			;	// skip
		else if( orgfunc[index1] == (BYTE)'\x68' )	// push
		{
			if( func2[index2] != (BYTE)'\x68' )
				return FALSE;
		}
		else if( memcmp( dd.result, "XOR ", 4 ) == 0 && 
				 memcmp( dd.result + 4, dd.result + 8, 3 ) == 0 &&
				 memcmp( dd2.result, "SUB ", 4 ) == 0 && 
				 memcmp( dd2.result + 4, dd2.result + 8, 3 ) == 0 && 
				 memcmp( dd.result + 4, dd2.result + 4, 3 ) == 0 )	// xor eax,eax == sub eax,eax
		{
			;	// skip
		}
		else if( memcmp( dd.result, "XOR ", 4 ) == 0 && 
				 memcmp( dd.result + 4, dd.result + 8, 3 ) == 0 &&
				 memcmp( dd2.result, "MOV ", 4 ) == 0 && 
				 memcmp( dd2.result + 8, "0", 1 ) == 0 && 
				 memcmp( dd.result + 4, dd2.result + 4, 3 ) == 0 )	// xor eax,eax == mov eax,0
		{
			;	// skip
		}
		else
		{
			if( memcmp( orgfunc + index1, func2 + index2, linelen1 ) != 0 )
				return FALSE;
		}
		index1 += linelen1;
		index2 += linelen2;
	}

	return TRUE;
}






DWORD jmpcallto( BYTE *instr, DWORD eip )
{
	DWORD *tmp;
	t_disasm dd;

	BYTE tmp8;

	switch( instr[0] )
	{
	case '\xe8':
	case '\xe9':
		tmp = (DWORD*)(instr + 1);
		return eip + 5 + *tmp;
		break;
	case '\xeb':
		tmp8 = instr[1];
		return eip + 2 + (DWORD)tmp8;
		break;
	}
	Disasm( (char*)instr, 20, eip, &dd, DISASM_CODE );

	if( dd.cmdtype == C_JMP || 
		dd.cmdtype == C_JMC ||
		dd.cmdtype == C_CAL )
		return dd.jmpconst;

	return 0;
}

DWORD FindModule( DWORD pid, char *name, OPTIONAL OUT char *modpath )
{
	MODULEENTRY32 me = {0,};
	me.dwSize = sizeof(me);

	HANDLE hs = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid );
	if( hs == INVALID_HANDLE_VALUE )
		eg( "CreateToolhelp32Snapshot" );

	if( Module32First( hs, &me ) == FALSE )
		eg( "Module32First" );

	if( name == NULL ||
		name[0] == NULL )
	{
		if( modpath != NULL )
			strncpy( modpath, me.szExePath, MAX_PATH );
		return (DWORD)me.hModule;
	}

	do {
		if( stricmp( name, me.szModule ) == 0 )
		{
			CloseHandle( hs );
			if( modpath != NULL )
				strncpy( modpath, me.szExePath, MAX_PATH );
			return (DWORD)( me.hModule );
		}
	} while( Module32Next( hs, &me ) );

	CloseHandle( hs );
	return 0;
}

BOOL IsRedirected( DWORD pid, BYTE *code, OPTIONAL OUT DWORD *redirectedTo )
{
	char module[MAX_PATH];
	char name[MAX_PATH];
	strncpy( module, (char*)code, MAX_PATH );
	char *ptr;
	ptr = strchr( module, '.' );
	if( ptr == NULL )
		return FALSE;

	*ptr = NULL;
	strncpy( name, ptr + 1, MAX_PATH );


	if( strlen( name ) > 100 )
		return FALSE;
	strcat( module, ".dll" );
	DWORD modaddr = FindModule( pid, module, NULL );
	if( modaddr == 0 )
		return FALSE;

	if( redirectedTo != NULL )
	{
		DWORD tmp = (DWORD)LoadLibrary( module );
		if( tmp == 0 )
			return FALSE;

		*redirectedTo = (DWORD)( GetProcAddress( (HMODULE)tmp, name ) ) - tmp + modaddr;
	}

	return TRUE;
}

#define MAX_JCC		5
typedef struct apis
{
//	char name[MAX_PATH];
	DWORD addr;
	BOOL redirecting;
	DWORD redirectedTo;
	DWORD jcc[MAX_JCC];
	int numOfJcc;
	int codesize;
	BYTE *codedump;
}apis;

typedef struct dllinfo
{
	char name[MAX_PATH];
	DWORD loadedbase;
	apis *apilist;
	int numofapi;
	dllinfo *next;
}dllinfo;






BOOL CollectJccInfoProcess( DWORD pid, OUT dllinfo **info )
{
	*info = (dllinfo*)calloc( sizeof(dllinfo), 1 );
	dllinfo *cur = NULL;
	MODULEENTRY32 me = {0,};
	me.dwSize = sizeof(me);
	BYTE *code = (BYTE*)calloc( 0x3000, 1 );

	HANDLE hs = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid );
	if( hs == INVALID_HANDLE_VALUE )
		eg( "CreateToolhelp32Snapshot" );

	if( Module32First( hs, &me ) == FALSE )
		eg( "Module32First" );

	do {
		if( cur == NULL )
			cur = *info;
		else
		{
			cur->next = (dllinfo*)calloc( sizeof(dllinfo), 1 );
			cur = cur->next;
		}
		strncpy( cur->name, me.szModule, MAX_PATH );
		pework pedll;
		if( pedll.Open( me.szExePath ) == FALSE )
		{
			printf( "pework error : %s\n", me.szModule );
			continue;
		}

		cur->loadedbase = (DWORD)me.hModule;

		if( pedll.GetNH()->OptionalHeader.DataDirectory[0].VirtualAddress == 0 )
			continue;

		IMAGE_EXPORT_DIRECTORY export;
		if( rread2( pid, 
					//pedll.GetImageBase() + pedll.GetNH()->OptionalHeader.DataDirectory[0].VirtualAddress, 
					(DWORD)me.hModule + pedll.GetNH()->OptionalHeader.DataDirectory[0].VirtualAddress, 
					&export, 
					sizeof(export) ) == FALSE )
		{
			puts( "rread2" );
			continue;
		}

		cur->apilist = (apis*)calloc( sizeof(apis) * export.NumberOfFunctions, 1 );
		if( cur->apilist == NULL )
			eg( "calloc" );
		cur->numofapi = export.NumberOfFunctions;

		DWORD funcAddr;
		funcAddr = pedll.GetImageBase() + export.AddressOfFunctions;
//		DWORD nameAddr;
//		nameAddr = pedll.GetImageBase() + export.AddressOfNames;


		for( int i = 0; i < (int)export.NumberOfFunctions; i ++ )
		{
			DWORD tmp;
			rread2( pid, funcAddr + (i * 4), &tmp, 4 );
			tmp += cur->loadedbase;
			cur->apilist[i].addr = tmp;

			// find first jcc
			if( rread2( pid, cur->apilist[i].addr, code, 0x3000 ) == FALSE )
			{
				if( rread2( pid, cur->apilist[i].addr, code, 0x1000 ) == FALSE )
					continue;
			}
			int index = 0;
			DWORD redirectedTo;
			if( IsRedirected( pid, code, &redirectedTo ) == TRUE )
			{
				cur->apilist[i].redirecting = TRUE;
				cur->apilist[i].redirectedTo = redirectedTo;
				continue;
			}
			while( TRUE )
			{
				t_disasm dd = {0,};
				int len = Disasm( (char*)( code + index ), 20, cur->apilist[i].addr + index, &dd, DISASM_CODE );
				if( len == 0 )
				{
					printf( "disasm error : %s %08x (%08x + %x)\n", 
							cur->name, 
							cur->apilist[i].addr + index, 
							cur->apilist[i].addr, 
							index );
					return FALSE;
				}
				if( dd.cmdtype == C_JMC )
				{
					if( cur->apilist[i].numOfJcc < MAX_JCC )
						cur->apilist[i].jcc[cur->apilist[i].numOfJcc++] = dd.jmpconst;
					// break;
				}

				if( code[index] == (BYTE)'\xe8' )
				{
					memcpy( code + index + 1, &dd.jmpconst, 4 );
				}

				if( dd.cmdtype == C_RET )
				{
					// dump code
					cur->apilist[i].codesize = index + len;
					cur->apilist[i].codedump = (BYTE*)calloc( index + len, 1 );
					memcpy( cur->apilist[i].codedump, code, index + len );
					break;
				}
				index += len;
			}
		}

	} while( Module32Next( hs, &me ) );

	CloseHandle( hs );

	free( code );
	return TRUE;
}


typedef struct codegadget
{
	BYTE code[15];
	int len;
}codegadget;




BOOL FindByCodeDump( stack<codegadget *> codestack, dllinfo *info, OUT char *dllname, OUT DWORD *original_apiaddr )
{
	// compare cleaned code
	// merge code dump
	BYTE thiscode[0x200] = {0,};
	int thiscodeindex = 0;

	// invert stack
	stack<codegadget*> reversestack;
	int lines = codestack.size();
	for( int i = 0; i < lines; i ++ )
	{
		reversestack.push( codestack.top() );
		codestack.pop();
	}

	for( i = 0; i < lines; i ++ )
	{
		memcpy( thiscode + thiscodeindex, reversestack.top()->code, reversestack.top()->len );
		thiscodeindex += reversestack.top()->len;
		free( reversestack.top() );
		reversestack.pop();
	}

	// deob
	Deobfuscate( thiscode, thiscodeindex, thiscode, &thiscodeindex );


	// search for matching code
	dllinfo *cur = info;
	do {
		if( cur->apilist == NULL )
			continue;

		for( int i = 0; i < cur->numofapi; i ++ )
		{
			if( cur->apilist[i].redirecting == TRUE )
				continue;
			if( IsSameFunc( cur->apilist[i].codedump, thiscode, cur->apilist[i].codesize, thiscodeindex ) == TRUE )
			{
				// found
				*original_apiaddr = cur->apilist[i].addr;
				strncpy( dllname, cur->name, MAX_PATH );
				return TRUE;
			}
		}
	} while( cur = cur->next );

	// not found T_T
	return FALSE;
}




BOOL MatchAddrApi( DWORD pid, dllinfo *info, DWORD calladdr, OUT char *dllname, OUT DWORD *original_apiaddr )
{
	// check redirected api
	dllinfo *cur = info;
	do {
		if( cur->apilist == NULL )
			continue;

		for( int i = 0; cur->apilist[i].addr != 0; i ++ )
		{
			if( cur->apilist[i].redirectedTo == calladdr )
			{
				strncpy( dllname, cur->name, MAX_PATH );
				*original_apiaddr = cur->apilist[i].addr;
				return TRUE;
			}
		}
	} while( cur = cur->next );




	// check direct call to api
	cur = info;
	do {
		if( cur->apilist == NULL )
			continue;

		for( int i = 0; cur->apilist[i].addr != 0; i ++ )
		{
			if( cur->apilist[i].addr == calladdr )
			{
				strncpy( dllname, cur->name, MAX_PATH );
				*original_apiaddr = cur->apilist[i].addr;
				return TRUE;
			}
		}
	} while( cur = cur->next );





	// chase detoured address + compare cleaned instructions
	t_disasm dd;
	int len;
	DWORD cureip = calladdr;
	BYTE code[30];
	DWORD jccfound = 0;
	BYTE cleanedcode[1000] = {0,};

	// 코드 기록/비교를 위한 변수
	BOOL pop_expected = FALSE;
	int pushad_count = 0;
	stack<codegadget*> codestack;

	// debug
	mylog( "debug.txt", "\n0x%08x:", calladdr );
	while( TRUE )
	{
		BOOL shouldRecord = TRUE;
		if( rread2autosize( pid, cureip, code ) == FALSE )
			return FALSE;

		len = Disasm( (char*)code, 15, cureip, &dd, DISASM_CODE );
		if( len == 0 )
		{
			// shouldn't be here
			printf( "disasm 0 in addr %08x : \n", cureip );
			return FALSE;
		}

		// debug
		mylog( "debug.txt", "0x%08x : %s", cureip, dd.result );

		// if jmp, follow
		if( dd.cmdtype == C_JMP )
		{
			// for exception check
			if( memcmp( code + 2, "\x00\x00\x00", 3 ) != 0 )
			{
				if( codestack.size() < 3 )
					return FALSE;
				return FindByCodeDump( codestack, info, dllname, original_apiaddr );
			}
			cureip = dd.jmpconst;
			continue;
		}
		// if call, check if it's to a dll. check by rva... to be fixed
		else if( dd.cmdtype == C_CAL )
		{
			// skip indirect call
			//if( memcmp( code, "\xff\x15", 2 ) == 0 )
			if( code[0] == (BYTE)'\xff' )
			{
			}

			// direct call to dll?
			else if( memcmp( code + 2, "\x00\x00\x00", 3 ) != 0 )
			{
				// change to dst addr
				memcpy( code + 1, &dd.jmpconst, 4 );
			}
			else
			{
				// otherwise, follow the call - it's used as jmp
				if( pushad_count == 0 )
					pop_expected = TRUE;
				cureip = dd.jmpconst;
				continue;
			}
		}

		else if( strnicmp( dd.result, "xchg ", 5 ) == 0 )
		{
			codegadget *last = codestack.top();
			t_disasm lastdisasm;
			Disasm( (char*)( last->code ), last->len, 0, &lastdisasm, DISASM_CODE );			

			if( strnicmp( lastdisasm.result, "xchg ", 5 ) == 0 )
			{
				// compare registers
				if( strcmp( dd.result, lastdisasm.result ) == 0 )
				{
					codestack.pop();
					free( last );

					shouldRecord = FALSE;
				}
			}
			else
			{
			}
		}

		// if jcc, find match with this address
		else if( dd.cmdtype == C_JMC )
		{
			if( abs( (int)( dd.jmpconst - cureip ) ) < 0x100 )
			{
				// printf( "small jcc found : 0x%08x\n", cureip );
			}
			else
			{
				jccfound = dd.jmpconst;
				
				// find matching jcc
				cur = info;
				do {
					if( cur == NULL )
						break;

					if( cur->apilist == NULL )
						continue;

					for( int i = 0; i < cur->numofapi; i ++ )
					{
						for( int j = 0; j < cur->apilist[i].numOfJcc; j ++ )
						{
							if( cur->apilist[i].jcc[j] == jccfound )
							{
								strncpy( dllname, cur->name, MAX_PATH );
								*original_apiaddr = cur->apilist[i].addr;
								return TRUE;
							}
						}
					}
				} while( cur = cur->next );
			}
		}

		// if retn... the whole api is redirected
		else if( dd.cmdtype == C_RET )
		{
			// add last retn
			codegadget *toadd = (codegadget*)calloc( sizeof(codegadget), 1 );
			memcpy( toadd->code, code, len );
			toadd->len = len;
			codestack.push( toadd );

			if( FindByCodeDump( codestack, info, dllname, original_apiaddr ) == TRUE )
				return TRUE;
			break;
		}

		// pushad/popad control
		else if( code[0] == (BYTE)'\x60' )	// pushad
		{
			pushad_count ++;
			shouldRecord = FALSE;
		}
		else if( code[0] == (BYTE)'\x61' )	// popad
		{
			if( pushad_count == 0 )
			{
				// uh-oh
				printf( "popad is more than pushad!! 0x%08x : \n", calladdr );
				return FALSE;
			}
			pushad_count --;
			shouldRecord = FALSE;
		}
		else if( memcmp( code, "\x89\x2c\x24", 3 ) == 0 )
		{
			codegadget *last = codestack.top();
			if( last->code[0] == (BYTE)'\x55' )
			{
				shouldRecord = FALSE;
			}
		}


		// work with cleaned code.
		// only when pushad stat is 0
		if( pushad_count == 0 && shouldRecord == TRUE )
		{
			// ignore these codes
			if( code[0] == (BYTE)'\x9c' ||				// pushfd
				code[0] == (BYTE)'\x9d' ||				// popfd
				memcmp( code, "\x0f\x31", 2 ) == 0		// rdtsc
				)
			{
				cureip += len;
				continue;
			}

			// if pop, check there was a push
			else if( dd.cmdtype == C_POP )
			{
				codegadget *last = codestack.top();
				t_disasm lastdisasm;
				Disasm( (char*)last->code, last->len, 0, &lastdisasm, DISASM_CODE );
				if( lastdisasm.cmdtype == C_PSH )
				{
					free( last );
					codestack.pop();
					cureip += len;
					continue;
				}
				else if( pop_expected == TRUE )
				{
					// ignore this line
					pop_expected = FALSE;
					// unnecessary
					cureip += len;
					continue;
				}
			}

			codegadget *toadd = (codegadget*)calloc( sizeof(codegadget), 1 );
			memcpy( toadd->code, code, len );
			toadd->len = len;
			codestack.push( toadd );

		}

		cureip += len;
	}

	if( jccfound == 0 )
		return FALSE;


	// find matching jcc
	cur = info;
	do {
		if( cur == NULL )
			break;

		if( cur->apilist == NULL )
			continue;

		for( int i = 0; i < cur->numofapi; i ++ )
		{
			for( int j = 0; j < cur->apilist[i].numOfJcc; j ++ )
			{
				if( cur->apilist[i].jcc[j] == jccfound )
				{
					strncpy( dllname, cur->name, MAX_PATH );
					*original_apiaddr = cur->apilist[i].addr;
					return TRUE;
				}
			}
		}
	} while( cur = cur->next );

	return FALSE;
}


typedef enum redir_type
{
	REDTYPE_INDIRECTCALL = 1,
	REDTYPE_INDIRECTJMP,
	REDTYPE_MOV,
}redir_type;

typedef struct code_recorded
{
	DWORD codeaddr;
	char dllname[MAX_PATH];
	DWORD apiaddr;
	redir_type type;
	code_recorded *next;
}code_recorded;

typedef struct dll_recorded
{
	char dllname[MAX_PATH];
	DWORD apiaddr[3000];	// temporary...
	dll_recorded *next;
}dll_recorded;

BOOL RecordFoundApi( DWORD codeaddr, 
					 char *dll, 
					 DWORD apiaddr, 
					 redir_type type, 
					 code_recorded *coderec, 
					 dll_recorded *dllrec )
{
	// record code
	code_recorded *cur = coderec;

	do {
		if( codeaddr == cur->codeaddr )
			return TRUE;

		if( cur->next == NULL )
			break;
	} while( cur = cur->next );

	cur->next = (code_recorded*)calloc( sizeof(code_recorded), 1 );
	if( cur->next == NULL )
		eg( "calloc" );

//	cur = cur->next;

	strncpy( cur->dllname, dll, MAX_PATH );
	cur->codeaddr = codeaddr;
	cur->apiaddr = apiaddr;
	cur->type = type;

	// record dll .. i'm gettin bored & tired...
	dll_recorded *cur2 = dllrec;
	BOOL apifound = FALSE;
	BOOL dllfound = FALSE;
	do {
		if( cur2->next == NULL )
			break;

		if( strcmp( cur2->dllname, dll ) == 0 )
		{
			dllfound = TRUE;
			for( int i = 0; cur2->apiaddr[i] != 0; i ++ )
			{
				if( cur2->apiaddr[i] == apiaddr )
				{
					apifound = TRUE;
					return TRUE;
					break;
				}
			}
			// add api
			cur2->apiaddr[i] = apiaddr;
			return TRUE;
		}
	} while( cur2 = cur2->next );

	if( dllfound == FALSE )
	{
		// add dll
		cur2->next = (dll_recorded *)calloc( sizeof(dll_recorded), 1 );
		if( cur2->next == NULL )
			eg( "calloc" );

//		cur2 = cur2->next;

		strncpy( cur2->dllname, dll, MAX_PATH );
		cur2->apiaddr[0] = apiaddr;

		return TRUE;
	}

	return TRUE;
}



BOOL FindRedirectionData( DWORD rediraddr, code_recorded *codes, OUT char *dllname, OUT DWORD *apiaddr )
{
	code_recorded *cur = codes;
	do{
		if( cur->codeaddr == 0 )
			break;
		if( cur->codeaddr == rediraddr )
		{
			// found
			strncpy( dllname, cur->dllname, MAX_PATH );
			*apiaddr = cur->apiaddr;
			return TRUE;
		}
	}while( cur = cur->next );

	return FALSE;
}


BOOL IsXrefPresent( DWORD pid, DWORD codeaddr, DWORD codelen, DWORD tofind )
{
	BOOL result = FALSE;
	BYTE *code = NULL;
	DWORD index = 0;
	t_disasm dd = {0,};

	code = (BYTE*)calloc( codelen, 1 );
	if( code == NULL )
		return FALSE;

	rread2( pid, codeaddr, code, codelen );

	while( index < codelen )
	{
		int len = Disasm( (char*)code + index, 20, codeaddr + index, &dd, DISASM_DATA );

		if( dd.jmpconst == tofind )
		{
			result = TRUE;
			break;
		}

		index += len;
	}

	free( code );

	return result;
}



BOOL healiat( DWORD pid, DWORD targetimage, char *targetpath )
{
	pework pe;
	if( pe.Open( targetpath ) == FALSE )
		eg( "pe.open" );

	// get code area
	DWORD start,end,size;
	start = targetimage + pe.GetSH(0)->VirtualAddress;
	size = pe.GetSH(0)->Misc.VirtualSize;
	end = start + size;

	// collect jcc information
	dllinfo *info;
	printf( "collecting exports/jcc information from target..." );
	CollectJccInfoProcess( pid, &info );
	puts( "done" );


	// set up datas
	code_recorded *codes = (code_recorded*)calloc( sizeof(code_recorded), 1 );
	dll_recorded *dlls = (dll_recorded*)calloc( sizeof(dll_recorded), 1 );
	if( codes == NULL || dlls == NULL )
		eg( "calloc" );


	// read code dump
	BYTE *code;
	code = (BYTE*)calloc( size, 1 );
	if( code == NULL )
		eg( "calloc" );

	if( rread2( pid, start, code, size ) == FALSE )
		eg( "rread2" );

	printf( "investigating redirections...\n" );
	int index = 0;
	int len = 0;
	int progress = 0;
	while( ( index + len ) < (int)size - 10 )
	{
		char dllname[MAX_PATH] = {0,};
		DWORD apiaddr;
		t_disasm dd;

		if( progress + 0x1000 < index )
		{
			progress += 0x1000;
			printf( "progress...0x%08x\n", progress );
		}

		// find call out of image
		index += len;
		len = Disasm( (char*)( code + index ), 20, start + index, &dd, DISASM_CODE );
		if( len == 0 )
		{
			printf( "disasm error : %08x\n", (start + index) );
			break;
		}

		// if it's CALL and goes out of image
		if( code[index] == (BYTE)'\xe8' && 
			( dd.jmpconst < start || dd.jmpconst > end ) )
		{
			// if it's not with a nop
			BOOL nopisahead = FALSE;
			if( code[index + 5] == (BYTE)'\x90' )
				nopisahead = FALSE;
			else if( index != 0 && code[index-1] == (BYTE)'\x90' )
				nopisahead = TRUE;
			else
			{
				// leave log 
				// printf( "not with a nop. check addr : %08x\n", start + index );
				continue;
			}

			// matching api found?
			// is jmpconst already analyzed?
			if( FindRedirectionData( dd.jmpconst, codes, dllname, &apiaddr ) == FALSE && 
				// check direct / detoured
				MatchAddrApi( pid, info, dd.jmpconst, dllname, &apiaddr ) == FALSE )
			{
				// log failure
				// printf( "redirection not handled : %08x\n", start + index + ( nopisahead ? -1 : 0 ) );
			}
			else
			{
				if( dllname[0] == NULL )
				{
					puts( "dll name not set!" );
					break;
				}
				// register apiaddr and offset
				if( nopisahead == TRUE )
					RecordFoundApi( start + index - 1, dllname, apiaddr, REDTYPE_INDIRECTCALL, codes, dlls );
				else
					RecordFoundApi( start + index, dllname, apiaddr, REDTYPE_INDIRECTCALL, codes, dlls );
			}
		}

		// if it's CALL and goes out of image
		if( code[index] == (BYTE)'\xe9' && 
			( dd.jmpconst < start || dd.jmpconst > end ) )
		{
			// first, check api
			if( FindRedirectionData( dd.jmpconst, codes, dllname, &apiaddr ) == FALSE && 
				MatchAddrApi( pid, info, dd.jmpconst, dllname, &apiaddr ) == FALSE )
			{
				// log failure
				// printf( "redirection not handled : %08x\n", start + index );
			}
			else
			{
				DWORD recaddr;
				// check xrefs
				if( IsXrefPresent( pid, start, size, dd.ip ) == TRUE )
				{
					recaddr = dd.ip;
					len ++;
				}
				else if( IsXrefPresent( pid, start, size, dd.ip - 1 ) == TRUE )
					recaddr = dd.ip - 1;
				else
					continue;


				// record
				if( dllname[0] == NULL )
				{
					puts( "dll name not set!" );
					break;
				}

				// register apiaddr and offset
				RecordFoundApi( recaddr, dllname, apiaddr, REDTYPE_INDIRECTJMP, codes, dlls );
			}
		}

		// if it's mov reg [imm32] and it's being called
		if( memcmp( dd.result, "MOV ", 4 ) == 0 &&
			dd.adrconst != 0 && 
			dd.indexed == 0 && 
			dd.immconst == 0 &&
			dd.cmdtype == C_CMD &&
			dd.memtype == 4 )
		{
			int tmpindex = index + len;
			int tmplen = 0;
			t_disasm tmpdasm = {0,};

			// get target register
			char targetreg[4] = {0,};
			memcpy( targetreg, dd.result + 4, 3 );

			DWORD readcodeaddr = 0;

			// check it's being called for... say 40 lines
			for( int i = 0; i < 40; i ++ )
			{
				tmplen = Disasm( (char*)code + tmpindex, 20, 0, &tmpdasm, DISASM_CODE );
				if( memcmp( tmpdasm.result, "CALL ", 5 ) == 0 )
				{
					if( memcmp( tmpdasm.result + 5, targetreg, 3 ) == 0 )
					{
						// found
						// read the imm32 addr and that's codeaddr
						if( rread2( pid, dd.adrconst, &readcodeaddr, 4 ) == FALSE )
							break;

						if( FindRedirectionData( readcodeaddr, codes, dllname, &apiaddr ) == FALSE &&
							MatchAddrApi( pid, info, readcodeaddr, dllname, &apiaddr ) == FALSE )
						{
							// log failure
							// printf( "redirection not handled : %08x\n", start + index );
							break;
						}

						RecordFoundApi( start + index, dllname, apiaddr, REDTYPE_MOV, codes, dlls );
						break;
					}
				}
				else if( strstr( tmpdasm.result, targetreg ) != NULL )
					break;

				tmpindex += tmplen;
			}
		}
	}

	// collection done. now patch
	// find a spot for new iat
	// count size
	int iatsize = 0;
	dll_recorded *cur = dlls;
	do {
		if( cur->dllname[0] == NULL )
			break;

		for( int i = 0; cur->apiaddr[i] != 0; i ++ )
			iatsize += 4;

		// space for null dword
		iatsize += 4;
	} while( cur = cur->next );

	printf( "size of IAT needed : 0x%08x\n", iatsize );

	DWORD iataddr = end - iatsize;

	// write
	cur = dlls;
	index = 0;
	do {
		for( int i = 0; cur->apiaddr[i] != 0; i ++, index += 4 )
		{
			rwrite2( pid, iataddr + index, (void*)&( cur->apiaddr[i] ), 4 );

			// search corresponding code
			code_recorded *curcode = codes;
			do {
				if( curcode->codeaddr == 0 )
					break;
				if( curcode->apiaddr == cur->apiaddr[i] )
				{
					if( curcode->type == REDTYPE_INDIRECTCALL )
					{
						// patch to ff 15 xxxxxxxx
						rwrite2( pid, curcode->codeaddr, "\xff\x15", 2 );
						DWORD tmp = iataddr + index;
						rwrite2( pid, curcode->codeaddr + 2, &tmp, 4 );
					}
					else if( curcode->type == REDTYPE_INDIRECTJMP )
					{
						// patch to ff 25 xxxxxxxx
						rwrite2( pid, curcode->codeaddr, "\xff\x25", 2 );
						DWORD tmp = iataddr + index;
						rwrite2( pid, curcode->codeaddr + 2, &tmp, 4 );
					}
					else if( curcode->type == REDTYPE_MOV )
					{
						t_disasm dd = {0,};
						int linelen = 0;
						BYTE linecode[20] = {0,};
						DWORD tmp = iataddr + index;
						rread2( pid, curcode->codeaddr, linecode, 20 );
						linelen = Disasm( (char*)linecode, 20, curcode->codeaddr, &dd, DISASM_CODE );
						if( linelen == 0 )
							continue;
						memcpy( linecode + linelen - 4, &tmp, 4 );
						rwrite2( pid, curcode->codeaddr, linecode, linelen );
					}
				}
			} while( curcode = curcode->next );
		}
		rwrite2( pid, iataddr + index, "\x00\x00\x00\x00", 4 );
		index += 4;
	} while( cur = cur->next );

	puts( "done." );

	return TRUE;
}

int main( int argc, char **argv )
{
	DWORD pid;

	puts  ( "=================================" );
	puts  ( " healiat. IAT recovery tool" );
	puts  ( " use it to wipe API Redirection" );
	puts  ( " your target must be running" );
	puts  ( " http://code.google.com/p/healiat" );
	puts  ( " http://jz.pe.kr" );
	puts  ( "=================================" );
	printf( " usage : healiat.exe pid module\n", argv[0] );
	if( argc < 2 )
	{
		char tmp[MAX_PATH];
		printf( " target pid : " );
		gets( tmp );
		pid = atoi( tmp );
	}
	else
		pid = atoi( argv[1] );
	if( pid == 0 )
	{
		puts( "wrong pid" );
		return 0;
	}

	RisePriv();

	char *module;
	if( argc < 3 )
	{
		module = (char*)calloc( MAX_PATH, 1 );
		printf( " target module ( ignore for main exe ) : " );
		gets( module );			// i know
	}
	else
		module = argv[2];

	char modpath[MAX_PATH];

	DWORD loadedbase = FindModule( pid, module, modpath );

/*	while( TRUE )
	{
		if( FindProcessWithName( "Themida.exe", &pid ) )
			break;
		Sleep( 1000 );
	}

	DWORD loadedbase = FindModule( pid, "Themida.exe", modpath );
*/
	if( loadedbase == 0 )
		eg( "FindModule" );

	if( healiat( pid, loadedbase, modpath ) == TRUE )
		puts( "use ImportREC to finish your unpack." );
	else
		puts( "healiat failed for some reason... :(" );


	return 0;
}
