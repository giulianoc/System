/*
 Copyright (C) Giuliano Catrambone (giuliano.catrambone@catrasoftware.it)

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either
 version 2 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 Commercial use other than under the terms of the GNU General Public
 License is allowed only after express negotiation of conditions
 with the authors.
*/

#include "System.h"
#include <chrono>
#include <cstring>
#include <deque>
#include <stdexcept>
#include <tuple>
#include <utility>
#ifdef WIN32
// #include <process.h>
#include <UserEnv.h>
#include <Winsock2.h>
#else
#include <sys/utsname.h>
#include <unistd.h>
#endif
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fstream>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <charconv>

/*
Copiati da Xenon
BOOL GetOSVersion(char *pOS)
{
#ifdef WIN32
	char *platform=NULL, *type=NULL,ver[80];
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;
	ver[0] = 0;

	// Try calling GetVersionEx using the OSVERSIONINFOEX structure.
	//
	// If that fails, try using the OSVERSIONINFO structure.
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	if( (bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) != 0 )
	{
	  // If OSVERSIONINFOEX doesn't work, try OSVERSIONINFO.

	  osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
	  if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) )
	  {
		  return mlmGetOSVersionOld(pOS);
	  }
	}

	switch (osvi.dwPlatformId)
	{
	  case VER_PLATFORM_WIN32_NT:

	  // Test for the product.

		 if ( osvi.dwMajorVersion <= 4 )
			 platform = "Windows NT";
		 else if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 )
			 platform = "Windows 2000";
		 else if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 )
			 platform = "Windows XP";
		 else if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2 )
			 platform = "Windows 2003";
		 else
			 platform = "Windows 2003 Future";

	  // Test for product type.
#ifndef _WIN32_WCE
		 if( bOsVersionInfoEx )
		 {
			if ( osvi.wProductType == VER_NT_WORKSTATION )
			{
	// For Wisler Edition
//			   if( osvi.wSuiteMask & VER_SUITE_PERSONAL )
//				  type = "Personal ";
//			   else
				  type = "Professional ";
			}
			else if ( osvi.wProductType == VER_NT_SERVER )
			{
			   if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
				  type = "DataCenter";
			   else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
				  type = "Enterprise";
			   else
				  type = "Server ";
			}
			else if ( osvi.wProductType == VER_NT_DOMAIN_CONTROLLER )
			{
				type = "Domain Controller";
			}
		 }
		 else
#endif //_WIN32_WCE
		 {
			HKEY hKey;
			char szProductType[80];
			DWORD dwBufLen;

			RegOpenKeyEx( HKEY_LOCAL_MACHINE,
			   "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
			   0, KEY_QUERY_VALUE, &hKey );
			RegQueryValueEx( hKey, "ProductType", NULL, NULL,
			   (LPBYTE) szProductType, &dwBufLen);
			RegCloseKey( hKey );
			if ( lstrcmpi( "WINNT", szProductType) == 0 )
			   type = "Workstation ";
			if ( lstrcmpi( "SERVERNT", szProductType) == 0 )
			   type = "Server ";
		 }

	  // Display version, service pack (if any), and build number.

		 if ( osvi.dwMajorVersion <= 4 )
		 {
			sprintf (ver,"version %d.%d %s Build %d",
			   osvi.dwMajorVersion,
			   osvi.dwMinorVersion,
			   osvi.szCSDVersion,
			   osvi.dwBuildNumber & 0xFFFF);
		 }
		 else
		 {
			sprintf (ver, "%s Build %d",
			   osvi.szCSDVersion,
			   osvi.dwBuildNumber & 0xFFFF);
		 }

		 //sprintf(retstr,"%s%s%s",platform,type,ver);
		 sprintf(pOS,"%s %s",platform,type);
		 //sprintf(retstr,"%s",platform);
		 break;

	  case VER_PLATFORM_WIN32_WINDOWS:

		 if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0)
		 {
			 platform = "Microsoft Windows 95";
			 if ( osvi.szCSDVersion[1] == 'C' )
				type = "OSR2 ";
		 }

		 if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 10)
		 {
			 platform = "Microsoft Windows 98";
			 if ( osvi.szCSDVersion[1] == 'A' )
				type = "SE ";
		 }

		 if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 90)
		 {
			 platform = "Microsoft Windows Me";
			 type = "";
		 }

		 //sprintf(retstr,"%s%s",platform,type);
		 sprintf(pOS,"%s",platform);
		 break;

	  case VER_PLATFORM_WIN32s:

		 platform = "Microsoft Win32s";
		 sprintf(pOS,"%s",platform);
		 break;
#ifdef _WIN32_WCE
	  case VER_PLATFORM_WIN32_CE:
		 platform = "Microsoft WinCE";
		  // Display version, service pack (if any), and build number.
		 sprintf (ver,"version %d.%d %s (Build %d)",
			   osvi.dwMajorVersion,
			   osvi.dwMinorVersion,
			   osvi.szCSDVersion,
			   osvi.dwBuildNumber & 0xFFFF);

		 sprintf(pOS,"%s%s",platform,ver);
		 break;
#endif // _WIN32_WCE
	  default:
		sprintf(pOS,"Unknown Platform");
	}

#else //Solaris & Linux all
	struct utsname sname;
	if(uname(&sname) < 0)
	{
		sprintf(pOS,"Unknown Platform");
		return FALSE;
	}

	// printf("sysname - (%s)\n", sname.sysname);
	// printf("nodename - (%s)\n", sname.nodename);
	// printf("release - (%s)\n", sname.release);
	// printf("version - (%s)\n", sname.version);
	// printf("machine - (%s)\n", sname.machine);

	sprintf(pOS,"%s %s %s", sname.sysname,sname.release, sname.machine);
#endif
	return TRUE;

}


BOOL GetOSVersionOld(char *pOS)
{
#ifdef WIN32
	DWORD dwWindowsMajorVersion, dwWindowsMinorVersion;
	DWORD dwBuild, dwVersion;

	dwVersion = GetVersion();

	// Get the Windows version.

	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	dwWindowsMinorVersion =  (DWORD)(HIBYTE(LOWORD(dwVersion)));

	// Get the build number.

	if (dwVersion < 0x80000000)              // Windows NT/2000, Whistler
	{
		if (dwWindowsMajorVersion < 2)      // Error
		{
			dwBuild = (DWORD)(HIWORD(dwVersion));
			strcpy(pOS,"Windows_NT_3.51_below");
		}
		else if (dwWindowsMajorVersion == 3)      // Windows NT 3.51
		{
			dwBuild = (DWORD)(HIWORD(dwVersion));
			strcpy(pOS,"Windows_NT_3.51");
		}
		else if (dwWindowsMajorVersion == 4)      // Windows NT
		{
			dwBuild = (DWORD)(HIWORD(dwVersion));
			strcpy(pOS,"Windows_NT_4.0");
		}
		else if (dwWindowsMajorVersion == 5)      // Windows 2000/Whisler
		{
			dwBuild = (DWORD)(HIWORD(dwVersion));
			if (dwWindowsMinorVersion == 0 )
				strcpy(pOS,"Windows_2000");
			else if (dwWindowsMinorVersion == 1 )
				strcpy(pOS,"Windows_XP");
			else if (dwWindowsMinorVersion == 2 )
				strcpy(pOS,"Windows_2003");
			else
				strcpy(pOS,"Windows_2003_Future_Version");
		}
		else
		{
			dwBuild = (DWORD)(HIWORD(dwVersion));
			strcpy(pOS,"Windows_2000_Future");
		}
	}
	else
	{
		if (dwWindowsMajorVersion < 4)      // Win32s
		{
			dwBuild = (DWORD)(HIWORD(dwVersion) & ~0x8000);
			strcpy(pOS,"Windows_3.1_Win32s");
		}
		else                                     // Windows 95/98/Me
		{
			dwBuild =  0;
			strcpy(pOS,"Windows_95_98_Me");
		}
	}
#endif
	return TRUE;
}

char *GetCPUInfo()
{
	char *retstr;
#ifdef WIN32

	SYSTEM_INFO si;

	GetSystemInfo(&si);

	switch (si.dwProcessorType)
	{
	case PROCESSOR_INTEL_386 :
		retstr = "INTEL_386";
		break;
	case PROCESSOR_INTEL_486 :
		retstr = "INTEL_486";
		break;
	case PROCESSOR_INTEL_PENTIUM :
		retstr = "INTEL_PENTIUM";
		break;
#ifdef _WIN32_WCE
//	case PROCESSOR_MIPS_R3000 :
//		retstr = "MIPS_R3000";
//		break;
	case PROCESSOR_MIPS_R4000 :
		retstr = "MIPS_R4000";
		break;
	case PROCESSOR_HITACHI_SH3 :
		retstr = "HITACHI_SH3";
		break;
	case PROCESSOR_HITACHI_SH4 :
		retstr = "HITACHI_SH4";
		break;
	case PROCESSOR_PPC_403 :
		retstr = "PPC_403";
		break;
//	case PROCESSOR_PPC_821 :
//		retstr = "PPC_821";
//		break;
	case PROCESSOR_STRONGARM :
		retstr = "STRONGARM";
		break;
	case PROCESSOR_ARM720 :
		retstr = "ARM720";
		break;
#endif //_WIN32_WCE
	default:
		retstr = "UNKNOWN";
	}
#elif defined(SOLARIS)
	char genericBuffer[1024] ;
	memset( genericBuffer, 0, sizeof(genericBuffer) );

	if(sysinfo(SI_ARCHITECTURE, genericBuffer, 1024) < 0)
	{
		retstr = "ERROR";
	}

	retstr = genericBuffer;

#elif defined(LINUX)
	struct utsname sname;
	if(uname(&sname) < 0)
	{
		sprintf(retstr,"Unknown Platform");
		return FALSE;
	}

	// printf("sysname - (%s)\n", sname.sysname);
	// printf("nodename - (%s)\n", sname.nodename);
	// printf("release - (%s)\n", sname.release);
	// printf("version - (%s)\n", sname.version);
	// printf("machine - (%s)\n", sname.machine);

	retstr = sname.machine;

#endif
	return retstr;
}

int GetProcessorNum()
{
#ifdef WIN32
	SYSTEM_INFO SystemInfo;
	GetSystemInfo(&SystemInfo);
	return SystemInfo.dwNumberOfProcessors;
#elif LINUX
	return get_nprocs();
#elif defined(SOLARIS)
	long nProcessorOnline 		= sysconf(_SC_NPROCESSORS_ONLN);
	return nProcessorOnline;
#else
	return 0;
#endif
}

BOOL GetLocalHostName(char *name)
{
	bool bRet = TRUE;
#ifdef WIN32
	DWORD dwLevel = 102;
	LPWKSTA_INFO_102 pBuf = NULL;
	NET_API_STATUS nStatus;
//	LPTSTR pszServerName = NULL;
//	char tmp[256];
	// Call the NetWkstaGetInfo function, specifying level 102.
	//
	nStatus = NetWkstaGetInfo(NULL,
							 dwLevel,
							 (LPBYTE *)&pBuf);
	//
	// If the call is successful,
	//  print the workstation data.
	//
	if (nStatus == NERR_Success)
	{
	//      TRACE(_T("\n\tPlatform: %d\n"), pBuf->wki102_platform_id);
	  //wctomb(tmp,pBuf->wki102_computername);
	 // mbstowcs(tmp,(char*)pBuf->wki102_computername,256);
	//	  TRACE(_T("\tName:     %ls\n"), pBuf->wki102_computername);
	  sprintf(name,_T("%s"), pBuf->wki102_computername);
	//      TRACE(_T("\tVersion:  %d.%d\n"), pBuf->wki102_ver_major,
	//                                  pBuf->wki102_ver_minor);
	//      TRACE(_T("\tDomain:   %ls\n"), pBuf->wki102_langroup);
	//      TRACE(_T("\tLan Root: %ls\n"), pBuf->wki102_lanroot);
	//      TRACE(_T("\t# Logged On Users: %d\n"), pBuf->wki102_logged_on_users);
	}
	//
	// Otherwise, indicate the system error.
	//
	else
	{
		//fprintf(stderr, "A system error has occurred: %d\n", nStatus);
		sprintf(name, "UNKNOWN(A system error has occurred: %d)\n", nStatus);
		//strcpy(name,"UNKNOWN(");
		bRet = FALSE;
	}

	//
	// Free the allocated memory.
	//
	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
#else
	struct utsname sname;
	if(uname(&sname) < 0)
	{
		sprintf(name,"Unknown hostname");
		return FALSE;
	}

	sprintf(name,"%s", sname.nodename);
#endif

	return bRet;
}
*/

std::string System::hostName()
{
// host name initialization
#ifdef WIN32
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_WSASTARTUP_FAILED);

		return err;
	}

	if (gethostname(pHostName, ulHostNameBufferLength) == -1)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_GETHOSTNAME_FAILED);

		if (WSACleanup())
		{
			Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_WSACLEANUP_FAILED);
		}

		return err;
	}

	if (WSACleanup())
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_WSACLEANUP_FAILED);

		return err;
	}
#else
	struct utsname unUtsname;

	if (uname(&unUtsname) == -1)
		throw std::runtime_error("uname failed");

	return unUtsname.nodename;
#endif
}

std::string System::homeDirectory()
{
// host name initialization
#ifdef WIN32
	{
		HANDLE hToken;
		TCHAR szHomeDirBuf[MAX_PATH] = {0};
		DWORD dwBufSize;

		hToken = 0;
		dwBufSize = MAX_PATH;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) == 0)
		{
			Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_OPENPROCESSTOKEN_FAILED, 1, (long)GetLastError());

			return err;
		}

		if (GetUserProfileDirectory(hToken, szHomeDirBuf, &dwBufSize) == FALSE)
		{
			Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_GETUSERPROFILEDIRECTORY_FAILED, 1, (long)GetLastError());

			return err;
		}

		CloseHandle(hToken);

		// TCHAR is a Microsoft-specific typedef for either
		// char or wchar_t (a wide character).
		// Conversion to char depends on which of these it actually is.
		// If TCHAR is actually a char, then you can do a simple cast,
		// but if it is truly a wchar_t, you'll need a routine
		// to convert between character sets.
		if (sizeof(TCHAR) != sizeof(wchar_t))
		{
			strcpy(pHomeDirectory, (const char *)szHomeDirBuf);
		}
		else
		{
			if (WideCharToMultiByte(CP_ACP, 0, (WCHAR *)szHomeDirBuf, -1, pHomeDirectory, ulBufferLength, NULL, NULL) == 0)
			{
				Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_WIDECHARTOMULTIBYTE_FAILED, 1, (long)GetLastError());

				return err;
			}
		}
	}
#else
	{
		const char *pHome = getenv("HOME");
		if (pHome == (const char *)NULL)
			throw std::runtime_error("HOME env var not defined");

		return pHome;
	}
#endif
}

// Per rendere il calcolo piu stabile possiamo:
// - aumentare l’intervallo tra le letture a 5 o 10 secondi per ridurre la sensibilità al traffico "a raffiche"
// - eseguire letture ogni secondo ma calcolando la media su, ad esempio, gli ultimi 5 secondi:
std::map<std::string, std::pair<uint64_t, uint64_t>>
System::getAvgAndPeakBandwidthInBytes(std::map<std::string, std::pair<uint64_t, uint64_t>> &peakInBytes, int intervalSeconds, int windowSize)
{
	// Per ogni interfaccia, manteniamo una coda degli ultimi N valori
	std::map<std::string, std::vector<std::pair<double, double>>> history;

	for (int windowIndex = 0; windowIndex < windowSize; windowIndex++)
	{
		auto current = getBandwidthInBytes(); // bytes/sec

		for (auto &[iface, usage] : current)
		{
			auto &[rx, tx] = usage;

			// Inserisci nuovo valore in coda
			history[iface].push_back({rx, tx});
		}

		std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
	}

	// da double arrotondiamo a uint64_t
	std::map<std::string, std::pair<uint64_t, uint64_t>> avgBandwidthInBytes;
	peakInBytes.clear();

	// Calcola la media e picco
	for (auto &[iface, traffic] : history)
	{
		double peakRx = 0, peakTx = 0;
		double totalRx = 0, totalTx = 0;

		for (auto &[r, t] : traffic)
		{
			if (r > peakRx)
				peakRx = r;
			if (t > peakTx)
				peakTx = t;

			totalRx += r;
			totalTx += t;
		}

		double avgRx = totalRx / traffic.size();
		double avgTx = totalTx / traffic.size();

		avgBandwidthInBytes[iface] = std::make_pair(avgRx, avgTx);
		peakInBytes[iface] = std::make_pair(peakRx, peakTx);
	}

	return avgBandwidthInBytes;
}

std::map<std::string, std::pair<double, double>> System::getBandwidthInBytes()
{
	std::map<std::string, std::pair<double, double>> bandwidthInMbps;

	// lettura iniziale
	auto before = getNetworkUsage();
	auto t1 = std::chrono::steady_clock::now();

	std::this_thread::sleep_for(std::chrono::seconds(1));

	// lettura finale
	auto after = getNetworkUsage();
	auto t2 = std::chrono::steady_clock::now();

	// Calcola il tempo trascorso in secondi per evitare imprecisioni dello sleep (come double)
	std::chrono::duration<double> elapsed = t2 - t1;
	double elapsedSeconds = elapsed.count();

	for (const auto &[iface, afterStats] : after)
	{
		// non real interface
		if (iface == "lo" || iface.starts_with("docker"))
			continue;

		auto it = before.find(iface);
		if (it != before.end())
		{
			auto [receivedBytesBefore, transmittedBytesBefore] = it->second;
			auto [receivedBytesAfter, transmittedBytesAfter] = afterStats;

			bandwidthInMbps[iface] = std::make_pair(
				(receivedBytesAfter - receivedBytesBefore) / elapsedSeconds, (transmittedBytesAfter - transmittedBytesBefore) / elapsedSeconds
			);
		}
	}

	return bandwidthInMbps;
}

std::map<std::string, std::pair<uint64_t, uint64_t>> System::getNetworkUsage()
{
	std::ifstream net("/proc/net/dev");
	std::string line;
	std::map<std::string, std::pair<uint64_t, uint64_t>> usage; // iface -> (rx, tx)

	while (getline(net, line))
	{
		// line: Interfaccia: bytes    packets errs drop fifo frame compressed multicast
		// es: eth0: 12345678 1000 0 0 0 0 0 0 9876543 2000 0 0 0 0 0 0
		if (line.find(":") == std::string::npos)
			continue;

		std::string iface;
		uint64_t receivedBytes, transmittedBytes;

		std::istringstream iss(line);
		getline(iss, iface, ':');
		iface.erase(0, iface.find_first_not_of(' '));

		iss >> receivedBytes;
		// skips next 7 fields
		for (int i = 0; i < 7; ++i)
		{
			uint64_t tmp;
			iss >> tmp;
		}
		iss >> transmittedBytes;
		usage[iface] = std::make_pair(receivedBytes, transmittedBytes);
	}

	return usage;
}

std::vector<std::tuple<std::string, std::string, bool, std::string>> System::getActiveNetworkInterface()
{
	std::vector<std::tuple<std::string, std::string, bool, std::string>> activeNetworkInterfaces;

	struct ifaddrs *ifaddr;
	char addrStr[INET6_ADDRSTRLEN];

	if (getifaddrs(&ifaddr) == -1)
	{
		int err = errno;
		throw std::runtime_error(std::format("getifad failed, {}", err, strerror(err)));
	}

	for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
			continue;

		// Salta il loopback
		if (ifa->ifa_flags & IFF_LOOPBACK)
			continue;

		// Mostra solo interfacce attive
		if (!(ifa->ifa_flags & IFF_UP))
			continue;

		int family = ifa->ifa_addr->sa_family;

		if (family == AF_INET)
		{ // IPv4
			const struct sockaddr_in *sa = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
			inet_ntop(AF_INET, &(sa->sin_addr), addrStr, INET_ADDRSTRLEN);
			activeNetworkInterfaces.emplace_back(ifa->ifa_name, "IPv4", isPrivateIPv4(addrStr),addrStr);
		}
		else if (family == AF_INET6)
		{ // IPv6
			const auto *sa6 = reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
			inet_ntop(AF_INET6, &(sa6->sin6_addr), addrStr, INET6_ADDRSTRLEN);
			activeNetworkInterfaces.emplace_back(ifa->ifa_name, "IPv6", isPrivateIPv6(sa6->sin6_addr), addrStr);
		}
	}

	freeifaddrs(ifaddr);

	return activeNetworkInterfaces;
}

bool System::isPrivateIPv4(const std::string& ip)
{
	int nums[4];
	const char* begin = ip.data();
	const char* end   = ip.data() + ip.size();

	for (int i = 0; i < 4; ++i)
	{
		// convert number
		auto [ptr, ec] = std::from_chars(begin, end, nums[i]);
		if (ec != std::errc() || nums[i] < 0 || nums[i] > 255)
			return false;

		// move ptr after the number
		begin = ptr;

		// expect dot (except last)
		if (i < 3) {
			if (begin >= end || *begin != '.')
				return false;
			begin++;
		}
	}

	// validate exact consumption
	if (begin != end)
		return false;

	const int a = nums[0];
	const int b = nums[1];

	// 10.0.0.0/8
	if (a == 10)
		return true;

	// 172.16.0.0/12
	if (a == 172 && b >= 16 && b <= 31)
		return true;

	// 192.168.0.0/16
	if (a == 192 && b == 168)
		return true;

	return false;
}

bool System::isPrivateIPv6(const in6_addr& addr)
{
	// Primo byte dell'indirizzo IPv6
	uint8_t b0 = addr.s6_addr[0];

	// fc00::/7  → 0b1111110x (== 0xFC o 0xFD)
	if ((b0 & 0xFE) == 0xFC)
		return true;

	return false;
}
