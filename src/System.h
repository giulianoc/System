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

#pragma once

#include <map>
#include <string>
#include <vector>
#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <netinet/in.h>
	#include <arpa/inet.h>
#endif

using namespace std;

/**
	The System class is a collection of static methods just
	to hide the differences to retrieve information between
	different operative system.
*/
class System
{
  public:
	/*
	metodi completi ma non ancora pubblicati
	BOOL GetOSVersion(char *pOS)
	char *GetCPUInfo()
	int GetProcessorNum()
	BOOL GetLocalHostName(char *name)
	*/

	/**
			Return the host name of the machine.
	*/
	static string hostName();

	static string homeDirectory();

	static map<string, pair<double, double>> getBandwidthInBytes();

	static map<string, pair<uint64_t, uint64_t>>
	getAvgAndPeakBandwidthInBytes(map<string, pair<uint64_t, uint64_t>> &peakInBytes, int intervalSeconds = 1, int windowSize = 5);

	// interface name, type, private, IP
	static vector<tuple<string, string, bool, string>> getActiveNetworkInterface();

  private:
	static map<string, pair<uint64_t, uint64_t>> getNetworkUsage();
	static bool isPrivateIPv4(const string& ip);
	static bool isPrivateIPv6(const in6_addr& addr);
};
