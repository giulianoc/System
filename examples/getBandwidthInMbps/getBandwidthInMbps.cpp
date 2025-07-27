/*
 Copyright (C) Giuliano Catrambone (giulianocatrambone@gmail.com)

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
#include <iostream>

using namespace std;

int main()
{
	map<string, pair<uint64_t, uint64_t>> bandwidth = System::getBandwidthInMbps();

	for (const auto &[iface, stats] : bandwidth)
	{
		auto [receivedBytes, transmittedBytes] = stats;
		cout << "Iface: " << iface << ", receivedBytes: " << receivedBytes << ", transmittedBytes: " << transmittedBytes << endl;
	}

	return 0;
}
