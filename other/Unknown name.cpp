/**********************************************************************************
First Growtopia Private Server made with ENet.
Copyright (C) 2018  Growtopia Noobs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
**********************************************************************************/


#include "stdafx.h"
#include <iostream>

#include "enet/enet.h"
#include <string>
#include <windows.h>
#include <vector>
#include <sstream>
#include <chrono>
#include <fstream>
#include "json.hpp"
#include "bcrypt.h"
#include "crypt_blowfish/crypt_gensalt.c"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.c"
#include "crypt_blowfish/wrapper.c"
#include "bcrypt.c"
#include <conio.h>
#include <thread> // TODO
#include <mutex> // TODO

using namespace std;
using json = nlohmann::json;

//#define TOTAL_LOG
#define REGISTRATION

ENetHost * server;
int cId = 1;
BYTE* itemsDat = 0;
int itemsDatSize = 0;

/***bcrypt***/

bool verifyPassword(string password, string hash) {
	int ret;

	ret = bcrypt_checkpw(password.c_str(), hash.c_str());
	assert(ret != -1);

	return !ret;
}

string hashPassword(string password) {
	char salt[BCRYPT_HASHSIZE];
	char hash[BCRYPT_HASHSIZE];
	int ret;

	ret = bcrypt_gensalt(12, salt);
	assert(ret == 0);
	ret = bcrypt_hashpw(password.c_str(), salt, hash);
	assert(ret == 0);
	return hash;
}

/***bcrypt**/

void sendData(ENetPeer* peer, int num, char* data, int len)
{
	/* Create a reliable packet of size 7 containing "packet\0" */
	ENetPacket * packet = enet_packet_create(0,
		len + 5,
		ENET_PACKET_FLAG_RELIABLE);
	/* Extend the packet so and append the string "foo", so it now */
	/* contains "packetfoo\0"                                      */
	/* Send the packet to the peer over channel id 0. */
	/* One could also broadcast the packet by         */
	/* enet_host_broadcast (host, 0, packet);         */
	memcpy(packet->data, &num, 4);
	if (data != NULL)
	{
		memcpy(packet->data + 4, data, len);
	}
	char zero = 0;
	memcpy(packet->data + 4 + len, &zero, 1);
	enet_peer_send(peer, 0, packet);
	enet_host_flush(server);
}

int getPacketId(char* data)
{
	return *data;
}

char* getPacketData(char* data)
{
	return data + 4;
}

string text_encode(char* text)
{
	string ret = "";
	while (text[0] != 0)
	{
		switch (text[0])
		{
		case '\n':
			ret += "\\n";
			break;
		case '\t':
			ret += "\\t";
			break;
		case '\b':
			ret += "\\b";
			break;
		case '\\':
			ret += "\\\\";
			break;
		case '\r':
			ret += "\\r";
			break;
		default:
			ret += text[0];
			break;
		}
		text++;
	}
	return ret;
}

struct Admin {
	string username;
	string password;
	int level = 0;
	long long int lastSB = 0;
	long long int lastWarp = 0;
	long long int lastSpawn = 0;
	long long int lastasb = 0;
};

vector<Admin> admins;

int ch2n(char x)
{
	switch (x)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'A':
		return 10;
	case 'B':
		return 11;
	case 'C':
		return 12;
	case 'D':
		return 13;
	case 'E':
		return 14;
	case 'F':
		return 15;
	default:
		break;
	}
}


char* GetTextPointerFromPacket(ENetPacket* packet)
{
	char zero = 0;
	memcpy(packet->data + packet->dataLength - 1, &zero, 1);
	return (char*)(packet->data + 4);
}

BYTE* GetStructPointerFromTankPacket(ENetPacket* packet)
{
	unsigned int packetLenght = packet->dataLength;
	BYTE* result = NULL;
	if (packetLenght >= 0x3C)
	{
		BYTE* packetData = packet->data;
		result = packetData + 4;
		if (*(BYTE*)(packetData + 16) & 8)
		{
			if (packetLenght < *(int*)(packetData + 56) + 60)
			{
				cout << "Packet too small for extended packet to be valid" << endl;
				cout << "Sizeof float is 4.  TankUpdatePacket size: 56" << endl;
				result = 0;
			}
		}
		else
		{
			int zero = 0;
			memcpy(packetData + 56, &zero, 4);
		}
	}
	return result;
}

int GetMessageTypeFromPacket(ENetPacket* packet)
{
	int result;

	if (packet->dataLength > 3u)
	{
		result = *(packet->data);
	}
	else
	{
		cout << "Bad packet length, ignoring message" << endl;
		result = 0;
	}
	return result;
}


vector<string> explode(const string &delimiter, const string &str)
{
	vector<string> arr;

	int strleng = str.length();
	int delleng = delimiter.length();
	if (delleng == 0)
		return arr;//no change

	int i = 0;
	int k = 0;
	while (i < strleng)
	{
		int j = 0;
		while (i + j < strleng && j < delleng && str[i + j] == delimiter[j])
			j++;
		if (j == delleng)//found delimiter
		{
			arr.push_back(str.substr(k, i - k));
			i += delleng;
			k = i;
		}
		else
		{
			i++;
		}
	}
	arr.push_back(str.substr(k, i - k));
	return arr;
}

struct GamePacket
{
	BYTE* data;
	int len;
	int indexes;
};


GamePacket appendFloat(GamePacket p, float val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 1;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 8];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 3;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	p.len = p.len + 2 + 8;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2, float val3)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 12];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 4;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	memcpy(n + p.len + 10, &val3, 4);
	p.len = p.len + 2 + 12;
	p.indexes++;
	return p;
}

GamePacket appendInt(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 9;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendIntx(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 5;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendString(GamePacket p, string str)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + str.length() + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 2;
	int sLen = str.length();
	memcpy(n + p.len + 2, &sLen, 4);
	memcpy(n + p.len + 6, str.c_str(), sLen);
	p.len = p.len + 2 + str.length() + 4;
	p.indexes++;
	return p;
}

GamePacket createPacket()
{
	BYTE* data = new BYTE[61];
	string asdf = "0400000001000000FFFFFFFF00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(data + (i / 2), &x, 1);
		if (asdf.length() > 61 * 2) throw 0;
	}
	GamePacket packet;
	packet.data = data;
	packet.len = 61;
	packet.indexes = 0;
	return packet;
}

GamePacket packetEnd(GamePacket p)
{
	BYTE* n = new BYTE[p.len + 1];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	char zero = 0;
	memcpy(p.data + p.len, &zero, 1);
	p.len += 1;
	//*(int*)(p.data + 52) = p.len;
	*(int*)(p.data + 56) = p.indexes;//p.len-60;//p.indexes;
	*(BYTE*)(p.data + 60) = p.indexes;
	//*(p.data + 57) = p.indexes;
	return p;
}

struct InventoryItem {
	__int16 itemID;
	__int8 itemCount;
};

struct PlayerInventory {
	vector<InventoryItem> items;
	int inventorySize = 250;
};

#define cloth0 cloth_hair
#define cloth1 cloth_shirt
#define cloth2 cloth_pants
#define cloth3 cloth_feet
#define cloth4 cloth_face
#define cloth5 cloth_hand
#define cloth6 cloth_back
#define cloth7 cloth_mask
#define cloth8 cloth_necklace 
#define cloth9 cloth_ances
vector <string> test1;
vector<string>test123;

// guild role
vector<string>guildmem;
vector<string>guildelder;
vector<string>guildco;


struct PlayerInfo {
	bool isIn = false;
	int netID;
	bool haveGrowId = false;
	string tankIDName = "";
	string tankIDPass = "";
	string requestedName = "";
	string rawName = "";
	string displayName = "";
	string Chatname = "";
	string lastMsger = "";
	string lastMsgerTrue = "";
	string lastMsgWorld = "";
	string invisname = "";
	string lastInfoTrue = "";
	string lastInfo = "";
	string lastInfoWorld = "";
	string lastsbworld = "";
	vector<string>friendinfo;
	int guildBg = 0;
	int guildFg = 0;
	string guildStatement = "";
	string guildLeader = "";

	vector <string> guildmatelist;
	vector<string>guildMembers;
	string lastgm = "";
	string lastgmname = "";
	string lastgmworld = "";
	string guildlast = "";
	string lastfriend = "";
	string lastFrn = "";
	string lastFrnName = "";
	string lastFrnWorld = "";
	string country = "";
	string wkid = "";
	string metaip = "";
	string hash2 = "";
	string macaddress = "";
	string gameversion = "";
	string rid = "";
	string hash = "";
	int guildlevel = 0;
	int guildexp = 0;


	bool isinvited = false;

	string createGuildName = "";
	string createGuildStatement = "";
	string createGuildFlagBg = "";
	string createGuildFlagFg = "";

	string guild = "";
	bool joinguild = false;
	int adminLevel = 0;
	string currentWorld = "EXIT";
	bool radio = true;
	int x;
	int y;
	int isonline = 0;
	bool isRotatedLeft = false;
	int lastdropitemcount = 0;
	int lastdropitem = 0;
	bool isUpdating = false;
	bool joinClothesUpdated = false;
	int entereffect = 0;
	int cloth_hair = 0; // 0
	int cloth_shirt = 0; // 1
	int cloth_pants = 0; // 2
	int cloth_feet = 0; // 3
	int cloth_face = 0; // 4
	int cloth_hand = 0; // 5
	int cloth_back = 0; // 6
	int cloth_mask = 0; // 7
	int cloth_necklace = 0; // 8
	int cloth_ances = 0;

	int blockbroken = 0; //block broken
	int level = 1;
	int gem = 0;
	int ban = 0;
	int mute = 0;

	int guildflagblock = 0;
	int guildflagbackground = 0;
	string friendlist = "";

	int puncheffect = 8421376;
	/*8421376*/

	int statecode = 0;

	int isMod = 0;


	bool canWalkInBlocks = false; // 1
	bool canDoubleJump = false; // 2
	bool cantsay = false; // 8192
	bool noHands = false; // 8
	bool noEyes = false; // 16
	bool noBody = false; // 32 
	bool devilHorns = false; // 642
	bool goldenHalo = false; // 128
	bool isFrozen = false; // 2048
	bool isCursed = false; // 4096
	bool isDuctaped = false; // 8192
	bool haveCigar = false; // 16384
	bool isShining = false; // 32768
	bool isZombie = false; // 65536
	bool isHitByLava = false; // 131072
	bool haveHauntedShadows = false; // 262144
	bool haveGeigerRadiation = false; // 524288
	bool haveReflector = false; // 1048576
	bool isEgged = false; // 2097152
	bool havePineappleFloag = false; // 4194304
	bool haveFlyingPineapple = false; // 8388608
	bool haveSuperSupporterName = false; // 16777216
	bool haveSupperPineapple = false; // 33554432
	bool isGod = false; // 1


	bool isInvisible = false; // 4



							  //bool 
	int skinColor = 0x8295C3FF;

	PlayerInventory inventory;

	long long int lastSB = 0;
	long long int lastWarp = 0;
	long long int lastSpin = 0;

};


int getState(PlayerInfo* info) {
	int val = 0;
	val |= info->canWalkInBlocks << 0;
	val |= info->canDoubleJump << 1;
	val |= info->cantsay << 13;
	val |= info->noHands << 3;
	val |= info->noEyes << 4;
	val |= info->noBody << 5;

	val |= info->goldenHalo << 7;
	val |= info->isFrozen << 8;
	val |= info->isCursed << 12;
	val |= info->isDuctaped << 10;
	return val;
}


struct WorldItem {
	__int16 foreground = 0;
	__int16 background = 0;
	int breakLevel = 0;
	long long int breakTime = 0;
	bool water = false;
	bool fire = false;
	bool glue = false;
	bool red = false;
	bool green = false;
	bool blue = false;

};

struct WorldInfo {
	int width = 100;
	int height = 60;
	string name = "TEST";
	WorldItem* items;
	string owner = "";
	string worldaccess = "";
	vector<string> accessworld;
	bool isPublic = false;
	int weather = 0;
};

WorldInfo generateWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.width = width;
	world.height = height;

	world.items = new WorldItem[world.width*world.height];
	for (int i = 0; i < world.width*world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50))
			world.items[i].foreground = 10;
		else if (i >= 3700 && i < 5400)
		{
			world.items[i].foreground = 2;
		}
		else if (i >= 5400) {
			world.items[i].foreground = 8;
		}
		if (i >= 3700)
			world.items[i].background = 14;
		if (i == 3650)
			world.items[i].foreground = 6;

		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}
WorldInfo generatemarsWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.width = width;
	world.height = height;

	world.items = new WorldItem[world.width*world.height];
	for (int i = 0; i < world.width*world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50))
			world.items[i].foreground = 10;
		else if (i >= 3700 && i < 5400)
		{
			world.items[i].foreground = 4;
		}
		else if (i >= 5400) {
			world.items[i].foreground = 8;
		}
		if (i >= 3700)
			world.items[i].background = 14;
		if (i == 3650)
			world.items[i].foreground = 6;

		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}

class PlayerDB {
public:
	static string getProperName(string name);
	static string PlayerDB::fixColors(string text);
	static int playerLogin(ENetPeer* peer, string username, string password);

	static int playerRegister(string username, string password);

	static int guildRegister(ENetPeer* peer, string guildName, string guildStatement, string guildFlagfg, string guildFlagbg);
};

string PlayerDB::getProperName(string name) {
	string newS;
	for (char c : name) newS += (c >= 'A' && c <= 'Z') ? c - ('A' - 'a') : c;
	string ret;
	for (int i = 0; i < newS.length(); i++)
	{
		if (newS[i] == '`') i++; else ret += newS[i];
	}
	string ret2;
	for (char c : ret) if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ret2 += c;
	return ret2;
}

string PlayerDB::fixColors(string text) {
	string ret = "";
	int colorLevel = 0;
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] == '`')
		{
			ret += text[i];
			if (i + 1 < text.length())
				ret += text[i + 1];


			if (i + 1 < text.length() && text[i + 1] == '`')
			{
				colorLevel--;
			}
			else {
				colorLevel++;
			}
			i++;
		}
		else {
			ret += text[i];
		}
	}
	for (int i = 0; i < colorLevel; i++) {
		ret += "``";
	}
	for (int i = 0; i > colorLevel; i--) {
		ret += "`w";
	}
	return ret;
}
void banlogin(ENetPeer* peer) {
	string text = "action|log\nmsg|`4Sorry, this account (`5" + ((PlayerInfo*)(peer->data))->rawName + "`4) has been suspended.\n";
	string text3 = "action|logon_fail\n";
	string dc = "https://discord.gg/tAkEksz";
	string url = "action|set_url\nurl|" + dc + "\nlabel|Join discord\n";


	BYTE* data = new BYTE[5 + text.length()];
	BYTE* data3 = new BYTE[5 + text3.length()];
	BYTE* dataurl = new BYTE[5 + url.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);

	memcpy(dataurl, &type, 4);
	memcpy(dataurl + 4, url.c_str(), url.length());
	memcpy(dataurl + 4 + url.length(), &zero, 1);

	memcpy(data3, &type, 4);
	memcpy(data3 + 4, text3.c_str(), text3.length());
	memcpy(data3 + 4 + text3.length(), &zero, 1);

	ENetPacket* p = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p);
	ENetPacket* p3 = enet_packet_create(dataurl,
		5 + url.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p3);
	ENetPacket* p2 = enet_packet_create(data3,
		5 + text3.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p2);

	delete data;
	delete dataurl;
	delete data3;


}
void loginfailed(ENetPeer* peer) {
	string text = "action|log\nmsg|`4Unable to log on: ``that `wGrowID ``doesn't seem valid or the password is wrong`w. ``if you dont have one click `wCancel``, un-check `w'i have a GrowID'``, then click Connect``.\n";
	string text3 = "action|logon_fail\n";
	string dc = "https://discord.gg/VMwPHnW";
	string url = "action|set_url\nurl|" + dc + "\nlabel|Join discord for Help\n";


	BYTE* data = new BYTE[5 + text.length()];
	BYTE* data3 = new BYTE[5 + text3.length()];
	BYTE* dataurl = new BYTE[5 + url.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);

	memcpy(dataurl, &type, 4);
	memcpy(dataurl + 4, url.c_str(), url.length());
	memcpy(dataurl + 4 + url.length(), &zero, 1);

	memcpy(data3, &type, 4);
	memcpy(data3 + 4, text3.c_str(), text3.length());
	memcpy(data3 + 4 + text3.length(), &zero, 1);

	ENetPacket* p = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p);
	ENetPacket* p3 = enet_packet_create(dataurl,
		5 + url.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p3);
	ENetPacket* p2 = enet_packet_create(data3,
		5 + text3.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p2);

	delete data;
	delete dataurl;
	delete data3;


}
int PlayerDB::playerLogin(ENetPeer* peer, string username, string password) {
	std::ifstream ifs("players/" + PlayerDB::getProperName(username) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		string pss = j["password"];
		if (verifyPassword(password, pss)) {
			ENetPeer * currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (currentPeer == peer)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(username))
				{
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Someone else logged into this account!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete p.data;
					}
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Someone else was logged into this account! He was kicked out now."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					//enet_host_flush(server);
					enet_peer_disconnect_later(currentPeer, 0);
				}
			}
			return 1;
		}
		else {
			return -1;
		}
	}
	else {
		return -2;
	}
}
int PlayerDB::guildRegister(ENetPeer* peer, string guildName, string guildStatement, string guildFlagfg, string guildFlagbg) {
	if (guildName.find(" ") != string::npos || guildName.find(".") != string::npos || guildName.find(",") != string::npos || guildName.find("@") != string::npos || guildName.find("[") != string::npos || guildName.find("]") != string::npos || guildName.find("#") != string::npos || guildName.find("<") != string::npos || guildName.find(">") != string::npos || guildName.find(":") != string::npos || guildName.find("{") != string::npos || guildName.find("}") != string::npos || guildName.find("|") != string::npos || guildName.find("+") != string::npos || guildName.find("_") != string::npos || guildName.find("~") != string::npos || guildName.find("-") != string::npos || guildName.find("!") != string::npos || guildName.find("$") != string::npos || guildName.find("%") != string::npos || guildName.find("^") != string::npos || guildName.find("&") != string::npos || guildName.find("`") != string::npos || guildName.find("*") != string::npos || guildName.find("(") != string::npos || guildName.find(")") != string::npos || guildName.find("=") != string::npos || guildName.find("'") != string::npos || guildName.find(";") != string::npos || guildName.find("/") != string::npos) {
		return -1;
	}

	if (guildName.length() < 3) {
		return -2;
	}
	if (guildName.length() > 15) {
		return -3;
	}
	int fg;
	int bg;

	try {
		fg = stoi(guildFlagfg);
	}
	catch (std::invalid_argument& e) {
		return -6;
	}
	try {
		bg = stoi(guildFlagbg);
	}
	catch (std::invalid_argument& e) {
		return -5;
	}
	if (guildFlagbg.length() > 4) {
		return -7;
	}
	if (guildFlagfg.length() > 4) {
		return -8;
	}

	string fixedguildName = PlayerDB::getProperName(guildName);

	std::ifstream ifs("guilds/" + fixedguildName + ".json");
	if (ifs.is_open()) {
		return -4;
	}


	/*std::ofstream o("guilds/" + fixedguildName + ".json");
	if (!o.is_open()) {
	cout << GetLastError() << endl;
	_getch();
	}

	json j;

	//  Guild Detail
	j["GuildName"] = guildName;
	j["GuildStatement"] = guildStatement;
	j["GuildWorld"] = ((PlayerInfo*)(peer->data))->currentWorld;

	//  Guild Level
	j["GuildLevel"] = 0;
	j["GuildExp"] = 0;

	// Guild Leader
	j["Leader"] = ((PlayerInfo*)(peer->data))->rawName;


	// Guild Flag
	j["foregroundflag"] = 0;
	j["backgroundflag"] = 0;


	// Role
	vector<string>guildmember;
	vector<string>guildelder;
	vector<string>guildco;

	j["CoLeader"] = guildelder;
	j["ElderLeader"] = guildco;
	j["Member"] = guildmem;

	o << j << std::endl; */
	return 1;
}

int PlayerDB::playerRegister(string username, string password) {
	username = PlayerDB::getProperName(username);
	if (username.length() < 3) return -2;
	std::ifstream ifs("players/" + username + ".json");
	if (ifs.is_open()) {
		return -1;
	}

	std::ofstream o("players/" + username + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	json j;
	PlayerInfo pinfo;
	j["username"] = username;
	j["password"] = hashPassword(password);
	j["adminLevel"] = 0;
	j["ClothBack"] = 0;
	j["ClothHand"] = 0;
	j["ClothFace"] = 0;
	j["ClothShirt"] = 0;
	j["ClothPants"] = 0;
	j["ClothNeck"] = 0;
	j["ClothHair"] = 0;
	j["ClothFeet"] = 0;
	j["ClothMask"] = 0;
	j["ClothAnces"] = 0;
	j["Level"] = 0;
	j["Skin"] = 0x8295C3FF;
	j["isMuted"] = 0;
	j["exp"] = 0;
	j["isBanned"] = 0;
	j["puncheffect"] = 8421376;
	vector<string>test123;
	j["friends"] = test123;
	j["entereffect"] = 0;
	j["gem"] = 0;
	j["gems"] = 0;
	j["friend"] = "";
	j["guild"] = "";
	j["joinguild"] = false;
	/*json friendlists = json::array();

	{
	json friendlist;
	friendlist[1] = "";
	friendlist[2] = "";
	friendlists.push_back(friendlist);
	}
	j["friend"] = friendlists;*/

	o << j << std::endl;
	return 1;
}


struct AWorld {
	WorldInfo* ptr;
	WorldInfo info;
	int id;
};

class WorldDB {
public:
	WorldInfo get(string name);
	AWorld get2(string name);
	void flush(WorldInfo info);
	void flush2(AWorld info);
	void save(AWorld info);
	void saveAll();
	void saveRedundant();

	vector<WorldInfo> getRandomWorlds();
	WorldDB();
private:
	vector<WorldInfo> worlds;

};

WorldDB::WorldDB() {
	// Constructor
}

string getStrUpper(string txt) {
	string ret;
	for (char c : txt) ret += toupper(c);
	return ret;
}

AWorld WorldDB::get2(string name) {
	if (worlds.size() > 20) {
#ifdef TOTAL_LOG
		cout << "Saving redundant worlds!" << endl;
#endif
		saveRedundant();
#ifdef TOTAL_LOG
		cout << "Redundant worlds are saved!" << endl;
#endif
	}
	AWorld ret;
	name = getStrUpper(name);
	if (name.length() < 1) throw 1; // too short name
	for (char c : name) {
		if ((c<'A' || c>'Z') && (c<'0' || c>'9'))
			throw 2; // wrong name
	}
	if (name == "EXIT") {
		throw 3;
	}
	for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			ret.id = i;
			ret.info = worlds.at(i);
			ret.ptr = &worlds.at(i);
			return ret;
		}

	}
	std::ifstream ifs("worlds/" + name + ".json");
	if (ifs.is_open()) {

		json j;
		ifs >> j;
		WorldInfo info;
		vector<string> worldacs;


		for (int i = 0; i < j["accessworld"].size(); i++) {
			worldacs.push_back(j["accessworld"][i]);
		}
		//vector<string>worldaccess;
		info.name = j["name"];

		info.width = j["width"];
		info.height = j["height"];
		info.owner = j["owner"];
		info.isPublic = j["isPublic"];
		info.weather = j["weather"];
		info.worldaccess = j["worldaccess"];
		info.accessworld = worldacs;

		json tiles = j["tiles"];

		int square = info.width*info.height;
		info.items = new WorldItem[square];
		for (int i = 0; i < square; i++) {
			info.items[i].foreground = tiles[i]["fg"];
			info.items[i].background = tiles[i]["bg"];
		}
		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	else {
		WorldInfo info = generateWorld(name, 100, 60);

		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	throw 1;
}

WorldInfo WorldDB::get(string name) {

	return this->get2(name).info;
}

void WorldDB::flush(WorldInfo info)
{
	std::ofstream o("worlds/" + info.name + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
	}
	json j;


	j["name"] = info.name;
	j["width"] = info.width;
	j["height"] = info.height;
	j["owner"] = info.owner;
	j["isPublic"] = info.isPublic;
	j["weather"] = info.weather;
	j["worldaccess"] = info.worldaccess;


	j["accessworld"] = info.accessworld;


	json tiles = json::array();
	int square = info.width*info.height;

	for (int i = 0; i < square; i++)
	{
		json tile;
		tile["fg"] = info.items[i].foreground;
		tile["bg"] = info.items[i].background;
		tiles.push_back(tile);
	}
	j["tiles"] = tiles;
	o << j << std::endl;
}

void WorldDB::flush2(AWorld info)
{
	this->flush(info.info);
}

void WorldDB::save(AWorld info)
{
	flush2(info);
	delete info.info.items;
	worlds.erase(worlds.begin() + info.id);
}

void WorldDB::saveAll()
{
	for (int i = 0; i < worlds.size(); i++) {
		flush(worlds.at(i));
		delete worlds.at(i).items;
	}
	worlds.clear();
}

vector<WorldInfo> WorldDB::getRandomWorlds() {
	vector<WorldInfo> ret;
	for (int i = 0; i < ((worlds.size() < 10) ? worlds.size() : 10); i++)
	{ // load first four worlds, it is excepted that they are special
		ret.push_back(worlds.at(i));
	}
	// and lets get up to 6 random
	if (worlds.size() > 4) {
		for (int j = 0; j < 6; j++)
		{
			bool isPossible = true;
			WorldInfo world = worlds.at(rand() % (worlds.size() - 4));
			for (int i = 0; i < ret.size(); i++)
			{
				if (world.name == ret.at(i).name || world.name == "EXIT")
				{
					isPossible = false;
				}
			}
			if (isPossible)
				ret.push_back(world);
		}
	}
	return ret;
}

void WorldDB::saveRedundant()
{
	for (int i = 4; i < worlds.size(); i++) {
		bool canBeFree = true;
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == worlds.at(i).name)
				canBeFree = false;
		}
		if (canBeFree)
		{
			flush(worlds.at(i));
			delete worlds.at(i).items;
			worlds.erase(worlds.begin() + i);
			i--;
		}
	}
}

//WorldInfo world;
// vector<WorldInfo> worlds;
WorldDB worldDB;


void saveAllPlayers()
{
	cout << "Saving player..." << endl;

}
void saveAllWorlds() // atexit hack plz fix
{

	worldDB.saveAll();

	cout << "Worlds saved!" << endl;


}

WorldInfo* getPlyersWorld(ENetPeer* peer)
{
	try {
		return worldDB.get2(((PlayerInfo*)(peer->data))->currentWorld).ptr;
	}
	catch (int e) {
		return NULL;
	}
}

struct PlayerMoving {
	int packetType;
	int netID;
	float x;
	float y;
	int characterState;
	int plantingTree;
	float XSpeed;
	float YSpeed;
	int punchX;
	int punchY;

};


enum ClothTypes {
	HAIR,
	SHIRT,
	PANTS,
	FEET,
	FACE,
	HAND,
	BACK,
	MASK,
	NECKLACE,
	NONE
};

enum BlockTypes {
	FOREGROUND,
	BACKGROUND,
	SEED,
	PAIN_BLOCK,
	BEDROCK,
	MAIN_DOOR,
	SIGN,
	DOOR,
	CLOTHING,
	FIST,

	UNKNOWN
};

struct ItemDefinition {
	int id;
	string name;
	int rarity;
	int breakHits;
	int growTime;
	ClothTypes clothType;
	BlockTypes blockType;
	string description = "Nothing to see.";
};

vector<ItemDefinition> itemDefs;

struct DroppedItem { // TODO
	int id;
	int uid;
	int count;
};

vector<DroppedItem> droppedItems;

ItemDefinition getItemDef(int id)
{
	if (id < itemDefs.size() && id > -1)
		return itemDefs.at(id);
	/*for (int i = 0; i < itemDefs.size(); i++)
	{
	if (id == itemDefs.at(i).id)
	{
	return itemDefs.at(i);
	}
	}*/
	throw 0;
	return itemDefs.at(0);
}
/*ItemDefinition getItemDef2(string blockname)
{
if (blockname == "");
return itemDefs.at(id);
/*for (int i = 0; i < itemDefs.size(); i++)
{
if (id == itemDefs.at(i).id)
{
return itemDefs.at(i);
}
}
throw 0;
return itemDefs.at(0);
} */
void craftItemDescriptions() {
	int current = -1;
	std::ifstream infile("Descriptions.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 3 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			if (atoi(ex[0].c_str()) + 1 < itemDefs.size())
			{
				itemDefs.at(atoi(ex[0].c_str())).description = ex[1];
				if (!(atoi(ex[0].c_str()) % 2))
					itemDefs.at(atoi(ex[0].c_str()) + 1).description = "This is tree.";
			}
		}
	}
}

void loadNews() {
	std::ifstream infile("news.txt");
	if (!infile) {
		cout << "Unable to open file";
		// terminate with error
	}
}
void buildItemsDatabase()
{
	int current = -1;
	std::ifstream infile("CoreData.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 8 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			def.id = atoi(ex[0].c_str());
			def.name = ex[1];
			def.rarity = atoi(ex[2].c_str());
			string bt = ex[4];
			if (bt == "Foreground_Block") {
				def.blockType = BlockTypes::FOREGROUND;
			}
			else if (bt == "Seed") {
				def.blockType = BlockTypes::SEED;
			}
			else if (bt == "Pain_Block") {
				def.blockType = BlockTypes::PAIN_BLOCK;
			}
			else if (bt == "Main_Door") {
				def.blockType = BlockTypes::MAIN_DOOR;
			}
			else if (bt == "Bedrock") {
				def.blockType = BlockTypes::BEDROCK;
			}
			else if (bt == "Door") {
				def.blockType = BlockTypes::DOOR;
			}
			else if (bt == "Fist") {
				def.blockType = BlockTypes::FIST;
			}
			else if (bt == "Sign") {
				def.blockType = BlockTypes::SIGN;
			}
			else if (bt == "Background_Block") {
				def.blockType = BlockTypes::BACKGROUND;
			}

			else {
				def.blockType = BlockTypes::UNKNOWN;
			}
			def.breakHits = atoi(ex[7].c_str());
			def.growTime = atoi(ex[8].c_str());
			string cl = ex[9];
			if (cl == "None") {
				def.clothType = ClothTypes::NONE;
			}
			else if (cl == "Hat") {
				def.clothType = ClothTypes::HAIR;
			}
			else if (cl == "Shirt") {
				def.clothType = ClothTypes::SHIRT;
			}
			else if (cl == "Pants") {
				def.clothType = ClothTypes::PANTS;
			}
			else if (cl == "Feet") {
				def.clothType = ClothTypes::FEET;
			}
			else if (cl == "Face") {
				def.clothType = ClothTypes::FACE;
			}
			else if (cl == "Hand") {
				def.clothType = ClothTypes::HAND;
			}
			else if (cl == "Back") {
				def.clothType = ClothTypes::BACK;
			}
			else if (cl == "Hair") {
				def.clothType = ClothTypes::MASK;
			}
			else if (cl == "Chest") {
				def.clothType = ClothTypes::NECKLACE;
			}
			else {
				def.clothType = ClothTypes::NONE;
			}

			if (++current != def.id)
			{
				cout << "Critical error! Unordered database at item " << std::to_string(current) << "/" << std::to_string(def.id) << "!" << endl;
			}

			itemDefs.push_back(def);
		}
	}
	craftItemDescriptions();
}

void addAdmin(string username, string password, int level)
{


	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);


}

int getAdminLevel(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level;
		}
	}
	return 0;
}

bool canSB(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level > 199) {
			using namespace std::chrono;
			if (admin.lastSB + 1 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level == 999)
			{
				admins[i].lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				return true;
			}
			else {
				return false;
			}
		}
	}
	return false;
}
bool isvip(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level > 99) {
			return true;
		}
	}
	return false;
}

bool canClear(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level > 0;
		}
	}
	return false;
}

bool isSuperAdmin(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level > 998) {
			using namespace std::chrono;
			if (admin.lastSpawn + 450000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level == 999)
			{
				admins[i].lastSpawn = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				return true;
			}
			else {
				return false;
			}
		}
	}
	return false;
}
bool isOwner(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1337) {
			return true;
		}
	}
	return false;
}

bool canban(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level >1199) {
			return true;
		}
	}
	return false;
}
bool isHere(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}

void sendInventory(ENetPeer* currentPeer, PlayerInventory inventory)
{
	string asdf2 = "0400000009A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000000000000000";
	int inventoryLen = inventory.items.size();
	int packetLen = (asdf2.length() / 2) + (inventoryLen * 4) + 4;
	BYTE* data2 = new BYTE[packetLen];
	for (int i = 0; i < asdf2.length(); i += 2)
	{
		char x = ch2n(asdf2[i]);
		x = x << 4;
		x += ch2n(asdf2[i + 1]);
		memcpy(data2 + (i / 2), &x, 1);
	}
	int endianInvVal = _byteswap_ulong(inventoryLen);
	memcpy(data2 + (asdf2.length() / 2) - 4, &endianInvVal, 4);
	endianInvVal = _byteswap_ulong(inventory.inventorySize);
	memcpy(data2 + (asdf2.length() / 2) - 8, &endianInvVal, 4);
	int val = 0;
	for (int i = 0; i < inventoryLen; i++)
	{
		val = 0;
		val |= inventory.items.at(i).itemID;
		val |= inventory.items.at(i).itemCount << 16;
		val &= 0x00FFFFFF;
		val |= 0x00 << 24;
		memcpy(data2 + (i * 4) + (asdf2.length() / 2), &val, 4);
	}
	ENetPacket * packet3 = enet_packet_create(data2,
		packetLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(currentPeer, 0, packet3);
	delete data2;
	//enet_host_flush(server);
}

BYTE* packPlayerMoving(PlayerMoving* dataStruct)
{
	BYTE* data = new BYTE[56];
	for (int i = 0; i < 56; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 4, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 20, &dataStruct->plantingTree, 4);
	memcpy(data + 24, &dataStruct->x, 4);
	memcpy(data + 28, &dataStruct->y, 4);
	memcpy(data + 32, &dataStruct->XSpeed, 4);
	memcpy(data + 36, &dataStruct->YSpeed, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	return data;
}

PlayerMoving* unpackPlayerMoving(BYTE* data)
{
	PlayerMoving* dataStruct = new PlayerMoving;
	memcpy(&dataStruct->packetType, data, 4);
	memcpy(&dataStruct->netID, data + 4, 4);
	memcpy(&dataStruct->characterState, data + 12, 4);
	memcpy(&dataStruct->plantingTree, data + 20, 4);
	memcpy(&dataStruct->x, data + 24, 4);
	memcpy(&dataStruct->y, data + 28, 4);
	memcpy(&dataStruct->XSpeed, data + 32, 4);
	memcpy(&dataStruct->YSpeed, data + 36, 4);
	memcpy(&dataStruct->punchX, data + 44, 4);
	memcpy(&dataStruct->punchY, data + 48, 4);
	return dataStruct;
}

void SendPacket(int a1, string a2, ENetPeer* enetPeer)
{
	if (enetPeer)
	{
		ENetPacket* v3 = enet_packet_create(0, a2.length() + 5, 1);
		memcpy(v3->data, &a1, 4);
		//*(v3->data) = (DWORD)a1;
		memcpy((v3->data) + 4, a2.c_str(), a2.length());

		//cout << std::hex << (int)(char)v3->data[3] << endl;
		enet_peer_send(enetPeer, 0, v3);
	}
}

void SendPacketRaw(int a1, void *packetData, size_t packetDataSize, void *a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket *p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE *)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD *)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			memcpy((char *)p->data + packetDataSize + 4, a4, *((DWORD *)packetData + 13));
			enet_peer_send(peer, 0, p);
		}
		else
		{
			p = enet_packet_create(0, packetDataSize + 5, packetFlag);
			memcpy(p->data, &a1, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			enet_peer_send(peer, 0, p);
		}
	}
	delete packetData;
}


void onPeerConnect(ENetPeer* peer)
{
	ENetPeer * currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (peer != currentPeer)
		{
			if (isHere(peer, currentPeer))
			{
				string netIdS = std::to_string(((PlayerInfo*)(currentPeer->data))->netID);
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + netIdS + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(currentPeer->data))->x) + "|" + std::to_string(((PlayerInfo*)(currentPeer->data))->y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(peer, 0, packet);
				delete p.data;
				string netIdS2 = std::to_string(((PlayerInfo*)(peer->data))->netID);
				GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS2 + "\nuserID|" + netIdS2 + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(peer->data))->x) + "|" + std::to_string(((PlayerInfo*)(peer->data))->y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				//enet_host_flush(server);
			}
		}
	}

}

void sendPuncheffect(ENetPeer* peer, int punch) {
	//return; // TODO
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	int netID = info->netID;
	ENetPeer * currentPeer;
	int state = getState(info);

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {


			PlayerMoving data;
			data.packetType = 0x14;
			data.characterState = 0; // animation
			data.x = 1000;
			data.y = 100;
			data.punchX = 0;
			data.punchY = 0;
			data.XSpeed = 300;
			data.YSpeed = 600;
			data.netID = netID;
			data.plantingTree = state;
			BYTE* raw = packPlayerMoving(&data);
			int var = punch; // punch effect
			memcpy(raw + 1, &var, 3);
			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);


		}

	}
	// TODO 
}


void updateGuild(ENetPeer*peer) {
	string guildname = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild);
	if (guildname != "") {
		std::ifstream ifff("guilds/" + guildname + ".json");
		if (ifff.fail()) {
			ifff.close();
			cout << "Failed loading guilds/" + guildname + ".json! From " + ((PlayerInfo*)(peer->data))->displayName + "." << endl;
			((PlayerInfo*)(peer->data))->guild = "";
			updateGuild;
		}
		json j;
		ifff >> j;

		int gfbg, gffg;

		string gstatement, gleader;

		vector<string> gmembers;

		gfbg = j["backgroundflag"];
		gffg = j["foregroundflag"];
		gstatement = j["GuildStatement"];
		gleader = j["Leader"];
		for (int i = 0; i < j["Member"].size(); i++) {
			gmembers.push_back(j["Member"][i]);
		}

		if (find(gmembers.begin(), gmembers.end(), ((PlayerInfo*)(peer->data))->rawName) == gmembers.end()) {
			((PlayerInfo*)(peer->data))->guild = "";
		}
		else {
			((PlayerInfo*)(peer->data))->guildBg = gfbg;
			((PlayerInfo*)(peer->data))->guildFg = gffg;
			((PlayerInfo*)(peer->data))->guildStatement = gstatement;
			((PlayerInfo*)(peer->data))->guildLeader = gleader;
			((PlayerInfo*)(peer->data))->guildMembers = gmembers;
		}

		ifff.close();
	}
}
void updateInvis(ENetPeer* peer)
{
	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{

			GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), ((PlayerInfo*)(peer->data))->isMod));

			memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2);
			delete p2.data;

			GamePacket p3 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), ((PlayerInfo*)(currentPeer->data))->isMod));

			memcpy(p3.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
			ENetPacket * packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet3);
			delete p3.data;


			GamePacket p2ww = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(peer->data))->country + "|showGuild"));
			memcpy(p2ww.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
			ENetPacket * packet2ww = enet_packet_create(p2ww.data,
				p2ww.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2ww);
			delete p2ww.data;
			GamePacket p2wwee = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(currentPeer->data))->country + "|showGuild"));
			memcpy(p2wwee.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
			ENetPacket * packet2wwee = enet_packet_create(p2wwee.data,
				p2wwee.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet2wwee);
			delete p2wwee.data;

			int flag1 = (65536 * ((PlayerInfo*)(peer->data))->guildBg) + ((PlayerInfo*)(peer->data))->guildFg;
			GamePacket p2gg = packetEnd(appendIntx(appendIntx(appendIntx(appendIntx(appendString(createPacket(), "OnGuildDataChanged"), 41179607), 41179607), flag1), 0));

			memcpy(p2gg.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
			ENetPacket * packet2gg = enet_packet_create(p2gg.data,
				p2gg.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2gg);
			delete p2gg.data;
			int flag2 = (65536 * ((PlayerInfo*)(currentPeer->data))->guildBg) + ((PlayerInfo*)(currentPeer->data))->guildFg;
			GamePacket p2xd = packetEnd(appendIntx(appendIntx(appendIntx(appendIntx(appendString(createPacket(), "OnGuildDataChanged"), 41179607), 41179607), flag2), 0));

			memcpy(p2xd.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
			ENetPacket * packet2xd = enet_packet_create(p2xd.data,
				p2xd.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet2xd);
			delete p2xd.data;
		}

	}
}
void updateAllClothes(ENetPeer* peer)
{
	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), ((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f));
			memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
			ENetPacket * packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet3);
			delete p3.data;
			//enet_host_flush(server);
			GamePacket p4 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(currentPeer->data))->cloth_hair, ((PlayerInfo*)(currentPeer->data))->cloth_shirt, ((PlayerInfo*)(currentPeer->data))->cloth_pants), ((PlayerInfo*)(currentPeer->data))->cloth_feet, ((PlayerInfo*)(currentPeer->data))->cloth_face, ((PlayerInfo*)(currentPeer->data))->cloth_hand), ((PlayerInfo*)(currentPeer->data))->cloth_back, ((PlayerInfo*)(currentPeer->data))->cloth_mask, ((PlayerInfo*)(currentPeer->data))->cloth_necklace), ((PlayerInfo*)(currentPeer->data))->skinColor), ((PlayerInfo*)(currentPeer->data))->cloth_ances, 0.0f, 0.0f));
			memcpy(p4.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4); // ffloor
			ENetPacket * packet4 = enet_packet_create(p4.data,
				p4.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet4);
			delete p4.data;
			//enet_host_flush(server);
		}
	}
}

void sendClothes(ENetPeer* peer)
{
	ENetPeer * currentPeer;
	GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), ((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{

			memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
			ENetPacket * packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet3);
		}

	}
	//enet_host_flush(server);
	delete p3.data;
}




void sendPData(ENetPeer* peer, PlayerMoving* data)
{
	ENetPeer * currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (peer != currentPeer)
		{
			if (isHere(peer, currentPeer))
			{
				data->netID = ((PlayerInfo*)(peer->data))->netID;

				SendPacketRaw(4, packPlayerMoving(data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
}

int getPlayersCountInWorld(string name)
{
	int count = 0;


	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->currentWorld == name)
			count++;
	}
	return count;
}
int otherplayer(string name)
{
	int count = 0;


	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->currentWorld == name)
			count++;
	}
	return count;
}
void sendRoulete(ENetPeer* peer, int x, int y)
{

	using namespace std::chrono;







	ENetPeer* currentPeer;
	int val = rand() % 37;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			string name = ((PlayerInfo*)(peer->data))->displayName;
			/*
			if (((PlayerInfo*)(peer->data))->lastSpin + 1500 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
			{
			((PlayerInfo*)(peer->data))->lastSpin = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
			}


			else {
			GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`4Please spin slow!"));
			ENetPacket * packet = enet_packet_create(po.data,
			po.len,
			ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete po.data;
			//enet_host_flush(server);
			continue;
			}*/

			if (val == 1 || val == 3 || val == 5 || val == 7 || val == 9 || val == 12 || val == 14 || val == 16 || val == 18 || val == 19 || val == 21 || val == 23 || val == 25 || val == 27 || val == 30 || val == 32 || val == 34 || val == 36) {
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + name + " `wspun the wheel and got `4" + std::to_string(val) + "`w!]"), 0));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7[`w" + name + " `ospun the wheel and got `4" + std::to_string(val) + "`o!`7]"));
				ENetPacket * packet2s = enet_packet_create(p2s.data,
					p2s.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2s);
				delete p2s.data;
			}
			else if (val == 2 || val == 4 || val == 6 || val == 8 || val == 10 || val == 11 || val == 13 || val == 15 || val == 17 || val == 20 || val == 22 || val == 24 || val == 26 || val == 28 || val == 29 || val == 31 || val == 33 || val == 35) {
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + name + " `wspun the wheel and got `b" + std::to_string(val) + "`w!]"), 0));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7[`w" + name + " `ospun the wheel and got `b" + std::to_string(val) + "`o!`7]"));
				ENetPacket * packet2s = enet_packet_create(p2s.data,
					p2s.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2s);
				delete p2s.data;

			}

			else if (val == 0 || val == 37) {

				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + name + " `wspun the wheel and got `20`w!]"), 0));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7[`w" + name + " `ospun the wheel and got `20`o!`7]"));
				ENetPacket * packet2s = enet_packet_create(p2s.data,
					p2s.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2s);
				delete p2s.data;
			}
		}


		//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
	}
}


void sendSlotmachine(ENetPeer* peer, int x, int y)
{
	ENetPeer* currentPeer;
	int val = rand() % 100;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			string name = ((PlayerInfo*)(peer->data))->displayName;

			string lose = "`7[`w" + name + " `4loses at slots.`7]";
			string win = "`7[`w" + name + " `2wins at slots!`7]";

			if (val > 80) {
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), win), 0));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), win));
				ENetPacket * packet2s = enet_packet_create(p2s.data,
					p2s.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2s);
				delete p2s.data;

			}
			else {
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), lose), 0));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);

				GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), lose));
				ENetPacket * packet2s = enet_packet_create(p2s.data,
					p2s.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2s);
				delete p2.data;
				delete p2s.data;
			}
		}


		//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
	}
}

void sendNothingHappened(ENetPeer* peer, int x, int y) {
	PlayerMoving data;
	data.netID = ((PlayerInfo*)(peer->data))->netID;
	data.packetType = 0x8;
	data.plantingTree = 0;
	data.netID = -1;
	data.x = x;
	data.y = y;
	data.punchX = x;
	data.punchY = y;
	SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
}
void sendDrop(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect)
{
	if (item >= 7196) return;
	if (item < 0) return;
	ENetPeer * currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			data.packetType = 14;
			data.x = x;
			data.y = y;
			data.netID = netID;
			data.plantingTree = item;
			float val = count; // item count
			BYTE val2 = specialEffect;

			BYTE* raw = packPlayerMoving(&data);
			memcpy(raw + 16, &val, 4);
			memcpy(raw + 1, &val2, 1);

			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}

void sendtake(ENetPeer* peer, int netID, int x, int y, int item)
{
	if (item >= 7196) return;
	if (item < 0) return;
	ENetPeer * currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			data.packetType = 14;
			data.x = x;
			data.y = y;
			data.netID = netID;
			data.plantingTree = item;


			BYTE* raw = packPlayerMoving(&data);


			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_EVENT_TYPE_RECEIVE);
		}
	}
}
void sendWorld(ENetPeer* peer, WorldInfo* worldInfo)
{
#ifdef TOTAL_LOG
	cout << "Entering a world..." << endl;
#endif
	((PlayerInfo*)(peer->data))->joinClothesUpdated = false;
	string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
	string worldName = worldInfo->name;
	int xSize = worldInfo->width;
	int ySize = worldInfo->height;
	//int weather = worldInfo->weather; //weather
	int square = xSize * ySize;
	__int16 nameLen = worldName.length();
	int payloadLen = asdf.length() / 2;
	int dataLen = payloadLen + 2 + nameLen + 12 + (square * 8) + 4;
	int allocMem = payloadLen + 2 + nameLen + 12 + (square * 8) + 4 + 16000;
	BYTE* data = new BYTE[allocMem];
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(data + (i / 2), &x, 1);
	}
	int zero = 0;
	__int16 item = 0;
	int smth = 0;
	for (int i = 0; i < square * 8; i += 4) memcpy(data + payloadLen + i + 14 + nameLen, &zero, 4);
	for (int i = 0; i < square * 8; i += 8) memcpy(data + payloadLen + i + 14 + nameLen, &item, 2);
	memcpy(data + payloadLen, &nameLen, 2);
	memcpy(data + payloadLen + 2, worldName.c_str(), nameLen);
	memcpy(data + payloadLen + 2 + nameLen, &xSize, 4);
	memcpy(data + payloadLen + 6 + nameLen, &ySize, 4);
	memcpy(data + payloadLen + 10 + nameLen, &square, 4);
	BYTE* blockPtr = data + payloadLen + 14 + nameLen;
	for (int i = 0; i < square; i++) {
		if ((worldInfo->items[i].foreground == 0) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100)/* || (worldInfo->items[i].foreground%2)*/)
		{
			memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
			int type = 0x00000000;
			// type 1 = locked
			if (worldInfo->items[i].water)
				type |= 0x04000000;
			if (worldInfo->items[i].glue)
				type |= 0x08000000;
			if (worldInfo->items[i].fire)
				type |= 0x10000000;
			if (worldInfo->items[i].red)
				type |= 0x20000000;
			if (worldInfo->items[i].green)
				type |= 0x40000000;
			if (worldInfo->items[i].blue)
				type |= 0x80000000;

			// int type = 0x04000000; = water
			// int type = 0x08000000 = glue
			// int type = 0x10000000; = fire
			// int type = 0x20000000; = red color
			// int type = 0x40000000; = green color
			// int type = 0x80000000; = blue color
			memcpy(blockPtr + 4, &type, 4);
			/*if (worldInfo->items[i].foreground % 2)
			{
			blockPtr += 6;
			}*/
		}
		else
		{
			memcpy(blockPtr, &zero, 2);
		}
		memcpy(blockPtr + 2, &worldInfo->items[i].background, 2);
		blockPtr += 8;
		/*if (blockPtr - data < allocMem - 2000) // realloc
		{
		int wLen = blockPtr - data;
		BYTE* oldData = data;

		data = new BYTE[allocMem + 16000];
		memcpy(data, oldData, allocMem);
		allocMem += 16000;
		delete oldData;
		blockPtr = data + wLen;

		}*/
	}
	memcpy(data + dataLen - 4, &smth, 4);
	ENetPacket * packet2 = enet_packet_create(data,
		dataLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2);
	//enet_host_flush(server);
	for (int i = 0; i < square; i++) {
		if ((worldInfo->items[i].foreground == 0) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100))
			; // nothing
		else
		{
			PlayerMoving data;
			//data.packetType = 0x14;
			data.packetType = 0x3;

			//data.characterState = 0x924; // animation
			data.characterState = 0x0; // animation
			data.x = i % worldInfo->width;
			data.y = i / worldInfo->height;
			data.punchX = i % worldInfo->width;
			data.punchY = i / worldInfo->width;
			data.XSpeed = 0;
			data.YSpeed = 0;
			data.netID = -1;
			data.plantingTree = worldInfo->items[i].foreground;
			SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
	((PlayerInfo*)(peer->data))->currentWorld = worldInfo->name;

	if (((PlayerInfo*)(peer->data))->haveGrowId) {

		PlayerInfo* p = ((PlayerInfo*)(peer->data));
		std::ifstream ifff("players/" + PlayerDB::getProperName(p->rawName) + ".json");
		json j;
		ifff >> j;

		p->currentWorld = worldInfo->name;

		int bac, han, fac, hai, fee, pan, nec, shi, mas, lvl, ban, pch, skin, mute, gem, anc, exp, join, gemnew;
		bac = j["ClothBack"];

		fac = j["ClothFace"];
		hai = j["ClothHair"];

		pan = j["ClothPants"];
		nec = j["ClothNeck"];
		shi = j["ClothShirt"];
		mas = j["ClothMask"];

		skin = j["Skin"];
		lvl = j["Level"];
		ban = j["isBanned"];
		pch = j["puncheffect"];
		mute = j["isMuted"];
		gem = j["gem"];
		if (j.count("ClothAnces") == 1) {
			anc = j["ClothAnces"];
		}
		else {
			anc = 0;
		}
		if (j.count("exp") == 1) {
			exp = j["exp"];
		}
		else {
			exp = 0;
		}
		if (j["ClothFeet"] == 7762) {
			fee = 0;
		}
		else {
			fee = j["ClothFeet"];
		}

		if (j["ClothHand"] == 6866 || j["ClothHand"] == 6868 || j["ClothHand"] == 6870 || j["ClothHand"] == 6872 || j["ClothHand"] == 6874 || j["ClothHand"] == 6876 || j["ClothHand"] == 6878) {
			han = 0;
		}
		else {
			han = j["ClothHand"];
		}
		vector <string>frns;
		if (j.count("friends") == 1) {
			for (int i = 0; i < j["friends"].size(); i++) {
				frns.push_back(j["friends"][i]);
			}
		}
		else {
			frns = {};
		}
		if (j.count("joinguild") == 1) {
			join = j["joinguild"];
		}
		else {
			join = false;
		}

		if (j.count("gems") == 1) {
			gemnew = j["gems"];
		}
		else {
			gemnew = 0;
		}
		string guild;
		if (j.count("guild") == 1) {
			guild = j["guild"];
		}
		else {
			guild = "";
		}

		p->guild = guild;
		p->friendinfo = frns;
		p->joinguild = join;
		string friendlist;
		friendlist = j["friend"];
		p->friendlist = friendlist;
		p->cloth_back = bac;
		p->cloth_hand = han;
		p->cloth_face = fac;
		p->cloth_hair = hai;
		p->cloth_feet = fee;
		p->cloth_pants = pan;
		p->cloth_necklace = nec;
		p->cloth_shirt = shi;
		p->cloth_mask = mas;
		p->cloth_ances = anc;
		p->skinColor = skin;
		p->ban = ban;
		p->level = lvl;
		p->mute = mute;
		p->gem = gemnew;

		sendClothes(peer);

		p->puncheffect = pch;
		sendPuncheffect(peer, p->puncheffect);
		updateInvis(peer);

		p->blockbroken = exp;
		ifff.close();
		string guildname = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild);
		if (guildname != "") {
			std::ifstream ifff("guilds/" + guildname + ".json");
			if (ifff.fail()) {
				ifff.close();
				cout << "Failed loading guilds/" + guildname + ".json! From " + ((PlayerInfo*)(peer->data))->displayName + "." << endl;
				((PlayerInfo*)(peer->data))->guild = "";

			}
			json j;
			ifff >> j;

			int gfbg, gffg;

			string gstatement, gleader;

			vector<string> gmembers;

			gfbg = j["backgroundflag"];
			gffg = j["foregroundflag"];
			gstatement = j["GuildStatement"];
			gleader = j["Leader"];
			for (int i = 0; i < j["Member"].size(); i++) {
				gmembers.push_back(j["Member"][i]);
			}

			((PlayerInfo*)(peer->data))->guildBg = gfbg;
			((PlayerInfo*)(peer->data))->guildFg = gffg;
			((PlayerInfo*)(peer->data))->guildStatement = gstatement;
			((PlayerInfo*)(peer->data))->guildLeader = gleader;
			((PlayerInfo*)(peer->data))->guildMembers = gmembers;

			ifff.close();
		}
	}

	delete data;

}
void sendState(ENetPeer* peer) {
	//return; // TODO
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	int netID = info->netID;
	ENetPeer * currentPeer;
	int state = getState(info);
	int states = ((PlayerInfo*)(peer->data))->statecode;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {

			PlayerMoving data;
			data.packetType = 0x14;
			data.characterState = 0; // animation
			data.x = 1000;
			data.y = 100;
			data.punchX = 0;
			data.punchY = 0;
			data.XSpeed = 300;
			data.YSpeed = 600;
			data.netID = netID;
			data.plantingTree = state;
			BYTE* raw = packPlayerMoving(&data);
			int var = ((PlayerInfo*)(peer->data))->puncheffect; // placing and breking
			memcpy(raw + 1, &var, 3);
			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);


		}
	}
}
void joinWorld(ENetPeer* peer, string act, int x2, int y2)
{
	try {
		WorldInfo info = worldDB.get(act);
		sendWorld(peer, &info);


		int x = 3040;
		int y = 736;

		for (int j = 0; j < info.width*info.height; j++)
		{
			if (info.items[j].foreground == 6) {
				x = (j%info.width) * 32;
				y = (j / info.width) * 32;
			}
		}


		if (x2 != 0 && y2 != 0)
		{
			x = x2;
			y = y2;
		}
		int id = 244;
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "|" + std::to_string(id) + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
		//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;

		/* Weather change
		{
		GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), info.weather));
		ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
		}
		*/

		((PlayerInfo*)(peer->data))->netID = cId;
		onPeerConnect(peer);
		cId++;
		sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);



		WorldInfo *world = getPlyersWorld(peer);
		string nameworld = world->name;
		string ownerworld = world->owner;
		int count = 0;
		ENetPeer * currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			count++;
		}


		{
			ENetPeer* currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
				{


					GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;

					int effect = ((PlayerInfo*)(peer->data))->entereffect;
					int x = ((PlayerInfo*)(peer->data))->x;
					int y = ((PlayerInfo*)(peer->data))->y;
					GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

					ENetPacket * packetd = enet_packet_create(psp.data,
						psp.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packetd);
					delete psp.data;
				}

			}

		}
		//updateInvis(peer);
		//sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->puncheffect);
		/*{
		ENetPeer* currentPeer;

		for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
		{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
		continue;
		if (isHere(peer, currentPeer))
		{

		int ID = ((PlayerInfo*)(currentPeer->data))->puncheffect;
		((PlayerInfo*)(currentPeer->data))->puncheffect = ID;
		sendPuncheffect(currentPeer);

		}

		}

		}
		*/

		int otherpeople = 0;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
				otherpeople++;
		}
		int otherpeoples = otherpeople - 1;

		GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWorld `0" + nameworld + " `oentered. There are `0" + std::to_string(otherpeoples) + " `oother people here`7, `0" + std::to_string(count) + " `oonline."));
		ENetPacket * packet2 = enet_packet_create(p2.data,
			p2.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet2);
		delete p2.data;
		if (ownerworld != "") {
			GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`0" + nameworld + " `$World Locked `oby " + ownerworld + "`5]"));
			ENetPacket * packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet3);
			delete p3.data;
		}

		if (((PlayerInfo*)(peer->data))->mute == 1) {
			((PlayerInfo*)(peer->data))->cantsay = true;
			sendState(peer);
		}
		GamePacket p22 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + ((PlayerInfo*)(peer->data))->Chatname + "`` `5entered, `w" + std::to_string(otherpeoples) + "`` others here>``"));


		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer) && ((PlayerInfo*)(peer->data))->isMod == 0) {
				{

					ENetPacket * packet2 = enet_packet_create(p22.data,
						p22.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);

				}
			}
		}


	}
	catch (int e) {
		if (e == 1) {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have exited the world."));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
		else if (e == 2) {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have entered bad characters in the world name!"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
		else if (e == 3) {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Exit from what? Click back if you're done playing."));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
		else {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "I know this menu is magical and all, but it has its limitations! You can't visit this world!"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
	}
}
void sendPlayerLeave(ENetPeer* peer, PlayerInfo* player)
{
	ENetPeer * currentPeer;
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->Chatname + "`` `5left, `w" + std::to_string(otherplayer(player->currentWorld)) + "`` others here>``"));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			{

				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet);

			}
			{

				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet2);

			}
		}
	}

	if (((PlayerInfo*)(peer->data))->isIn)
	{
		if (((PlayerInfo*)(peer->data))->haveGrowId) {

			PlayerInfo* p = ((PlayerInfo*)(peer->data));

			string username = PlayerDB::getProperName(p->rawName);

			std::ofstream o("players/" + username + ".json");
			if (!o.is_open()) {
				cout << GetLastError() << endl;
				_getch();
			}
			json j;

			int clothback = p->cloth_back;
			int clothhand = p->cloth_hand;
			int clothface = p->cloth_face;
			int clothhair = p->cloth_hair;
			int clothfeet = p->cloth_feet;
			int clothpants = p->cloth_pants;
			int clothneck = p->cloth_necklace;
			int clothshirt = p->cloth_shirt;
			int clothmask = p->cloth_mask;
			int clothances = p->cloth_ances;
			int level = p->level;
			int skin = p->skinColor;
			int exp = p->blockbroken;
			int ban = p->ban;
			int puncheffect = p->puncheffect;
			int mute = p->mute;
			int gem = 0;

			int newgem = p->gem;
			int entereffect = p->entereffect;
			string friendlist = p->friendlist;
			bool join = p->joinguild;
			string guild = p->guild;
			string password = ((PlayerInfo*)(peer->data))->tankIDPass;
			j["username"] = username;
			j["password"] = hashPassword(password);
			j["adminLevel"] = p->adminLevel;
			j["ClothBack"] = clothback;
			j["ClothHand"] = clothhand;
			j["ClothFace"] = clothface;
			j["ClothShirt"] = clothshirt;
			j["ClothPants"] = clothpants;
			j["ClothNeck"] = clothneck;
			j["ClothHair"] = clothhair;
			j["ClothFeet"] = clothfeet;
			j["ClothMask"] = clothmask;
			j["ClothAnces"] = clothances;
			j["Level"] = level;
			j["Skin"] = skin;
			j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
			j["puncheffect"] = puncheffect;
			j["gem"] = gem;
			j["gems"] = newgem;
			j["entereffect"] = entereffect;
			j["isMuted"] = mute;
			j["isBanned"] = ban;
			j["exp"] = exp;

			j["guild"] = guild;
			j["joinguild"] = join;
			j["friend"] = friendlist;
			o << j << std::endl;

		}
	}
	delete p.data;
	delete p2.data;
	return;
}
void showDoormover(ENetPeer*peer) {
	GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`wDoor Mover|left|1404|\nadd_spacer|small|\nadd_label|small|`oAre you sure to use the door mover? This will use 1,000 gem.``|left|4|\nadd_button|doormoverbutton|`4Yes|0|0|\nadd_quick_exit"));

	ENetPacket * packet22 = enet_packet_create(wrench.data,
		wrench.len,
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet22);
	delete wrench.data;

}
void sendTileUpdate(int x, int y, int tile, int causedBy, ENetPeer* peer)
{
	PlayerMoving data;
	//data.packetType = 0x14;
	data.packetType = 0x3;

	//data.characterState = 0x924; // animation
	data.characterState = 0x0; // animation
	data.x = x;
	data.y = y;
	data.punchX = x;
	data.punchY = y;
	data.XSpeed = 0;
	data.YSpeed = 0;
	data.netID = causedBy;
	data.plantingTree = tile;

	WorldInfo *world = getPlyersWorld(peer);

	if (world == NULL) return;
	if (x<0 || y<0 || x>world->width || y>world->height) return;
	sendNothingHappened(peer, x, y);
	if (world->items[x + (y*world->width)].foreground == 758)
		sendRoulete(peer, x, y);
	if (world->items[x + (y*world->width)].foreground == 756)
		sendSlotmachine(peer, x, y);

	if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
		if (tile == 242) {

			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4You must register before you can lock a world!``"), 0));


			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet2);
			delete p2.data;

			return;

		}

	}
	if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
	{
		if (world->items[x + (y*world->width)].foreground == 6 || world->items[x + (y*world->width)].foreground == 8 || world->items[x + (y*world->width)].foreground == 3760) {
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`wIt's too strong to break.``"), 0));


			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet2);
			delete p2.data;

			return;
		}

		if (tile == 6 || tile == 8 || tile == 3760 || tile == 1790 || tile == 1900 || tile == 7372)
		{
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`wIt's too strong to break.``"), 0));


			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet2);
			delete p2.data;

			return;
		}
	}
	if (world->name == "ADMIN" && !getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
	{
		if (world->items[x + (y*world->width)].foreground == 758)
			sendRoulete(peer, x, y);
		return;
	}


	if (world->items[x + (y*world->width)].foreground == 1790)
	{
		if (tile == 32) {
			string ownername = world->owner;

			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Legendary Wizard!`|left|1790|\nadd_label|small|`oGreetings, traveler! I am the Legendary Wizard. Should you wish to embark on a Legendary Quest, simply choose one below.``|left|4|\n\nadd_spacer|small|\nadd_button|legendname|`9Quest For Honor``|0|0|\nadd_button|legenddragon|`9Quest For Fire``|0|0|\nadd_button|legendbot|`9Quest Of Steel``|0|0|\nadd_button|legendwing|`9Quest Of The Heavens``|0|0|\nadd_button|legendkatana|`9Quest For The Blade``|0|0|\nadd_button|legendwhip|`9Quest For Candour``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);

			//enet_host_flush(server);
			delete p.data;

			return;
		}
	}
	if (world->items[x + (y*world->width)].foreground == 1900) {


		if (tile == 32) {
			string ownername = world->owner;

			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Ringmaster!`|left|1900|\nadd_label|small|`oGreetings, traveler! I am the Ringmaster. Should you wish to embark on a Ring, simply choose one below.``|left|4|\n\nadd_spacer|small|\nadd_button|ringforce|`9Ring Of Force``|0|0|\nadd_button|ringwinds|`9Ring Of Winds``|0|0|\nadd_button|ringone|`9The One Ring``|0|0|\nadd_button|ringwisdom|`9Ring of Wisdom ``|0|0|\nadd_button|ringwater|`9Ring Of Water``|0|0|\nadd_button|ringsaving|`9Ring Of Savings``|0|0|\nadd_button|ringsmithing|`9Ring Of Smithing``|0|0|\nadd_button|ringshrinking|`9Ring Of Shrinking``|0|0|\nadd_button|ringnature|`9Ring of Nature``|0|0|\nadd_button|geminiring|`9Gemini Ring``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);

			//enet_host_flush(server);
			delete p.data;

			return;
		}
	}
	if (world->name != "ADMIN") {
		if (world->owner != "") {

			if (((PlayerInfo*)(peer->data))->rawName == world->owner || (((PlayerInfo*)(peer->data))->rawName == world->worldaccess || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))) {
				if (((PlayerInfo*)(peer->data))->rawName == "") return;
				if (world->items[x + (y*world->width)].foreground == 2398) {
					if (world->items[x + (y*world->width)].foreground == 242 && (((PlayerInfo*)(peer->data))->rawName == world->worldaccess))
					{
						return;
					}

					if (tile == 32 && ((PlayerInfo*)(peer->data))->rawName == world->worldaccess) {
						return;
					}

					if (tile == 32) {


						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Locke The Salesman`|left|2398|\nadd_label|small|`oGreetings, traveler! I am Locke The Salesman. What should i do for you? Simply choose one below.``|left|4|\n\nadd_spacer|small|\nadd_button|weather|`2Change Weather``|0|0|\nadd_button|searchitems|`2Search item``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;

						return;
					}
				}
			}
		}
	}
	if (world->name != "ADMIN") {
		if (world->owner != "") {

			if (((PlayerInfo*)(peer->data))->rawName == world->owner || (((PlayerInfo*)(peer->data))->rawName == world->worldaccess || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) || isOwner(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))) {
				if (((PlayerInfo*)(peer->data))->rawName == "") return;
				// WE ARE GOOD TO GO

				if (world->items[x + (y*world->width)].foreground == 242 && (((PlayerInfo*)(peer->data))->rawName == world->worldaccess))
				{
					return;
				}

				if (tile == 32 && ((PlayerInfo*)(peer->data))->rawName == world->worldaccess) {
					return;
				}
				string offlinelist = "";
				string offname = "";
				int ischecked;

				for (std::vector<string>::const_iterator i = world->accessworld.begin(); i != world->accessworld.end(); ++i) {
					offname = *i;
					offlinelist += "\nadd_checkbox|isAccessed|" + offname + "|0|\n";

				}

				if (world->isPublic == true) {
					ischecked = 1;
				}
				else {
					ischecked = 0;
				}
				if (tile == 32) {
					if (world->accessworld.size() == 0) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit World Lock``|left|242|\nadd_textbox|`wAccess list:|left|\nadd_spacer|small|\nadd_textbox|Currently, you're the only one with the access.|left|\nadd_spacer|small|\nadd_player_picker|netid|`wAdd|\nadd_checkbox|isWorldPublic|Allow anyone to build|" + std::to_string(ischecked) + "| \nend_dialog|wlmenu|Cancel|OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}

					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit World Lock``|left|242|\nadd_textbox|`wAccess list:|left|\nadd_spacer|small|" + offlinelist + "add_spacer|small|\nadd_player_picker|netid|`wAdd|\nadd_checkbox|isWorldPublic|Allow anyone to build|" + std::to_string(ischecked) + "| \nend_dialog|wlmenu|Cancel|OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}

				}

			}




			else if (world->isPublic)
			{
				if (world->items[x + (y*world->width)].foreground == 242)
				{
					string ownername = world->owner;

					GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0" + ownername + "'s `$World Lock`0. (Open to Public)"), 0));


					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet2);
					delete p2.data;

					return;
				}

			}
			else {
				return;
			} /*lockeds*/
			if (tile == 242) {



				GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0Only one `$World Lock`0 can be placed in a world!"), 0));


				ENetPacket * packet3 = enet_packet_create(p3.data,
					p3.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet3);
				delete p3.data;
				return;
			}

		}
	}



	if (tile == 1404) {
		//world->items[x + (y*world->width)].water = !world->items[x + (y*world->width)].water;
		//if (isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {

		if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {
			if (world->items[x + (y*world->width)].foreground != 0) {
				GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Here is no space for the main door!"));


				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet2);
				delete p2.data;

			}
			else if (world->items[x + (y*world->width) + 100].foreground != 0) {
				GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Here is no space for the main door!"));


				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet2);
				delete p2.data;

			}
			else if (((PlayerInfo*)(peer->data))->gem < 1000) {
				GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You don't not have enought gem to use door mover! " + std::to_string(((PlayerInfo*)(peer->data))->gem - 1000) + " more gem"));
				ENetPacket * packet8 = enet_packet_create(p8.data,
					p8.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet8);
			}
			else

			{
				//	showDoormover(peer);
				for (int i = 0; i < world->width*world->height; i++)
				{
					if (i >= 5400) {
						world->items[i].foreground = 8;
					}
					else if (world->items[i].foreground == 6) {

						world->items[i].foreground = 0;
						world->items[i + 100].foreground = 0;

					}

					else if (world->items[i].foreground != 6) {
						world->items[x + (y*world->width)].foreground = 6;
						world->items[x + (y*world->width) + 100].foreground = 8;
					}


				}

				WorldInfo* wrld = getPlyersWorld(peer);
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						string act = ((PlayerInfo*)(peer->data))->currentWorld;
						//WorldInfo info = worldDB.get(act);
						// sendWorld(currentPeer, &info);


						sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
						joinWorld(currentPeer, act, 0, 0);
						updateAllClothes(peer);
						((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 1000;
						GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "you used door mover!"));
						ENetPacket * packet8 = enet_packet_create(p8.data,
							p8.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet8);

					}

				}
			}
			return;
		}
	}

	if (tile == 32) {
		// TODO
		return;
	}
	if (tile == 822) {
		world->items[x + (y*world->width)].water = !world->items[x + (y*world->width)].water;
		return;
	}
	if (tile == 3062)
	{
		world->items[x + (y*world->width)].fire = !world->items[x + (y*world->width)].fire;
		return;
	}
	if (tile == 1866)
	{
		world->items[x + (y*world->width)].glue = !world->items[x + (y*world->width)].glue;
		return;
	}
	ItemDefinition def;
	try {
		def = getItemDef(tile);
		if (def.clothType != ClothTypes::NONE) return;
	}
	catch (int e) {
		def.breakHits = 4;
		def.blockType = BlockTypes::UNKNOWN;
#ifdef TOTAL_LOG
		cout << "Ugh, unsupported item " << tile << endl;
#endif
	}

	if (tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 4520 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
	if (tile == 5708 || tile == 5709 || tile == 5780 || tile == 5781 || tile == 5782 || tile == 5783 || tile == 5784 || tile == 5785 || tile == 5710 || tile == 5711 || tile == 5786 || tile == 5787 || tile == 5788 || tile == 5789 || tile == 5790 || tile == 5791 || tile == 6146 || tile == 6147 || tile == 6148 || tile == 6149 || tile == 6150 || tile == 6151 || tile == 6152 || tile == 6153 || tile == 5670 || tile == 5671 || tile == 5798 || tile == 5799 || tile == 5800 || tile == 5801 || tile == 5802 || tile == 5803 || tile == 5668 || tile == 5669 || tile == 5792 || tile == 5793 || tile == 5794 || tile == 5795 || tile == 5796 || tile == 5797 || tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
	if (tile == 1902 || tile == 1508 || tile == 428) return;
	if (tile == 410 || tile == 1770 || tile == 4720 || tile == 4882 || tile == 6392 || tile == 3212 || tile == 1832 || tile == 4742 || tile == 3496 || tile == 3270 || tile == 4722) return;
	if (tile >= 7558) return;
	if (tile == 0 || tile == 18) {

		if (world->items[x + (y*world->width)].background == 6864 && world->items[x + (y*world->width)].foreground == 0) return;
		if (world->items[x + (y*world->width)].background == 0 && world->items[x + (y*world->width)].foreground == 0) return;
		//data.netID = -1;
		data.packetType = 0x8;
		data.plantingTree = 4; // old is 4
		using namespace std::chrono;
		//if (world->items[x + (y*world->width)].foreground == 0) return;
		if ((duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() - world->items[x + (y*world->width)].breakTime >= 4000)
		{
			world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
			world->items[x + (y*world->width)].breakLevel = 4; // TODO

		}
		else
			if (y < world->height && world->items[x + (y*world->width)].breakLevel + 4 >= def.breakHits * 4) { // TODO
				data.packetType = 0x3;// 0xC; // 0xF // World::HandlePacketTileChangeRequest
				data.netID = -1;
				data.plantingTree = tile;
				data.punchX = x;
				data.punchY = y;
				world->items[x + (y*world->width)].breakLevel = 0;
				if (world->items[x + (y*world->width)].foreground != 0)

				{
					if (world->items[x + (y*world->width)].foreground == 242)
					{
						world->owner = "";
						world->worldaccess = "";
						world->isPublic = true;

						world->accessworld = {};

						WorldInfo *world = getPlyersWorld(peer);
						string nameworld = world->name;
						GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`w" + nameworld + " `ohas had its `$World Lock `oremoved!`5]"));
						ENetPacket * packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet3);
					}
					if (world->items[x + (y*world->width)].foreground == 3402)
					{


						int x = 3040;
						int y = 736;



						std::vector<int> list{ 384, 386, 388,1458, 390, 4422, 4424, 4416, 5644, 5652, 366, 364, 362 ,2390, 2396, 2384 };
						int index = rand() % list.size(); // pick a random index
						int value = list[index];

						if (value == 390) {
							sendDrop(peer, -1, x, y, value, 5, 0);
						}
						else {

							sendDrop(peer, -1, data.punchX, data.punchY, value, 1, 0);
						}
					}
					world->items[x + (y*world->width)].foreground = 0;

					//world->items[x + (y*world->width)].background = 0;
					{ // gem thing

						int valzz = rand() % 10;
						((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + valzz;


						GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						// levelup code starts here
						((PlayerInfo*)(peer->data))->blockbroken = ((PlayerInfo*)(peer->data))->blockbroken + 1;
						int level = ((PlayerInfo*)(peer->data))->level;
						if (((PlayerInfo*)(peer->data))->blockbroken == 150) //block need to break to level up!
						{

							int blc = ((PlayerInfo*)(peer->data))->blockbroken;
							((PlayerInfo*)(peer->data))->blockbroken = 0; // set to 0
							((PlayerInfo*)(peer->data))->level = ((PlayerInfo*)(peer->data))->level + 1; // level up


							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									string name = ((PlayerInfo*)(peer->data))->Chatname;

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2" + name + " `wis now level " + std::to_string(((PlayerInfo*)(peer->data))->level) + "!"));
									string text = "action|play_sfx\nfile|audio/levelup2.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);

									ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									int effect = 46;
									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);

									//                `w(`2" + std::to_string(level) + "`w) "
									//((PlayerInfo*)(peer->data))->displayName = "`w(`2"+((PlayerInfo*)(peer->data))->level +"`w) " + ((PlayerInfo*)(peer->data))->tankIDName;
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`w(`2" + std::to_string(((PlayerInfo*)(peer->data))->level) + "`w) " + ((PlayerInfo*)(peer->data))->Chatname));


									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2ss = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2ss);
									delete p2.data;
									delete psp.data;
									delete data;
									delete p.data;

									GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`2" + name + " `wis now level " + std::to_string(((PlayerInfo*)(peer->data))->level) + "!"));
									ENetPacket * packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);

									/*if (((PlayerInfo*)(peer->data))->haveGrowId) {

									PlayerInfo* p = ((PlayerInfo*)(peer->data));

									string username = PlayerDB::getProperName(p->rawName);



									std::ofstream o("players/" + username + ".json");
									if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
									}
									json j;

									int clothback = p->cloth_back;
									int clothhand = p->cloth_hand;
									int clothface = p->cloth_face;
									int clothhair = p->cloth_hair;
									int clothfeet = p->cloth_feet;
									int clothpants = p->cloth_pants;
									int clothneck = p->cloth_necklace;
									int clothshirt = p->cloth_shirt;
									int clothmask = p->cloth_mask;
									int level = p->level;

									int gem = p->gem;
									int ban = p->ban;
									// int puncheffect = p->puncheffect;

									string password = ((PlayerInfo*)(peer->data))->tankIDPass;
									j["username"] = username;
									j["password"] = hashPassword(password);
									j["adminLevel"] = p->adminLevel;
									j["ClothBack"] = clothback;
									j["ClothHand"] = clothhand;
									j["ClothFace"] = clothface;
									j["ClothShirt"] = clothshirt;
									j["ClothPants"] = clothpants;
									j["ClothNeck"] = clothneck;
									j["ClothHair"] = clothhair;
									j["ClothFeet"] = clothfeet;
									j["ClothMask"] = clothmask;
									j["Level"] = level; //save the level

									j["isBanned"] = ban;
									//  j["puncheffect"] = puncheffect;
									o << j << std::endl;
									}*/




									delete p3.data;

								}
							}
						}
					}
				}



				else {
					world->items[x + (y*world->width)].background = 0;
					data.plantingTree = 6864;
					world->items[x + (y*world->width)].background = 6864;

					/*GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`1Test``"));
					ENetPacket * packetd = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packetd);
					delete p2.data;
					return;*/
				}

			}
			else
				if (y < world->height)
				{
					world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					world->items[x + (y*world->width)].breakLevel += 4; // TODO
					if (world->items[x + (y*world->width)].foreground == 758)
						sendRoulete(peer, x, y);
					if (world->items[x + (y*world->width)].foreground == 756)
						sendSlotmachine(peer, x, y);
				}

	}
	else {
		for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
		{
			if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == tile)
			{
				if ((unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount > 1)
				{
					((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount--;
				}
				else {
					((PlayerInfo*)(peer->data))->inventory.items.erase(((PlayerInfo*)(peer->data))->inventory.items.begin() + i);

				}
			}
		}
		if (def.blockType == BlockTypes::BACKGROUND)
		{
			world->items[x + (y*world->width)].background = tile;
		}
		else {
			world->items[x + (y*world->width)].foreground = tile;
			if (tile == 242) {
				world->owner = ((PlayerInfo*)(peer->data))->rawName;

				world->isPublic = false;
				ENetPeer * currentPeer;



				string nameworld = world->name;
				string ownerworld = world->owner;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer)) {
						{
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`w" + nameworld + "`o has been `$World Locked `oby " + ownerworld + "`5]"));

							ENetPacket * packetd = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packetd);
							GamePacket p23 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5[`w" + nameworld + "`w has been `$World Locked `wby " + ownerworld + "`5]"), 0));

							ENetPacket * packet23 = enet_packet_create(p23.data,
								p23.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet23);
							delete p23.data;
							delete p2.data;

						}
					}
				}
			}
		}

		world->items[x + (y*world->width)].breakLevel = 0;

	}

	ENetPeer * currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
			SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);

		//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
	}
}



/*void sendChatMessage(ENetPeer* peer, int netID, string message)
{



if (((PlayerInfo*)(peer->data))->haveGrowId == false) {


GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`oYou `4MUST `2Register `obefore you can chat!"));
ENetPacket * packet4 = enet_packet_create(p4.data,
p4.len,
ENET_PACKET_FLAG_RELIABLE);

enet_peer_send(peer, 0, packet4);
delete p4.data;
return;
}
if (((PlayerInfo*)(peer->data))->haveGrowId) {
if (message.length() == 0) return;
ENetPeer * currentPeer;
string name = "";
for (currentPeer = server->peers;
currentPeer < &server->peers[server->peerCount];
++currentPeer)
{
if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
continue;
if (((PlayerInfo*)(currentPeer->data))->netID == netID)
name = ((PlayerInfo*)(currentPeer->data))->Chatname;

}

GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> " + message));
GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
for (currentPeer = server->peers;
currentPeer < &server->peers[server->peerCount];
++currentPeer)
{
if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
continue;
if (isHere(peer, currentPeer))
{

ENetPacket * packet = enet_packet_create(p.data,
p.len,
ENET_PACKET_FLAG_RELIABLE);

enet_peer_send(currentPeer, 0, packet);

//enet_host_flush(server);

ENetPacket * packet2 = enet_packet_create(p2.data,
p2.len,
ENET_PACKET_FLAG_RELIABLE);
enet_peer_send(currentPeer, 0, packet2);

//enet_host_flush(server);
}
}
delete p.data;
delete p2.data;
}
}*/

void sendChatMessage(ENetPeer* peer, int netID, string message)
{
	if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
		if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 199) {
			if (message.length() == 0) return;
			ENetPeer * currentPeer;
			string name = "";
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->netID == netID)
					name = ((PlayerInfo*)(currentPeer->data))->Chatname;

			}


			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> `^" + message));
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`^" + message), 0));
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
				{

					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet);

					//enet_host_flush(server);

					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);

					//enet_host_flush(server);
				}
			}
			delete p.data;
			delete p2.data;
		}
		else if (((PlayerInfo*)(peer->data))->mute == 1) {
			ENetPeer * currentPeer;
			string name = "";
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->netID == netID)
					name = ((PlayerInfo*)(currentPeer->data))->Chatname;

			}
			const string mf[4] = { "mf ff mf fm","f fmf fmfmf fmm","mfm ff mf mf","mff ffmf mf " };

			string word = mf[rand() % 4];
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> " + word));
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), word), 0));
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
				{

					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet);

					//enet_host_flush(server);

					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);

					//enet_host_flush(server);
				}
			}
			delete p.data;
			delete p2.data;
		}


		else {
			if (message.length() == 0) return;
			ENetPeer * currentPeer;
			string name = "";
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->netID == netID)
					name = ((PlayerInfo*)(currentPeer->data))->Chatname;

			}
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> " + message));
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
				{

					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet);

					//enet_host_flush(server);

					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);

					//enet_host_flush(server);
				}
			}
			delete p.data;
			delete p2.data;
		}
	}
	else {
		if (((PlayerInfo*)(peer->data))->haveGrowId == false) {

			GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You MUST `2Register `4before you can chat!"));
			ENetPacket * packet0 = enet_packet_create(p0.data,
				p0.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet0);
			delete p0.data;
			GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4You MUST `2Register `4before you can chat!"));
			ENetPacket * packet4 = enet_packet_create(p4.data,
				p4.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet4);
			delete p4.data;
			return;
		}

	}
}

void sendWho(ENetPeer* peer)
{
	ENetPeer * currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer) && ((PlayerInfo*)(currentPeer->data))->isMod == 0)
		{
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(currentPeer->data))->netID), ((PlayerInfo*)(currentPeer->data))->displayName), 1));
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet2);
			delete p2.data;
			//enet_host_flush(server);
		}
	}
}
// show new show gazette
void sendGazette(ENetPeer* peer) {

	std::ifstream ifff("news.json");
	json j;
	ifff >> j;

	string news;
	news = j["news"];

	//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wServer News``|left|5016|\n\nadd_spacer|small|\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\nadd_spacer|small|\n\nadd_textbox|`0December 1st: `5DECEMBER IOTM Update!|left|4|\n\nadd_spacer|small|\nadd_label|small|`2Welcome to Growtopia Private Server|left|4|\nadd_url_button||``Discord: `1Make sure to Join our discord server!``|NOFLAGS|https://discord.gg/G6nqzGG| Join discord server?|0|0|\nadd_label|small|`9Now you only can get legendary item in `9LEGENDARY world!|left|4|\nadd_spacer|small|\n\nadd_textbox|`^We're Selling Moderator,|left|4||\n\nadd_textbox|`^When you bought the Moderator we can run the server longer! `4For more info Please Join our discord server!|left|4|\nadd_spacer|small|\n\nadd_textbox|`^Also we accept Payment via DLs aka `1Diamond Locks`^!|left|4|\nadd_spacer|small|\n\nadd_textbox|`1Server Update : `4No longer put update on here|left|4|\nadd_label|small|- Roulette wheel is working normal now.|left|4|\nadd_label|small|- Added world enter message.|left|4|\nadd_label|small|- Clothes auto save!|left|4|\nadd_label|small|- Added /gem command|left|4|\nadd_label|small|- Added /weather command.|left|4|\nadd_label|small|- New guest name|left|4|\nadd_label|small|- Added admin command /nick|left|4|\nadd_label|small|- Admin now have access to private world|left|4|\nadd_label|small|- Updated to 2.983 Server!|left|4|\nadd_label|small|- Added admin command /block|left|4|\nadd_label|small|- Added admin command /invis|left|4|\nadd_label|small|- Add /weather for World Owner! Now is not visual!|left|4|\nadd_label|small|- Added /sweather command same /weather but visual!|left|4|\nadd_label|small|- Added admin command /spawn!|left|4|\nadd_label|small|- Added Level System!!!|left|4|\nadd_spacer|small|\nadd_label|small|`$- The Private Server Team.|left|4|\nadd_spacer|small|\nadd_label|small|`4Make sure to Join Dark's New discord server!|left|4|\nadd_url_button||``New discord server!``|NOFLAGS|https://discord.gg/G6nqzGG| Join discord server?|0|0|\nadd_spacer|small|\nadd_label_with_icon|small|`4WARNING:`` `5Worlds (and accounts)`` might be deleted at any time if database issues appear (once per day or week).|left|4|\nadd_label_with_icon|small|`4WARNING:`` `5Accounts`` are in beta, bugs may appear and they will be probably deleted often, because of new accounts updates, which will cause database incompatibility.|left|4|\nadd_spacer|small|\nadd_spacer|small|\nadd_url_button||``Growtopia Noobs youtube channel``|NOFLAGS|https://www.youtube.com/channel/UCLXtuoBlrXFDRtFU8vPy35g|Open link?|0|0|\nadd_url_button||``Items: `1Items database by Nenkai``|NOFLAGS|https://raw.githubusercontent.com/Nenkai/GrowtopiaItemDatabase/master/GrowtopiaItemDatabase/CoreData.txt|Open link?|0|0|\nadd_url_button||``Discord: `1Make sure to Join our discord server!``|NOFLAGS|https://discord.gg/G6nqzGG| Join discord server?|0|0|\nadd_url_button||`wDeveloper's world: `1START`` by `#Dark```|NOFLAGS|OPENWORLD|START|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nadd_spacer|small|\nnend_dialog|gazette||OK|"));
	string discord = "https://discord.gg/srJT4s";

	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), news));

	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);

	//enet_host_flush(server);
	delete p.data;

}



void sendAction(ENetPeer* peer, int netID, string action)
{
	ENetPeer * currentPeer;
	string name = "";
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnAction"), action));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {

			memcpy(p2.data + 8, &netID, 4);
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2);

			//enet_host_flush(server);
		}
	}

	delete p2.data;
}


// droping items WorldObjectMap::HandlePacket








void sendWorldOffers(ENetPeer* peer)
{
	if (!((PlayerInfo*)(peer->data))->isIn) return;
	vector<WorldInfo> worlds = worldDB.getRandomWorlds();
	string worldOffers = "default|";
	if (worlds.size() > 0) {
		worldOffers += worlds[0].name;
	}

	worldOffers += "\nadd_button|Showing: `wBest Worlds``|_catselect_|0.6|3529161471|\n";
	for (int i = 0; i < worlds.size(); i++) {
		worldOffers += "add_floater|" + worlds[i].name + "|" + std::to_string(getPlayersCountInWorld(worlds[i].name)) + "|0.55|3529161471\n";
	}
	//GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
	GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), worldOffers));
	ENetPacket * packet3 = enet_packet_create(p3.data,
		p3.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete p3.data;
	//enet_host_flush(server);
}





BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
	saveAllWorlds();

	return FALSE;
}

void showWrong(ENetPeer * peer, string listFull, string itemFind) {
	GamePacket fff = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFind item: " + itemFind + "``|left|206|\nadd_spacer|small|\n" + listFull + "add_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\n"));
	ENetPacket * packetd = enet_packet_create(fff.data,
		fff.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packetd);

	//enet_host_flush(server);
	delete fff.data;
}

/*
action|log
msg|`4UPDATE REQUIRED!`` : The `$V2.981`` update is now available for your device.  Go get it!  You'll need to install it before you can play online.
[DBG] Some text is here: action|set_url
url|http://ubistatic-a.akamaihd.net/0098/20180909/GrowtopiaInstaller.exe
label|Download Latest Version
*/
int _tmain(int argc, _TCHAR* argv[])
{
	/*
	999 super admin
	200 donator/mod
	100 vip
	800 can ban
	*/


	cout << "Growtopia   private server (c) Growtopia Noobs" << endl;
	enet_initialize();
	if (atexit(saveAllWorlds)) {
		cout << "Worlds won't be saved for this session..." << endl;
	}
	/*if (RegisterApplicationRestart(L" -restarted", 0) == S_OK)
	{
	cout << "Autorestart is ready" << endl;
	}
	else {
	cout << "Binding autorestart failed!" << endl;
	}
	Sleep(65000);
	int* p = NULL;
	*p = 5;*/
	SetConsoleCtrlHandler(HandlerRoutine, true);

	// load items.dat
	{
		std::ifstream file("items.dat", std::ios::binary | std::ios::ate);
		itemsDatSize = file.tellg();


		itemsDat = new BYTE[60 + itemsDatSize];
		string asdf = "0400000010000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		for (int i = 0; i < asdf.length(); i += 2)
		{
			char x = ch2n(asdf[i]);
			x = x << 4;
			x += ch2n(asdf[i + 1]);
			memcpy(itemsDat + (i / 2), &x, 1);
			if (asdf.length() > 60 * 2) throw 0;
		}
		memcpy(itemsDat + 56, &itemsDatSize, 4);
		file.seekg(0, std::ios::beg);

		if (file.read((char*)(itemsDat + 60), itemsDatSize))
		{
			cout << "Updating items data suecess!" << endl;

		}
		else {
			cout << "Updating items data failed!" << endl;
		}
	}


	//world = generateWorld();
	worldDB.get("TEST");
	worldDB.get("MAIN");
	worldDB.get("NEW");
	worldDB.get("ADMIN");
	worldDB.get("START");

	ENetAddress address;
	/* Bind the server to the default localhost.     */
	/* A specific host address can be specified by   */
	enet_address_set_host(&address, "0.0.0.0");
	//address.host = ENET_HOST_ANY;
	/* Bind the server to port 1234. */
	address.port = 17091;
	server = enet_host_create(&address /* the address to bind the server host to */,
		1024      /* allow up to 32 clients and/or outgoing connections */,
		5     /* allow up to 2 channels to be used, 0 and 1 */,
		0      /* assume any amount of incoming bandwidth */,
		0      /* assume any amount of outgoing bandwidth */);
	if (server == NULL)
	{
		fprintf(stderr,
			"An error occurred while trying to create an ENet server host.\n");
		while (1);
		exit(EXIT_FAILURE);
	}
	server->checksum = enet_crc32;
	enet_host_compress_with_range_coder(server);

	cout << "Building items database..." << endl;
	buildItemsDatabase();
	cout << "Database is built!" << endl;

	ENetEvent event;
	/* Wait up to 1000 milliseconds for an event. */
	while (true)
		while (enet_host_service(server, &event, 1000) > 0)
		{
			ENetPeer* peer = event.peer;
			switch (event.type)
			{
			case ENET_EVENT_TYPE_CONNECT:
			{
#ifdef TOTAL_LOG
				printf("A new client connected.\n");
#endif
				/* Store any relevant client information here. */
				//event.peer->data = "Client information";
				ENetPeer * currentPeer;
				int count = 0;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (currentPeer->address.host == peer->address.host)
						count++;
				}

				event.peer->data = new PlayerInfo;
				if (count > 5)
				{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Too much accounts are logged on from this IP. If you don't think so, then please let server relax and connect again in half minute or so.``"));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					enet_peer_disconnect_later(peer, 0);
				}
				else {
					sendData(peer, 1, 0, 0);
				}


				continue;
			}
			case ENET_EVENT_TYPE_RECEIVE:
			{
				if (((PlayerInfo*)(peer->data))->isUpdating)
				{
					cout << "packet drop" << endl;
					continue;
				}
				/*printf("A packet of length %u containing %s was received from %s on channel %u.\n",
				event.packet->dataLength,
				event.packet->data,
				event.peer->data,
				event.channelID);
				cout << (int)*event.packet->data << endl;*/
				//cout << text_encode(getPacketData((char*)event.packet->data));
				/*for (int i = 0; i < event.packet->dataLength; i++)
				{
				cout << event.packet->data[i];
				}
				sendData(7, 0, 0);
				string x = "eventType|0\neventName|102_PLAYER.AUTHENTICATION\nAuthenticated|0\nAuthentication_error|6\nDevice_Id|^^\nGrow_Id|0\nName|^^Elektronik\nWordlock_balance|0\n";
				//string x = "eventType | 0\neventName | 102_PLAYER.AUTHENTICATION\nAuthenticated | 0\nAuthentication_error | 6\nDevice_Id | ^^\nGrow_Id | 0\nName | ^^Elektronik\nWorldlock_balance | 0\n";
				sendData(6, (char*)x.c_str(), x.length());
				string y = "action|quit\n";
				sendData(3, (char*)y.c_str(), y.length());
				cout << endl;
				string asdf = "0400000001000000FFFFFFFF0000000008000000000000000000000000000000000000000000000000000000000000000000000000000000400000000600020E0000004F6E53656E64546F5365727665720109ED4200000209834CED00030910887F0104020D0000003230392E35392E3139302E347C05090100000000C";
				//asdf = "0400000001000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000040000000060002220000004F6E53757065724D61696E53746172744163636570744C6F676F6E464232313131330109ED4200000209834CED00030910887F0104020D0000003230392E35392E3139302E347C05090100000000C";
				ENetPacket * packet = enet_packet_create(0,
				asdf.length()/2,
				ENET_PACKET_FLAG_RELIABLE);
				for (int i = 0; i < asdf.length(); i += 2)
				{
				char x = ch2n(asdf[i]);
				x = x << 4;
				x += ch2n(asdf[i + 1]);
				memcpy(packet->data + (i / 2), &x, 1);
				}
				enet_peer_send(peer, 0, packet);
				enet_host_flush(server);
				/* Clean up the packet now that we're done using it. */
				//enet_packet_destroy(event.packet);
				//sendData(7, 0, 0);
				int messageType = GetMessageTypeFromPacket(event.packet);
				//cout << "Packet type is " << messageType << endl;
				//cout << (event->packet->data+4) << endl;
				WorldInfo* world = getPlyersWorld(peer);
				switch (messageType) {
				case 2:
				{
					//cout << GetTextPointerFromPacket(event.packet) << endl;
					string cch = GetTextPointerFromPacket(event.packet);
					string str = cch.substr(cch.find("text|") + 5, cch.length() - cch.find("text|") - 1);
					cout << cch << endl;
					if (cch.find("action|respawn") == 0)
					{
						int x = 3040;
						int y = 736;

						if (!world) continue;

						for (int i = 0; i < world->width*world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i%world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						{
							PlayerMoving data;
							data.packetType = 0x0;
							data.characterState = 0x924; // animation
							data.x = x;
							data.y = y;
							data.punchX = -1;
							data.punchY = -1;
							data.XSpeed = 0;
							data.YSpeed = 0;
							data.netID = ((PlayerInfo*)(peer->data))->netID;
							data.plantingTree = 0x0;
							SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
						}

						{
							int x = 3040;
							int y = 736;

							for (int i = 0; i < world->width*world->height; i++)
							{
								if (world->items[i].foreground == 6) {
									x = (i%world->width) * 32;
									y = (i / world->width) * 32;
								}
							}
							GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							//enet_host_flush(server);
						}
						{
							int x = 3040;
							int y = 736;

							for (int i = 0; i < world->width*world->height; i++)
							{
								if (world->items[i].foreground == 6) {
									x = (i%world->width) * 32;
									y = (i / world->width) * 32;
								}
							}
							GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							//enet_host_flush(server);
						}
#ifdef TOTAL_LOG
						cout << "Respawning... " << endl;
#endif
					}
					if (cch.find("action|growid") == 0)
					{
#ifndef REGISTRATION
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Registration is not supported yet!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}
#endif
#ifdef REGISTRATION
						//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGet your GrowID Now!``|left|32|\n\nadd_spacer|small|\nadd_text_input|username|GrowID: ||15|\nadd_text_input|password|Password: ||100|\nend_dialog|register|Cancel|OK|\n"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						enet_host_flush(server);
						delete p.data;
#endif
					}
					if (cch.find("action|store") == 0)
					{
						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|Welcome to the `2Growtopia Store``!  Tap the item you'd like more info on.`o  `wWant to get `5Supporter`` status? Any Gem purchase (or `57,000`` Gems earned with free `5Tapjoy`` offers) will make you one. You'll get new skin colors, the `5Recycle`` tool to convert unwanted items into Gems, and more bonuses!\nadd_button|iap_menu|Buy Gems|interface/large/store_buttons5.rttex||0|2|0|0||\nadd_button|subs_menu|Subscriptions|interface/large/store_buttons22.rttex||0|1|0|0||\nadd_button|token_menu|Growtoken Items|interface/large/store_buttons9.rttex||0|0|0|0||\nadd_button|pristine_forceps|`oAnomalizing Pristine Bonesaw``|interface/large/store_buttons20.rttex|Built to exacting specifications by GrowTech engineers to find and remove temporal anomalies from infected patients, and with even more power than Delicate versions! Note : The fragile anomaly - seeking circuitry in these devices is prone to failure and may break (though with less of a chance than a Delicate version)! Use with care!|0|3|3500|0||\nadd_button|itemomonth|`oItem Of The Month``|interface/large/store_buttons16.rttex|`2September 2018:`` `9Sorcerer's Tunic of Mystery!`` Capable of reflecting the true colors of the world around it, this rare tunic is made of captured starlight and aether. If you think knitting with thread is hard, just try doing it with moonbeams and magic! The result is worth it though, as these clothes won't just make you look amazing - you'll be able to channel their inherent power into blasts of cosmic energy!``|0|3|200000|0||\nadd_button|contact_lenses|`oContact Lens Pack``|interface/large/store_buttons22.rttex|Need a colorful new look? This pack includes 10 random Contact Lens colors (and may include Contact Lens Cleaning Solution, to return to your natural eye color)!|0|7|15000|0||\nadd_button|locks_menu|Locks And Stuff|interface/large/store_buttons3.rttex||0|4|0|0||\nadd_button|itempack_menu|Item Packs|interface/large/store_buttons3.rttex||0|3|0|0||\nadd_button|bigitems_menu|Awesome Items|interface/large/store_buttons4.rttex||0|6|0|0||\nadd_button|weather_menu|World Lock Pack|interface/large/store_buttons18.rttex|This pack contains 10 World locks!|0|3|1||\n"));
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}

					if (cch.find("action|help") == 0)
					{
						GamePacket help = packetEnd(appendString(appendString(createPacket(), "OnHelpRequest"), "set_description_text|Welcome to the `2unknown page``!  |\nadd_button|token_menu|Growtoken Items|interface/large/store_buttons9.rttex||0|0|0|0||\nadd_button|pristine_forceps|`oAnomalizing Pristine Bonesaw``|interface/large/store_buttons20.rttex|Built to exacting specifications by GrowTech engineers to find and remove temporal anomalies from infected patients, and with even more power than Delicate versions! Note : The fragile anomaly - seeking circuitry in these devices is prone to failure and may break (though with less of a chance than a Delicate version)! Use with care!|0|3|3500|0||\nadd_button|itemomonth|`oItem Of The Month``|interface/large/store_buttons16.rttex|`2September 2018:`` `9Sorcerer's Tunic of Mystery!`` Capable of reflecting the true colors of the world around it, this rare tunic is made of captured starlight and aether. If you think knitting with thread is hard, just try doing it with moonbeams and magic! The result is worth it though, as these clothes won't just make you look amazing - you'll be able to channel their inherent power into blasts of cosmic energy!``|0|3|200000|0||\nadd_button|contact_lenses|`oContact Lens Pack``|interface/large/store_buttons22.rttex|Need a colorful new look? This pack includes 10 random Contact Lens colors (and may include Contact Lens Cleaning Solution, to return to your natural eye color)!|0|7|15000|0||\nadd_button|locks_menu|Locks And Stuff|interface/large/store_buttons3.rttex||0|4|0|0||\nadd_button|itempack_menu|Item Packs|interface/large/store_buttons3.rttex||0|3|0|0||\nadd_button|bigitems_menu|Awesome Items|interface/large/store_buttons4.rttex||0|6|0|0||\nadd_button|weather_menu|Weather Machines|interface/large/store_buttons5.rttex|Tired of the same sunny sky?  We offer alternatives within...|0|4|0|0||\n"));
						ENetPacket * packet22 = enet_packet_create(help.data,
							help.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet22);
						delete help.data;
						//enet_host_flush(server);
					}

					if (cch.find("action|friends") == 0)
					{
						if (((PlayerInfo*)(peer->data))->joinguild == true) {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|showguild|Show Guild Members``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						else {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|createguildinfo|Create Guild``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}

					}

					/*
					if (cch.find("action|wrench") == 0) {
					std::stringstream ss(cch);
					std::string to;
					int netid = -1;
					while (std::getline(ss, to, '\n')) {
					vector<string> infoDat = explode("|", to);
					if (infoDat[1] == "netid") {
					netid = atoi(infoDat[2].c_str());
					}
					}
					ENetPeer * currentPeer;
					for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
					{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
					if (((PlayerInfo*)(currentPeer->data))->netID == netid) {
					string name = ((PlayerInfo*)(currentPeer->data))->Chatname;
					string money = std::to_string(((PlayerInfo*)(currentPeer->data))->gem);
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + name + "|left|18|\n\nadd_spacer|\n\nadd_textbox|`6Player has:`` `r" + money + "```t$```6 in his wallet!``|left|small|\n\nadd_spacer|\n\nadd_textbox|`6Player rank:`` (`wplayer has no rank``)|left|small|\nadd_label_with_icon|small|\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|\nadd_spacer|small|\n"));
					ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);

					enet_host_flush(server);
					delete p.data;
					break;
					}
					}
					}*/

					if (cch.find("action|wrench") == 0)
					{
						std::stringstream ss(cch);
						std::string to;
						int netid = -1;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat[1] == "netid") {
								netid = atoi(infoDat[2].c_str());
							}
						}
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (((PlayerInfo*)(currentPeer->data))->netID == netid) {
								((PlayerInfo*)(peer->data))->lastInfoTrue = ((PlayerInfo*)(currentPeer->data))->Chatname;
								((PlayerInfo*)(peer->data))->lastInfo = ((PlayerInfo*)(currentPeer->data))->rawName;
								((PlayerInfo*)(peer->data))->lastInfoWorld = ((PlayerInfo*)(currentPeer->data))->currentWorld;
								//	((PlayerInfo*)(peer->data))->lastfriend = ((PlayerInfo*) (currentPeer->data))->rawName;
								string name = ((PlayerInfo*)(currentPeer->data))->Chatname;
								string levels = std::to_string(((PlayerInfo*)(currentPeer->data))->level);
								string gems = std::to_string(((PlayerInfo*)(currentPeer->data))->gem);
								int blocksbroken = ((PlayerInfo*)(currentPeer->data))->blockbroken;


								string fg, bg, guildname;

								string guildleader = ((PlayerInfo*)(peer->data))->guildLeader;





								if (currentPeer == peer) {
									if (((PlayerInfo*)(currentPeer->data))->isinvited == true) {
										GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_player_info|" + name + "|" + levels + "|" + std::to_string(blocksbroken) + "|150|\nadd_spacer|small|\nadd_label_with_icon|small|`wBlocks Required To Level Up = `2" + std::to_string(150 - blocksbroken) + " `w!|left|2|\nadd_button|joinguild|`2Join Guild " + ((PlayerInfo*)(currentPeer->data))->guildlast + "!|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

										ENetPacket * packet22 = enet_packet_create(wrench.data,
											wrench.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet22);
										delete wrench.data;
									}
									else {
										GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_player_info|" + name + "|" + levels + "|" + std::to_string(blocksbroken) + "|150|\nadd_spacer|small|\nadd_label_with_icon|small|`wBlocks Required To Level Up = `2" + std::to_string(150 - blocksbroken) + " `w!|left|2|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

										ENetPacket * packet22 = enet_packet_create(wrench.data,
											wrench.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet22);
										delete wrench.data;
									}

								}
								else {
									if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 199) {
										if (((PlayerInfo*)(peer->data))->rawName == guildleader) {


											if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
												if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|worldbanbutton|`4World Ban|0|0| \nadd_button|inviteguildbutton|`2Invite to guild``|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;

												}
												else {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|infobutton|`wInfo|0|0|\nadd_button|banbutton|`4Ban|0|0|\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
											}
											else {
												if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|infobutton|`wInfo|0|0|\nadd_button|banbutton|`4Ban|0|0|  \nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
												else {
													if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
														GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|infobutton|`wInfo|0|0|\nadd_button|banbutton|`4Ban|0|0|\nadd_button|inviteguildbutton|`2Invite to guild``|0|0| \nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

														ENetPacket * packet22 = enet_packet_create(wrench.data,
															wrench.len,
															ENET_PACKET_FLAG_RELIABLE);

														enet_peer_send(peer, 0, packet22);
														delete wrench.data;

													}
													else {
														GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|infobutton|`wInfo|0|0|\nadd_button|banbutton|`4Ban|0|0|\nadd_button|inviteguildbutton|`2Invite to guild``|0|0|\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

														ENetPacket * packet22 = enet_packet_create(wrench.data,
															wrench.len,
															ENET_PACKET_FLAG_RELIABLE);

														enet_peer_send(peer, 0, packet22);
														delete wrench.data;
													}
												}
											}
										}


										else {
											if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) {
												GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small| \nadd_button||Continue|0|0|\nadd_quick_exit"));

												ENetPacket * packet22 = enet_packet_create(wrench.data,
													wrench.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(peer, 0, packet22);
												delete wrench.data;
											}
											else {
												if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|infobutton|`wInfo|0|0|\nadd_button|banbutton|`4Ban|0|0| \nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
												else {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|infobutton|`wInfo|0|0|\nadd_button|banbutton|`4Ban|0|0|\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
											}

										}
									}
									else if (((PlayerInfo*)(peer->data))->rawName == world->owner) {
										if (((PlayerInfo*)(peer->data))->rawName == guildleader) {
											if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
												if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|worldbanbutton|`4World Ban|0|0| \nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;

												}
												else {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|worldbanbutton|`4World Ban|0|0|\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
											}
											else {
												if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|worldbanbutton|`4World Ban|0|0| \nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
												else {
													if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
														GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|worldbanbutton|`4World Ban|0|0| \nadd_button|inviteguildbutton|`2Invite to guild``|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

														ENetPacket * packet22 = enet_packet_create(wrench.data,
															wrench.len,
															ENET_PACKET_FLAG_RELIABLE);

														enet_peer_send(peer, 0, packet22);
														delete wrench.data;

													}
													else {
														GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|worldbanbutton|`4World Ban|0|0|\nadd_button|inviteguildbutton|`2Invite to guild``|0|0|\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

														ENetPacket * packet22 = enet_packet_create(wrench.data,
															wrench.len,
															ENET_PACKET_FLAG_RELIABLE);

														enet_peer_send(peer, 0, packet22);
														delete wrench.data;
													}
												}
											}
										}

										else {
											if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) {
												GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small| \nadd_button||Continue|0|0|\nadd_quick_exit"));

												ENetPacket * packet22 = enet_packet_create(wrench.data,
													wrench.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(peer, 0, packet22);
												delete wrench.data;
											}
											else {
												if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|worldbanbutton|`4World Ban|0|0| \nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;

												}
												else {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|kickbutton|`4Kick|0|0|\nadd_button|pullbutton|`5Pull|0|0|\nadd_button|worldbanbutton|`4World Ban|0|0|\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
											}
										}

									}

									else {
										if (((PlayerInfo*)(peer->data))->rawName == guildleader) {
											if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
												if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|  \nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;

												}
												else {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small| \nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
											}
											else {
												if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|   \nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
												else {
													if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
														GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|  \nadd_button|inviteguildbutton|`2Invite to guild``|0|0|\nadd_button||Continue|0|0|\nadd_quick_exit"));

														ENetPacket * packet22 = enet_packet_create(wrench.data,
															wrench.len,
															ENET_PACKET_FLAG_RELIABLE);

														enet_peer_send(peer, 0, packet22);
														delete wrench.data;

													}
													else {
														GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|inviteguildbutton|`2Invite to guild``|0|0|\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_button||Continue|0|0|\nadd_quick_exit"));

														ENetPacket * packet22 = enet_packet_create(wrench.data,
															wrench.len,
															ENET_PACKET_FLAG_RELIABLE);

														enet_peer_send(peer, 0, packet22);
														delete wrench.data;
													}
												}
											}
										}

										// else not guild leader
										else {
											// check added friend then remove add friend button

											if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) {
												GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small| \nadd_button||Continue|0|0|\nadd_quick_exit"));

												ENetPacket * packet22 = enet_packet_create(wrench.data,
													wrench.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(peer, 0, packet22);
												delete wrench.data;
											}
											else {
												if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small| \nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
													//enet_host_flush(server);
												}
												else {
													// add friend button
													GamePacket wrench = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`0\n\nadd_label_with_icon|big|`w" + name + " `w(`2" + levels + "`w)|left|18|\nadd_spacer|small|\nadd_label_with_icon|small|`wGems = `2" + gems + "|left|112|\nadd_spacer|small|\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_button||Continue|0|0|\nadd_quick_exit"));

													ENetPacket * packet22 = enet_packet_create(wrench.data,
														wrench.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet22);
													delete wrench.data;
												}
											}
										}

									}
								}
							}
						}
					}


					if (cch.find("action|info") == 0)
					{
						std::stringstream ss(cch);
						std::string to;
						int id = -1;
						int count = -1;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 3) {
								if (infoDat[1] == "itemID") id = atoi(infoDat[2].c_str());
								if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
							}
						}
						if (id == -1 || count == -1) continue;
						if (itemDefs.size() < id || id < 0) continue;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + " <" + std::to_string(id) + ">``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}

					string dropText = "action|drop\n|itemID|";
					if (cch.find(dropText) == 0)
					{

						//      sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y, atoi(cch.substr(dropText.length(), cch.length() - dropText.length() - 1).c_str()), 0, 0);
						std::stringstream ss(cch);
						std::string to;
						int idx = -1;
						int count = -1;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 3) {
								if (infoDat[1] == "itemID") idx = atoi(infoDat[2].c_str());
								if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
							}
						}
						((PlayerInfo*)(peer->data))->lastdropitem = idx;
						((PlayerInfo*)(peer->data))->lastdropitemcount = count;
						if (idx == -1) continue;
						if (itemDefs.size() < idx || idx < 0) continue;
						if (((PlayerInfo*)(peer->data))->lastdropitem == 18 || ((PlayerInfo*)(peer->data))->lastdropitem == 32) {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You can't drop that."));
							ENetPacket * packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
							continue;
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wDrop " + itemDefs.at(idx).name + "``|left|" + std::to_string(idx) + "|\nadd_textbox|`oHow many to drop?|\nadd_text_input|dropitemcount|||3|\nend_dialog|dropdialog|Cancel|Ok|\n"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
					}


					if (cch.find("action|dialog_return") == 0)
					{
						std::stringstream ss(cch);
						std::string to;
						string btn = "";
						bool isRegisterDialog = false;
						string username = "";
						string password = "";

						bool isMSGDialog = false;
						string messagez = "";

						bool isFindDialog = false;
						string itemFind = "";

						bool isDropDialog = false;
						string dropitemcount = "";
						string netid = "";
						bool Accesspicker = false;
						string showloc = "";
						string notif = "";
						bool showlocs = false;
						bool shownotification = false;

						bool isGuildDialog = false;
						string guildName = "";
						string guildStatement = "";
						string guildFlagBg = "";
						string guildFlagFg = "";
						//int id = 0;
						//int dropitemcount = 0;

						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);

							if (infoDat.size() == 2) {
								if (infoDat[0] == "buttonClicked") btn = infoDat[1];
								if (infoDat[0] == "checkbox_public") showloc = infoDat[1];
								if (infoDat[0] == "checkbox_notifications") notif = infoDat[1];

								if (showloc != "") {
									if (showloc == "1") {
										showlocs = true;
									}
									else {
										showlocs = false;
									}
								}

								if (notif != "") {
									if (notif == "1") {
										shownotification = true;
									}
									else {
										shownotification = false;
									}
								}

								if (infoDat[0] == "dialog_name" && infoDat[1] == "register")
								{
									isRegisterDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "msgdia")
								{
									isMSGDialog = true;
								}
								if (isMSGDialog) {

									if (infoDat[0] == "msgtext") messagez = infoDat[1];
								}

								if (isRegisterDialog) {
									if (infoDat[0] == "username") username = infoDat[1];

									if (infoDat[0] == "password") password = infoDat[1];
								}

								if (infoDat[0] == "dialog_name" && infoDat[1] == "findid")
								{
									isFindDialog = true;
								}
								if (isFindDialog) {
									if (infoDat[0] == "item") itemFind = infoDat[1];
								}

								if (infoDat[0] == "dialog_name" && infoDat[1] == "dropdialog")
								{
									isDropDialog = true;
								}
								if (isDropDialog) {
									if (infoDat[0] == "dropitemcount") dropitemcount = infoDat[1];

								}



								if (infoDat[0] == "dialog_name" && infoDat[1] == "wlmenu")
								{
									Accesspicker = true;
								}
								if (Accesspicker) {
									if (infoDat[0] == "netid") netid = infoDat[1];

								}



								if (infoDat[0] == "dialog_name" && infoDat[1] == "guildconfirm")
								{
									isGuildDialog = true;
								}
								if (isGuildDialog) {
									if (infoDat[0] == "gname") guildName = infoDat[1];
									if (infoDat[0] == "gstatement") guildStatement = infoDat[1];
									if (infoDat[0] == "ggcflagbg") guildFlagBg = infoDat[1];
									if (infoDat[0] == "ggcflagfg") guildFlagFg = infoDat[1];
								}

								if (infoDat[0] == "isWorldPublic" && infoDat[1] == "1")
								{
									if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = true;
								}
								if (infoDat[0] == "isWorldPublic" && infoDat[1] == "0")
								{
									if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = false;
								}

							}



						}
						if (Accesspicker) {
							GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "aaaaaaaaaaaaaa"));
							ENetPacket * packet1 = enet_packet_create(p1.data,
								p1.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet1);
							delete p1.data;


						}
						if (isMSGDialog) {

							ENetPeer * currentPeer;
							if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oTo prevent abuse, you `4must `obe `2registered `oin order to use this feature!"));
								ENetPacket * packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet0);
								delete p0.data;
								continue;
							}
							{
								if (((PlayerInfo*)(peer->data))->mute == 1) {
									GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oThis feature `4can't `obe used while you are `4muted`o!"));
									ENetPacket * packet1 = enet_packet_create(p1.data,
										p1.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet1);
									delete p1.data;
									continue;
								}

							}


							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastFrn) {

									((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
									((PlayerInfo*)(currentPeer->data))->lastMsgerTrue = ((PlayerInfo*)(peer->data))->displayName;
									((PlayerInfo*)(currentPeer->data))->lastMsgWorld = ((PlayerInfo*)(peer->data))->currentWorld;
									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `2" + ((PlayerInfo*)(currentPeer->data))->displayName + "`6)"));
									ENetPacket * packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `2" + ((PlayerInfo*)(peer->data))->displayName + "`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + messagez + "`o"));
									string text = "action|play_sfx\nfile|audio/pay_time.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete data;
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete ps.data;

								}
							}
						}

						if (isGuildDialog) {


							int GCState = PlayerDB::guildRegister(peer, guildName, guildStatement, guildFlagFg, guildFlagBg);
							if (GCState == -1) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oSpecial characters are not allowed in Guild name.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -2) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild name you've entered is too short.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -3) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild name you've entered is too long.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -4) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild name you've entered is already taken.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -5) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild Flag Background ID you've entered must be a number.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -6) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild Flag Foreground ID you've entered must be a number.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -7) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild Flag Background ID you've entered is too long or too short.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -8) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild Flag Foreground ID you've entered is too long or too short.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (world->owner != ((PlayerInfo*)(peer->data))->rawName) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oYou must make guild in world you owned!``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							else {
								if (GCState == 1) {

									((PlayerInfo*)(peer->data))->createGuildName = guildName;
									((PlayerInfo*)(peer->data))->createGuildStatement = guildStatement;


									((PlayerInfo*)(peer->data))->createGuildFlagBg = guildFlagBg;
									((PlayerInfo*)(peer->data))->createGuildFlagFg = guildFlagFg;

									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild|left|5814|\nadd_textbox|`1Guild Name: `o" + guildName + "``|\nadd_textbox|`1Guild Statement: `o" + guildStatement + "``|\nadd_label_with_icon|small|`1<-Guild Flag Background``|left|" + guildFlagBg + "|\nadd_label_with_icon|small|`1<-Guild Flag Foreground``|left|" + guildFlagFg + "|\n\nadd_spacer|small|\nadd_textbox|`oCost: `4250,000 Gems``|\n\nadd_spacer|small|\nadd_button|confirmcreateguild|`oCreate Guild``|\nend_dialog||`wCancel``||\n"));
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete ps.data;

								}
							}
						}

						if (isDropDialog) {
							int x;

							try {
								x = stoi(dropitemcount);
							}
							catch (std::invalid_argument& e) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Please enter how many u want to drop"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								continue;
							}
							if (x < 0 || x >200) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "That too many or too less to drop"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								continue;
							}

							else {

								
							}
						}

						if (btn == "worldPublic") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = true;
						if (btn == "worldPrivate") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = false;


						/*	if (btn == "doormoverbutton") {
						//if (isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {

						for (int i = 0;i < world->width*world->height;i++)
						{
						if (i >=5400) {
						world->items[i].foreground = 8;
						}
						else if (world->items[i].foreground == 6) {

						world->items[i].foreground = 0;
						world->items[i + 100].foreground = 0;

						}

						else if (world->items[i].foreground != 6) {
						world->items[x + (y*world->width)].foreground = 6;
						world->items[x + (y*world->width)+100].foreground = 8;
						}


						}

						WorldInfo* wrld = getPlyersWorld(peer);
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (isHere(peer, currentPeer))
						{
						string act = ((PlayerInfo*)(peer->data))->currentWorld;
						//WorldInfo info = worldDB.get(act);
						// sendWorld(currentPeer, &info);


						sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
						joinWorld(currentPeer, act, 0, 0);
						updateAllClothes(peer);
						((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 1000;
						GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "you used door mover!"));
						ENetPacket * packet8 = enet_packet_create(p8.data,
						p8.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet8);

						}

						}
						} */



						if (btn == "pullbutton") {
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{

									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) {

										int x = ((PlayerInfo*)(peer->data))->x;
										int y = ((PlayerInfo*)(peer->data))->y;

										GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
										memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
										ENetPacket * packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										delete p2.data;

										/*GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o" + ((PlayerInfo*)(peer->data))->Chatname + " `5pulls `o" + ((PlayerInfo*)(currentPeer->data))->Chatname + "!"));
										string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);
										ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										delete data;
										ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet);
										delete ps.data;*/
										GamePacket p23 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wYou were pulled by " + ((PlayerInfo*)(peer->data))->Chatname));
										ENetPacket * packet23 = enet_packet_create(p23.data,
											p23.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet23);
										delete p23.data;
									}
									{
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o" + ((PlayerInfo*)(peer->data))->Chatname + " `5pulls `o" + ((PlayerInfo*)(peer->data))->lastInfo + "!"));
										string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);
										ENetPacket * packet2 = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										delete data;
										ENetPacket * packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet);
										delete ps.data;

									}
								}
							}

						}





						if (btn == "kickbutton") {
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{

									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) {
										sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
										((PlayerInfo*)(currentPeer->data))->currentWorld = "EXIT";
										sendWorldOffers(currentPeer);
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wYou were `4kicked`w by " + ((PlayerInfo*)(peer->data))->Chatname));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet);
										delete p.data;
										/*GamePacket p22 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o" + ((PlayerInfo*)(peer->data))->Chatname + " `4kick `o" + ((PlayerInfo*)(currentPeer->data))->Chatname + "!"));
										ENetPacket * packet22 = enet_packet_create(p22.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet22);
										delete p22.data;*/
									}
									{
										GamePacket p22 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o" + ((PlayerInfo*)(peer->data))->Chatname + " `4kick `o" + ((PlayerInfo*)(peer->data))->lastInfo + "!"));
										ENetPacket * packet22 = enet_packet_create(p22.data,
											p22.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet22);
									}
								}
							}
						}

						if (btn == "banbutton") {


						}

						if (btn == "joinguildzzz") {
							((PlayerInfo*)(peer->data))->guild = ((PlayerInfo*)(peer->data))->guildlast;
							((PlayerInfo*)(peer->data))->isinvited = false;
							((PlayerInfo*)(peer->data))->joinguild = true;

							string fixedguildName = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild);

							/*
							std::ifstream ifs2("guilds/" + fixedguildName + ".json");
							if (ifs2.fail()) {
							ifs2.close();
							}
							if (ifs2.is_open()) {

							}
							json j2;
							ifs2 >> j2;*/

							guildmem.push_back(((PlayerInfo*)(peer->data))->rawName);

							std::ifstream ifff("guilds/" + fixedguildName + ".json");
							if (ifff.fail()) {
								ifff.close();
								continue;
							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["Member"] = guildmem; //edit

							std::ofstream o("guilds/" + fixedguildName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}
							o << j << std::endl;
						}

						if (btn == "inviteguildbutton") {
							if (((PlayerInfo*)(peer->data))->guild != "") {
								int number = ((PlayerInfo*)(peer->data))->guildmatelist.size();
								if (number > 9) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND ERROR: `oYou already have `450 `ofriends! Please remove some before adding new ones!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
									continue;
								}
								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) {
											string name = ((PlayerInfo*)(currentPeer->data))->rawName;
											if (((PlayerInfo*)(currentPeer->data))->guild != "") {
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3GUILD ERROR: `w" + ((PlayerInfo*)(currentPeer->data))->displayName + "`o is already in a Guild!"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
											else {
												GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5[`wGuild request sent to `2" + ((PlayerInfo*)(currentPeer->data))->displayName + "`5]"));
												ENetPacket * packet4 = enet_packet_create(p4.data,
													p4.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(peer, 0, packet4);
												delete p4.data;
												string text = "action|play_sfx\nfile|audio/tip_start.wav\ndelayMS|0\n";
												BYTE* data = new BYTE[5 + text.length()];
												BYTE zero = 0;
												int type = 3;
												memcpy(data, &type, 4);
												memcpy(data + 4, text.c_str(), text.length());
												memcpy(data + 4 + text.length(), &zero, 1);
												ENetPacket * packet2 = enet_packet_create(data,
													5 + text.length(),
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet2);
												delete data;
												((PlayerInfo*)(currentPeer->data))->guildlast = ((PlayerInfo*)(peer->data))->guild;
												((PlayerInfo*)(currentPeer->data))->isinvited = true;
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[GUILD REQUEST] `oYou've been invited to join `2" + ((PlayerInfo*)(peer->data))->guild + "`o by `w" + ((PlayerInfo*)(peer->data))->displayName + "`o! To accept, `wwrench yourself `oand then choose `2Join " + ((PlayerInfo*)(peer->data))->guild + "`o."));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet);
												delete p.data;
											}
										}
									}
								}
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[GUILD ERROR] `oYou must be in a Guild as a Elder or higher in order to invite players!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "joinguild") {
							vector<string> gmembers;
							string guildname = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guildlast);
							if (guildname != "") {
								std::ifstream ifff("guilds/" + guildname + ".json");
								if (ifff.fail()) {
									ifff.close();
									cout << "Failed loading guilds/" + guildname + ".json! From " + ((PlayerInfo*)(peer->data))->displayName + "." << endl;
								}
								json j;
								ifff >> j;

								for (int i = 0; i < j["Member"].size(); i++) {
									gmembers.push_back(j["Member"][i]);
								}

								ifff.close();

								int membercount = gmembers.size();

								if (membercount > 14) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[GUILD ALERT] `oThat guild is already full!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								else {
									((PlayerInfo*)(peer->data))->guild = ((PlayerInfo*)(peer->data))->guildlast;
									((PlayerInfo*)(peer->data))->guildlast = "";
									((PlayerInfo*)(peer->data))->isinvited = false;
									((PlayerInfo*)(peer->data))->joinguild = true;
									updateInvis(peer);
									std::ifstream ifff("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
									if (ifff.fail()) {
										ifff.close();
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Error: `oGuild does not exist! If you are seeing this message, please take a screenshot and send it to a developer!"));
										ENetPacket * packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									if (ifff.is_open()) {
									}
									json j;
									ifff >> j; //load

									vector<string> gmlist;

									for (int i = 0; i < j["Member"].size(); i++) {
										gmlist.push_back(j["Member"][i]);
									}

									gmlist.push_back(((PlayerInfo*)(peer->data))->rawName);

									j["Member"] = gmlist; //edit

									std::ofstream o("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json"); //save
									if (!o.is_open()) {
										cout << GetLastError() << endl;
										_getch();
									}

									o << j << std::endl;
									ENetPeer * currentPeer;

									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (((PlayerInfo*)(currentPeer->data))->guild == ((PlayerInfo*)(peer->data))->guild)
										{
											updateGuild(peer);
											updateGuild(currentPeer);
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[GUILD ALERT] `2" + ((PlayerInfo*)(peer->data))->displayName + " `ojoined the guild!"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet);
											delete p.data;
											updateInvis(peer);
										}
									}
								}
							}
						}


						if (btn == "showguild") {
							string onlinegmlist = "";
							string grole = "";
							int onlinecount = 0;
							string guildname = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild);
							if (guildname != "") {
								std::ifstream ifff("guilds/" + guildname + ".json");
								if (ifff.fail()) {
									ifff.close();
									cout << "Failed loading guilds/" + guildname + ".json! From " + ((PlayerInfo*)(peer->data))->displayName + "." << endl;
									((PlayerInfo*)(peer->data))->guild = "";

								}
								json j;
								ifff >> j;

								int gfbg, gffg, guildlvl, guildxp;

								string gstatement, gleader;

								vector<string> gmembers;

								gfbg = j["backgroundflag"];
								gffg = j["foregroundflag"];
								gstatement = j["GuildStatement"];
								gleader = j["Leader"];
								guildlvl = j["GuildLevel"];
								guildxp = j["GuildExp"];
								for (int i = 0; i < j["Member"].size(); i++) {
									gmembers.push_back(j["Member"][i]);
								}
								((PlayerInfo*)(peer->data))->guildlevel = guildlvl;
								((PlayerInfo*)(peer->data))->guildexp = guildxp;

								((PlayerInfo*)(peer->data))->guildBg = gfbg;
								((PlayerInfo*)(peer->data))->guildFg = gffg;
								((PlayerInfo*)(peer->data))->guildStatement = gstatement;
								((PlayerInfo*)(peer->data))->guildLeader = gleader;
								((PlayerInfo*)(peer->data))->guildMembers = gmembers;

								ifff.close();
							}
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								string name = ((PlayerInfo*)(currentPeer->data))->rawName;
								if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->guildLeader) {
										onlinegmlist += "\nadd_button|onlinegm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " `e(GL)``|0|0|";
										onlinecount++;
									}
									else {
										onlinegmlist += "\nadd_button|onlinegm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " " + grole + "``|0|0|";
										onlinecount++;
									}
								}
							}
							if (((PlayerInfo*)(peer->data))->rawName == ((PlayerInfo*)(peer->data))->guildLeader) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + std::to_string(((PlayerInfo*)(peer->data))->guildBg) + "|" + std::to_string(((PlayerInfo*)(peer->data))->guildFg) + "|1.0|0|\n\nadd_spacer|small|\nadd_textbox|`oGuild Name : " + ((PlayerInfo*)(peer->data))->guild + "``|\nadd_textbox|`oStatement : " + ((PlayerInfo*)(peer->data))->guildStatement + "``|\nadd_textbox|`oGuild size: " + std::to_string(((PlayerInfo*)(peer->data))->guildMembers.size()) + "/15 members|\nadd_textbox|`oGuild Level : " + std::to_string(((PlayerInfo*)(peer->data))->guildlevel) + "|\nadd_textbox|`oGuild Exp : " + std::to_string(((PlayerInfo*)(peer->data))->guildexp) + "|\n\nadd_spacer|small|\nadd_button|guildoffline|`wShow offline too``|0|0|\nadd_button|goguildhome|`wGo to Guild Home``|0|0|\nadd_button|editguildstatement|`wEdit Guild Statement``|0|0|\n\nadd_spacer|small|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(((PlayerInfo*)(peer->data))->guildMembers.size()) + " `wGuild Members Online|" + onlinegmlist + "\n\nadd_spacer|small|\nadd_button|backsocialportal|`wBack``|0|0|\nadd_button||`wClose``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + std::to_string(((PlayerInfo*)(peer->data))->guildBg) + "|" + std::to_string(((PlayerInfo*)(peer->data))->guildFg) + "|1.0|0|\n\nadd_spacer|small|\nadd_textbox|`oGuild Name : " + ((PlayerInfo*)(peer->data))->guild + "``|\nadd_textbox|`oStatement : " + ((PlayerInfo*)(peer->data))->guildStatement + "``|\nadd_textbox|`oGuild size: " + std::to_string(((PlayerInfo*)(peer->data))->guildMembers.size()) + "/15 members|\nadd_textbox|`oGuild Level : " + std::to_string(((PlayerInfo*)(peer->data))->guildlevel) + "|\nadd_textbox|`oGuild Exp : " + std::to_string(((PlayerInfo*)(peer->data))->guildexp) + "|\n\nadd_spacer|small|\nadd_button|guildoffline|`wShow offline too``|0|0|\nadd_button|goguildhome|`wGo to Guild Home``|0|0| \n\nadd_spacer|small|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(((PlayerInfo*)(peer->data))->guildMembers.size()) + " `wGuild Members Online|" + onlinegmlist + "\n\nadd_spacer|small|\nadd_button|backsocialportal|`wBack``|0|0|\nadd_button||`wClose``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}

						if (btn == "showguildzz") {

							string fg, bg, guildname, guildleader, gstatement;
							int guildlvl, guildexp;
							string guildName = ((PlayerInfo*)(peer->data))->guild;
							std::ifstream ifs("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
							if (ifs.is_open()) {
								json j;
								ifs >> j;

								gstatement = j["GuildStatement"];
								fg = j["foregroundflag"];
								bg = j["backgroundflag"];
								guildname = j["GuildName"];
								guildlvl = j["GuildLevel"];
								guildexp = j["GuildExp"];
								guildleader = j["Leader"];

								vector<string> gmlists;

								for (int i = 0; i < j["Member"].size(); i++) {
									gmlists.push_back(j["Member"][i]);
								}
								((PlayerInfo*)(peer->data))->guildmatelist = gmlists;

							}

							int block = stoi(fg);
							int wallpaper = stoi(bg);
							int flag = ((65536 * wallpaper) + block);

							string onlinefrnlist = "";
							int onlinecount = 0;
							int totalcount = ((PlayerInfo*)(peer->data))->guildmatelist.size();
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								string name = ((PlayerInfo*)(currentPeer->data))->rawName;
								if (find(((PlayerInfo*)(peer->data))->guildmatelist.begin(), ((PlayerInfo*)(peer->data))->guildmatelist.end(), name) != ((PlayerInfo*)(peer->data))->guildmatelist.end()) {
									if (((PlayerInfo*)(currentPeer->data))->rawName == guildleader) {
										onlinefrnlist += "\nadd_button|onlinefrns_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " `e(GL)``|0|0|";
										onlinecount++;
									}
									else {
										onlinefrnlist += "\nadd_button|onlinefrns_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + "``|0|0|";
										onlinecount++;
									}
								}

							}
							if (guildleader == ((PlayerInfo*)(peer->data))->rawName) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + bg + "|" + fg + "|1.0|0|\nadd_label|small|" + gstatement + "|left|4|\n\nadd_spacer|small|\nadd_textbox|Guild size: " + std::to_string(totalcount) + "/10 members``|\nadd_textbox|`oGuild Level : " + std::to_string(guildlvl) + "|\nadd_textbox|`oGuild Exp : " + std::to_string(guildexp) + "|\nadd_textbox|Guild Name : " + guildname + "|\nadd_textbox|`oGuild Leader : " + guildleader + "|\nadd_spacer|small|\nadd_button|guildoffline|`wShow offline too``|0|0|\nadd_button|goguildhome|`wGo to Guild Home``|0|0|\nadd_button|editguildstatement|`wEdit Guild Statement``|0|0|\nadd_spacer|big|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wGuild Members Online|\nadd_spacer|small|" + onlinefrnlist + "\nadd_spacer|small|\nadd_button|backsocialportal|`wBack|\nadd_button|cl0se|`wClose|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + bg + "|" + fg + "|1.0|0|\nadd_label|small|" + gstatement + "|left|4|\n\nadd_spacer|small|\nadd_textbox|Guild size: " + std::to_string(totalcount) + "/10 members``|\nadd_textbox|`oGuild Level : " + std::to_string(guildlvl) + "|\nadd_textbox|`oGuild Exp : " + std::to_string(guildexp) + "|\nadd_textbox|Guild Name : " + guildname + "|\nadd_textbox|`oGuild Leader : " + guildleader + "|\nadd_spacer|small|\nadd_button|guildoffline|`wShow offline too``|0|0|\nadd_button|goguildhome|`wGo to Guild Home``|0|0| \nadd_spacer|big|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wGuild Members Online|\nadd_spacer|small|" + onlinefrnlist + "\nadd_spacer|small|\nadd_button|backsocialportal|`wBack|\nadd_button|cl0se|`wClose|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;

							}

						}
						if (btn == "guildoffline") {


							string onlinegmlist = "";
							string offname, offlinegm;
							string grole = "";
							int onlinecount = 0;
							int totalcount = ((PlayerInfo*)(peer->data))->guildMembers.size();

							string gstatement = ((PlayerInfo*)(peer->data))->guildLeader;
							string bg = std::to_string(((PlayerInfo*)(peer->data))->guildBg);
							string fg = std::to_string(((PlayerInfo*)(peer->data))->guildFg);
							string guildname = ((PlayerInfo*)(peer->data))->guild;
							string guildleader = ((PlayerInfo*)(peer->data))->guildLeader;
							string guildlvl = "0";
							string guildexp = "0";
							ENetPeer * currentPeer;
							vector<string>offlineguild = ((PlayerInfo*)(peer->data))->guildMembers;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								string name = ((PlayerInfo*)(currentPeer->data))->rawName;
								if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->guildLeader) {
										onlinegmlist += "\nadd_button|onlinegm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " `e(GL)``|0|0|";
										onlinecount++;
									}
									else {
										onlinegmlist += "\nadd_button|onlinegm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " " + grole + "``|0|0|";
										onlinecount++;
										offlineguild.erase(std::remove(offlineguild.begin(), offlineguild.end(), name), offlineguild.end());
									}
								}
							}
							for (std::vector<string>::const_iterator i = offlineguild.begin(); i != offlineguild.end(); ++i) {
								offname = *i;
								offlinegm += "\nadd_button|offlinegm_" + offname + "|`4OFFLINE: `o" + offname + "``|0|0|";

							}
							/*if (onlinecount > 0) {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\n\nadd_spacer|small|\nadd_textbox|All of your friend are online!|\n\nadd_spacer|small| \n\nadd_spacer|small| \nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backonlinelist|Back``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							}
							else {*/
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + bg + "|" + fg + "|1.0|0|\nadd_label|small|" + gstatement + "|left|4|\n\nadd_spacer|small|\nadd_textbox|Guild size: " + std::to_string(totalcount) + "/10 members``|\nadd_textbox|`oGuild Level : " + guildlvl + "|\nadd_textbox|`oGuild Exp : " + guildexp + "|\nadd_textbox|Guild Name : " + guildname + "|\nadd_textbox|`oGuild Leader : " + guildleader + "|\nadd_spacer|small| \nadd_button|goguildhome|`wGo to Guild Home``|0|0| \nadd_spacer|big|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wGuild Members Online|\nadd_spacer|small|" + offlinegm + "\nadd_spacer|small|\nadd_button|showguild|`wBack|\nadd_button|cl0se|`wClose|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;

						}
						if (btn == "goguildhome") {
							string gworld;
							string guildName = ((PlayerInfo*)(peer->data))->guild;
							std::ifstream ifs("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
							if (ifs.is_open()) {
								json j;
								ifs >> j;

								gworld = j["GuildWorld"];

							}
							sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
							joinWorld(peer, gworld, 0, 0);
						}
						if (btn == "confirmcreateguild") {
							if (((PlayerInfo*)(peer->data))->gem < 250000) {
								GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You don't not have enought gem to create guild! " + std::to_string(250000 - ((PlayerInfo*)(peer->data))->gem) + "  more gem"));
								ENetPacket * packet8 = enet_packet_create(p8.data,
									p8.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet8);
							}
							else {
								string guildName = ((PlayerInfo*)(peer->data))->createGuildName;
								string guildStatement = ((PlayerInfo*)(peer->data))->createGuildStatement;
								string fixedguildName = PlayerDB::getProperName(guildName);
								string guildFlagbg = ((PlayerInfo*)(peer->data))->createGuildFlagBg;
								string guildFlagfg = ((PlayerInfo*)(peer->data))->createGuildFlagFg;

								//guildmem.push_back(((PlayerInfo*)(peer->data))->rawName);

								std::ofstream o("guilds/" + fixedguildName + ".json");
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}
								json j;
								vector<string> test1s;
								vector<string>test2s;

								((PlayerInfo*)(peer->data))->guildMembers.push_back(((PlayerInfo*)(peer->data))->rawName);
								j["GuildName"] = ((PlayerInfo*)(peer->data))->createGuildName;
								j["GuildRawName"] = fixedguildName;
								j["GuildStatement"] = ((PlayerInfo*)(peer->data))->createGuildStatement;
								j["Leader"] = ((PlayerInfo*)(peer->data))->rawName;
								j["Co-Leader"] = test1s;
								j["Elder-Leader"] = test2s;
								j["Member"] = ((PlayerInfo*)(peer->data))->guildMembers;
								j["GuildLevel"] = 0;
								j["GuildExp"] = 0;
								j["GuildWorld"] = ((PlayerInfo*)(peer->data))->currentWorld;
								j["backgroundflag"] = stoi(((PlayerInfo*)(peer->data))->createGuildFlagBg);
								j["foregroundflag"] = stoi(((PlayerInfo*)(peer->data))->createGuildFlagFg);
								o << j << std::endl;

								updateInvis(peer);

								((PlayerInfo*)(peer->data))->guild = guildName;
								((PlayerInfo*)(peer->data))->joinguild = true;
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 250000;
								for (int i = 0; i < world->width*world->height; i++)
								{

									if (world->items[i].foreground == 242) {
										world->items[i].foreground = 5814;
									}

								}


							}
						}
						if (btn == "backsocialportal") {
							if (((PlayerInfo*)(peer->data))->joinguild == true) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|showguild|Show Guild Members``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|createguildinfo|Create Guild``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}

						if (btn == "createguildinfo") {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild|left|5814|\nadd_label|small|`oWelcome to Grow Guilds where you can create a Guild! With a Guild you can level up the Guild to add more members.``|left|4|\n\nadd_spacer|small|\nadd_textbox|`oYou will be charged `6250,000 `oGems.``|\nadd_spacer|small|\nadd_button|createguild|`oCreate a Guild``|0|0|\nadd_button|backsocialportal|Back|0|0|\nend_dialog||Close||\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;

						}

						if (btn == "createguild") {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation``|left|5814|  \nadd_spacer|small|\nadd_text_input|gname|Guild Name: ||20|\nadd_text_input|gstatement|Guild Statement: ||100|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``||5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``||5|\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\nadd_spacer|small|\nadd_textbox|`8Remember`o: A guild can only be created in a world owned by you and locked with a `5World Lock`o!|\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\nadd_spacer|small|\nend_dialog|guildconfirm||Create Guild|\nadd_spacer|big|\nadd_button|cl0se|Close|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "ftnoption") {
							string checkboxshit = "add_checkbox|checkbox_public|Show location to friends|1";
							string checkboxshits = "add_checkbox|checkbox_notifications|Show friend notifications|1";;
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wFriend Options``|left|1366|\n\nadd_spacer|small|\n" + checkboxshit + "\n" + checkboxshits + "\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "backonlinelist") {

							string onlinefrnlist = "";
							int onlinecount = 0;
							int totalcount = ((PlayerInfo*)(peer->data))->friendinfo.size();
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								string name = ((PlayerInfo*)(currentPeer->data))->rawName;
								if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
									onlinefrnlist += "\nadd_button|onlinefrns_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + "``|0|0|";
									onlinecount++;

								}

							}
							if (totalcount == 0) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_label|small|`oYou currently have no friends.  That's just sad.  To make some, click a person's wrench icon, then choose `5Add as friend`o.``|left|4|\n\nadd_spacer|small|\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backsocialportal|Back|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else if (onlinecount == 0) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\nadd_label|small|`oNone of your friends are currently online.``|left|4|\n\nadd_spacer|small|\nadd_button|showoffline|`oShow offline``|0|0|\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backsocialportal|Back|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}

							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|" + onlinefrnlist + "\n\nadd_spacer|small|\nadd_button|showoffline|`oShow offline``|0|0|\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backsocialportal|Back|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn.substr(0, 10) == "offlinegm_") {
							((PlayerInfo*)(peer->data))->lastgm = btn.substr(10, cch.length() - 10 - 1);
							if (btn.substr(10, cch.length() - 10 - 1) == ((PlayerInfo*)(peer->data))->guildLeader) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastgm + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastgm + " is `4offline`o.``|\nadd_spacer|small| \nadd_button|guildoffline|`oBack``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastgm + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastgm + " is `4offline`o.``|\nadd_spacer|small|\nadd_button|removegmoffline|`oKick from the guild``|0|0|\nadd_button|guildoffline|`oBack``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "removegmoffline") {
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->guild == ((PlayerInfo*)(peer->data))->guild) {
									std::ifstream ifff("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
									if (ifff.fail()) {
										ifff.close();
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Error: `oGuild does not exist! If you are seeing this message, please take a screenshot and send it to a developer!"));
										ENetPacket * packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									if (ifff.is_open()) {
									}
									json j;
									ifff >> j; //load

									vector<string> gmlist;

									for (int i = 0; i < j["Member"].size(); i++) {
										gmlist.push_back(j["Member"][i]);
									}

									gmlist.erase(std::remove(gmlist.begin(), gmlist.end(), ((PlayerInfo*)(peer->data))->lastgm), gmlist.end());


									j["Member"] = gmlist; //edit

									std::ofstream o("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json"); //save
									if (!o.is_open()) {
										cout << GetLastError() << endl;
										_getch();
									}

									o << j << std::endl;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[GUILD ALERT] `2" + ((PlayerInfo*)(peer->data))->lastgm + "`o has been kicked from the guild!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`4Guild Member removed``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastgm + " is no longer in the guild.``|\n\nadd_spacer|small|\nadd_button|guildportalbutton|`oOK``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;

						}
						if (btn == "removegmonline") {
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastgm) {
									std::ifstream ifff("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
									if (ifff.fail()) {
										ifff.close();
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Error: `oGuild does not exist! If you are seeing this message, please take a screenshot and send it to a developer!"));
										ENetPacket * packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									if (ifff.is_open()) {
									}
									json j;
									ifff >> j; //load

									vector<string> gmlist;

									for (int i = 0; i < j["Member"].size(); i++) {
										gmlist.push_back(j["Member"][i]);
									}

									gmlist.erase(std::remove(gmlist.begin(), gmlist.end(), ((PlayerInfo*)(peer->data))->lastgm), gmlist.end());


									j["Member"] = gmlist; //edit

									std::ofstream o("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json"); //save
									if (!o.is_open()) {
										cout << GetLastError() << endl;
										_getch();
									}

									o << j << std::endl;
									((PlayerInfo*)(currentPeer->data))->guildBg = 0;
									((PlayerInfo*)(currentPeer->data))->guildFg = 0;
									((PlayerInfo*)(currentPeer->data))->guildLeader = "";
									((PlayerInfo*)(currentPeer->data))->guild = "";
									((PlayerInfo*)(currentPeer->data))->guildStatement = "";
									//((PlayerInfo*)(currentPeer->data))->guildRole = 0;
									((PlayerInfo*)(currentPeer->data))->guildlast = "";
									((PlayerInfo*)(currentPeer->data))->lastgm = "";
									((PlayerInfo*)(currentPeer->data))->lastgmname = "";
									((PlayerInfo*)(currentPeer->data))->joinguild = false;
									((PlayerInfo*)(currentPeer->data))->lastgmworld = "";
									((PlayerInfo*)(currentPeer->data))->guildMembers.clear();
									updateInvis(currentPeer);
									updateInvis(peer);
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[GUILD ALERT] `oYou have been kicked from the guild by `2" + ((PlayerInfo*)(peer->data))->displayName + "`o."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
								if (((PlayerInfo*)(currentPeer->data))->guild == ((PlayerInfo*)(peer->data))->guild) {
									updateGuild(currentPeer);
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[GUILD ALERT] `2" + ((PlayerInfo*)(peer->data))->lastgmname + "`o has been kicked from the guild!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`4Guild Member removed``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastgmname + " is no longer in the guild.``|\n\nadd_spacer|small|\nadd_button|guildportalbutton|`oOK``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}



						if (btn.substr(0, 9) == "onlinegm_") {
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == btn.substr(9, cch.length() - 9 - 1)) {
									((PlayerInfo*)(peer->data))->lastgmworld = ((PlayerInfo*)(currentPeer->data))->currentWorld;
									((PlayerInfo*)(peer->data))->lastgmname = ((PlayerInfo*)(currentPeer->data))->displayName;
									((PlayerInfo*)(peer->data))->lastgm = ((PlayerInfo*)(currentPeer->data))->rawName;
								}
							}
							if (btn.substr(9, cch.length() - 9 - 1) == ((PlayerInfo*)(peer->data))->rawName) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastgmname + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|This is you!|\n\nadd_spacer|small|\nadd_button|showguild|`oBack``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {
								if (((PlayerInfo*)(peer->data))->rawName == ((PlayerInfo*)(peer->data))->guildLeader) {
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastgmname + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastgmname + " is `2online `onow in the world `5" + ((PlayerInfo*)(peer->data))->lastgmworld + "`o.|\n\nadd_spacer|small|\nadd_button|gmwarpbutton|`oWarp to `5" + ((PlayerInfo*)(peer->data))->lastgmworld + "``|0|0|\nadd_button|gmmsgbutton|`5Send message``|0|0|\n\nadd_spacer|small| \nadd_button|removegmonline|Kick from guild|0|0|\nadd_button|showguild|`oBack``|0|0|\nadd_quick_exit|"));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;
								}
								else {
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastgmname + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastgmname + " is `2online `onow in the world `5" + ((PlayerInfo*)(peer->data))->lastgmworld + "`o.|\n\nadd_spacer|small|\nadd_button|gmwarpbutton|`oWarp to `5" + ((PlayerInfo*)(peer->data))->lastgmworld + "``|0|0|\nadd_button|gmmsgbutton|`5Send message``|0|0|\n\nadd_spacer|small| \nadd_button|showguild|`oBack``|0|0|\nadd_quick_exit|"));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;
								}
							}
						}
						if (btn == "showoffline") {
							string onlinelist = "";
							string offlinelist = "";
							string offname = "";
							int onlinecount = 0;
							int totalcount = ((PlayerInfo*)(peer->data))->friendinfo.size();
							vector<string>offliness = ((PlayerInfo*)(peer->data))->friendinfo;

							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								string name = ((PlayerInfo*)(currentPeer->data))->rawName;

								if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
									onlinelist += "\nadd_button|onlinefrns_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + "``|0|0|";
									onlinecount++;

									offliness.erase(std::remove(offliness.begin(), offliness.end(), name), offliness.end());
								}
							}
							for (std::vector<string>::const_iterator i = offliness.begin(); i != offliness.end(); ++i) {
								offname = *i;
								offlinelist += "\nadd_button|offlinefrns_" + offname + "|`4OFFLINE: `o" + offname + "``|0|0|";

							}

							/*if (onlinecount > 0) {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\n\nadd_spacer|small|\nadd_textbox|All of your friend are online!|\n\nadd_spacer|small| \n\nadd_spacer|small| \nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backonlinelist|Back``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							}
							else {*/
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\nadd_spacer|small|" + offlinelist + "\nadd_spacer|small|\n\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backonlinelist|Back``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;

						}
						if (btn == "removecon") {
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastFrn) {


									((PlayerInfo*)(peer->data))->friendinfo.erase(std::remove(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), ((PlayerInfo*)(peer->data))->lastFrn), ((PlayerInfo*)(peer->data))->friendinfo.end());


									((PlayerInfo*)(currentPeer->data))->friendinfo.erase(std::remove(((PlayerInfo*)(currentPeer->data))->friendinfo.begin(), ((PlayerInfo*)(currentPeer->data))->friendinfo.end(), ((PlayerInfo*)(peer->data))->rawName), ((PlayerInfo*)(currentPeer->data))->friendinfo.end());


									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND ALERT: `2" + ((PlayerInfo*)(peer->data))->displayName + " `ohas removed you as a friend."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`4Friend removed``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`oOk, you are no longer friends with `o" + ((PlayerInfo*)(peer->data))->lastFrnName + ".``|\n\nadd_spacer|small|\nadd_button||`oOK``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "removeconoff") {
							((PlayerInfo*)(peer->data))->friendinfo.erase(std::remove(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), ((PlayerInfo*)(peer->data))->lastFrn), ((PlayerInfo*)(peer->data))->friendinfo.end());

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->lastFrn + ".json");
							if (ifff.fail()) {
								ifff.close();
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Error: `oPlayer `5" + ((PlayerInfo*)(peer->data))->lastFrn + " `odoes not exist!"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								continue;
							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load

							vector<string> friends;

							for (int i = 0; i < j["friends"].size(); i++) {
								friends.push_back(j["friends"][i]);
							}

							friends.erase(std::remove(friends.begin(), friends.end(), ((PlayerInfo*)(peer->data))->rawName), friends.end());

							j["friends"] = friends; //edit

							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->lastFrn + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;

							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`4Friend removed``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`oOk, you are no longer friends with `o" + ((PlayerInfo*)(peer->data))->lastFrn + ".``|\n\nadd_spacer|small|\nadd_button||`oOK``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn.substr(0, 11) == "onlinefrns_") {
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == btn.substr(11, cch.length() - 11 - 1)) {
									((PlayerInfo*)(peer->data))->lastFrnWorld = ((PlayerInfo*)(currentPeer->data))->currentWorld;
									((PlayerInfo*)(peer->data))->lastFrnName = ((PlayerInfo*)(currentPeer->data))->displayName;
									((PlayerInfo*)(peer->data))->lastFrn = ((PlayerInfo*)(currentPeer->data))->rawName;
								}
							}

							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastFrnName + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastFrnName + " is `2online `onow in the world `5" + ((PlayerInfo*)(peer->data))->lastFrnWorld + "`o.|\n\nadd_spacer|small|\nadd_button|frnwarpbutton|`oWarp to `5" + ((PlayerInfo*)(peer->data))->lastFrnWorld + "``|0|0|\nadd_button|msgbutton|`5Send message``|0|0|\n\nadd_spacer|small|\nadd_button|removecon|`oRemove as friend``|0|0|\nadd_button|backonlinelist|`oBack``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "frnwarpbutton") {
							sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
							joinWorld(peer, ((PlayerInfo*)(peer->data))->lastFrnWorld, 0, 0);
						}
						if (btn == "gmwarpbutton") {
							sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
							joinWorld(peer, ((PlayerInfo*)(peer->data))->lastgmworld, 0, 0);
						}
						if (btn == "msgbutton") {

							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`5Message to `o" + ((PlayerInfo*)(peer->data))->lastFrnName + "|left|660|\nadd_spacer|small|\nadd_text_input|msgtext|||50|\nend_dialog|msgdia|Cancel|`5Send``| \nadd_spacer|big|\nadd_button|backonlinelist|`oBack``|0|0|\nadd_quick_exit|\n"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn.substr(0, 12) == "offlinefrns_") {
							((PlayerInfo*)(peer->data))->lastFrn = btn.substr(12, cch.length() - 12 - 1);

							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastFrn + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastFrn + " is `4offline`o.``|\nadd_spacer|small|\nadd_button|removeconoff|`oRemove as friend``|0|0|\nadd_button|showoffline|`oBack``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "addfriendrnbutton") {
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) { // if last wrench

									if (((PlayerInfo*)(peer->data))->lastfriend == ((PlayerInfo*)(currentPeer->data))->rawName) { // last  h friend

										((PlayerInfo*)(peer->data))->friendinfo.push_back(((PlayerInfo*)(currentPeer->data))->rawName); //add


										((PlayerInfo*)(currentPeer->data))->friendinfo.push_back(((PlayerInfo*)(peer->data))->rawName);

										string text = "action|play_sfx\nfile|audio/love_in.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);
										ENetPacket * packet2 = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										enet_peer_send(peer, 0, packet2);
										delete data;
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND ADDED: `oYou're now friends with `w" + ((PlayerInfo*)(peer->data))->rawName + "`o!"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										delete p.data;
										GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND ADDED: `oYou're now friends with `w" + ((PlayerInfo*)(currentPeer->data))->rawName + "`o!"));
										ENetPacket * packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet3);
										delete p3.data;


									}
									else {
										GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5[`wFriend request sent to `2" + ((PlayerInfo*)(currentPeer->data))->rawName + "`5]"));
										ENetPacket * packet4 = enet_packet_create(p4.data,
											p4.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet4);
										delete p4.data;
										string text = "action|play_sfx\nfile|audio/tip_start.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);
										ENetPacket * packet2 = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										delete data;
										((PlayerInfo*)(currentPeer->data))->lastfriend = ((PlayerInfo*)(peer->data))->rawName;
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND REQUEST: `oYou've received a `wfriend request `ofrom `w" + ((PlayerInfo*)(peer->data))->rawName + "`o! To accept, click the `wwrench by his/her name `oand then choose `wAdd as friend`o."));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										delete p.data;
									}
								}
							}
						}





						if (isFindDialog && btn.substr(0, 4) == "tool") {
							int Id = atoi(btn.substr(4, btn.length() - 4).c_str());

							size_t invsize = 250;
							if (((PlayerInfo*)(peer->data))->inventory.items.size() == invsize) {
								PlayerInventory inventory;
								InventoryItem item;
								item.itemID = Id;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemID = 32;
								inventory.items.push_back(item);
								((PlayerInfo*)(peer->data))->inventory = inventory;

							}
							else {
								InventoryItem item;
								item.itemID = Id;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
							}
							sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
						}
						else if (isFindDialog) {
							string itemLower2;
							vector<ItemDefinition> itemDefsfind;
							for (char c : itemFind) if (c < 0x20 || c>0x7A) goto SKIPFind;
							if (itemFind.length() < 3) goto SKIPFind3;
							for (const ItemDefinition &item : itemDefs)
							{
								string itemLower;
								for (char c : item.name) if (c < 0x20 || c>0x7A) goto SKIPFind2;
								if (!(item.id % 2 == 0)) goto SKIPFind2;
								itemLower2 = item.name;
								std::transform(itemLower2.begin(), itemLower2.end(), itemLower2.begin(), ::tolower);
								if (itemLower2.find(itemLower) != std::string::npos) {
									itemDefsfind.push_back(item);
								}
							SKIPFind2:;
							}
						SKIPFind3:;
							string listMiddle = "";
							string listFull = "";

							for (const ItemDefinition &item : itemDefsfind)
							{
								string kys = item.name;
								std::transform(kys.begin(), kys.end(), kys.begin(), ::tolower);
								string kms = itemFind;
								std::transform(kms.begin(), kms.end(), kms.begin(), ::tolower);
								if (kys.find(kms) != std::string::npos)
									listMiddle += "add_button_with_icon|tool" + to_string(item.id) + "|`$" + item.name + "``|left|" + to_string(item.id) + "||\n";
							}
							if (itemFind.length() < 3) {
								listFull = "add_textbox|`4Word is less then 3 letters!``|\nadd_spacer|small|\n";
								showWrong(peer, listFull, itemFind);
							}
							else if (itemDefsfind.size() == 0) {
								//listFull = "add_textbox|`4Found no item match!``|\nadd_spacer|small|\n";
								showWrong(peer, listFull, itemFind);

							}
							else {
								GamePacket fff = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFound item : " + itemFind + "``|left|6016|\nadd_spacer|small|\nadd_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||20|\nend_dialog|findid|Cancel|Find the item!|\nadd_spacer|big|\n" + listMiddle + "add_quick_exit|\n"));
								ENetPacket * packetd = enet_packet_create(fff.data,
									fff.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packetd);

								//enet_host_flush(server);
								delete fff.data;
							}
						}
					SKIPFind:;

						if (btn == "legendbot") {
							((PlayerInfo*)(peer->data))->cloth_shirt = 1780;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have legendary bot now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);


							delete p2.data;
							delete p.data;
							int effect = 90;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);
									GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->Chatname + " `5earned the achievement ''DARY!''!"));
									ENetPacket * packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
									delete p3.data;
									delete psp.data;
								}
							}
						}
						if (btn == "legendwing") {
							((PlayerInfo*)(peer->data))->cloth_back = 1784;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have legendary wing now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							delete p.data;
							int effect = 90;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);
									GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->Chatname + " `5earned the achievement ''DARY!''!"));
									ENetPacket * packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
									delete p3.data;
									delete psp.data;
								}
							}
						}

						if (btn == "legendkatana") {
							((PlayerInfo*)(peer->data))->cloth_hand = 2592;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have legendary katana now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							delete p.data;
							int effect = 90;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);
									GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->Chatname + " `5earned the achievement ''DARY!''!"));
									ENetPacket * packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
									delete p3.data;
									delete psp.data;
								}
							}
						}

						if (btn == "legenddragon") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1782;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have legendary dragon now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							delete p.data;
							int effect = 90;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);
									GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->Chatname + " `5earned the achievement ''DARY!''!"));
									ENetPacket * packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
									delete p3.data;
									delete psp.data;
								}
							}
						}

						if (btn == "legendwhip") {
							((PlayerInfo*)(peer->data))->cloth_hand = 6026;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have whip of truth now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							delete p.data;
							int effect = 90;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);
									GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->Chatname + " `5earned the achievement ''DARY!''!"));
									ENetPacket * packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
									delete p3.data;
									delete psp.data;
								}
							}
						}

						if (btn == "ringforce") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1874;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have Ring Of Force now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringwinds") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1876;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have Ring Of Winds now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringone") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1904;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have The One Ring now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringwisdom") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1996;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have Ring of Wisdom now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringwater") {
							((PlayerInfo*)(peer->data))->cloth_hand = 2970;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have Ring Of Water now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringsaving") {
							((PlayerInfo*)(peer->data))->cloth_hand = 3140;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have Ring Of Savings now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringsmithing") {
							((PlayerInfo*)(peer->data))->cloth_hand = 3174;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have Ring Of Smithing now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringshrinking") {
							((PlayerInfo*)(peer->data))->cloth_hand = 6028;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have Ring Of Shrinking now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringnature") {
							((PlayerInfo*)(peer->data))->cloth_hand = 6846;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have Ring of Nature now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "geminiring") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1986;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have Gemini Ring now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}

						if (btn == "searchitems") {

							//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Search item``|left|2398|\nadd_label|small|`4Sorry, this feature is not working :( ``|left|4|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|cancel||gazette||"));


							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFind item``|left|6016|\nadd_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\nadd_quick_exit|\n"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}



						if (btn == "weather") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Weather Manager``|left|2398|\nadd_label|small|`oType of weather``|left|4|\n\nadd_spacer|small|\nadd_button|weathermachine|`2Weather Machine``|0|0|\nadd_button|worldweather|`2World Weather``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
						if (btn == "worldweather") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Weather Manager``|left|2398|\nadd_label|small|`oChoose one weather``|left|4|\n\nadd_spacer|small|\nadd_button|beach|`2Beach``|0|0|\nadd_button|harvestfest|`2Harvest Fest ``|0|0|\nadd_button|mars|`2Mars ``|0|0|\nadd_button|growganoth|`2Growganoth ``|0|0|\nadd_button|growchangry|`2Growch Angry ``|0|0|\nadd_button|growchhappy|`2Growch Happy ``|0|0|\nadd_button|deepsea|`2Deep sea ``|0|0|\nadd_button|greencomet|`2Green Comet ``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
						if (btn == "beach") {
							world->weather = 1;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "harvestfest") {
							world->weather = 6;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "mars") {
							world->weather = 7;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "growganoth") {
							world->weather = 9;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "growchangry") {
							world->weather = 12;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "growchhappy") {
							world->weather = 13;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "deepsea") {
							world->weather = 14;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "greencomet") {
							world->weather = 16;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}


						if (btn == "weathermachine") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Weather Manager``|left|2398|\nadd_label|small|`oChoose one weather``|left|4|\n\nadd_spacer|small|\nadd_button|sunny|`2Sunny``|0|0|\nadd_button|night|`2Night ``|0|0|\nadd_button|arid|`2Arid ``|0|0|\nadd_button|rain|`2Rainy City ``|0|0|\nadd_button|spooky|`2Spooky ``|0|0|\nadd_button|nothingness|`2Nothingness ``|0|0|\nadd_button|arid|`2Snowy ``|0|0|\nadd_button|warpspeed|`2Warp Speed ``|0|0|\nadd_button|bluecomet|`2Blue Comet ``|0|0|\nadd_button|party|`2Party ``|0|0|\nadd_button|pineapples|`2Pineapples ``|0|0|\nadd_button|snowynight|`2Snowy Night ``|0|0|\nadd_button|spring|`2Spring ``|0|0|\nadd_button|howlingsky|`2Howling Sky ``|0|0|\nadd_button|heatwave|`2Heatwave ``|0|0|\nadd_button|stuff|`2Stuff ``|0|0|\nadd_button|pagoda|`2Pagoda ``|0|0|\nadd_button|apocalypse|`2Apocalypse ``|0|0|\nadd_button|jungle|`2Jungle ``|0|0|\nadd_button|balloonwarz|`2Balloon Warz ``|0|0|\nadd_button|background|`2Background ``|0|0|\nadd_button|autumn|`2Autumn ``|0|0|\nadd_button|valentine|`2Valentine's ``|0|0|\nadd_button|paddyday|`2St. Paddy's Day ``|0|0|\nadd_button|epoch|`2Epoch Machine ``|0|0|\nadd_button|digitalrain|`2Digital Rain ``|0|0|\nadd_button|wsnowy|`2White snowy ``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}

						if (btn == "sunny") {
							world->weather = 0;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "night") {
							world->weather = 2;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "arid") {
							world->weather = 3;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "rain") {
							world->weather = 5;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "spooky") {
							world->weather = 8;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "nothingness") {
							world->weather = 10;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "snowy") {
							world->weather = 11;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "warpspeed") {
							world->weather = 15;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "bluecomet") {
							world->weather = 17;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "party") {
							world->weather = 18;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "pineapples") {
							world->weather = 19;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "snowynight") {
							world->weather = 20;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "spring") {
							world->weather = 21;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "howlingsky") {
							world->weather = 22;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "stuff") {
							world->weather = 29;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "pagoda") {
							world->weather = 30;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "apocalypse") {
							world->weather = 31;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "jungle") {
							world->weather = 32;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "balloonwarz") {
							world->weather = 33;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "background") {
							world->weather = 34;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "autumn") {
							world->weather = 35;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "valentine") {
							world->weather = 36;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "paddyday") {
							world->weather = 37;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "digitalrain") {
							world->weather = 42;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "wsnowy") {
							world->weather = 43;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}









						if (btn == "heatwave") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Locke`|left|2398|\nadd_label|small|`oChoose colour of heatwave``|left|4|\n\nadd_spacer|small|\nadd_button|heatwave24|`2Heatwave Pink ``|0|0|\nadd_button|heatwave25|`2Heatwave Orange ``|0|0|\nadd_button|heatwave26|`2Heatwave Green ``|0|0|\nadd_button|heatwave27|`2Heatwave Blue ``|0|0|\nadd_button|heatwave28|`2Heatwave Orange 2 ``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}

						if (btn == "heatwave24") {
							world->weather = 24;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "heatwave25") {
							world->weather = 25;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}
						if (btn == "heatwave26") {
							world->weather = 26;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}
						if (btn == "heatwave27") {
							world->weather = 27;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}
						if (btn == "heatwave28") {
							world->weather = 28;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}
						if (btn == "epoch") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Locke`|left|2398|\nadd_label|small|`oChoose Type of weather``|left|4|\n\nadd_spacer|small|\nadd_button|iceland|`2Ice Land ``|0|0|\nadd_button|volcano|`2Volcano ``|0|0|\nadd_button|skycastle|`2Sky Castle ``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
						if (btn == "iceland") {
							world->weather = 38;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}
						if (btn == "volcano") {
							world->weather = 39;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}
						if (btn == "skycastle") {
							world->weather = 40;
							worldDB.saveAll();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									continue;
								}
							}
						}

						if (btn == "weather_menu") { //weatherm
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|`2Weather Machines!  `wTap the item you'd like more info on, or Back to go back.``|\nadd_button|wsunny|Sunny|interface/large/store_buttons5.rttex|The useless item in growtopia ever...|0|5|1000|0||\nadd_button|wsunny|Sunny|interface/large/store_buttons5.rttex|The useless item in growtopia ever...|0|6|1000|0||\nadd_button|wsunny|Sunny|interface/large/store_buttons5.rttex|The useless item in growtopia ever...|0|7|1000|0||\n"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}




#ifdef REGISTRATION

						if (isRegisterDialog) {

							int regState = PlayerDB::playerRegister(username, password);
							if (regState == 1) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rYour account was created!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								GamePacket p2 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), 1), username), password));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);

								//enet_host_flush(server);
								delete p2.data;
								enet_peer_disconnect_later(peer, 0);
							}
							else if (regState == -1) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rCreation of account failed, because it already exists!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -2) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rCreation of account failed, because name is too short!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}

#endif
					}




					/*int itemID = atoi(cch.substr(dropText.length(), cch.length() - dropText.length() - 1).c_str());
					PlayerMoving data;
					data.packetType = 14;
					data.x = ((PlayerInfo*)(peer->data))->x;
					data.y = ((PlayerInfo*)(peer->data))->y;
					data.netID = -1;
					data.plantingTree = itemID;
					float val = 1; // item count
					BYTE val2 = 0; // if 8, then geiger effect

					BYTE* raw = packPlayerMoving(&data);
					memcpy(raw + 16, &val, 4);
					memcpy(raw + 1, &val2, 1);
					SendPacketRaw(4, raw, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/

					if (cch.find("text|") != std::string::npos) {
						/*if (str == "/noclip")
						{

						if (((PlayerInfo*)(peer->data))->currentWorld == "GROWCH")  {
						//if (!canban(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))continue;
						// if (isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))continue;


						GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4You can't noclip in this world!"));
						ENetPacket * packet4 = enet_packet_create(p4.data,
						p4.len,
						ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet4);
						delete p4.data;
						continue;
						}
						else if (((PlayerInfo*)(peer->data))->currentWorld != "GROWCH") {
						((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Noclip Mode `2Enable`o!"));
						ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						PlayerMoving data;
						data.packetType = 0x14;
						data.characterState = 0x0; // animation
						data.x = 1000;
						data.y = 1;
						data.punchX = 0;
						data.punchY = 0;
						data.XSpeed = 300;
						data.YSpeed = 600;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = 0xFF;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
						}
						}*/

						if (str == "/noclip") {
							GamePacket p;
							if (((PlayerInfo*)(peer->data))->canWalkInBlocks) {
								p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Noclip mode disabled!"));
								((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
								sendState(peer);
							}
							else {
								p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Noclip mode enabled!"));
								((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
								sendState(peer);
							}

							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (str.substr(0, 6) == "/team ")
						{
							int val = 0;
							val = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
							PlayerMoving data;
							//data.packetType = 0x14;

							data.characterState = 2097200; // animation
							data.x = 0;
							data.y = 0;
							data.punchX = -1;
							data.punchY = -1;
							data.XSpeed = 0;
							data.YSpeed = 0;
							data.netID = ((PlayerInfo*)(peer->data))->netID;
							data.plantingTree = 0;
							SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

						} /*
						  else if (str == "/zoom") {
						  GamePacket p = packetEnd(appendIntx(appendFloat(appendString(createPacket(), "OnZoomCamera"), 1.000000), 1));
						  ENetPacket * packet = enet_packet_create(p.data,
						  p.len,
						  ENET_PACKET_FLAG_RELIABLE);

						  enet_peer_send(peer, 0, packet);
						  delete p.data;
						  } */
						  /*else if (str.substr(0, 6) == "/test ")
						  {
						  AWorld ret;
						  string name = str.substr(6, cch.length() - 6 - 1);
						  vector<WorldInfo> worlds ;

						  WorldInfo info = generatemarsWorld(name, 100, 60);

						  worlds.push_back(info);
						  ret.id = worlds.size() - 1;
						  ret.info = info;
						  ret.ptr = &worlds.at(worlds.size() - 1);

						  joinWorld(peer, name, 0, 0);




						  int x = 3040;
						  int y = 736;
						  for (int j = 0; j < 100*60; j++)
						  {
						  if (name.items[j].foreground == 6) {
						  x = (j%worlds.at(i).width) * 32;
						  y = (j / worlds.at(i).width) * 32;
						  }
						  }
						  GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
						  //for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
						  ENetPacket * packet = enet_packet_create(p.data,
						  p.len,
						  ENET_PACKET_FLAG_RELIABLE);
						  enet_peer_send(currentPeer, 0, packet);
						  }
						  else if (str.substr(0, 6) == "/t3st ")
						  {

						  AWorld ret;
						  for (int i = 0; i < worlds.size(); i++) {
						  AWorld WorldDB::get2(string name) {






						  }*/


						else if (str.substr(0, 7) == "/state ")
						{
							ENetPeer * currentPeer;




							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {


									PlayerMoving data;
									data.packetType = 0x14;
									data.characterState = 0x0; // animation
									data.x = 1000;
									data.y = 0;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = ((PlayerInfo*)(peer->data))->netID;
									data.plantingTree = atoi(str.substr(7, cch.length() - 7 - 1).c_str());

									SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
								}
							}
						}
						/*int statenumber = atoi(str.substr(7, cch.length() - 7 - 1).c_str());
						if (statenumber == 2)
						{
						enet_peer_disconnect_later(peer, 0);
						}
						}*/
						else if (str.substr(0, 6) == "/test ") {

							string offlinelist = "";
							string offname = "";


							for (std::vector<string>::const_iterator i = world->accessworld.begin(); i != world->accessworld.end(); ++i) {
								offname = *i;
								offlinelist += offname;

							}

							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "MAC ADDRESS : " + ((PlayerInfo*)(peer->data))->macaddress + "  MEta : " + ((PlayerInfo*)(peer->data))->metaip));
							ENetPacket * packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

						}
						/* else if (str.substr(0, 8) == "/friend ") {
						string username = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->rawName);

						string test = str.substr(8, cch.length() - 8 - 1);

						test123.push_back(test);
						((PlayerInfo*)(peer->data))->friendinfo = test123;
						std::ifstream ifs("players/" + username + ".json");
						if (ifs.fail()) {
						ifs.close();
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "error"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						continue;
						}
						if (ifs.is_open()) {

						}
						json j;
						ifs >> j; //load
						j["friends"] = test123; //add stuff



						std::ofstream o("players/" + username + ".json");
						if (!o.is_open()) {
						cout << GetLastError() << endl;
						_getch();
						}



						o << j << std::endl;
						ifs.close();


						}
						else if (str.substr(0, 5) == "/fred") {
						string username = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->rawName);
						std::ifstream ifff("players/" + username + ".json");
						json j;
						ifff >> j;
						string *scr;
						scr = new string[j["friends"].size()];
						for (int i = 0;i < j["friends"].size(); i++) {
						test123.push_back(j["friends"][i]);
						cout << test123[i] << endl;;

						scr[i]  =test123[i];
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "List = "+scr[i]));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						}



						ifff.close();
						}*/
						else if (str.substr(0, 7) == "/ipban ")
						{

							if (!isOwner(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))break;
							if (str.substr(7, cch.length() - 7 - 1) == "") continue;
							if (((PlayerInfo*)(peer->data))->rawName == str.substr(7, cch.length() - 7 - 1)) continue;


							// current date/time based on current system
							time_t now = time(0);

							// convert now to string form
							char* dt = ctime(&now);

							// convert now to tm struct for UTC
							tm *gmtm = gmtime(&now);
							dt = asctime(gmtm);


							cout << dt << "Server operator " << ((PlayerInfo*)(peer->data))->rawName << " has banned " << str.substr(7, cch.length() - 7 - 1) << "." << endl;

							ENetPeer * currentPeer;

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancient Ones `ohave `4ip-banned `2" + str.substr(7, cch.length() - 7 - 1) + " `#** `o(`4/rules `oto see the rules!)"));
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(7, cch.length() - 7 - 1)) {
									if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancient Ones `ohave used `#Ip-Ban `oon `2" + str.substr(7, cch.length() - 7 - 1) + "`o! `#**"));
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);

									GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`0Warning from `4System`0: You've been `4BANNED `0from Private Server for 730 days"), "audio/hub_open.wav"), 0));
									ENetPacket * packet2 = enet_packet_create(ps2.data,
										ps2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWarning from `4System`o: You've been `4BANNED `ofrom Private Server for 730 days"));
									ENetPacket * packet3 = enet_packet_create(ps3.data,
										ps3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);

									string ipban = "";
									std::ifstream ifs("ipban.json");
									ENetPeer* peer123 = currentPeer;
									string ip = std::to_string(peer123->address.host);
									if (ifs.is_open()) {

										json j3;
										ifs >> j3;
										ipban = j3["ip"];
										ipban = ipban.append("|" + ip + "|");
									}
									std::ofstream od("ipban.json");
									if (od.is_open()) {

									}

									std::ofstream o("ipban.json");
									if (!o.is_open()) {
										cout << GetLastError() << endl;
										_getch();
									}
									json j;

									j["ip"] = ipban;
									o << j << std::endl;



									if (((PlayerInfo*)(currentPeer->data))->isIn)
									{
										if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

											PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));

											string username = PlayerDB::getProperName(p->rawName);

											std::ofstream o("players/" + username + ".json");
											if (!o.is_open()) {
												cout << GetLastError() << endl;
												_getch();
											}
											json j;

											int clothback = p->cloth_back;
											int clothhand = p->cloth_hand;
											int clothface = p->cloth_face;
											int clothhair = p->cloth_hair;
											int clothfeet = p->cloth_feet;
											int clothpants = p->cloth_pants;
											int clothneck = p->cloth_necklace;
											int clothshirt = p->cloth_shirt;
											int clothmask = p->cloth_mask;
											int clothances = p->cloth_ances;
											int level = p->level;
											int skin = p->skinColor;
											int exp = p->blockbroken;
											int ban = p->ban;
											int puncheffect = p->puncheffect;
											int mute = p->mute;
											int gem = 0;

											int newgem = p->gem;
											int entereffect = p->entereffect;






											bool join = p->joinguild;
											string guild = p->guild;

											string friendlist = p->friendlist;
											string password = ((PlayerInfo*)(currentPeer->data))->tankIDPass;
											j["username"] = username;
											j["password"] = hashPassword(password);
											j["adminLevel"] = p->adminLevel;
											j["ClothBack"] = clothback;
											j["ClothHand"] = clothhand;
											j["ClothFace"] = clothface;
											j["ClothShirt"] = clothshirt;
											j["ClothPants"] = clothpants;
											j["ClothNeck"] = clothneck;
											j["ClothHair"] = clothhair;
											j["ClothFeet"] = clothfeet;
											j["ClothMask"] = clothmask;
											j["ClothAnces"] = clothances;
											j["Level"] = level;
											j["Skin"] = skin;
											j["puncheffect"] = puncheffect;
											j["gem"] = gem;
											j["gems"] = newgem;
											j["entereffect"] = entereffect;
											j["isMuted"] = mute;
											j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
											j["isBanned"] = 1;
											j["exp"] = exp;

											j["guild"] = guild;
											j["joinguild"] = join;

											j["friend"] = friendlist;
											o << j << std::endl;
										}
									}
									delete ps.data;
									enet_peer_disconnect_later(currentPeer, 0);

								}

								enet_peer_send(currentPeer, 0, packet);

								//enet_host_flush(server);
							}
							delete p.data;
						}
						else if (str.substr(0, 7) == "/ipwew ")
						{

							if (!isOwner(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))break;


							string ipban = "";
							std::ifstream ifs("test.json");

							string ip = str.substr(7, cch.length() - 7 - 1);
							if (ifs.is_open()) {

								json j3;
								ifs >> j3;
								ipban = j3["test"];
								ipban = ipban.append("|" + ip + "|");
							}
							std::ofstream od("test.json");
							if (od.is_open()) {

							}

							std::ofstream o("test.json");
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}
							json j;

							j["test"] = ipban;
							o << j << std::endl;

						}
						else if (str == "/magic")
						{
							PlayerInfo * playerData = ((PlayerInfo*)peer->data);
							for (int x = 0; x < 1000; x++) {
								GamePacket p1 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 3), playerData->x + x, playerData->y + x));
								ENetPacket * packet = enet_packet_create(p1.data,
									p1.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p1.data;
								GamePacket p2 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 3), playerData->x - x, playerData->y - x));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								GamePacket p3 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 3), playerData->x + x, playerData->y - x));
								ENetPacket * packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;
								GamePacket p4 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 3), playerData->x - x, playerData->y + x));
								ENetPacket * packet4 = enet_packet_create(p4.data,
									p4.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet4);
								delete p4.data;

							}
						}
						else if (str.substr(0, 5) == "/save") {


							if (!canban(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))break;

							cout << "Server operator " << ((PlayerInfo*)(peer->data))->rawName << " saving player json " << endl;

							ENetPeer * currentPeer;


							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9>> Saving data And you will disconnect!"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);

								enet_peer_disconnect_later(currentPeer, 0);
							}
						}
						else if (str.substr(0, 5) == "/pay ") {
							using namespace std::chrono;

							string lvl_info = str;

							size_t extra_space = lvl_info.find("  ");
							if (extra_space != std::string::npos) {
								lvl_info.replace(extra_space, 2, " ");
							}

							string delimiter = " ";
							size_t pos = 0;
							string lvl_user;
							string lvl_amount;
							if ((pos = lvl_info.find(delimiter)) != std::string::npos) {
								lvl_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease specify a `2player `othat you want to pay."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}

							if ((pos = lvl_info.find(delimiter)) != std::string::npos) {
								lvl_user = lvl_info.substr(0, pos);
								lvl_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease enter your desired `2gem amount`o."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}
							lvl_amount = lvl_info;
							if (lvl_amount == "") {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease enter your desired `2gem amount`o."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								continue;
							}
							if (lvl_amount.length() > 9) {
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oThat `2gem amount `ois `4too high`o!"));
								ENetPacket * packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet0);
								delete p0.data;
								continue;
							}
							int x;

							try {
								x = stoi(lvl_amount);
							}
							catch (std::invalid_argument& e) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease enter `4only numbers `ofor `2gem amount`o!"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								continue;
							}
							if (lvl_amount.find(" ") != string::npos || lvl_amount.find(".") != string::npos || lvl_amount.find(",") != string::npos || lvl_amount.find("@") != string::npos || lvl_amount.find("[") != string::npos || lvl_amount.find("]") != string::npos || lvl_amount.find("#") != string::npos || lvl_amount.find("<") != string::npos || lvl_amount.find(">") != string::npos || lvl_amount.find(":") != string::npos || lvl_amount.find("{") != string::npos || lvl_amount.find("}") != string::npos || lvl_amount.find("|") != string::npos || lvl_amount.find("+") != string::npos || lvl_amount.find("_") != string::npos || lvl_amount.find("~") != string::npos || lvl_amount.find("-") != string::npos || lvl_amount.find("!") != string::npos || lvl_amount.find("$") != string::npos || lvl_amount.find("%") != string::npos || lvl_amount.find("^") != string::npos || lvl_amount.find("&") != string::npos || lvl_amount.find("`") != string::npos || lvl_amount.find("*") != string::npos || lvl_amount.find("(") != string::npos || lvl_amount.find(")") != string::npos || lvl_amount.find("=") != string::npos || lvl_amount.find("'") != string::npos || lvl_amount.find(";") != string::npos || lvl_amount.find("/") != string::npos) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease `4do not include symbols `ofor `2gem amount`o!"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								continue;
							}
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(lvl_user)) {
									if (stoi(lvl_amount) <= 0) {
										GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oThat `2gem amount `ois too small!"));
										ENetPacket * packet8 = enet_packet_create(p8.data,
											p8.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet8);
										delete p8.data;
										continue;
									}
									if (((PlayerInfo*)(peer->data))->gem < stoi(lvl_amount)) {
										GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYou `4do not have enough `2gems `oto pay that person. You are short of `2" + std::to_string(stoi(lvl_amount) - ((PlayerInfo*)(peer->data))->gem) + " gems`o."));
										ENetPacket * packet8 = enet_packet_create(p8.data,
											p8.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet8);
										delete p8.data;
										continue;
									}
									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->rawName) {
										GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYou `4can't `opay yourself!"));
										ENetPacket * packet0 = enet_packet_create(p0.data,
											p0.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet0);
										delete p0.data;
										continue;
									}
									string gem = std::to_string(((PlayerInfo*)(currentPeer->data))->gem + stoi(lvl_amount));
									if (gem.length() > 9) {
										GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oThat player already have `4too many `2gems`0!"));
										ENetPacket * packet0 = enet_packet_create(p0.data,
											p0.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet0);
										delete p0.data;
										continue;
									}

									((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - stoi(lvl_amount);
									((PlayerInfo*)(currentPeer->data))->gem = ((PlayerInfo*)(currentPeer->data))->gem + stoi(lvl_amount);

									GamePacket p67 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
									ENetPacket * packet67 = enet_packet_create(p67.data,
										p67.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet67);
									delete p67.data;
									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYou have paid `5" + ((PlayerInfo*)(currentPeer->data))->Chatname + " `2" + lvl_amount + " gems`o."));
									ENetPacket * packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									GamePacket p68 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(currentPeer->data))->gem));
									ENetPacket * packet68 = enet_packet_create(p68.data,
										p68.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet68);
									delete p68.data;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2" + ((PlayerInfo*)(peer->data))->Chatname + " `ohave paid you `2" + lvl_amount + " gems `o."));
									string text = "action|play_sfx\nfile|audio/piano_nice.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete data;

									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete ps.data;
									break;
								}
							}
						}
						else if (str.substr(0, 5) == "/gem ")
						{
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), atoi(str.substr(5).c_str())));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							continue;

							// thank to iProgramInCpp#0489       


						}
						else if (str.substr(0, 6) == "/give ")
						{
							if (!isOwner(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							((PlayerInfo*)(peer->data))->gem = atoi(str.substr(6).c_str());
							GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							continue;

							// thank to iProgramInCpp#0489       


						}
						/*	else if (str.substr(0, 5) == "/gfl ") {
						using namespace std::chrono;

						string lvl_info = str;

						size_t extra_space = lvl_info.find("  ");

						if (extra_space != std::string::npos) {
						lvl_info.replace(extra_space, 2, " ");
						}

						string delimiter = " ";
						size_t pos = 0;
						string fr;
						string bg;
						if ((pos = lvl_info.find(delimiter)) != std::string::npos) {
						lvl_info.erase(0, pos + delimiter.length());
						}

						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6Please use like this /gfl <block id> <wallpaper id>"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}


						if ((pos = lvl_info.find(delimiter)) != std::string::npos) {
						fr = lvl_info.substr(0, pos);
						lvl_info.erase(0, pos + delimiter.length());
						}
						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6Please use like this /gfl <block id> <wallpaper id>"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}
						bg = lvl_info;
						if (bg == "") {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6Please use like this /gfl <block id> <wallpaper id>"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						continue;
						}
						if (bg.length() > 4) {
						GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oThat background id is too hight!"));
						ENetPacket * packet0 = enet_packet_create(p0.data,
						p0.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet0);
						delete p0.data;
						continue;
						}
						int background;
						int foreground;
						try {
						background = stoi(bg);
						foreground = stoi(fr);
						}
						catch (std::invalid_argument& e) {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6Please use like this /gfl <block id> <wallpaper id>"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						continue;
						}
						if (bg.find(" ") != string::npos || bg.find(".") != string::npos || bg.find(",") != string::npos || bg.find("@") != string::npos || bg.find("[") != string::npos || bg.find("]") != string::npos || bg.find("#") != string::npos || bg.find("<") != string::npos || bg.find(">") != string::npos || bg.find(":") != string::npos || bg.find("{") != string::npos || bg.find("}") != string::npos || bg.find("|") != string::npos || bg.find("+") != string::npos || bg.find("_") != string::npos || bg.find("~") != string::npos || bg.find("-") != string::npos || bg.find("!") != string::npos || bg.find("$") != string::npos || bg.find("%") != string::npos || bg.find("^") != string::npos || bg.find("&") != string::npos || bg.find("`") != string::npos || bg.find("*") != string::npos || bg.find("(") != string::npos || bg.find(")") != string::npos || bg.find("=") != string::npos || bg.find("'") != string::npos || bg.find(";") != string::npos || bg.find("/") != string::npos) {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease only put number!"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						continue;
						}
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (isHere(peer, currentPeer))
						{
						((PlayerInfo*)(peer->data))->guildflagblock = foreground;
						((PlayerInfo*)(peer->data))->guildflagbackground = background;
						int flag = (65536 * ((PlayerInfo*)(peer->data))->guildflagbackground) + ((PlayerInfo*)(peer->data))->guildflagblock;

						GamePacket p2 = packetEnd(appendIntx(appendIntx(appendIntx(appendIntx(appendString(createPacket(), "OnGuildDataChanged"), 41179607), 41179607), flag), 0));

						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;

						updateInvis(peer);


						}
						}
						}
						*/


						else if (str.substr(0, 7) == "/ances ") {
							((PlayerInfo*)(peer->data))->cloth_ances = atoi(str.substr(7).c_str());
							updateAllClothes(peer);

						}
						else if (str.substr(0, 5) == "/eff ")
						{
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							((PlayerInfo*)(peer->data))->entereffect = atoi(str.substr(5).c_str());
						}
						else if (str.substr(0, 9) == "/weather ") {
							if (world->name != "ADMIN") {
								if (world->owner != "") {
									if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))

									{
										world->weather = atoi(str.substr(9).c_str());
										worldDB.saveAll();


										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlayer `2" + ((PlayerInfo*)(peer->data))->displayName + "`o has just changed the world's weather!"));
												ENetPacket * packet1 = enet_packet_create(p1.data,
													p1.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet1);
												delete p1.data;

												GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
												ENetPacket * packet2 = enet_packet_create(p2.data,
													p2.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet2);
												delete p2.data;
												continue;
											}
										}
									}
								}
							}
						}
						else if (str.substr(0, 10) == "/sweather ")

						{
							GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), atoi(str.substr(10).c_str())));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							continue;

						}

						else if (str.substr(0, 6) == "/wtest")

						{
							GamePacket p = packetEnd(appendIntx(appendInt(appendInt(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), 29), 242), 500), 0));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							continue;

						}

						/*else if (str.substr(0, 6) == "/acce ") {
						if (!((PlayerInfo*)(peer->data))->haveGrowId) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), ">> `4Guest accounts can't use that command!"));
						ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
						}
						//sendConsoleMsg(peer, "`6" + str);
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (isHere(peer, currentPeer))
						{

						string name = str.substr(6, cch.length() - 6 - 1);
						if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
						if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {
						vector<string> worldaccess;

						std::ifstream ifs("" + ((PlayerInfo*)(peer->data))->currentWorld + ".json");
						if (ifs.is_open()) {
						json j;
						ifs >> j;
						vector<string> acc2 = j["worldaccess"];
						worldaccess = acc2;
						}

						worldaccess.push_back(((PlayerInfo*)(currentPeer->data))->rawName);
						}
						}
						}
						}
						}*/



						else if (str.substr(0, 8) == "/access ") {
							string accessname = str.substr(8, cch.length() - 8 - 1);
							if (((PlayerInfo*)(peer->data))->rawName == world->owner || isOwner(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
							{
								std::ifstream ifff("worlds/" + ((PlayerInfo*)(peer->data))->currentWorld + ".json");
								if (ifff.fail()) {
									ifff.close();
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Error: `oGuild does not exist! If you are seeing this message, please take a screenshot and send it to a developer!"));
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;
									continue;
								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load

								vector<string> wrlaccess;

								for (int i = 0; i < j["accessworld"].size(); i++) {
									wrlaccess.push_back(j["accessworld"][i]);
								}

								wrlaccess.push_back(accessname);

								j["accessworld"] = wrlaccess; //edit
								world->accessworld = wrlaccess;
								std::ofstream o("worlds/" + ((PlayerInfo*)(peer->data))->currentWorld + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;
							}
						}


						else if (str.substr(0, 7) == "/block ")
						{
							if (!isvip(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							((PlayerInfo*)(peer->data))->cloth_face = atoi(str.substr(7).c_str());
							sendState(peer);
							((PlayerInfo*)(peer->data))->skinColor = 2;
							sendClothes(peer);

							int block = atoi(str.substr(7).c_str());

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You are " + std::to_string(block) + " now!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (str.substr(0, 7) == "/spawn ")
						{

							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;

							cout << "!!!   " << ((PlayerInfo*)(peer->data))->rawName << " !!!    in world " << ((PlayerInfo*)(peer->data))->currentWorld << "    !!!      Spawned " << atoi(str.substr(7, cch.length() - 7 - 1).c_str()) << endl;


							//right same line player 
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//left same line player 
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//up lr 1


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 27, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//up lr 2


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 54, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//up lr 3


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 81, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);


							//up lr 4


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 108, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//up lr 5


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 135, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//up lr 6


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 162, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//up lr 7


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 189, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//up lr 8


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 216, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//up lr 9


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 243, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//up lr 10


							//right
							/*0*/ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y - 270, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//down lr 1

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 35, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//down lr 2

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 70, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//down lr 3

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 105, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//down lr 4

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 140, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//down lr 5

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 175, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//down lr 6

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 210, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//down lr 7

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 245, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//down lr 8

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 280, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//down lr 9

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 315, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);

							//down lr 10

							//right
							/* 0 */ sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 0 : 0)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 6 : -6)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 7 : -7)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 8 : -8)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 9 : -9)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 10 : -10)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);




							//left
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -6 : 6)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -7 : 7)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -8 : 8)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -9 : 9)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);
							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -10 : 10)), ((PlayerInfo*)(peer->data))->y + 350, atoi(str.substr(7, cch.length() - 7 - 1).c_str()), 1, 0);


							int block = atoi(str.substr(7, cch.length() - 7 - 1).c_str());

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You Spawned `2" + std::to_string(block) + "`o!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

						}

						else if (str == "/dev")
						{

							((PlayerInfo*)(peer->data))->isDuctaped = true;
							sendState(peer);



							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Invisible mode Enabled! If you want hide name do /nick"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (str == "/invis" || str == "/invisible")
						{
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;

							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer) && !canSB(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass))
								{

									((PlayerInfo*)(peer->data))->isMod = 1;
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 1));

									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Invisible mode Enabled!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}
						else if (str == "/vis")
						{

							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									((PlayerInfo*)(peer->data))->isMod = 0;
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 0));

									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Invisible mode Disabled!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}

						else if (str == "/wizard")
						{


							((PlayerInfo*)(peer->data))->cloth_ances = 5078;
							sendState(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`^Legendary Wizard Set Mod has been Enabled! "));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (str == "/destructo")
						{

							((PlayerInfo*)(peer->data))->cloth_back = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_face = 576;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_feet = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_hair = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_hand = 1010;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_mask = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_necklace = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_pants = 468;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_shirt = 466;
							sendState(peer);
							((PlayerInfo*)(peer->data))->skinColor = 2;
							sendClothes(peer);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`^Dr.Destructo Set Mod has been Enabled! "));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						/* else if (str.substr(0, 6) == "/nick ") {
						if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						cout << ((PlayerInfo*)(peer->data))->rawName << " nicked into " << str.substr(6, cch.length() - 6 - 1) << endl;
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);

						((PlayerInfo*)(peer->data))->Chatname = str.substr(6, cch.length() - 6 - 1);
						((PlayerInfo*)(peer->data))->displayName= str.substr(6, cch.length() - 6 - 1);
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your nickname has been changed to `2" + str.substr(6, cch.length() - 6 - 1) + "`o!"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete ps.data;
						//enet_host_flush(server);
						} */
						else if (str.substr(0, 6) == "/nick ") {
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), str.substr(6, cch.length() - 6 - 1)));
									((PlayerInfo*)(peer->data))->Chatname = str.substr(6, cch.length() - 6 - 1);
									((PlayerInfo*)(peer->data))->displayName = str.substr(6, cch.length() - 6 - 1);
									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
								}
							}
						}


						else if (str.substr(0, 6) == "/role ") {



							GamePacket p2 = packetEnd(appendInt(appendIntx(appendIntx(appendString(createPacket(), "OnSetRoleSkinsAndIcons"), 6), 6), atoi(str.substr(6).c_str())));

							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;





						}

						/*		 else if (str.substr(0, 4) == "/ge ") {
						if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						string msg_info = str;

						size_t extra_space = msg_info.find("  ");
						if (extra_space != std::string::npos) {
						msg_info.replace(extra_space, 2, " ");
						}

						string delimiter = " ";
						size_t pos = 0;
						string blc;
						string bg;
						string role;
						if ((pos = msg_info.find(delimiter)) != std::string::npos) {
						msg_info.erase(0, pos + delimiter.length());
						}
						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease put foreground id."));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}

						if ((pos = msg_info.find(delimiter)) != std::string::npos) {
						bg = msg_info.substr(0, pos);
						msg_info.erase(0, pos + delimiter.length());
						}
						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease put background id`o."));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}


						blc = msg_info;
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (isHere(peer, currentPeer))
						{

						string message = getStrUpper(bg);
						string user = getStrUpper(blc);
						if (
						message.find("a") || message.find("f") || message.find("k") || message.find("p") || message.find("y") || message.find("v"
						) || message.find("b") || message.find("g") || message.find("l") || message.find("q") || message.find("z"
						) || message.find("c") || message.find("h") || message.find("m") || message.find("r") || message.find("t"
						) || message.find("d") || message.find("i") || message.find("n") || message.find("w") || message.find("u"
						) || message.find("e") || message.find("j") || message.find("o") || message.find("x") || message.find("s"
						)   || message.find(".") || message.find(",") || message.find("@") || message.find("[") || message.find("]") || message.find("#"
						) || message.find("<") || message.find(">") || message.find(":") || message.find("{") || message.find("}") || message.find("|") || message.find("+"
						) || message.find("_") || message.find("~") || message.find("-") || message.find("!") || message.find("$") || message.find("%") || message.find("^"
						) || message.find("&") || message.find("`") || message.find("*") || message.find("(") || message.find(")") || message.find("=") || message.find("'"
						) || message.find(";") || message.find("/")

						) {
						bg = "0";
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "bg`o."));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}
						else if (
						user.find("a") || user.find("f") || user.find("k") || user.find("p") || user.find("y") || user.find("v"
						) || user.find("b") || user.find("g") || user.find("l") || user.find("q") || user.find("z"
						) || user.find("c") || user.find("h") || user.find("m") || user.find("r") || user.find("t"
						) || user.find("d") || user.find("i") || user.find("n") || user.find("w") || user.find("u"
						) || user.find("e") || user.find("j") || user.find("o") || user.find("x") || user.find("s"
						)   || user.find(".") || user.find(",") || user.find("@") || user.find("[") || user.find("]") || user.find("#"
						) || user.find("<") || user.find(">") || user.find(":") || user.find("{") || user.find("}") || user.find("|") || user.find("+"
						) || user.find("_") || user.find("~") || user.find("-") || user.find("!") || user.find("$") || user.find("%") || user.find("^"
						) || user.find("&") || user.find("`") || user.find("*") || user.find("(") || user.find(")") || user.find("=") || user.find("'"
						) || user.find(";") || user.find("/")
						) {
						blc = "0";
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "blc`o."));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}
						else {
						int flag = (65536 * stoi(bg)) + stoi(blc);

						GamePacket p2 = packetEnd(appendIntx(appendIntx(appendIntx(appendIntx(appendString(createPacket(), "OnGuildDataChanged"), 41179607), 41179607), flag), 3));

						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						}
						}
						}
						}*/
						else if (str.substr(0, 6) == "/hide ") {
							// if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnDisguiseChanged"), atoi(str.substr(6).c_str())));

									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;

								}
							}
						}

						else if (str.substr(0, 6) == "/flag ") {
							// if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), str.substr(6, cch.length() - 6 - 1) + "|showGuild|maxLevel"));
									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
								}
							}
						}

						else if (str.substr(0, 7) == "/flags ") {
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), "../" + str.substr(7, cch.length() - 7 - 1)));
									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
								}
							}
						}

						else if (str.substr(0, 8) == "/kickall") {

							if (world->name != "ADMIN") {
								if (world->owner != "") {
									if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))

									{
										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												sendPlayerLeave(currentPeer, (PlayerInfo*)(event.peer->data));
												((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
												sendWorldOffers(currentPeer);



												GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "All kicked out the world!"));
												ENetPacket * packet = enet_packet_create(ps.data,
													ps.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(peer, 0, packet);
												delete ps.data;
											}
										}
									}
								}
							}

						}


						else if (str == "/help") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Supporteds comands are: /help, /news, /noclip (Go through walls), /unmod, /inventory, /item (ID), /team (ID), /color (NUMBER), /who, /state (NUMBER), /count, /sb (MESSAGE), /jsb (MESSAGE), /alt, /radio, /gem (AMOUNT), /weather, /sweather, /howgay, /access (NAME), /accesslist, /msg, /calc (CALCULATOR)"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}
						else if (str == "/?") {
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Admin command : `2/ban, /nuke, /nick, /asb, /block, /weather, /msb, /spawn, /find, /mods, /sweather, /invis, /vis, /gsm, /restart, /jsb, /xp, /level"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}

						else if (str.substr(0, 7) == "/unban ") {
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							std::ifstream ifff("players/" + PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1)) + ".json");
							if (ifff.fail()) {
								ifff.close();
								continue;
							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["isBanned"] = 0; //edit

							std::ofstream o("players/" + PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1)) + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;
						}
						else if (str.substr(0, 8) == "/unmute ") {
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							std::ifstream ifff("players/" + PlayerDB::getProperName(str.substr(8, cch.length() - 8 - 1)) + ".json");
							if (ifff.fail()) {
								ifff.close();
								continue;
							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["isMuted"] = 0; //edit

							std::ofstream o("players/" + PlayerDB::getProperName(str.substr(8, cch.length() - 8 - 1)) + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;

							GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), str.substr(8, cch.length() - 8 - 1) + " unmuted!"));
							ENetPacket * packet1 = enet_packet_create(p1.data,
								p1.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet1);

							ENetPeer * currentPeer;


							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;


								if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(8, cch.length() - 8 - 1)) {
									((PlayerInfo*)(currentPeer->data))->mute = 0;

									((PlayerInfo*)(currentPeer->data))->cantsay = false;
									sendState(currentPeer);
									GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Duct tape removed.  OUCH! (`$Duct Tape `omod removed!)"));
									ENetPacket * packet1 = enet_packet_create(p1.data,
										p1.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet1);

								}
							}
						}

						else if (str.substr(0, 11) == "/giveworld ") {
							//owner
							if (world->name != "ADMIN") {
								if (world->owner != "") {
									if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))

									{
										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{

												string name = str.substr(11, cch.length() - 11 - 1);
												if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(11, cch.length() - 11 - 1)) {
													if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
													world->owner = str.substr(11, cch.length() - 11 - 1);
													worldDB.saveAll();
													GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlayer `2" + name + "`o is the world owner " + name + "!"));
													ENetPacket * packet1 = enet_packet_create(p1.data,
														p1.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(currentPeer, 0, packet1);
													delete p1.data;
												}
											}
										}
									}
								}
							}
						}

						else if (str.substr(0, 6) == "/pull ") {
							if (canClear(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) || (((PlayerInfo*)(peer->data))->rawName == world->owner)) {
								/*using namespace std::chrono;
								if (((PlayerInfo*)(peer->data))->lastPull + 10000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || isOwner(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
								{
								((PlayerInfo*)(peer->data))->lastPull = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
								}
								else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Please wait for `210`` seconds before pulling again!"));
								ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
								continue;
								}*/
								if (str.substr(6, cch.length() - 6 - 1) == "") continue;

								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{

										if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
											if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 1) {
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't pull that player because that player is a Moderator or an Administrator!"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
											else {
												int x = ((PlayerInfo*)(peer->data))->x;
												int y = ((PlayerInfo*)(peer->data))->y;

												GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
												memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
												ENetPacket * packet2 = enet_packet_create(p2.data,
													p2.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet2);
												delete p2.data;
												{
													GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o" + ((PlayerInfo*)(peer->data))->Chatname + " `5pulls `o" + ((PlayerInfo*)(currentPeer->data))->Chatname + "!"));
													string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
													BYTE* data = new BYTE[5 + text.length()];
													BYTE zero = 0;
													int type = 3;
													memcpy(data, &type, 4);
													memcpy(data + 4, text.c_str(), text.length());
													memcpy(data + 4 + text.length(), &zero, 1);
													ENetPacket * packet2 = enet_packet_create(data,
														5 + text.length(),
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(currentPeer, 0, packet2);
													delete data;
													ENetPacket * packet = enet_packet_create(ps.data,
														ps.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(currentPeer, 0, packet);
													delete ps.data;
													GamePacket p23 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wYou were pulled by " + ((PlayerInfo*)(peer->data))->Chatname));
													ENetPacket * packet23 = enet_packet_create(p23.data,
														p23.len,
														ENET_PACKET_FLAG_RELIABLE);
													enet_peer_send(currentPeer, 0, packet23);
													delete p23.data;
												}
												{
													GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o" + ((PlayerInfo*)(peer->data))->Chatname + " `5pulls `o" + ((PlayerInfo*)(currentPeer->data))->Chatname + "!"));
													string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
													BYTE* data = new BYTE[5 + text.length()];
													BYTE zero = 0;
													int type = 3;
													memcpy(data, &type, 4);
													memcpy(data + 4, text.c_str(), text.length());
													memcpy(data + 4 + text.length(), &zero, 1);
													ENetPacket * packet2 = enet_packet_create(data,
														5 + text.length(),
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet2);
													delete data;
													ENetPacket * packet = enet_packet_create(ps.data,
														ps.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet);
													delete ps.data;

												}
											}
										}

									}
								}
							}
						}
						else if (str.substr(0, 4) == "/xp ") {
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							((PlayerInfo*)(peer->data))->blockbroken = atoi(str.substr(4).c_str());
							int xp = ((PlayerInfo*)(peer->data))->blockbroken;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Now your xp are `2" + std::to_string(xp) + "`0!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (str.substr(0, 7) == "/level ") {
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							((PlayerInfo*)(peer->data))->level = atoi(str.substr(7).c_str());
							int level = ((PlayerInfo*)(peer->data))->level;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Now your level are `2" + std::to_string(level) + "`0!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}

						/*else if (str.substr(0, 6) == "/flag  ") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

						((PlayerInfo*)(event.peer->data))->country = str.substr(6, cch.length() - 6 - 1);
						}
						else if (str.substr(0, 7) == "/flags  ") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

						((PlayerInfo*)(event.peer->data))->country = str.substr(6, cch.length() - 6 - 1);
						}*/

						else if (str.substr(0, 9) == "/checklvl") {

							ENetPeer* currentPeer;
							int level = ((PlayerInfo*)(peer->data))->level;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									string name = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`2" + name + "`0's level are" + std::to_string(level) + "!"), 0));
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2" + name + "`0's level are " + std::to_string(level) + "`0!"));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									ENetPacket * packetgay = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetgay);
									delete p.data;
								}
							}
						}
						else if (str.substr(0, 7) == "/howgay")
						{
							ENetPeer* currentPeer;
							int val = rand() % 100;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									string name = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`2" + name + " `0are `4" + std::to_string(val) + "% `pgay!"), 0));
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2" + name + "`0 are `4" + std::to_string(val) + "% `pgay!"));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									ENetPacket * packetgay = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetgay);
									delete p.data;
								}
							}
						}
						else if (str == "/count") {
							int count = 0;
							ENetPeer * currentPeer;
							string name = "";
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								count++;
							}
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "There is " + std::to_string(count) + " people out of 1024 limit."));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}
						else if (str.substr(0, 5) == "/asb ") {
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							cout << "ASB from " << ((PlayerInfo*)(peer->data))->rawName << "in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
							GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), str.substr(4, cch.length() - 4 - 1).c_str()), "audio/hub_open.wav"), 0));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								enet_peer_send(currentPeer, 0, packet);
							}

							//enet_host_flush(server);
							delete p.data;
						}
						else if (str.substr(0, 4) == "/se ") {
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/pop_up_button.rttex"), str.substr(4, cch.length() - 4 - 1).c_str()), "audio/hub_open.wav"), 0));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								enet_peer_send(currentPeer, 0, packet);
							}

							//enet_host_flush(server);
							delete p.data;
						}
						else if (str.substr(0, 6) == "/fban ")
						{
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancients Ones `ohave `4banned `0" + str.substr(6, cch.length() - 6 - 1) + " `#** `o(`4/rules `oto view rules!)"));
							ENetPacket * packetba = enet_packet_create(ban.data,
								ban.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								enet_peer_send(currentPeer, 0, packetba);
							}

							//enet_host_flush(server);
							delete ban.data;
						}
						else if (str == "/accesslist") {
							string accesslist = world->worldaccess;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Access list :  `^" + accesslist));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (str == "/unaccess") {
							world->worldaccess = "";
							worldDB.saveAll();
						}
						else if (str.substr(0, 5) == "/mods") {

							string mods = "";

							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 0) {
									mods += ((PlayerInfo*)(currentPeer->data))->rawName + " ";
								}
							}
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Mods online: `#" + mods));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}


						else if (str.substr(0, 5) == "/devs") {

							string devs = "";

							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 900) {
									devs += ((PlayerInfo*)(currentPeer->data))->rawName + " ";
								}
							}
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Devs online: `#" + devs));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}

						else if (str.substr(0, 7) == "/online") {

							string online = "";

							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
								if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) >= 0) {
									online += ((PlayerInfo*)(currentPeer->data))->Chatname + "`o, `w";
								}
							}
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o>>`5Players online: `w" + online));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (str.substr(0, 8) == "/kickall") {

							if (world->name != "ADMIN") {
								if (world->owner != "") {
									if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))

									{
										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												sendPlayerLeave(currentPeer, (PlayerInfo*)(event.peer->data));
												((PlayerInfo*)(currentPeer->data))->currentWorld = "EXIT";
												sendWorldOffers(currentPeer);


												GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You were kicked out of the world!"));
												ENetPacket * packet = enet_packet_create(ps.data,
													ps.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(peer, 0, packet);
												delete ps.data;
											}
										}
									}
								}
							}
						}
						else if (str == "/menu") {


						}
						/*else if (str == "/msg") {
						ENetPeer * currentPeer;
						if (((PlayerInfo*)(peer->data))->haveGrowId == false) {


						GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4You need to register before use this command!"));
						ENetPacket * packet4 = enet_packet_create(p4.data,
						p4.len,
						ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet4);
						delete p4.data;
						continue;
						}
						if (((PlayerInfo*)(peer->data))->haveGrowId) {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wMessage A Guy!``|left|32|\n\nadd_spacer|small|\nadd_text_input|username|Raw Name: ||15|\nadd_text_input|message|Message: ||100|\nend_dialog|msg|Cancel|OK|\n"));
						ENetPacket * packet3 = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet3);

						enet_host_flush(server);
						delete ps.data;
						}
						}


						/*else if (str.substr(0, 5) == "/msg ") {
						ENetPeer * currentPeer;


						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;

						if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(5, cch.length() - 5 - 1)) {
						if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;

						string username = ((PlayerInfo*)(peer->data))->displayName;
						string worldname = ((PlayerInfo*)(peer->data))->currentWorld;
						string message = "Test msg this no work !";
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `0" + username + "`6 (`$in " + worldname+ "`6) : "+message+"`6."));
						GamePacket ps2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `$"+ str.substr(5, cch.length() - 5 - 1) +"`6)"));
						ENetPacket * packet2 = enet_packet_create(ps2.data,
						ps2.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete ps2.data;
						delete ps.data;

						}
						}
						}*/
						/*else if (str.substr(0, 5) == "/msg ") {

						string delimiter = " ";
						size_t pos = 0;
						string pm_user;
						string pm_message;
						if ((pos = str.find(delimiter)) != std::string::npos) {
						str.erase(0, pos + delimiter.length());
						}
						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Error: `oNo target player specified."));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						continue;
						}

						if ((pos = str.find(delimiter)) != std::string::npos) {
						pm_user = str.substr(0, pos);
						str.erase(0, pos + delimiter.length());
						}
						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Error: `oPlease enter a message"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						continue;
						}
						pm_message = str;
						ENetPeer * currentPeer;

						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (((PlayerInfo*)(currentPeer->data))->rawName == pm_user) {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `2" + ((PlayerInfo*)(peer->data))->displayName + "`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + pm_message + "`6"));
						GamePacket ps2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6/msg "+pm_user+" "+pm_message));
						GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `$" + pm_message+"`6)"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete ps.data;

						ENetPacket * packet2 = enet_packet_create(ps2.data,
						ps2.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete ps2.data;

						ENetPacket * packet3 = enet_packet_create(ps3.data,
						ps3.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet3);
						delete ps3.data;

						break;
						}
						}
						}*/

						else if (str.substr(0, 5) == "/msg ") {
							if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oTo prevent abuse, you `4must `obe `2registered `oin order to use this command!"));
								ENetPacket * packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet0);
								delete p0.data;
								continue;
							}


							string msg_info = str;

							size_t extra_space = msg_info.find("  ");
							if (extra_space != std::string::npos) {
								msg_info.replace(extra_space, 2, " ");
							}

							string delimiter = " ";
							size_t pos = 0;
							string pm_user;
							string pm_message;
							if ((pos = msg_info.find(delimiter)) != std::string::npos) {
								msg_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease specify a `2player `oyou want your message to be delivered to."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}

							if ((pos = msg_info.find(delimiter)) != std::string::npos) {
								pm_user = msg_info.substr(0, pos);
								msg_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease enter your `2message`o."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}

							pm_message = msg_info;
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(pm_user)) {

									((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
									((PlayerInfo*)(currentPeer->data))->lastMsgerTrue = ((PlayerInfo*)(currentPeer->data))->Chatname;
									((PlayerInfo*)(currentPeer->data))->lastMsgWorld = ((PlayerInfo*)(peer->data))->currentWorld;
									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `2" + ((PlayerInfo*)(currentPeer->data))->Chatname + "`6)"));
									ENetPacket * packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `2" + ((PlayerInfo*)(peer->data))->Chatname + "`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + pm_message + "`o"));
									string text = "action|play_sfx\nfile|audio/pay_time.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete data;
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete ps.data;
									break;
								}
							}
						}
						else if (str.substr(0, 3) == "/r ") {
							if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oTo prevent abuse, you `4must `obe `2registered `oin order to use this command!"));
								ENetPacket * packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet0);
								delete p0.data;
								continue;
							}


							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastMsger) {

									((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
									GamePacket ps2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6/r " + ((PlayerInfo*)(peer->data))->lastMsger + " " + str.substr(3, cch.length() - 3 - 1)));

									ENetPacket * packet23 = enet_packet_create(ps2.data,
										ps2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet23);
									delete ps2.data;
									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `2" + ((PlayerInfo*)(peer->data))->lastMsger + "`6)"));
									ENetPacket * packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `2" + ((PlayerInfo*)(peer->data))->Chatname + "`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + str.substr(3, cch.length() - 3 - 1) + "`o"));
									string text = "action|play_sfx\nfile|audio/pay_time.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete data;
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete ps.data;
									break;
								}
							}
						}

						else if (str.substr(0, 4) == "/rgo") {
							string act = ((PlayerInfo*)(peer->data))->lastMsgWorld;
							if (act == "") {
								GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`4Oops where we are going?"));
								ENetPacket * packet = enet_packet_create(po.data,
									po.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
							else if (act == ((PlayerInfo*)(peer->data))->currentWorld) {
								GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`4Oops you already in the world!"));
								ENetPacket * packet = enet_packet_create(po.data,
									po.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
							else {
								sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
								joinWorld(peer, act, 0, 0);
							}
						}
						else if (str.substr(0, 3) == "/go") {
							string act = ((PlayerInfo*)(peer->data))->lastsbworld;
							if (act == "") {
								GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`4Oops where we are going?"));
								ENetPacket * packet = enet_packet_create(po.data,
									po.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
							else if (act == ((PlayerInfo*)(peer->data))->currentWorld) {
								GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`4Oops you already in the world!"));
								ENetPacket * packet = enet_packet_create(po.data,
									po.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
							else {
								sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
								joinWorld(peer, act, 0, 0);
							}
						}
						/*else if (str.substr(0, 5) == "/msg ") {


						string msg_info = str;

						size_t extra_space = msg_info.find("  ");
						if (extra_space != std::string::npos) {
						msg_info.replace(extra_space, 2, " ");
						}

						string delimiter = " ";
						size_t pos = 0;
						string pm_user;
						string pm_message;
						if ((pos = msg_info.find(delimiter)) != std::string::npos) {
						msg_info.erase(0, pos + delimiter.length());
						}
						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease specify a `2player `oyou want your message to be delivered to."));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}

						if ((pos = msg_info.find(delimiter)) != std::string::npos) {
						pm_user = msg_info.substr(0, pos);
						msg_info.erase(0, pos + delimiter.length());
						}
						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease enter your `2message`o."));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}

						pm_message = msg_info;
						ENetPeer * currentPeer;

						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (((PlayerInfo*)(currentPeer->data))->rawName == pm_user) {
						GamePacket ps2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6/msg " + pm_user + " " + pm_message));

						ENetPacket * packet23 = enet_packet_create(ps2.data,
						ps2.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet23);
						delete ps2.data;
						GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `2" + ((PlayerInfo*)(currentPeer->data))->Chatname + "`6)"));
						ENetPacket * packet0 = enet_packet_create(p0.data,
						p0.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet0);
						delete p0.data;
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `2" + ((PlayerInfo*)(peer->data))->Chatname + "`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + pm_message + "`o"));
						string text = "action|play_sfx\nfile|audio/pay_time.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPacket * packet2 = enet_packet_create(data,
						5 + text.length(),
						ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete data;
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete ps.data;
						break;
						}
						}
						}*/
						else if (str.substr(0, 6) == "/warn ") {
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;

							string warn_info = str;

							size_t extra_space = warn_info.find("  ");
							if (extra_space != std::string::npos) {
								warn_info.replace(extra_space, 2, " ");
							}

							string delimiter = " ";
							size_t pos = 0;
							string warn_user;
							string warn_message;
							if ((pos = warn_info.find(delimiter)) != std::string::npos) {
								warn_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease specify a player you want to warn."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}

							if ((pos = warn_info.find(delimiter)) != std::string::npos) {
								warn_user = warn_info.substr(0, pos);
								warn_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease enter your warn reason."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}

							warn_message = warn_info;
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == warn_user) {

									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Warned " + warn_user));
									ENetPacket * packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									GamePacket ps = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`wWarning from `4Admin`0: " + warn_message), "audio/hub_open.wav"), 0));

									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete ps.data;
									break;
								}
							}
						}
						/*else if (str.substr(0, 6) == "/warn ") {


						string msg_info = str;

						size_t extra_space = msg_info.find("  ");
						if (extra_space != std::string::npos) {
						msg_info.replace(extra_space, 2, " ");
						}

						string delimiter = " ";
						size_t pos = 0;
						string pm_user;
						string warn_reason;
						if ((pos = msg_info.find(delimiter)) != std::string::npos) {
						msg_info.erase(0, pos + delimiter.length());
						}
						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease specify a `2player `oyou want your message to be delivered to."));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}

						if ((pos = msg_info.find(delimiter)) != std::string::npos) {
						pm_user = msg_info.substr(0, pos);
						msg_info.erase(0, pos + delimiter.length());
						}
						else {
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Please enter warn reason!"));
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						}

						warn_reason = msg_info;
						ENetPeer * currentPeer;

						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (((PlayerInfo*)(currentPeer->data))->rawName == pm_user) {
						GamePacket ps2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6/warn " + pm_user + " " + warn_reason));

						ENetPacket * packet23 = enet_packet_create(ps2.data,
						ps2.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet23);
						delete ps2.data;
						GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Warned `$"+pm_user+"`6)"));
						ENetPacket * packet0 = enet_packet_create(p0.data,
						p0.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet0);
						delete p0.data;
						GamePacket ps = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`wWarning from `4Admin`0: " + warn_reason), "audio/hub_open.wav"), 0));
						//GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wWarning from `4Admin`0: "+warn_reason));
						GamePacket ps4 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wWarning from `4Admin`0: " + warn_reason));
						string text = "action|play_sfx\nfile|audio/hub_open.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPacket * packet2 = enet_packet_create(data,
						5 + text.length(),
						ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete data;
						ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete ps.data;
						ENetPacket * packet44 = enet_packet_create(ps4.data,
						ps4.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet44);
						delete ps.data;
						break;
						}
						}
						}
						/*else if (str.substr(0, 7) == "/trade ") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTradeStatus"), "txt"));
						ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						}*/



						else if (str.substr(0, 5) == "/ban ") {
							if (!canban(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))break;
							if (str.substr(5, cch.length() - 5 - 1) == "") continue;
							if (str.substr(5, cch.length() - 5 - 1) == "dark") continue;
							if (((PlayerInfo*)(peer->data))->rawName == str.substr(5, cch.length() - 5 - 1)) continue;


							// current date/time based on current system
							time_t now = time(0);

							// convert now to string form
							char* dt = ctime(&now);

							// convert now to tm struct for UTC
							tm *gmtm = gmtime(&now);
							dt = asctime(gmtm);


							cout << dt << "Server operator " << ((PlayerInfo*)(peer->data))->rawName << " has banned " << str.substr(5, cch.length() - 5 - 1) << "." << endl;

							ENetPeer * currentPeer;

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancient Ones `ohave `4banned `2" + str.substr(5, cch.length() - 5 - 1) + " `#** `o(`4/rules `oto see the rules!)"));
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(5, cch.length() - 5 - 1)) {
									if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancient Ones `ohave used `#Ban `oon `2" + str.substr(5, cch.length() - 5 - 1) + "`o! `#**"));
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);

									GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`0Warning from `4System`0: You've been `4BANNED `0from Private Server for 730 days"), "audio/hub_open.wav"), 0));
									ENetPacket * packet2 = enet_packet_create(ps2.data,
										ps2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWarning from `4System`o: You've been `4BANNED `ofrom Private Server for 730 days"));
									ENetPacket * packet3 = enet_packet_create(ps3.data,
										ps3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
									if (((PlayerInfo*)(currentPeer->data))->isIn)
									{
										if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

											PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));
											p->ban = 1;
											string username = PlayerDB::getProperName(p->rawName);

											std::ofstream o("players/" + username + ".json");
											if (!o.is_open()) {
												cout << GetLastError() << endl;
												_getch();
											}
											json j;

											int clothback = p->cloth_back;
											int clothhand = p->cloth_hand;
											int clothface = p->cloth_face;
											int clothhair = p->cloth_hair;
											int clothfeet = p->cloth_feet;
											int clothpants = p->cloth_pants;
											int clothneck = p->cloth_necklace;
											int clothshirt = p->cloth_shirt;
											int clothmask = p->cloth_mask;
											int clothances = p->cloth_ances;
											int level = p->level;
											int skin = p->skinColor;
											int exp = p->blockbroken;
											int ban = p->ban;
											int puncheffect = p->puncheffect;
											int mute = p->mute;
											int gem = 0;

											int newgem = p->gem;
											int entereffect = p->entereffect;
											string friendlist = p->friendlist;
											bool join = p->joinguild;
											string guild = p->guild;
											string password = ((PlayerInfo*)(currentPeer->data))->tankIDPass;
											j["username"] = username;
											j["password"] = hashPassword(password);
											j["adminLevel"] = p->adminLevel;
											j["ClothBack"] = clothback;
											j["ClothHand"] = clothhand;
											j["ClothFace"] = clothface;
											j["ClothShirt"] = clothshirt;
											j["ClothPants"] = clothpants;
											j["ClothNeck"] = clothneck;
											j["ClothHair"] = clothhair;
											j["ClothFeet"] = clothfeet;
											j["ClothMask"] = clothmask;
											j["ClothAnces"] = clothances;
											j["Level"] = level;
											j["Skin"] = skin;
											j["puncheffect"] = puncheffect;
											j["gem"] = gem;
											j["gems"] = newgem;
											j["entereffect"] = entereffect;
											j["isMuted"] = mute;
											j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
											j["isBanned"] = ban;
											j["exp"] = exp;

											j["guild"] = guild;
											j["joinguild"] = join;
											j["friend"] = friendlist;
											o << j << std::endl;
										}
									}
									delete ps.data;
									enet_peer_disconnect_later(currentPeer, 0);

								}

								enet_peer_send(currentPeer, 0, packet);

								//enet_host_flush(server);
							}
							delete p.data;
						}
						else if (str.substr(0, 6) == "/mute ") {
							if (!canban(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))break;
							if (str.substr(6, cch.length() - 6 - 1) == "") continue;
							if (((PlayerInfo*)(peer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) continue;



							ENetPeer * currentPeer;

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancient Ones `ohave `4mute `2" + str.substr(6, cch.length() - 6 - 1) + " `#** `o(`4/rules `oto see the rules!)"));
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
									if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;

									GamePacket ps3d = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oDuct tape has covered your mouth! (`$Duct Tape `omod added)"));
									ENetPacket * packet3d = enet_packet_create(ps3d.data,
										ps3d.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3d);

									GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`0Warning from `4System`0: You've been `4MUTED `0from Private Server for 730 days"), "audio/hub_open.wav"), 0));
									ENetPacket * packet2 = enet_packet_create(ps2.data,
										ps2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWarning from `4Admin`o: You've been `4duct-taped `ofrom Private Server"));
									ENetPacket * packet3 = enet_packet_create(ps3.data,
										ps3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);

									((PlayerInfo*)(currentPeer->data))->cantsay = true;
									sendState(currentPeer);
									if (((PlayerInfo*)(currentPeer->data))->isIn)
									{
										if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

											PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));
											p->mute = 1;
											string username = PlayerDB::getProperName(p->rawName);

											std::ofstream o("players/" + username + ".json");
											if (!o.is_open()) {
												cout << GetLastError() << endl;
												_getch();
											}
											json j;

											int clothback = p->cloth_back;
											int clothhand = p->cloth_hand;
											int clothface = p->cloth_face;
											int clothhair = p->cloth_hair;
											int clothfeet = p->cloth_feet;
											int clothpants = p->cloth_pants;
											int clothneck = p->cloth_necklace;
											int clothshirt = p->cloth_shirt;
											int clothmask = p->cloth_mask;
											int clothances = p->cloth_ances;
											int level = p->level;
											int skin = p->skinColor;
											int exp = p->blockbroken;
											int ban = p->ban;
											int puncheffect = p->puncheffect;
											int mute = p->mute;
											int gem = 0;

											int newgem = p->gem;
											int entereffect = p->entereffect;
											string friendlist = p->friendlist;
											bool join = p->joinguild;
											string guild = p->guild;
											string password = ((PlayerInfo*)(currentPeer->data))->tankIDPass;
											j["username"] = username;
											j["password"] = hashPassword(password);
											j["adminLevel"] = p->adminLevel;
											j["ClothBack"] = clothback;
											j["ClothHand"] = clothhand;
											j["ClothFace"] = clothface;
											j["ClothShirt"] = clothshirt;
											j["ClothPants"] = clothpants;
											j["ClothNeck"] = clothneck;
											j["ClothHair"] = clothhair;
											j["ClothFeet"] = clothfeet;
											j["ClothMask"] = clothmask;
											j["ClothAnces"] = clothances;
											j["Level"] = level;
											j["Skin"] = skin;
											j["puncheffect"] = puncheffect;
											j["gem"] = gem;
											j["gems"] = newgem;
											j["entereffect"] = entereffect;
											j["isMuted"] = mute;
											j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
											j["isBanned"] = ban;
											j["exp"] = exp;

											j["guild"] = guild;
											j["joinguild"] = join;
											j["friend"] = friendlist;
											o << j << std::endl;
										}
									}

									// enet_peer_disconnect_later(currentPeer, 0);

								}

								enet_peer_send(currentPeer, 0, packet);

								//enet_host_flush(server);
							}
							delete p.data;
						}


						else if (str.substr(0, 5) == "/msb ") {
							using namespace std::chrono;

							if (!canSB(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass)) continue;

							string name = ((PlayerInfo*)(peer->data))->Chatname;

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Mod-SB`` from `$`2" + name + "```` (in `#" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1)));
							string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (!((PlayerInfo*)(currentPeer->data))->radio)
									continue;
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);




								ENetPacket * packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
							delete data;
							delete p.data;
						}
						else if (str.substr(0, 5) == "/vsb ") {
							using namespace std::chrono;

							if (!isvip(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass)) continue;

							string name = ((PlayerInfo*)(peer->data))->Chatname;

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `1VIP-SB`` from `$`2" + name + "```` (in `#" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1)));
							string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (!((PlayerInfo*)(currentPeer->data))->radio)
									continue;
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);




								ENetPacket * packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
							delete data;
							delete p.data;
						}
						else if (str.substr(0, 4) == "/jsb") {
							using namespace std::chrono;





							if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
							{
								((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
							}


							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You are spamming sb too fast, calm down."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
								continue;
							}
							if (((PlayerInfo*)(peer->data))->haveGrowId == false) {


								GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4You need to register before use this command!"));
								ENetPacket * packet4 = enet_packet_create(p4.data,
									p4.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet4);
								delete p4.data;
								continue;
							}
							if (((PlayerInfo*)(peer->data))->haveGrowId) {
								string name = ((PlayerInfo*)(peer->data))->Chatname;





								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `4JAMMED``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1)));
								string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (!((PlayerInfo*)(currentPeer->data))->radio)
										continue;
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet);




									ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);

									//enet_host_flush(server);

								}
							}
						}
						else if (str.substr(0, 5) == "/gsm ") {


							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

							string name = ((PlayerInfo*)(peer->data))->displayName;

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`$** Global System Message:`5 " + str.substr(4, cch.length() - 4 - 1)));
							string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (!((PlayerInfo*)(currentPeer->data))->radio)
									continue;
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);



								ENetPacket * packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
							delete data;
							delete p.data;
						}
						else if (str.substr(0, 7) == "/items ")
						{
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							PlayerInventory inventory;
							InventoryItem item;

							string id = (str.substr(7, cch.length() - 7 - 1).c_str());
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oItem `w" + id + "`o has been `2added `oto your inventory."));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;

							item.itemID = atoi(str.substr(6, cch.length() - 7 - 1).c_str());
							item.itemCount = 1;
							inventory.items.push_back(item);

							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemID = 32;
							inventory.items.push_back(item);

							sendInventory(peer, inventory);

						}
						else if (str.substr(0, 4) == "/sb ") {
							using namespace std::chrono;





							if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
							{
								((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
							}


							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are spamming sb too fast, calm down."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
								continue;
							}
							if (((PlayerInfo*)(peer->data))->haveGrowId == false) {


								GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4You need to register before use this command!"));
								ENetPacket * packet4 = enet_packet_create(p4.data,
									p4.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet4);
								delete p4.data;
								continue;
							}
							if (((PlayerInfo*)(peer->data))->haveGrowId) {
								string name = ((PlayerInfo*)(peer->data))->Chatname;

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1)));
								string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (!((PlayerInfo*)(currentPeer->data))->radio)
										continue;

									((PlayerInfo*)(currentPeer->data))->lastsbworld = ((PlayerInfo*)(peer->data))->currentWorld;

									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet);




									ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);

									//enet_host_flush(server);
								}
								delete data;
								delete p.data;
							}
						}

						else if (str.substr(0, 5) == "/news") {
							sendGazette(peer);
						}

						else if (str.substr(0, 6) == "/find ") {
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							if (str.substr(6, cch.length() - 6 - 1) == "") continue;

							ENetPeer * currentPeer;

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Finding user: " + str.substr(6, cch.length() - 6 - 1)));

							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
									if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
									GamePacket psp = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Found  " + str.substr(6, cch.length() - 6 - 1) + " at: " + ((PlayerInfo*)(currentPeer->data))->currentWorld));

									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packetd);
									delete psp.data;
								}
							}
						}
						else if (str.substr(0, 4) == "/pe ") {



							int effect = atoi(str.substr(4).c_str());
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);
									delete psp.data;
								}
							}
						}


						else if (str.substr(0, 4) == "/ms ") {



							int effect = atoi(str.substr(4).c_str());
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									int x2 = ((PlayerInfo*)(peer->data))->x + 32;
									int y2 = ((PlayerInfo*)(peer->data))->y + 32;
									int x3 = ((PlayerInfo*)(peer->data))->x + 64;
									int y3 = ((PlayerInfo*)(peer->data))->y + 64;
									int y4 = ((PlayerInfo*)(peer->data))->y + 128;
									int x4 = ((PlayerInfo*)(peer->data))->x + 128;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));
									GamePacket psp2 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x2, y2));
									GamePacket psp3 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x3, y3));
									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);
									ENetPacket * packetd2 = enet_packet_create(psp2.data,
										psp2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd2);
									ENetPacket * packetd3 = enet_packet_create(psp3.data,
										psp3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd3);
									delete psp.data;
									delete psp2.data;
									delete psp3.data;

									int effect2 = 0x1;
									GamePacket psp31 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect2), x4, y4));
									GamePacket psp32 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect2), x4, y4));
									GamePacket psp33 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect2), x4, y4));
									ENetPacket * packetd31 = enet_packet_create(psp31.data,
										psp31.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd31);
									ENetPacket * packetd32 = enet_packet_create(psp32.data,
										psp32.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd32);
									ENetPacket * packetd33 = enet_packet_create(psp33.data,
										psp33.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd33);




								}
							}
						}





						else if (str.substr(0, 4) == "/te ") {



							int effect = atoi(str.substr(4).c_str());
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendIntx(appendString(createPacket(), "OnItemEffect"), effect));

									ENetPacket * packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);
									delete psp.data;
								}
							}
						}



						/*else if (str.substr(0, 6) == "/flag ") {

						if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						((PlayerInfo*)(peer->data))->country = "../"+ str.substr(6, cch.length() - 6 - 1);

						}
						else if (str.substr(0, 7) == "/flags ") {

						if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						((PlayerInfo*)(peer->data))->country = "../flags/" + str.substr(7, cch.length() - 7 - 1);

						}*/
						else if (str.substr(0, 5) == "/pe2 ") {



							int effect = atoi(str.substr(5).c_str());
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									int bitem = atoi(str.substr(5, cch.length() - 5 - 1).c_str());
									if (bitem == 40)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Sorry this effect has been disabled!"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p.data;
									}
									else {
										int x = ((PlayerInfo*)(peer->data))->x;
										int y = ((PlayerInfo*)(peer->data))->y;
										GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffectV2"), effect), x, y));

										ENetPacket * packetd = enet_packet_create(psp.data,
											psp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packetd);
										delete psp.data;
									}
								}
							}
						}

						else if (str.substr(0, 6) == "/send ") {
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							string lvl_info = str;

							size_t extra_space = lvl_info.find("  ");
							if (extra_space != std::string::npos) {
								lvl_info.replace(extra_space, 2, " ");
							}

							string delimiter = " ";
							size_t pos = 0;
							string lvl_user;
							string lvl_amount;
							if ((pos = lvl_info.find(delimiter)) != std::string::npos) {
								lvl_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease specify a `2player `othat you want to teleport."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}

							if ((pos = lvl_info.find(delimiter)) != std::string::npos) {
								lvl_user = lvl_info.substr(0, pos);
								lvl_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease enter your desired `2world`o."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}
							lvl_amount = lvl_info;
							if (lvl_amount == "") {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease enter your desired `2world`o."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								continue;
							}
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeer->data))->rawName == lvl_user) {

									string act = lvl_amount;
									if (act == "exit" || act == "EXIT" || act == "Exit") continue;

									{
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oTeleporting player `5" + ((PlayerInfo*)(currentPeer->data))->displayName + "`o to `2" + lvl_amount + "`o..."));
										string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);
										ENetPacket * packet2 = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet2);
										delete data;
										ENetPacket * packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet);
										delete ps.data;
									}

									sendPlayerLeave(peer, (PlayerInfo*)(currentPeer->data));
									joinWorld(currentPeer, act, 0, 0);

									GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYou were teleported by `5" + ((PlayerInfo*)(peer->data))->displayName + "`o."));
									string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket * packet3 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet3);
									delete data;
									ENetPacket * packeto = enet_packet_create(po.data,
										po.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packeto);
									delete po.data;
								}
							}
						}
						else if (str.substr(0, 6) == "/txts ") {
							GamePacket psp = packetEnd(appendString(appendString(createPacket(), "OnSDBroadcast"), str.substr(6, cch.length() - 6 - 1) + "!"));

							ENetPacket * packetd = enet_packet_create(psp.data,
								psp.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetd);
							delete psp.data;
						}

						else if (str.substr(0, 3) == "/p ") {
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									int ID = atoi(str.substr(3).c_str());
									((PlayerInfo*)(peer->data))->puncheffect = ID;
									sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->puncheffect);
									/*if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

									PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));

									string username = PlayerDB::getProperName(p->rawName);

									std::ifstream od("players/" + username + ".json");
									if (od.is_open()) {
									}

									std::ofstream o("players/" + username + ".json");
									if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
									}
									json j;

									int clothback = p->cloth_back;
									int clothhand = p->cloth_hand;
									int clothface = p->cloth_face;
									int clothhair = p->cloth_hair;
									int clothfeet = p->cloth_feet;
									int clothpants = p->cloth_pants;
									int clothneck = p->cloth_necklace;
									int clothshirt = p->cloth_shirt;
									int clothmask = p->cloth_mask;
									int level = p->level;
									int puncheffect = p->puncheffect;
									int ban = p->ban;
									string password = ((PlayerInfo*)(currentPeer->data))->tankIDPass;

									j["ClothBack"] = clothback;
									j["ClothHand"] = clothhand;
									j["ClothFace"] = clothface;
									j["ClothShirt"] = clothshirt;
									j["ClothPants"] = clothpants;
									j["ClothNeck"] = clothneck;
									j["ClothHair"] = clothhair;
									j["ClothFeet"] = clothfeet;
									j["ClothMask"] = clothmask;

									j["isBanned"] = ban;
									j["Level"] = level;
									j["puncheffect"] = puncheffect;

									j["adminLevel"] = p->adminLevel;
									j["password"] = hashPassword(password);
									j["username"] = username;


									o << j << std::endl;
									}*/

								}
							}
						}

						/*PlayerInfo* info = ((PlayerInfo*)(peer->data));
						int netID = info->netID;
						ENetPeer * currentPeer;
						int state = getState(info);
						/*for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (isHere(peer, currentPeer)) {


						PlayerMoving data;
						data.packetType = 0x14;
						data.characterState = 0; // animation
						data.x = 1000;
						data.y = 100;
						data.punchX = 0;
						data.punchY = 0;
						data.XSpeed = 300;
						data.YSpeed = 600;
						data.netID = netID;
						data.plantingTree = state;
						BYTE* raw = packPlayerMoving(&data);
						int var = atoi(str.substr(3).c_str()); // placing and breking
						memcpy(raw + 1, &var, 3);
						SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);

						}
						}
						}
						//((PlayerInfo*)(peer->data))->puncheffect;

						/*PlayerInfo* info = ((PlayerInfo*)(peer->data));
						int netID = info->netID;*/
						/*ENetPeer * currentPeer;





						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (isHere(peer, currentPeer)) {
						int ID = atoi(str.substr(3).c_str());
						((PlayerInfo*)(currentPeer->data))->puncheffect = ID;
						sendPuncheffect(currentPeer);
						/*PlayerMoving data;
						data.packetType = 0x14;
						data.characterState = 0; // animation
						data.x = 1000;
						data.y = 100;
						data.punchX = 0;
						data.punchY = 0;
						data.XSpeed = 300;
						data.YSpeed = 600;
						data.netID = netID;
						data.plantingTree = state;
						BYTE* raw = packPlayerMoving(&data);
						int var = ((PlayerInfo*)(currentPeer->data))->puncheffect; // placing and breking
						memcpy(raw + 1, &var, 3);
						SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE); */


						else if (str.substr(0, 8) == "/summon ")
						{
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(8, cch.length() - 8 - 1)) {


									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oSummoned " + ((PlayerInfo*)(currentPeer->data))->displayName + "`o!"));

									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet);
									delete ps.data;



									sendPlayerLeave(peer, (PlayerInfo*)(currentPeer->data));
									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									string act = ((PlayerInfo*)(peer->data))->currentWorld;
									joinWorld(currentPeer, act, x, y);




									GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wYou were summon by `5" + ((PlayerInfo*)(peer->data))->Chatname + "`w."));
									string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket * packet3 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet3);
									delete data;
									ENetPacket * packeto = enet_packet_create(po.data,
										po.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packeto);
									delete po.data;

								}
							}
						}


						else if (str.substr(0, 6) == "/kick ") {
							if (((PlayerInfo*)(peer->data))->rawName == world->owner || (((PlayerInfo*)(peer->data))->rawName == world->worldaccess || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))) {

								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{

										if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
											sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
											((PlayerInfo*)(currentPeer->data))->currentWorld = "EXIT";
											sendWorldOffers(currentPeer);
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Kicked by " + ((PlayerInfo*)(peer->data))->Chatname + " in " + world->name));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet);
											delete p.data;
											GamePacket p22 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Kicked " + str.substr(6, cch.length() - 6 - 1)));
											ENetPacket * packet22 = enet_packet_create(p22.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(peer, 0, packet22);
											delete p22.data;
										}
									}
								}
							}
						}
						else if (str.substr(0, 8) == "/freeze ") {
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{

									if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(8, cch.length() - 8 - 1)) {
										if (((PlayerInfo*)(currentPeer->data))->rawName == "dark") {
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't freeze that player because that player is an Owner!"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(peer, 0, packet);
											delete p.data;
											continue;
										}

										GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 1));
										memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
										ENetPacket * packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										delete p2.data;
										{
											GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#" + ((PlayerInfo*)(peer->data))->Chatname + " `1freezed `oyou!"));
											string text = "action|play_sfx\nfile|audio/freeze.wav\ndelayMS|0\n";
											BYTE* data = new BYTE[5 + text.length()];
											BYTE zero = 0;
											int type = 3;
											memcpy(data, &type, 4);
											memcpy(data + 4, text.c_str(), text.length());
											memcpy(data + 4 + text.length(), &zero, 1);
											ENetPacket * packet2 = enet_packet_create(data,
												5 + text.length(),
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet2);
											delete data;
											ENetPacket * packet = enet_packet_create(ps.data,
												ps.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet);
											delete ps.data;
										}
										{
											GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5" + ((PlayerInfo*)(currentPeer->data))->Chatname + " `ohas been `1frozen`o!"));
											ENetPacket * packet = enet_packet_create(ps.data,
												ps.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(peer, 0, packet);
											delete ps.data;
										}
									}
								}
							}
						}

						else if (str.substr(0, 6) == "/warp ") {
							using namespace std::chrono;
							string name = getStrUpper(str.substr(6, cch.length() - 6 - 1));

							if (name == "EXIT") {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oHuh? Why you want warp to exit?"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete p.data;
								continue;
							}



							else if (((PlayerInfo*)(peer->data))->lastWarp + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) || canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
							{
								((PlayerInfo*)(peer->data))->lastWarp = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
							}


							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Please wait 15ses to use command again!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
								continue;
							}
							string act = str.substr(6, cch.length() - 6 - 1);
							sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
							joinWorld(peer, act, 0, 0);
						}

						else if (str.substr(0, 8) == "/warpto ") {
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(8, cch.length() - 8 - 1)) {

									string act = ((PlayerInfo*)(currentPeer->data))->currentWorld;
									sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
									joinWorld(peer, act, 0, 0);

									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWarping to world `5" + act + "`o..."));
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet);
									delete ps.data;
								}
							}
						}

						else if (str.substr(0, 6) == "/radio") {
							GamePacket p;
							if (((PlayerInfo*)(peer->data))->radio) {
								p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You now won't recieve broadcast anymore."));
								((PlayerInfo*)(peer->data))->radio = false;
							}
							else {
								p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You will now recieve broadcasts again."));
								((PlayerInfo*)(peer->data))->radio = true;
							}

							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}
						else if (str.substr(0, 8) == "/restart") {
							if (!isOwner(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							cout << "Restart from " << ((PlayerInfo*)(peer->data))->displayName << endl;
							GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Restarting soon!"), "audio/mp3/suspended.mp3"), 0));
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Global System Message`o: Restarting server for update soon"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							ENetPacket * packetreset = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								enet_peer_send(currentPeer, 0, packet);
								enet_peer_send(currentPeer, 0, packetreset);
							}



							delete p2.data;
							delete p.data;
							//enet_host_flush(server);
						}

						else if (str.substr(0, 6) == "/clear") {
							if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {

								WorldInfo* wrld = getPlyersWorld(peer);

								ENetPeer * currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->currentWorld == wrld->name)
									{
										string act = ((PlayerInfo*)(peer->data))->currentWorld;
										//WorldInfo info = worldDB.get(act);
										// sendWorld(currentPeer, &info);
										int x = 3040;
										int y = 736;



										for (int i = 0; i < world->width*world->height; i++)
										{
											if (world->items[i].foreground == 6) {
												//world->items[i].foreground =0;
											}
											else if (world->items[i].foreground == 8) {

											}
											else if (world->items[i].foreground == 242) {

											}
											else {
												world->items[i].foreground = 0;
												world->items[i].background = 0;
											}
										}

										sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
										joinWorld(currentPeer, act, 0, 0);





									}

								}
							}
						}



						/*else if (str.substr(0, 6) == "/clear") {
						if (!canClear(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						vector<WorldInfo> worlds;
						AWorld ret;
						cout << "World cleared by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
						WorldInfo* wrld = getPlyersWorld(peer);
						for (int i = 0; i < worlds.size(); i++) {
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (((PlayerInfo*)(currentPeer->data))->currentWorld == wrld->name)
						{
						string act = ((PlayerInfo*)(peer->data))->currentWorld;
						WorldInfo info = generateWorld(act, 100, 60);
						worlds.push_back(info);
						ret.id = worlds.size() - 1;
						ret.info = info;
						ret.ptr = &worlds.at(worlds.size() - 1);

						int x = 3040;
						int y = 736;
						for (int j = 0; j < info.width*info.height; j++)
						{
						if (info.items[j].foreground == 6) {
						x = (j%info.width) * 32;
						y = (j / info.width) * 32;
						}
						}



						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
						//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
						ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						WorldInfo infos = worldDB.get(act);
						sendWorld(currentPeer, &infos);

						//joinWorld(currentPeer, act, 0, 0);

						((PlayerInfo*)(currentPeer->data))->netID = cId;
						onPeerConnect(currentPeer);
						cId++;
						sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
						}

						}
						}
						}*/

						else if (str == "tex") {

						}


						else if (str == "/resetset")
						{
							((PlayerInfo*)(peer->data))->cloth_back = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_face = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_feet = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_hair = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_hand = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_mask = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_necklace = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_pants = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_shirt = 0;
							sendState(peer);
							((PlayerInfo*)(peer->data))->skinColor = 2;
							sendClothes(peer);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your set has been reseted!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						/*else if (str == "/hadi")
						{
						((PlayerInfo*)(peer->data))->cloth_back = 1674;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_face = 1204;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_feet = 1822;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_hair = 4818;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_hand = 1438;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_mask = 4820;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_necklace = 1466;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_pants = 0;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_shirt = 0;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`^Hadi Set Mod Enabled! Re-enter world!"));
						ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						}
						else if (str.substr(0, 6) == "/calc ") {

						}

						else if (str == "/admin")
						{
						((PlayerInfo*)(peer->data))->cloth_back = 3308;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_face = 1204;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_feet = 1822;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_hair = 2872;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_hand = 6026;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_mask = 6782;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_necklace = 1466;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_pants = 1462;
						sendState(peer);
						((PlayerInfo*)(peer->data))->cloth_shirt = 5646;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`^Admin Set Mod Enabled! Re-enter world!"));
						ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						}*/

						else if (str == "/beta") {
							//if (!isvip(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBetaMode"), 1));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							//enet_host_flush(server);
						}
						else
							if (str == "/inventory")
							{
								PlayerInventory inventory;
								for (int i = 0; i < 200; i++)
								{
									InventoryItem it;
									it.itemID = (i * 2) + 2;
									it.itemCount = 200;
									inventory.items.push_back(it);
								}
								((PlayerInfo*)(peer->data))->inventory = inventory;
								sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
							}

						if (str == "/set") {
							/*

							((PlayerInfo*)(peer->data))->

							*/
							size_t invsize = 250;
							if (((PlayerInfo*)(peer->data))->inventory.items.size() == invsize) {
								PlayerInventory inventory;
								InventoryItem item;
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_hair;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_shirt;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_pants;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_feet;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_face;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_hand;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_back;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_mask;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_necklace;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_ances;
								item.itemCount = 200;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemID = 32;
								inventory.items.push_back(item);
								((PlayerInfo*)(peer->data))->inventory = inventory;
							}
							else {
								InventoryItem item;
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_hair;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_shirt;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_pants;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_feet;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_face;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_hand;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_back;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_mask;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_necklace;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
								item.itemID = ((PlayerInfo*)(peer->data))->cloth_ances;
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
							}
							sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
						}


						else
							if (str.substr(0, 6) == "/item ")
							{

								PlayerInventory inventory;
								InventoryItem item;
								int bitem = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
								if (bitem == 6868 || bitem == 6870 || bitem == 6872 || bitem == 6874 || bitem == 6876 || bitem == 6878)
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Sorry this item has been disabled!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								int devitem = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
								if (devitem == 1790 || devitem == 1900 || devitem == 2592 || devitem == 1780 || devitem == 1782 || devitem == 1784 || devitem == 1874 || devitem == 2970 || devitem == 1876 || devitem == 1904 || devitem == 1986 || devitem == 1996 || devitem == 3140 || devitem == 3174 || devitem == 6028 || devitem == 6846 || devitem == 7098 || devitem == 1444)

								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Sorry, You can't get this item!!!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}

								else {
									string id = (str.substr(6, cch.length() - 6 - 1).c_str());
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Item `w" + id + "`o has been `2added `oto your inventory."));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet2);
									delete p2.data;

									size_t invsize = 250;
									if (((PlayerInfo*)(peer->data))->inventory.items.size() == invsize) {
										PlayerInventory inventory;
										InventoryItem item;
										item.itemID = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										item.itemCount = 200;
										inventory.items.push_back(item);
										item.itemCount = 1;
										item.itemID = 18;
										inventory.items.push_back(item);
										item.itemID = 32;
										inventory.items.push_back(item);
										((PlayerInfo*)(peer->data))->inventory = inventory;
									}
									else {
										InventoryItem item;
										item.itemID = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										item.itemCount = 999;
										((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
									}
									sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
								}
							}


							else if (str.substr(0, 7) == "/color ")
							{
								((PlayerInfo*)(peer->data))->skinColor = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
								sendClothes(peer);
							}


						if (str.substr(0, 4) == "/who")
						{
							sendWho(peer);

						}
						if (str.length() && str[0] == '/')
						{
							sendAction(peer, ((PlayerInfo*)(peer->data))->netID, str);
						}
						else if (str.length() > 0)
						{
							sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, str);
						}








					}


					if (!((PlayerInfo*)(event.peer->data))->isIn)
					{
						GamePacket p = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(), "OnSuperMainStartAcceptLogonHrdxs47254722215a"), 1385479555), "ubistatic-a.akamaihd.net"), "0098/CDNContent/cache/"), "cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"), "proto=13|choosemusic=audio/mp3/ykoops.mp3|active_holiday=4"));
						//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
						std::stringstream ss(GetTextPointerFromPacket(event.packet));
						std::string to;
						while (std::getline(ss, to, '\n')) {
							string id = to.substr(0, to.find("|"));
							string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
							if (id == "tankIDName")
							{
								((PlayerInfo*)(event.peer->data))->tankIDName = act;
								((PlayerInfo*)(event.peer->data))->haveGrowId = true;
							}
							else if (id == "tankIDPass")
							{
								((PlayerInfo*)(event.peer->data))->tankIDPass = act;
							}
							else if (id == "requestedName")
							{
								((PlayerInfo*)(event.peer->data))->requestedName = act;
							}
							else if (id == "country")
							{
								((PlayerInfo*)(event.peer->data))->country = act;
							}


							else if (id == "mac")
							{
								((PlayerInfo*)(event.peer->data))->macaddress = act;
							}
							else if (id == "meta")
							{
								((PlayerInfo*)(event.peer->data))->metaip = act;
							}
							else if (id == "wk")
							{
								((PlayerInfo*)(event.peer->data))->wkid = act;
							}
							else if (id == "hash2")
							{
								((PlayerInfo*)(event.peer->data))->hash2 = act;
							}
							else if (id == "game_version")
							{
								((PlayerInfo*)(event.peer->data))->gameversion = act;
							}
							else if (id == "rid")
							{
								((PlayerInfo*)(event.peer->data))->rid = act;
							}
							else if (id == "hash")
							{
								((PlayerInfo*)(event.peer->data))->hash = act;
							}
						}
						if (!((PlayerInfo*)(event.peer->data))->haveGrowId)
						{
							((PlayerInfo*)(event.peer->data))->rawName = "guest" + PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length() > 15 ? 15 : ((PlayerInfo*)(event.peer->data))->requestedName.length()));
							((PlayerInfo*)(event.peer->data))->displayName = "Guest_" + PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length() > 15 ? 15 : ((PlayerInfo*)(event.peer->data))->requestedName.length()));
							((PlayerInfo*)(event.peer->data))->Chatname = "Guest_" + PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length() > 15 ? 15 : ((PlayerInfo*)(event.peer->data))->requestedName.length()));
						}
						else {
							((PlayerInfo*)(event.peer->data))->rawName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
#ifdef REGISTRATION
							int logStatus = PlayerDB::playerLogin(peer, ((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass);
							if (logStatus == -11) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Sorry, this account (`5" + ((PlayerInfo*)(event.peer->data))->rawName + "`4) has been ip-banned."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								enet_peer_disconnect_later(peer, 0);
							}
							if (logStatus == -5) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Your name is over 18 letter ! Please change"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								enet_peer_disconnect_later(peer, 0);
							}
							if (logStatus == 1) {
								GamePacket pss = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4If you stuck at login please make sure to use `2Newest `4 growtopia and login to normal server first"));
								ENetPacket * packetss = enet_packet_create(pss.data,
									pss.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packetss);
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You successfully logged into your account!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								string username = ((PlayerInfo*)(event.peer->data))->rawName;
								std::ifstream ifs("players/" + PlayerDB::getProperName(username) + ".json");
								if (ifs.is_open()) {
									json j;
									ifs >> j;

									int level = j["Level"];

									((PlayerInfo*)(event.peer->data))->displayName = ((PlayerInfo*)(event.peer->data))->tankIDName;
									((PlayerInfo*)(event.peer->data))->Chatname = ((PlayerInfo*)(event.peer->data))->tankIDName;
									//((PlayerInfo*)(event.peer->data))->puncheffect = punch;
								}
							}
							else {
								loginfailed(peer);
								enet_peer_disconnect_later(peer, 0);
							}
#else

							((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->tankIDName.substr(0, ((PlayerInfo*)(event.peer->data))->tankIDName.length() > 18 ? 18 : ((PlayerInfo*)(event.peer->data))->tankIDName.length()));
							if (((PlayerInfo*)(event.peer->data))->displayName.length() < 3) ((PlayerInfo*)(event.peer->data))->displayName = "Person that don't know how name looks!";
#endif
						}
						for (char c : ((PlayerInfo*)(event.peer->data))->displayName) if (c < 0x20 || c>0x7A) ((PlayerInfo*)(event.peer->data))->displayName = "`4Bad characters in name, remove them!";

						if (((PlayerInfo*)(event.peer->data))->country.length() > 4)
						{
							((PlayerInfo*)(event.peer->data))->country = "us";
						}
						if (getAdminLevel(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
						{
							((PlayerInfo*)(event.peer->data))->country = "../token_icon_overlay";
						}

						//token_icon_overlay
						//cash_icon_overlay

						/*GamePacket p3= packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
						//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
						ENetPacket * packet3 = enet_packet_create(p3.data,
						p3.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet3);
						enet_host_flush(server);*/

						GamePacket p2 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), ((PlayerInfo*)(event.peer->data))->haveGrowId), ((PlayerInfo*)(peer->data))->tankIDName), ((PlayerInfo*)(peer->data))->tankIDPass));
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;


					}
					string pStr = GetTextPointerFromPacket(event.packet);
					//if (strcmp(GetTextPointerFromPacket(event.packet), "action|enter_game\n") == 0 && !((PlayerInfo*)(event.peer->data))->isIn)
					if (pStr.substr(0, 17) == "action|enter_game" && !((PlayerInfo*)(event.peer->data))->isIn)
					{
#ifdef TOTAL_LOG
						cout << "And we are in!" << endl;
#endif



						ENetPeer* currentPeer;
						((PlayerInfo*)(event.peer->data))->isIn = true;





						/*for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just entered game..."));
						ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);

						enet_host_flush(server);
						delete p.data;
						}*/
						sendWorldOffers(peer);
						int counts = 0;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							counts++;

						}
						string name = ((PlayerInfo*)(peer->data))->Chatname;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Welcome back `2" + name + "`o! `2" + std::to_string(counts) + " `oplayers are online! ``"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);


						//enet_host_flush(server);
						delete p.data;
						if (((PlayerInfo*)(peer->data))->haveGrowId) {

							PlayerInfo* p = ((PlayerInfo*)(peer->data));
							std::ifstream ifff("players/" + PlayerDB::getProperName(p->rawName) + ".json");
							json j;
							ifff >> j;

							//p->currentWorld = worldInfo->name;

							int bac, han, fac, hai, fee, pan, nec, shi, mas, lvl, ban, pch, skin, mute, gem, enter, anc, exp, join, gemnew;
							bac = j["ClothBack"];

							fac = j["ClothFace"];
							hai = j["ClothHair"];

							pan = j["ClothPants"];
							nec = j["ClothNeck"];
							shi = j["ClothShirt"];
							mas = j["ClothMask"];
							//anc = j["ClothAnces"];
							skin = j["Skin"];
							lvl = j["Level"];
							ban = j["isBanned"];
							pch = j["puncheffect"];
							mute = j["isMuted"];
							gem = j["gem"];
							enter = j["entereffect"];

							if (j.count("ClothAnces") == 1) {
								anc = j["ClothAnces"];
							}
							else {
								anc = 0;
							}

							if (j.count("exp") == 1) {
								exp = j["exp"];
							}
							else {
								exp = 0;
							}

							if (j["ClothFeet"] == 7762) {
								fee = 0;
							}
							else {
								fee = j["ClothFeet"];
							}

							if (j["ClothHand"] == 6866 || j["ClothHand"] == 6868 || j["ClothHand"] == 6870 || j["ClothHand"] == 6872 || j["ClothHand"] == 6874 || j["ClothHand"] == 6876 || j["ClothHand"] == 6878) {
								han = 0;
							}
							else {
								han = j["ClothHand"];
							}
							vector <string>frns;
							if (j.count("friends") == 1) {
								for (int i = 0; i < j["friends"].size(); i++) {
									frns.push_back(j["friends"][i]);
								}
							}
							else {
								frns = {};
							}

							if (j.count("joinguild") == 1) {
								join = j["joinguild"];
							}
							else {
								join = false;
							}

							string guild;
							if (j.count("guild") == 1) {
								guild = j["guild"];
							}
							else {
								guild = "";
							}
							if (j.count("gems") == 1) {
								gemnew = j["gems"];
							}
							else {
								gemnew = 0;
							}
							p->guild = guild;
							p->friendinfo = frns;
							p->joinguild = join;
							string friendlist;
							friendlist = j["friend"];
							p->friendlist = friendlist;
							p->cloth_back = bac;
							p->cloth_hand = han;
							p->cloth_face = fac;
							p->cloth_hair = hai;
							p->cloth_feet = fee;
							p->cloth_pants = pan;
							p->cloth_necklace = nec;
							p->cloth_shirt = shi;
							p->cloth_mask = mas;
							p->cloth_ances = anc;
							p->entereffect = enter;
							p->skinColor = skin;
							p->ban = ban;
							p->level = lvl;
							p->mute = mute;
							p->gem = gemnew;
							sendClothes(peer);

							p->puncheffect = pch;
							//sendPuncheffect(peer, p->puncheffect);
							//updateInvis(peer);
							p->blockbroken = exp;
							ifff.close();

							string guildname = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild);
							if (guildname != "") {
								std::ifstream ifff("guilds/" + guildname + ".json");
								if (ifff.fail()) {
									ifff.close();
									cout << "Failed loading guilds/" + guildname + ".json! From " + ((PlayerInfo*)(peer->data))->displayName + "." << endl;
									((PlayerInfo*)(peer->data))->guild = "";

								}
								json j;
								ifff >> j;

								int gfbg, gffg, glvl, gexp;

								string gstatement, gleader;

								vector<string> gmembers;

								gfbg = j["backgroundflag"];
								gffg = j["foregroundflag"];
								gstatement = j["GuildStatement"];
								gleader = j["Leader"];
								glvl = j["GuildLevel"];
								gexp = j["GuildExp"];
								for (int i = 0; i < j["Member"].size(); i++) {
									gmembers.push_back(j["Member"][i]);
								}
								((PlayerInfo*)(peer->data))->guildlevel = glvl;
								((PlayerInfo*)(peer->data))->guildexp = gexp;
								((PlayerInfo*)(peer->data))->guildBg = gfbg;
								((PlayerInfo*)(peer->data))->guildFg = gffg;
								((PlayerInfo*)(peer->data))->guildStatement = gstatement;
								((PlayerInfo*)(peer->data))->guildLeader = gleader;
								((PlayerInfo*)(peer->data))->guildMembers = gmembers;

								ifff.close();
							}
						}



						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							string name = ((PlayerInfo*)(currentPeer->data))->rawName;

							if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND ALERT: `o" + ((PlayerInfo*)(peer->data))->rawName + " `ohas `2logged on`o."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
							}
							else if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3GUILD ALERT: `o" + ((PlayerInfo*)(peer->data))->rawName + " `ohas `2logged on`o."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);

							}
						}


						PlayerInventory inventory;
						for (int i = 0; i < 200; i++)
						{
							InventoryItem it;
							it.itemID = (i * 2) + 2;
							it.itemCount = 200;
							inventory.items.push_back(it);
						}
						((PlayerInfo*)(event.peer->data))->inventory = inventory;

						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe Growtopia Gazette``|left|5016|\n\nadd_spacer|small|\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\nadd_spacer|small|\n\nadd_textbox|`wSeptember 10:`` `5Surgery Stars end!``|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Hello Growtopians,|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Surgery Stars is over! We hope you enjoyed it and claimed all your well-earned Summer Tokens!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|As we announced earlier, this month we are releasing the feature update a bit later, as we're working on something really cool for the monthly update and we're convinced that the wait will be worth it!|left|\n\nadd_spacer|small|\n\nadd_textbox|Check the Forum here for more information!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wSeptember Updates Delay``|noflags|https://www.growtopiagame.com/forums/showthread.php?510657-September-Update-Delay&p=3747656|Open September Update Delay Announcement?|0|0|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|Also, we're glad to invite you to take part in our official Growtopia survey!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wTake Survey!``|noflags|https://ubisoft.ca1.qualtrics.com/jfe/form/SV_1UrCEhjMO7TKXpr?GID=26674|Open the browser to take the survey?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Click on the button above and complete the survey to contribute your opinion to the game and make Growtopia even better! Thanks in advance for taking the time, we're looking forward to reading your feedback!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|And for those who missed PAW, we made a special video sneak peek from the latest PAW fashion show, check it out on our official YouTube channel! Yay!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wPAW 2018 Fashion Show``|noflags|https://www.youtube.com/watch?v=5i0IcqwD3MI&feature=youtu.be|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Lastly, check out other September updates:|left|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|IOTM: The Sorcerer's Tunic of Mystery|left|24|\n\nadd_label_with_icon|small|New Legeny Summer Clash Branch|left|24|\n\nadd_spacer|small|\n\nadd_textbox|`$- The Growtopia Team``|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\n\n\n\n\nadd_url_button|comment|`wOfficial YouTube Channel``|noflags|https://www.youtube.com/c/GrowtopiaOfficial|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_url_button|comment|`wSeptember's IOTM: `8Sorcerer's Tunic of Mystery!````|noflags|https://www.growtopiagame.com/forums/showthread.php?450065-Item-of-the-Month&p=3392991&viewfull=1#post3392991|Open the Growtopia website to see item of the month info?|0|0|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|`4WARNING:`` `5Drop games/trust tests`` and betting games (like `5Casinos``) are not allowed and will result in a ban!|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` Using any kind of `5hacked client``, `5spamming/text pasting``, or `5bots`` (even with an alt) will likely result in losing `5ALL`` your accounts. Seriously.|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` `5NEVER enter your GT password on a website (fake moderator apps, free gemz, etc) - it doesn't work and you'll lose all your stuff!|left|24|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wGrowtopia on Facebook``|noflags|http://growtopiagame.com/facebook|Open the Growtopia Facebook page in your browser?|0|0|\n\nadd_spacer|small|\n\nadd_button|rules|`wHelp - Rules - Privacy Policy``|noflags|0|0|\n\n\nadd_quick_exit|\n\nadd_spacer|small|\nadd_url_button|comment|`wVisit Growtopia Forums``|noflags|http://www.growtopiagame.com/forums|Visit the Growtopia forums?|0|0|\nadd_spacer|small|\nadd_url_button||`wWOTD: `1THELOSTGOLD`` by `#iWasToD````|NOFLAGS|OPENWORLD|THELOSTGOLD|0|0|\nadd_spacer|small|\nadd_url_button||`wVOTW: `1Yodeling Kid - Growtopia Animation``|NOFLAGS|https://www.youtube.com/watch?v=UMoGmnFvc58|Watch 'Yodeling Kid - Growtopia Animation' by HyerS on YouTube?|0|0|\nend_dialog|gazette||OK|"));
						}
					}
					if (strcmp(GetTextPointerFromPacket(event.packet), "action|refresh_item_data\n") == 0)
					{
						if (itemsDat != NULL) {
							ENetPacket * packet = enet_packet_create(itemsDat,
								itemsDatSize + 60,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							((PlayerInfo*)(peer->data))->isUpdating = true;
							enet_peer_disconnect_later(peer, 0);
							//enet_host_flush(server);
						}
						// TODO FIX refresh_item_data ^^^^^^^^^^^^^^
					}
					break;
				}
				default:
					cout << "Unknown packet type " << messageType << endl;
					break;
				case 3:
				{
					//cout << GetTextPointerFromPacket(event.packet) << endl;
					std::stringstream ss(GetTextPointerFromPacket(event.packet));
					std::string to;
					bool isJoinReq = false;
					while (std::getline(ss, to, '\n')) {
						string id = to.substr(0, to.find("|"));
						string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
						if (id == "name" && isJoinReq)
							joinWorld(peer, act, 0, 0);



						if (id == "action")
						{

							if (act == "join_request")
							{
								isJoinReq = true;

							}
							if (act == "quit_to_exit")
							{

								sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								sendWorldOffers(peer);
								if (((PlayerInfo*)(peer->data))->isIn)
								{
									if (((PlayerInfo*)(peer->data))->haveGrowId) {

										PlayerInfo* p = ((PlayerInfo*)(peer->data));

										string username = PlayerDB::getProperName(p->rawName);

										std::ofstream o("players/" + username + ".json");
										if (!o.is_open()) {
											cout << GetLastError() << endl;
											_getch();
										}
										json j;

										int clothback = p->cloth_back;
										int clothhand = p->cloth_hand;
										int clothface = p->cloth_face;
										int clothhair = p->cloth_hair;
										int clothfeet = p->cloth_feet;
										int clothpants = p->cloth_pants;
										int clothneck = p->cloth_necklace;
										int clothshirt = p->cloth_shirt;
										int clothmask = p->cloth_mask;
										int clothances = p->cloth_ances;
										int level = p->level;
										int skin = p->skinColor;
										int exp = p->blockbroken;
										int entereffect = p->entereffect;
										int ban = p->ban;
										int puncheffect = p->puncheffect;
										int mute = p->mute;
										int gem = 0;

										int newgem = p->gem;
										string friendlist = p->friendlist;
										bool join = p->joinguild;
										string guild = p->guild;
										string password = ((PlayerInfo*)(peer->data))->tankIDPass;
										j["username"] = username;
										j["password"] = hashPassword(password);
										j["adminLevel"] = p->adminLevel;
										j["ClothBack"] = clothback;
										j["ClothHand"] = clothhand;
										j["ClothFace"] = clothface;
										j["ClothShirt"] = clothshirt;
										j["ClothPants"] = clothpants;
										j["ClothNeck"] = clothneck;
										j["ClothHair"] = clothhair;
										j["ClothFeet"] = clothfeet;
										j["ClothMask"] = clothmask;
										j["ClothAnces"] = clothances;
										j["Level"] = level;
										j["Skin"] = skin;
										j["puncheffect"] = puncheffect;
										j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
										j["gem"] = gem;
										j["gems"] = newgem;
										j["entereffect"] = entereffect;
										j["isMuted"] = mute;
										j["isBanned"] = ban;
										j["exp"] = exp;

										j["guild"] = guild;
										j["joinguild"] = join;
										j["friend"] = friendlist;
										o << j << std::endl;
									}
								}

							}
							if (act == "quit")
							{
								sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
								if (((PlayerInfo*)(peer->data))->isIn)
								{
									if (((PlayerInfo*)(peer->data))->haveGrowId) {

										PlayerInfo* p = ((PlayerInfo*)(peer->data));

										string username = PlayerDB::getProperName(p->rawName);

										std::ofstream o("players/" + username + ".json");
										if (!o.is_open()) {
											cout << GetLastError() << endl;
											_getch();
										}
										json j;
										int entereffect = p->entereffect;
										int clothback = p->cloth_back;
										int clothhand = p->cloth_hand;
										int clothface = p->cloth_face;
										int clothhair = p->cloth_hair;
										int clothfeet = p->cloth_feet;
										int clothpants = p->cloth_pants;
										int clothneck = p->cloth_necklace;
										int clothshirt = p->cloth_shirt;
										int clothmask = p->cloth_mask;
										int clothances = p->cloth_ances;
										int level = p->level;
										int skin = p->skinColor;
										int exp = p->blockbroken;
										int ban = p->ban;
										int puncheffect = p->puncheffect;
										int mute = p->mute;
										int gem = 0;

										int newgem = p->gem;
										string friendlist = p->friendlist;
										bool join = p->joinguild;
										string guild = p->guild;
										string password = ((PlayerInfo*)(peer->data))->tankIDPass;
										j["username"] = username;
										j["password"] = hashPassword(password);
										j["adminLevel"] = p->adminLevel;
										j["ClothBack"] = clothback;
										j["ClothHand"] = clothhand;
										j["ClothFace"] = clothface;
										j["ClothShirt"] = clothshirt;
										j["ClothPants"] = clothpants;
										j["ClothNeck"] = clothneck;
										j["ClothHair"] = clothhair;
										j["ClothFeet"] = clothfeet;
										j["ClothMask"] = clothmask;
										j["ClothAnces"] = clothances;
										j["Level"] = level;
										j["Skin"] = skin;
										j["puncheffect"] = puncheffect;
										j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
										j["gem"] = gem;
										j["gems"] = newgem;
										j["entereffect"] = entereffect;
										j["isMuted"] = mute;
										j["isBanned"] = ban;
										j["exp"] = exp;

										j["guild"] = guild;
										j["joinguild"] = join;
										j["friend"] = friendlist;
										o << j << std::endl;
									}
								}
								enet_peer_disconnect_later(peer, 0);

							}

						}
					}
					break;
				}
				case 4:
				{
					{
						BYTE* tankUpdatePacket = GetStructPointerFromTankPacket(event.packet);

						if (tankUpdatePacket)
						{
							PlayerMoving* pMov = unpackPlayerMoving(tankUpdatePacket);
							switch (pMov->packetType)
							{
							case 0:
								((PlayerInfo*)(event.peer->data))->x = pMov->x;
								((PlayerInfo*)(event.peer->data))->y = pMov->y;
								((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10;
								sendPData(peer, pMov);
								if (!((PlayerInfo*)(peer->data))->joinClothesUpdated)
								{
									((PlayerInfo*)(peer->data))->joinClothesUpdated = true;
									updateAllClothes(peer);
									updateInvis(peer);
									sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->puncheffect);
									GamePacket p222 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
									ENetPacket * packet222 = enet_packet_create(p222.data,
										p222.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet222);

									if (((PlayerInfo*)(peer->data))->isMod == 1) {
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`^You in invis mode!``"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

									}
								}
								break;

							default:
								break;
							}
							PlayerMoving *data2 = unpackPlayerMoving(tankUpdatePacket);
							//	 cout << data2->packetType << endl;
							if (data2->packetType == 11)
							{
								sendtake(peer, ((PlayerInfo*)(event.peer->data))->netID, ((PlayerInfo*)(event.peer->data))->x, ((PlayerInfo*)(event.peer->data))->y, data2->plantingTree);
								// sendDrop(((PlayerInfo*)(event.peer->data))->netID, ((PlayerInfo*)(event.peer->data))->x, ((PlayerInfo*)(event.peer->data))->y, pMov->punchX, 1, 0);

								// lets take item
							}
							if (data2->packetType == 7)
							{

								sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
								//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << endl;
								/*GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
								//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
								ENetPacket * packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								enet_host_flush(server);*/
								sendWorldOffers(peer);
								// lets take item
							}
							if (data2->packetType == 10)
							{
								//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << ";" << pMov->punchY << ";" << pMov->characterState << endl;
								ItemDefinition def;
								try {
									def = getItemDef(pMov->plantingTree);
								}
								catch (int e) {
									goto END_CLOTHSETTER_FORCE;
								}

								switch (def.clothType) {
								case 0:
									if (((PlayerInfo*)(event.peer->data))->cloth0 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth0 = pMov->plantingTree;
									break;
								case 1:
									if (((PlayerInfo*)(event.peer->data))->cloth1 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth1 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth1 = pMov->plantingTree;
									break;
								case 2:
									if (((PlayerInfo*)(event.peer->data))->cloth2 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth2 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth2 = pMov->plantingTree;
									break;
								case 3:
									if (((PlayerInfo*)(event.peer->data))->cloth3 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth3 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth3 = pMov->plantingTree;
									break;
								case 4:
									if (((PlayerInfo*)(event.peer->data))->cloth4 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth4 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth4 = pMov->plantingTree;
									break;
								case 5: //ldragon
									if (((PlayerInfo*)(event.peer->data))->cloth5 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth5 = 0;
										((PlayerInfo*)(peer->data))->puncheffect = 8421376;
										sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->puncheffect);
										break;
									}
									{
										((PlayerInfo*)(event.peer->data))->cloth5 = pMov->plantingTree;
										int item = pMov->plantingTree;
										if (item == 1782) {  //legendary dragon
											((PlayerInfo*)(peer->data))->puncheffect = 8421397;

										}
										// ^^^^ Hand /       puncheffect        
										sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->puncheffect);
									}
									break;
								case 6:
									if (((PlayerInfo*)(event.peer->data))->cloth6 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth6 = 0;
										((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
										sendState(peer);
										break;
									}
									{
										((PlayerInfo*)(event.peer->data))->cloth6 = pMov->plantingTree;
										int item = pMov->plantingTree;
										if (item == 156 || item == 362 || item == 678 || item == 736 || item == 818 || item == 1206 || item == 1460 || item == 1550 || item == 1574 || item == 1668 || item == 1672 || item == 1674 || item == 1784 || item == 1824 || item == 1936 || item == 1938 || item == 1970 || item == 2254 || item == 2256 || item == 2258 || item == 2260 || item == 2262 || item == 2264 || item == 2390 || item == 2392 || item == 3120 || item == 3308 || item == 3512 || item == 4534 || item == 4986 || item == 5754 || item == 6144 || item == 6334 || item == 6694 || item == 6818 || item == 6842 || item == 1934 || item == 3134 || item == 6004 || item == 1780 || item == 2158 || item == 2160 || item == 2162 || item == 2164 || item == 2166 || item == 2168 || item == 2438 || item == 2538 || item == 2778 || item == 3858 || item == 350 || item == 998 || item == 1738 || item == 2642 || item == 2982 || item == 3104 || item == 3144 || item == 5738 || item == 3112 || item == 2722 || item == 3114 || item == 4970 || item == 4972 || item == 5020 || item == 6284 || item == 4184 || item == 4628 || item == 5322 || item == 4112 || item == 4114 || item == 3442) {
											((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
										}
										else {
											((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
										}
										// ^^^^ wings
										sendState(peer);
									}
									break;
								case 7:
									if (((PlayerInfo*)(event.peer->data))->cloth7 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth7 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth7 = pMov->plantingTree;
									break;
								case 8:
									if (((PlayerInfo*)(event.peer->data))->cloth8 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth8 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth8 = pMov->plantingTree;

									break;
								default:
									if (
										def.id == 7166
										|| def.id == 5078 || def.id == 5080 || def.id == 5082 || def.id == 5084
										|| def.id == 5126 || def.id == 5128 || def.id == 5130 || def.id == 5132
										|| def.id == 5144 || def.id == 5146 || def.id == 5148 || def.id == 5150
										|| def.id == 5162 || def.id == 5164 || def.id == 5166 || def.id == 5168
										|| def.id == 5180 || def.id == 5182 || def.id == 5184 || def.id == 5186
										|| def.id == 7168 || def.id == 7170 || def.id == 7172 || def.id == 7174
										) {
										if (((PlayerInfo*)(event.peer->data))->cloth_ances == pMov->plantingTree) {

											((PlayerInfo*)(event.peer->data))->cloth_ances = 0;
											break;
										}

										((PlayerInfo*)(event.peer->data))->cloth_ances = pMov->plantingTree;

									}

#ifdef TOTAL_LOG
									cout << "Invalid item activated: " << pMov->plantingTree << " by " << ((PlayerInfo*)(event.peer->data))->displayName << endl;
#endif
									break;
								}
								sendClothes(peer);
								// activate item
							END_CLOTHSETTER_FORCE:;
							}
							if (data2->packetType == 18)
							{
								// player state talking  / brb / ...
								sendPData(peer, pMov);
								// add talk buble
							}
							if (data2->punchX != -1 && data2->punchY != -1) {
								//cout << data2->packetType << endl;
								if (data2->packetType == 3)
								{
									sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
								}
								else {

								}
								/*PlayerMoving data;
								//data.packetType = 0x14;
								data.packetType = 0x3;
								//data.characterState = 0x924; // animation
								data.characterState = 0x0; // animation
								data.x = data2->punchX;
								data.y = data2->punchY;
								data.punchX = data2->punchX;
								data.punchY = data2->punchY;
								data.XSpeed = 0;
								data.YSpeed = 0;
								data.netID = ((PlayerInfo*)(event.peer->data))->netID;
								data.plantingTree = data2->plantingTree;
								SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
								cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;*/

							}
							delete data2;
							delete pMov;
						}

						else {
							cout << "Got bad tank packet";
						}
						/*char buffer[2048];
						for (int i = 0; i < event->packet->dataLength; i++)
						{
						sprintf(&buffer[2 * i], "%02X", event->packet->data[i]);
						}
						cout << buffer;*/
					}
				}
				break;
				case 5:
					break;
				case 6:
					//cout << GetTextPointerFromPacket(event.packet) << endl;
					break;
				}
				enet_packet_destroy(event.packet);
				break;
			}
			case ENET_EVENT_TYPE_DISCONNECT:
#ifdef TOTAL_LOG
				printf("Peer disconnected.\n");
#endif     //dcdc

				ENetPeer * currentPeer;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					string name = ((PlayerInfo*)(currentPeer->data))->rawName;

					if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND ALERT: `o" + ((PlayerInfo*)(peer->data))->rawName + " `ohas `4logged off`o."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
					}
					else if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3GUILD ALERT: `o" + ((PlayerInfo*)(peer->data))->rawName + " `ohas `4logged off`o."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
					}
				}



				if (((PlayerInfo*)(peer->data))->isIn)
				{
					if (((PlayerInfo*)(peer->data))->haveGrowId) {

						PlayerInfo* p = ((PlayerInfo*)(peer->data));

						string username = PlayerDB::getProperName(p->rawName);

						std::ofstream o("players/" + username + ".json");
						if (!o.is_open()) {
							cout << GetLastError() << endl;
							_getch();
						}
						json j;

						int clothback = p->cloth_back;
						int clothhand = p->cloth_hand;
						int clothface = p->cloth_face;
						int clothhair = p->cloth_hair;
						int clothfeet = p->cloth_feet;
						int clothpants = p->cloth_pants;
						int clothneck = p->cloth_necklace;
						int clothshirt = p->cloth_shirt;
						int clothmask = p->cloth_mask;
						int clothances = p->cloth_ances;
						int level = p->level;
						int skin = p->skinColor;
						int exp = p->blockbroken;
						int entereffect = p->entereffect;
						int ban = p->ban;
						int puncheffect = p->puncheffect;
						int mute = p->mute;
						int gem = 0;

						int newgem = p->gem;
						string friendlist = p->friendlist;
						bool join = p->joinguild;
						string guild = p->guild;
						string password = ((PlayerInfo*)(peer->data))->tankIDPass;
						j["username"] = username;
						j["password"] = hashPassword(password);
						j["adminLevel"] = p->adminLevel;
						j["ClothBack"] = clothback;
						j["ClothHand"] = clothhand;
						j["ClothFace"] = clothface;
						j["ClothShirt"] = clothshirt;
						j["ClothPants"] = clothpants;
						j["ClothNeck"] = clothneck;
						j["ClothHair"] = clothhair;
						j["ClothFeet"] = clothfeet;
						j["ClothMask"] = clothmask;
						j["ClothAnces"] = clothances;
						j["Level"] = level;
						j["Skin"] = skin;
						j["puncheffect"] = puncheffect;


						j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;


						j["gem"] = gem;
						j["gems"] = newgem;
						j["entereffect"] = entereffect;
						j["isMuted"] = mute;
						j["isBanned"] = ban;
						j["exp"] = exp;

						j["guild"] = guild;
						j["joinguild"] = join;
						j["friend"] = friendlist;
						o << j << std::endl;
					}
				}




				/* Reset the peer's client information. */
				/*ENetPeer* currentPeer;
				for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
				{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;

				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just left game..."));
				ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet);
				enet_host_flush(server);
				}*/
				enet_peer_disconnect_later(event.peer, 0);
				sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
				((PlayerInfo*)(event.peer->data))->inventory.items.clear();
				delete event.peer->data;
				event.peer->data = NULL;
			}
		}
	cout << "Program ended??? Huh?" << endl;
	while (1);
	return 0;
}
