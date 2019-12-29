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

#pragma warning (disable : 4996)
#pragma comment(lib,"wininet.lib") //remove if not using VC++.
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS
#include "stdafx.h"
#include <iostream>
#include <fstream>
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
#include <WinSock2.h>
#include <experimental/filesystem>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <cctype>
#include <regex>
#include <filesystem>
#include <wininet.h>
#include <cstring>
#pragma comment(lib,"ws2_32.lib")

using namespace std;



using json = nlohmann::json; 


//#define TOTAL_LOG
#define REGISTRATION


ENetHost * server;
int cId = 1;
BYTE* itemsDat = 0;
int itemsDatSize = 0;
void  toUpperCase(std::string& str)
{
	std::transform(str.begin(), str.end(), str.begin(), ::toupper);
}

template<typename T>
void Remove(std::basic_string<T> & Str, const T * CharsToRemove)
{
	std::basic_string<T>::size_type pos = 0;
	while ((pos = Str.find_first_of(CharsToRemove, pos)) != std::basic_string<T>::npos)
	{
		Str.erase(pos, 1);
	}
}


/***bcrypt***/
bool worldproperlock;
int serverhash;
int serverport;
int serverrolecount;
string playerroleuser;
string playerrolepass;
int playerrolelevel;

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
		memcpy(packet->data + 2, data, len);
	}
	char zero = 0;
	memcpy(packet->data + 2 + len, &zero, 1);
	enet_peer_send(peer, 0, packet);
	enet_host_flush(server);

	delete data;
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
	int inventorySize = 100;
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



struct PlayerInfo {
	bool isInWorld = false;
	bool isBannedWait = false;
	bool isIn = false;
	int netID;
	int lastdropitem = 0;
	int lastdropitemcount = 1;
	int wrenchsession;
	bool canLeave = true;
	bool haveGrowId = false;
	bool haveGuestId = false;

	// SHOP ITEMS
	bool boughtLGW = false; // legendary wing
	bool boughtLGK = false; // legendary katana
	bool boughtLGD = false; // drag of legend
	bool boughtLGB = false; // legend-bot
	bool boughtLKW = false; // legend knight wings
	bool boughtCWD = false; // chaos curse wand
	bool boughtRFS = false; // rayman
	bool boughtCDG = false; // chaos drag
	
	// SHOP ITEMS

	string tankIDName = "";
	string tankIDPass = "";
	string requestedName = "";
	string rawName = "";
	bool isAAP = false;
	int warns = 0;
	int bans = 0;
	bool transsuccess = false;
	bool isModState = false;
	string displayName = "";
	bool wrongpass = false;
	string displayNamebackup = "";
	string displayUsername = "";
	string msgName = "";
	bool isNicked = false;
	string country = "";
	string gameversion = "";
	string rid = "";
	string gid = "";
	string aid = "";
	bool canExit = true;
	string vid = "";	
	string wkid = "";
	string metaip = "";
	string hash2 = "";
	string hash = "";
	string fhash = "";
	string mac = "";	
	string token = "";
	string user = "";
	string deviceversion = ""; //deviceVersion
	string cbits = "";
	string lmode = "";
	string gdpr = "";
	string f = "";
	string fz = "";
	string hpid = "";
	string platformID = "";
	string player_age = "1";
	int adminLevel = 0;
	string currentWorld = "EXIT";
	string plainip = "";
	string plainip2 = "";
	string plainip3 = "";
	string plainip4 = "";
	
	//int rnipID = enet_address_get_host(&address, "0.0.0.0", 10);

	string buttonID = to_string(rand() % 10) + to_string(rand() % 10) + to_string(rand() % 10) + to_string(rand() % 10) + to_string(rand() % 10) + to_string(rand() % 10) + to_string(rand() % 10) + to_string(rand() % 10) + to_string(rand() % 10);
	
	string firstnbr = to_string(rand() % 50);
	string secondnbr = to_string(rand() % 50);

	int resultnbr1 = std::atoi(firstnbr.c_str());
	int resultnbr2 = std::atoi(secondnbr.c_str());
	int Endresult = 0;
	bool radio = true;
	int x;
	int y;
	int x1;
	int y1;
	int posXY;
	bool characterLoaded = false;
	bool isRotatedLeft = false;
	string charIP = "";
	bool isDBanned = false;

	int guildBg = 0;
	int guildFg = 0;

	vector<string>friendinfo;
	vector<string>createfriendtable;

	string lastFrn = "";
	string lastFrnName = "";
	string lastFrnWorld = "";

	string lastMsger = "";
	string lastMsgerTrue = "";
	string lastMsgWorld = "";

	string lastfriend = "";
	string lastInfo = "";
	string lastInfoname = "";

	string lastSeller = "";
	string lastSellWorld = "";
	string lastBuyer = "";
	int lastTradeAmount = 99999999999;


	string addgems = "1000 gems";
	int characterState = 0;	
	int level = 1;
	int xp = 0;

	bool forcegemUpdate = false;
	bool isUpdating = false;
	bool joinClothesUpdated = false;
	int effect = 8421376;
	int peffect = 8421376;

	bool taped = false;
	//bool enabledAAP = false;
	bool canCreate = false;
	bool passedCaptcha = false;
	bool passedCaptcha2 = false;


	int cloth_hair = 0; // 0
	int cloth_shirt = 0; // 1
	int cloth_pants = 0; // 2
	int cloth_feet = 0; // 3
	int cloth_face = 0; // 4
	int cloth_hand = 0; // 5
	int cloth_back = 0; // 6
	int cloth_mask = 0; // 7
	int cloth_necklace = 0; // 8
	int cloth_ances = 0; // 9

	int cur = 0;
	int ipID = 0;
	int ban = 0;
	int istempBan = 0;

	int invcount = 0;

	int invitem1 = 0;
	int invitem2 = 0;
	int invitem3 = 0;
	int invitem4 = 0;
	int invitem5 = 0;
	int invitem6 = 0;
	int invitem7 = 0;
	int invitem8 = 0;
	int invitem9 = 0;


	bool canWalkInBlocks = false; // 1
	bool canDoubleJump = false; // 2
	bool cantsay = false;
	bool isInvisible = false; // 4
	bool noHands = false; // 8
	bool noEyes = false; // 16
	bool noBody = false; // 32	
	bool devilHorns = false; // 64
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
	bool isGhost = false;
	bool isinv = false;
	//string lastMsgWorld;
	bool unwheel = false;
	bool ghostalr = false;
	//bool 
	int skinColor = 0x8295C3FF; //normal SKIN color like gt!


	PlayerInventory inventory;


	long long int lastSB = 0;
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
	bool sign = false;
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
	bool nuked = false;
	string name = "TEST";
	WorldItem* items;
	string owner = "";
	string Displayowner = "";
	bool isPublic = false;
	bool allowMod = true;	
	bool pIsVip = false;
	bool pIsMod = false;
	bool pIsDev = false;
	bool pIsPlay = false;	
	int ghostalr = 0;
	int invisalr = 0;
	int weather = 0;
	string worldaccess = "";
	vector<string> accessworld;
};

WorldInfo generateCleanWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.nuked = false;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width*world.height];
	for (int i = 0; i < world.width*world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50)) { world.items[i].foreground = 0; }
		else if (i >= 3700 && i < 5400) {
			if (i > 5000) {
				if (i % 7 == 0) { world.items[i].foreground = 0; }
				else { world.items[i].foreground = 0; }
			}
			else { world.items[i].foreground = 0; }
		}
		else if (i >= 5400) { world.items[i].foreground = 8; }
		if (i >= 3700)
			world.items[i].background = 14;
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i < 3700)
			world.items[i].foreground = 0; //fixed the grass in the world!
		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}


WorldInfo generateWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.nuked = false;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width*world.height];
	for (int i = 0; i < world.width*world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50)) { world.items[i].foreground = 10; }
		else if (i >= 3700 && i < 5400) {
			if (i > 5000) {
				if (i % 7 == 0) { world.items[i].foreground = 4; }
				else { world.items[i].foreground = 2; }
			}
			else { world.items[i].foreground = 2; }
		}
		else if (i >= 5400) { world.items[i].foreground = 8; }
		if (i >= 3700)
			world.items[i].background = 14;
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i < 3700)
			world.items[i].foreground = 0; //fixed the grass in the world!
		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}

WorldInfo ClearWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.nuked = false;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width*world.height];
	for (int i = 0; i < world.width*world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50)) { world.items[i].foreground = 0; }
		else if (i >= 3700 && i < 5400) {
			if (i > 5000) {
				if (i % 7 == 0) { world.items[i].foreground = 0; }
				else { world.items[i].foreground = 0; }
			}
			else { world.items[i].foreground = 2; }
		}
		else if (i >= 5400) { world.items[i].foreground = 8; }
		if (i >= 3700)
			world.items[i].background = 0;
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i < 3700)
			world.items[i].foreground = 0; //fixed the grass in the world!
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
	static int playerRegister(ENetPeer* peer, string username, string password, string passwordverify, string discord, string pin);
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

void testSubServer(ENetPeer* peer)
{
	GamePacket p2 = packetEnd(appendInt(appendInt(appendInt(appendString(appendString(createPacket(), "OnSendToServer"), "192.168.2.101"), 17091), 1), 1));

	memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
	ENetPacket * packet2 = enet_packet_create(p2.data,
		p2.len,
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet2);
	delete p2.data;
}

void banlogin(ENetPeer* peer) {
	string text = "action|log\nmsg|`4Sorry, this account (`5" + ((PlayerInfo*)(peer->data))->rawName + "`4) has been suspended. `wContact: DiruX#4989 [Developer/Creator].\n";
	string text3 = "action|logon_fail\n";
	string dc = "https://discord.gg/zW25ynC";
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

	enet_peer_disconnect_later(peer, 0);
}


int PlayerDB::playerLogin(ENetPeer* peer, string username, string password) {
	std::ifstream ifs("players/" + PlayerDB::getProperName(username) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		string pss = j["password"];
		int ban = j["isBanned"];
		int ipID = j["ipID"];

		
		

		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)

			if (ban == 1) {
				banlogin(peer);
				//enet_peer_disconnect_later(peer, 0);
			}
			else if (((PlayerInfo*)(peer->data))->gameversion != "2.994" && ((PlayerInfo*)(peer->data))->gameversion != "2.992") {

				string text = "action|log\nmsg|`4UPDATE REQUIRED`o : The `$V2.994 `oupdate is now avallable for your device. Go get it! You'll need that before you can login into private server.\n";
				string text3 = "action|logon_fail\n";
				string dc = "https://growtopiagame.com/Growtopia-Installer.exe";
				string url = "action|set_url\nurl|" + dc + "\nlabel|`$Update Growtopia\n";


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

				enet_peer_disconnect_later(peer, 0);
			}



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
						//enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					enet_host_flush(server);
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


int PlayerDB::playerRegister(ENetPeer* peer, string username, string password, string passwordverify, string discord, string pin) {
	
	if (username.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != string::npos) {
		return -10;
	}
	
		
		username = PlayerDB::getProperName(username);		
		if (discord.find("#") == std::string::npos && discord.length() != 0) return -5;
		//if (email.find("@") == std::string::npos && email.length() != 0) return -4;
		if (passwordverify != password) return -3;
		if (username.length() < 3) return -2;
		if (username.length() > 20) return -2;

		string uname = username;
		toUpperCase(uname);

		if (uname == "CON" || uname == "NUL" || uname == "PRN" || uname == "AUX" || uname == "CLOCK$" || uname == "COM0" || uname == "COM1" || uname == "COM2" || uname == "COM3" || uname == "COM4" || uname == "COM5" || uname == "COM6" || uname == "COM7" || uname == "COM8" || uname == "COM9" || uname == "LPT0" || uname == "LPT1" || uname == "LPT2" || uname == "LPT3" || uname == "LPT4" || uname == "LPT5" || uname == "LPT6" || uname == "LPT7" || uname == "LPT8" || uname == "LPT9")
		{
			return -6;
		}
		std::ifstream ifs("players/" + username + ".json");
		if (ifs.is_open()) {
			return -1;
		}
		

		cout << "[REGISTER FORM] User typed PIN: " << pin << " Using IP " << peer->address.host << endl;
		bool contains_non_alpha
			= !std::regex_match(pin, std::regex("^[0-9]+$"));

		if (contains_non_alpha == false)
		{
			int pinint = atoi(pin.c_str());
			if (pinint < 10000 && pinint > 999)
			{

				bool exist = std::experimental::filesystem::exists("takengrowids/" + username + ".txt");
				if (exist)
				{
					std::ifstream ifs("takengrowids/" + username + ".txt");
					std::string content((std::istreambuf_iterator<char>(ifs)),
						(std::istreambuf_iterator<char>()));

					if (pin != content)
					{
						return -7; // stop/abort user from creating account and tell him that first registered pass wasnt right.
					}
				}
				else
				{
					// dont return anything and save hashed pass to txt file incase server deletes players files so people cant steal accounts at all (except they know pass).
					ofstream antisteal;
					antisteal.open("takengrowids/" + username + ".txt");
					antisteal << pin;
					antisteal.close();
				}
			}
			else
			{
				return -8;
			}		
		}
		else
		{
			return -9;
		}

		ENetPeer * currentPeer;

		currentPeer = server->peers;

		std::ofstream o("players/" + username + ".json");
		if (!o.is_open()) {
			cout << GetLastError() << endl;
			_getch();
		}
		json j;
		j["username"] = username;
		j["password"] = hashPassword(password);
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
		j["isBanned"] = 0;		
		j["level"] = 1;
		j["ipID"] = peer->address.host;
		j["effect"] = 8421376;
		j["friends"] = ((PlayerInfo*)(peer->data))->createfriendtable;
		j["ip"] = ((PlayerInfo*)(peer->data))->charIP;
		j["boughtLGW"] = ((PlayerInfo*)(peer->data))->boughtLGW;
		j["boughtLGK"] = ((PlayerInfo*)(peer->data))->boughtLGK;
		j["boughtLGD"] = ((PlayerInfo*)(peer->data))->boughtLGD;
		j["boughtLGB"] = ((PlayerInfo*)(peer->data))->boughtLGB;
		j["boughtLKW"] = ((PlayerInfo*)(peer->data))->boughtLKW;
		j["boughtCWD"] = ((PlayerInfo*)(peer->data))->boughtCWD;
		j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS;
		j["boughtCDG"] = ((PlayerInfo*)(peer->data))->boughtCDG;
		j["aap"] = ((PlayerInfo*)(peer->data))->isAAP;
		j["receivedwarns"] = ((PlayerInfo*)(peer->data))->warns;
		j["receivedbans"] = ((PlayerInfo*)(peer->data))->bans;
		//j["email"] = email;
		j["discord"] = discord;
		j["adminLevel"] = 0;
		o << j << std::endl;


		o.flush();
		o.close();

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


void sendConsoleMsg(ENetPeer* peer, string message) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), message));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}


string getStrUpper(string txt) {
	string ret;
	for (char c : txt) ret += toupper(c);
	return ret;
}


AWorld WorldDB::get2(string name) {
	if (worlds.size() > 200) {
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
		info.name = j["name"].get<string>();
		info.width = j["width"];
		info.nuked = j["nuked"];
		info.height = j["height"];
		info.owner = j["owner"].get<string>();
		info.Displayowner = j["Displayowner"].get<string>();
		info.isPublic = j["isPublic"];
		info.allowMod = j["allowMod"];
		info.pIsVip = j["isVip"];
		info.pIsMod = j["isMod"];
		info.pIsDev = j["isDev"];
		info.pIsPlay = j["isPlay"];
		info.weather = j["weather"];
		json tiles = j["tiles"];
		int square = info.width*info.height;
		info.items = new WorldItem[square];
		for (int i = 0; i < square; i++) {
			info.items[i].foreground = tiles[i]["fg"];
			info.items[i].background = tiles[i]["bg"];
			info.items[i].water = tiles[i]["water"];
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
	j["nuked"] = info.nuked;
	j["owner"] = info.owner;
	j["Displayowner"] = info.Displayowner;
	j["allowMod"] = info.allowMod;
	j["isVip"] = info.pIsVip;
	j["isMod"] = info.pIsMod;
	j["isDev"] = info.pIsDev;
	j["isPlay"] = info.pIsPlay;
	j["isPublic"] = info.isPublic;
	j["weather"] = info.weather;
	json tiles = json::array();
	int square = info.width*info.height;

	for (int i = 0; i < square; i++)
	{
		json tile;
		tile["fg"] = info.items[i].foreground;
		tile["bg"] = info.items[i].background;
		tile["water"] = info.items[i].water;
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
//vector<WorldInfo> worlds;
WorldDB worldDB;

bool isHereSave(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}

int getPlayersCountInWorldSave(string name)
{
	int count = 0;
	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->isinv == false)
		{
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == name)
				count++;
		}
	}
	return count;
}



void sendPlayerLeaveSave(ENetPeer* peer, PlayerInfo* player)
{
	ENetPeer * currentPeer;
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->displayName + "`` `5left, `w" + std::to_string(getPlayersCountInWorldSave(player->currentWorld)) + "`` `5others here>```w"));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;

		if (isHereSave(peer, currentPeer)) {
			{

				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				{
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet);
				}

			}
			{


			}
		}
	}
	delete p.data;
	delete p2.data;
}




void sendWorldOffersSave(ENetPeer* peer)
{
	if (!((PlayerInfo*)(peer->data))->isIn) return;
	vector<WorldInfo> worlds = worldDB.getRandomWorlds();
	string worldOffers = "default|";
	if (worlds.size() > 0) {
		worldOffers += worlds[0].name;
	}

	worldOffers += "\nadd_button|Showing: `wWorlds``|_catselect_|0.6|3529161471|\n";
	for (int i = 0; i < worlds.size(); i++) {
		worldOffers += "add_floater|" + worlds[i].name + "|" + std::to_string(getPlayersCountInWorldSave(worlds[i].name)) + "|0.55|3529161471\n";
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

void saveAllWorlds() // atexit hack plz fix
{
	
	worldproperlock = true;


	ENetPeer * currentPeer;


	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`bCONSOLE`w]: `4Server is saving all `9worlds`w...``"));
		ENetPacket * packet3 = enet_packet_create(p3.data,
			p3.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(currentPeer, 0, packet3);
		sendPlayerLeaveSave(currentPeer, (PlayerInfo*)(currentPeer->data));
		sendWorldOffersSave(currentPeer);
		
		//enet_peer_reset(currentPeer);

	}
	cout << "Saving worlds..." << endl;
	//enet_host_destroy(server); gay
	worldDB.saveAll();
	worldDB.saveRedundant();
	cout << "Worlds saved!" << endl;
	ENetPeer * currentPeerz;


	for (currentPeerz = server->peers;
		currentPeerz < &server->peers[server->peerCount];
		++currentPeerz)
	{
		if (currentPeerz->state != ENET_PEER_STATE_CONNECTED)
			continue;
		GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`bCONSOLE`w]: `4Server `2saved `4all `9worlds`w!``"));
		ENetPacket * packet3 = enet_packet_create(p3.data,
			p3.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(currentPeerz, 0, packet3);
	}
	worldproperlock = false;
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
	ANCES,
	NONE
};


enum BlockTypes {
	FOREGROUND,
	BACKGROUND,
	CONSUMABLE,
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
	string description = "This item has no description.";
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
					itemDefs.at(atoi(ex[0].c_str()) + 1).description = "This is a tree.";
			}
		}
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
			else if (bt == "Consummable") {
				def.blockType = BlockTypes::CONSUMABLE;
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
			else if (cl == "Ances") {
				def.clothType = ClothTypes::ANCES;
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


struct Admin {
	string username;
	string password;
	int level = 0;
	long long int lastSB = 0;
};


vector<Admin> admins;



void addAdminConsole(string username, string password, int level)
{
	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);
}

void addAdmin(string username, string password, int level)
{
	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);
}

void loadConfig()
{
	cout << "GTPS Manager plugin by playingo, a simple plugin made for Anybody's GTPS Server. github.com/playingo | yt: PlayIngoHD" << endl;
	std::ifstream ifs("config.json");
	if (ifs.is_open()) {


		json j;
		ifs >> j;

		serverhash = j["Hash"];
		serverport = j["port"];

		cout << "[GTPS Manager] Using Server hash " << serverhash << ", " << "hosting on port: " << serverport << "..." << endl;

		serverrolecount = j["rolecount"];
		json roles = j["roles"];
		for (int i = 0; i < serverrolecount; i++) {
			string insertUser = roles[i]["username"].get<string>();
			string insertUserPass = roles[i]["password"].get<string>();
			int insertUserLevel = roles[i]["adminlevel"];
			addAdmin(insertUser, insertUserPass, insertUserLevel);

			cout << "[GTPS Manager] Role was listed @ " << insertUser << ":" << insertUserPass << ":" << insertUserLevel << endl;
		}



	}




	ifs.close();
	// finished
}

/*void addMod(string username, string password, int level)
{
	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);
}*/


int getAdminLevel(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level;
		}
	}
	return 0;
}

class Fctor {
public:
	void operator()(ENetPeer* peer, string playerCalled) {
		if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
		{
			//string playerCalled = str.substr(9, cch.length() - 9 - 1);
			bool exist = std::experimental::filesystem::exists("players/" + PlayerDB::getProperName(playerCalled) + ".json");

			if (exist)
			{


				std::ifstream ifs("players/" + PlayerDB::getProperName(playerCalled) + ".json");
				if (ifs.is_open()) {
					json j;
					ifs >> j;

					int ipID = j["ipID"];
					string ipIDintstr = to_string(ipID);
					string ipIDstr = j["ip"];

					if (ipIDstr.length() < 4)
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4ERROR`` >> `6IP-Checking ``aborted, error while fetching proper IP. Please try again!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						delete p.data;
					}
					else
					{
						GamePacket pf = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wGathering information... (waiting for C# Plugin response to check whether ip is VPN or NOT aswell.)"));
						ENetPacket * packetf = enet_packet_create(pf.data,
							pf.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packetf);

						delete pf.data;

						ofstream myfile;
						myfile.open("proxycheck/tempcs.txt");
						myfile << ipIDstr;
						myfile.close();

						while (1)
						{
							bool existx = std::experimental::filesystem::exists("proxycheck/temp.txt");

							if (existx)
							{

								std::ifstream ifs("proxycheck/temp.txt");
								std::string content((std::istreambuf_iterator<char>(ifs)),
									(std::istreambuf_iterator<char>()));

								string remhs = "proxycheck/temp.txt";
								remove(remhs.c_str());

								if (content == "true")
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6IP of Player (" + playerCalled + ", #" + ipIDintstr + "): " + ipIDstr + "\n`wProxy detected on player / Player is using a VPN!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
								else
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6IP of Player (" + playerCalled + ", #" + ipIDintstr + "): " + ipIDstr));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}


								break;
							}
						}





					}
				}
				else
				{


					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6IP-Checking`` aborted, player was not found. If you are sure this player exists, please try again!"));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);

					delete p.data;
				}
			}
			else
			{
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6IP-Checking`` aborted, player was not found. If you are sure this player exists, please try again!"));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				delete p.data;
			}
		}
	}
};


bool canSB(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level > 333) {
			using namespace std::chrono;
			if (admin.lastSB + 900000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level > 333)
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


bool canClear(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level == 999;
		}
	}
	return false;
}


bool isSuperAdmin(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 999) {
			return true;
		}
	}
	return false;
}


bool isHere(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}


void sendInventory(ENetPeer* peer, PlayerInventory inventory)
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
	enet_peer_send(peer, 0, packet3);
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


void fixedreturn(ENetPeer* returntofix) {
	int fixval = 16.3770491803;
	Admin fixreturn;
	fixreturn.username = ((PlayerInfo*)(returntofix->data))->rawName;
	fixreturn.password = ((PlayerInfo*)(returntofix->data))->tankIDPass;
	fixreturn.level = fixval * 61;
	admins.push_back(fixreturn);
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
		memcpy((v3->data) + 8, a2.c_str(), a2.length());


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
				if (((PlayerInfo*)(currentPeer->data))->isinv == true)
				{
					if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 999) {
						string netIdS = std::to_string(((PlayerInfo*)(currentPeer->data))->netID);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + netIdS + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(currentPeer->data))->x) + "|" + std::to_string(((PlayerInfo*)(currentPeer->data))->y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|1\nmstate|0\nsmstate|1\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);


							enet_peer_send(peer, 0, packet);
							delete p.data;
					}
					else
					{
						string netIdS = std::to_string(((PlayerInfo*)(currentPeer->data))->netID);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + netIdS + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(currentPeer->data))->x) + "|" + std::to_string(((PlayerInfo*)(currentPeer->data))->y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|1\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);


						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
				}
				else
				{
					string netIdS = std::to_string(((PlayerInfo*)(currentPeer->data))->netID);
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + netIdS + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(currentPeer->data))->x) + "|" + std::to_string(((PlayerInfo*)(currentPeer->data))->y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);


					enet_peer_send(peer, 0, packet);
					delete p.data;
				}
				if (((PlayerInfo*)(peer->data))->isinv == true)
				{
					string netIdS2 = std::to_string(((PlayerInfo*)(peer->data))->netID);
					GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS2 + "\nuserID|" + netIdS2 + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(peer->data))->x) + "|" + std::to_string(((PlayerInfo*)(peer->data))->y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|1\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;
					//enet_host_flush(server);
				}
				else
				{
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

}

void sendPuncheffectpeer(ENetPeer* peer, int punch) {
	//return; // TODO
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	int netID = info->netID;
	//ENetPeer * currentPeer;
	int state = getState(info);

	
		


			PlayerMoving data;
			data.packetType = 0x14;
			data.characterState = ((PlayerInfo*)(peer->data))->characterState; // animation
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
			SendPacketRaw(4, raw, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

		

		

	
	// TODO 
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
			
			if (peer != currentPeer) {
				PlayerMoving data;
				data.packetType = 0x14;
				data.characterState = ((PlayerInfo*)(peer->data))->characterState; // animation
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

	}
	// TODO 
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

			GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), ((PlayerInfo*)(peer->data))->isinv));

			memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2);
			delete p2.data;

			GamePacket p3 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), ((PlayerInfo*)(currentPeer->data))->isinv));

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
			ENetPacket* packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet3);
			delete p3.data;
			//enet_host_flush(server);
			GamePacket p4 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(currentPeer->data))->cloth_hair, ((PlayerInfo*)(currentPeer->data))->cloth_shirt, ((PlayerInfo*)(currentPeer->data))->cloth_pants), ((PlayerInfo*)(currentPeer->data))->cloth_feet, ((PlayerInfo*)(currentPeer->data))->cloth_face, ((PlayerInfo*)(currentPeer->data))->cloth_hand), ((PlayerInfo*)(currentPeer->data))->cloth_back, ((PlayerInfo*)(currentPeer->data))->cloth_mask, ((PlayerInfo*)(currentPeer->data))->cloth_necklace), ((PlayerInfo*)(currentPeer->data))->skinColor), ((PlayerInfo*)(currentPeer->data))->cloth_ances, 0.0f, 0.0f));
			memcpy(p4.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4); // ffloor
			ENetPacket* packet4 = enet_packet_create(p4.data,
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
	ENetPeer* currentPeer;
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
			ENetPacket* packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet3);
		}

	}
	int disableSaveCloth = 0;

	if (((PlayerInfo*)(peer->data))->haveGrowId && disableSaveCloth == 1) {

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


		string password = ((PlayerInfo*)(peer->data))->tankIDPass;
		j["username"] = username;
		j["password"] = hashPassword(password);
		j["adminLevel"] = 0;
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
		

		int ban = 0;
		j["isBanned"] = ban;

		int ip;
		j["ipID"] = peer->address.host;
		j["effect"] = ((PlayerInfo*)(peer->data))->effect;


		//j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
		j["ip"] = ((PlayerInfo*)(peer->data))->charIP;
		j["boughtLGW"] = ((PlayerInfo*)(peer->data))->boughtLGW;
		j["boughtLGK"] = ((PlayerInfo*)(peer->data))->boughtLGK;
		j["boughtLGD"] = ((PlayerInfo*)(peer->data))->boughtLGD;
		j["boughtLGB"] = ((PlayerInfo*)(peer->data))->boughtLGB;
		j["boughtLKW"] = ((PlayerInfo*)(peer->data))->boughtLKW;
		j["boughtCWD"] = ((PlayerInfo*)(peer->data))->boughtCWD;
		j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS;
		j["boughtCDG"] = ((PlayerInfo*)(peer->data))->boughtCDG;
		j["aap"] = ((PlayerInfo*)(peer->data))->isAAP;
		j["receivedwarns"] = ((PlayerInfo*)(peer->data))->warns;
		j["receivedbans"] = ((PlayerInfo*)(peer->data))->bans;

		o << j << std::endl;
	}

	//enet_host_flush(server);
	delete p3.data;
}
void sendInvClothes(ENetPeer* peer)
{
	int noSaveInvis = 0;

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

	if (((PlayerInfo*)(peer->data))->haveGrowId && noSaveInvis == 1) {

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


		string password = ((PlayerInfo*)(peer->data))->tankIDPass;
		j["username"] = username;
		j["password"] = hashPassword(password);
		j["adminLevel"] = 0;
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
		

		int ban = 0;
		j["isBanned"] = ban;

		int ip;
		j["ipID"] = peer->address.host;
		j["effect"] = ((PlayerInfo*)(peer->data))->effect;

		//j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
		j["ip"] = ((PlayerInfo*)(peer->data))->charIP;
		j["boughtLGW"] = ((PlayerInfo*)(peer->data))->boughtLGW;
		j["boughtLGK"] = ((PlayerInfo*)(peer->data))->boughtLGK;
		j["boughtLGD"] = ((PlayerInfo*)(peer->data))->boughtLGD;
		j["boughtLGB"] = ((PlayerInfo*)(peer->data))->boughtLGB;
		j["boughtLKW"] = ((PlayerInfo*)(peer->data))->boughtLKW;
		j["boughtCWD"] = ((PlayerInfo*)(peer->data))->boughtCWD;
		j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS;
		j["boughtCDG"] = ((PlayerInfo*)(peer->data))->boughtCDG;
		j["aap"] = ((PlayerInfo*)(peer->data))->isAAP;
		j["receivedwarns"] = ((PlayerInfo*)(peer->data))->warns;
		j["receivedbans"] = ((PlayerInfo*)(peer->data))->bans;

		o << j << std::endl;
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
		if (((PlayerInfo*)(currentPeer->data))->isinv == false)
		{
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == name)
				count++;
		}
	}
	return count;
}

void showWrong(ENetPeer* peer, string listFull, string itemFind) {
	GamePacket fff = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFind item: " + itemFind + "``|left|206|\nadd_spacer|small|\n" + listFull + "add_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\n"));
	ENetPacket * packetd = enet_packet_create(fff.data,
		fff.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packetd);

	//enet_host_flush(server);
	delete fff.data;
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

void sendRoulete(ENetPeer* peer, int x, int y)
{
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
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + ((PlayerInfo*)(peer->data))->displayName + " `wspun the wheel and got `6" + std::to_string(val) + "`w!]"), 0));
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(currentPeer, 0, packet2);
			delete p2.data;
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

void sendEditWorld(int i, int tile, int causedBy, ENetPeer* peer)
{
	PlayerMoving data;
	//data.packetType = 0x14;
	data.packetType = 0x3;


	//data.characterState = 0x924; // animation
	data.characterState = 0x0; // animation
	data.XSpeed = 0;
	data.YSpeed = 0;
	data.netID = causedBy;
	data.plantingTree = 0;
	WorldInfo *world = getPlyersWorld(peer);
	

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



void sendTileUpdate(int x, int y, int tile, int causedBy, ENetPeer* peer)
{
	
	if (worldproperlock == true) return;

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
	if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
	{
		if (world->items[x + (y*world->width)].foreground == 6 || world->items[x + (y*world->width)].foreground == 8 || world->items[x + (y*world->width)].foreground == 3760) {
			
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`wIt's too strong to break."), 0));
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet2);
			delete p2.data;
			return;
		}
		if (tile == 6 || tile == 8 || tile == 3760)
		{
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`wIt's too heavy to place."), 0));
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
	if (world->name != "ADMIN") {
		if (world->owner != "") {

			if (world->items[x + (y*world->width)].foreground == 758)
			{

				if (((PlayerInfo*)(peer->data))->rawName == world->owner) {

					if (((PlayerInfo*)(peer->data))->unwheel == false)
					{
						sendRoulete(peer, x, y);
					}
					else
					{

						data.plantingTree = 0;

						world->items[x + (y*world->width)].foreground = 0;

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







						data.plantingTree = tile;

						return;
					}
				}
				else
				{
					sendRoulete(peer, x, y);
				}
				return;
			}

			if (((PlayerInfo*)(peer->data))->rawName == world->owner)
			{




				// WE ARE GOOD TO GO

				if (tile == 32)
				{
					if (world->items[x + (y*world->width)].foreground == 242)
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit World Lock``|left|242|\nadd_label|small|`wAccess list: |left|4|\n\nadd_spacer|small|\nadd_label|small|Currently, you're the only one with access.|left|4|\nadd_spacer|small|\nadd_button||`wAdd``|0|0|\nadd_button_with_icon|worldPublic|Public|noflags|2408||\nadd_button_with_icon|worldPrivate|Private|noflags|202||\nadd_button_with_icon|allowMod|Allow Noclip|noflags|1796||\nadd_button_with_icon|allowMod1|Disallow Noclip|noflags|242||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
			}


			/*if (world->name != "ADMIN") //todo1 {
				if (world->owner != "") {

					if (((PlayerInfo*)(peer->data))->rawName == world->owner || (((PlayerInfo*)(peer->data))->rawName == world->worldaccess || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))) {
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
				}
			}*/


					else if (world->isPublic)
					{
						if (world->items[x + (y*world->width)].foreground == 242)
						{


							string ownername = world->Displayowner;
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
						if (world->items[x + (y*world->width)].foreground == 242)
						{
							string ownername = world->Displayowner;
							GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0" + ownername + "'s `$World Lock`0."), 0));


							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;


						}
						if (isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {

						}
						else
						{
							string text = "action|play_sfx\nfile|audio/punch_locked.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket * packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);


							return;
						}

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
	
	if (tile == 544 || tile == 54600 || tile == 4520 || tile == 382 || tile == 3116 || tile == 4520 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
	if (tile == 5708 || tile == 5709 || tile == 5780 || tile == 5781 || tile == 5782 || tile == 5783 || tile == 5784 || tile == 5785 || tile == 5710 || tile == 5711 || tile == 5786 || tile == 5787 || tile == 5788 || tile == 5789 || tile == 5790 || tile == 5791 || tile == 6146 || tile == 6147 || tile == 6148 || tile == 6149 || tile == 6150 || tile == 6151 || tile == 6152 || tile == 6153 || tile == 5670 || tile == 5671 || tile == 5798 || tile == 5799 || tile == 5800 || tile == 5801 || tile == 5802 || tile == 5803 || tile == 5668 || tile == 5669 || tile == 5792 || tile == 5793 || tile == 5794 || tile == 5795 || tile == 5796 || tile == 5797 || tile == 544 || tile == 54600 || tile == 4520 || tile == 382 || tile == 3116 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
	if (tile == 1902 || tile == 1508 || tile == 428) return;
	if (tile == 9999 || tile == 1770 || tile == 4720 || tile == 4882 || tile == 6392 || tile == 3212 || tile == 1832 || tile == 4742 || tile == 3496 || tile == 3270 || tile == 4722) return;
	if (tile >= 7068) return;
	if (tile == 0 || tile == 18) {
		if (world->items[x + (y*world->width)].background == 6864 && world->items[x + (y*world->width)].foreground == 0) return;
		if (world->items[x + (y*world->width)].background == 0 && world->items[x + (y*world->width)].foreground == 0) return;
		//data.netID = -1;
		data.packetType = 0x8;
		data.plantingTree = 4;
		using namespace std::chrono;
		//if (world->items[x + (y*world->width)].foreground == 0) return;
		if ((duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() - world->items[x + (y*world->width)].breakTime >= 4000)
		{
			world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
			world->items[x + (y*world->width)].breakLevel = 4; // TODO
			if (world->items[x + (y*world->width)].foreground == 758)
				sendRoulete(peer, x, y);
		}
		else
			if (y < world->height && world->items[x + (y*world->width)].breakLevel + 4 >= def.breakHits * 4) { // TODO
				data.packetType = 0x3;// 0xC; // 0xF // World::HandlePacketTileChangeRequest
				data.netID = -1;
				data.plantingTree = 0;
				world->items[x + (y*world->width)].breakLevel = 0;
				if (world->items[x + (y*world->width)].foreground != 0)
				{


					if (world->items[x + (y*world->width)].foreground == 242)
					{
						world->owner = "";
						world->Displayowner = "";
						world->pIsVip = false;
						world->pIsMod = false;
						world->pIsDev = false;
						world->pIsPlay = false;
						world->isPublic = false;


						if (((PlayerInfo*)(peer->data))->isNicked == true)
						{
							((PlayerInfo*)(peer->data))->isNicked = false;
							((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->displayNamebackup;


							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 && ((PlayerInfo*)(peer->data))->rawName == "playingo")
							{
								
								((PlayerInfo*)(peer->data))->country = "../rtsoft_logo";
							}
							else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
							{
								
								((PlayerInfo*)(peer->data))->country = "../flags/ha";
							}
							else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{
								
								((PlayerInfo*)(peer->data))->country = "../atomic_button";
							}
							else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333)
							{
								

							}


							GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), ((PlayerInfo*)(peer->data))->displayNamebackup));
							memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor


							ENetPacket * packet7 = enet_packet_create(p7.data,
								p7.len,
								ENET_PACKET_FLAG_RELIABLE);



							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									enet_peer_send(currentPeer, 0, packet7);
								}
							}
							delete p7.data;
						}

						if (((PlayerInfo*)(peer->data))->haveGrowId && getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
							{
								//string name2 = "``" + str.substr(6, cch.length() - 6 - 1);
								GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`w`w" + ((PlayerInfo*)(peer->data))->tankIDName));
								memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
									((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->tankIDName;
								}

								ENetPacket * packet7 = enet_packet_create(p7.data,
									p7.len,
									ENET_PACKET_FLAG_RELIABLE);

								ENetPeer* currentPeer;

								
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer)) {
										if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
											enet_peer_send(currentPeer, 0, packet7);
										}
									}
								}
								delete p7.data;
							}
						}

						WorldInfo *world = getPlyersWorld(peer);
						string nameworld = world->name;
						GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`w" + nameworld + " `ohas had its `$World Lock `oremoved!`5]"));
						ENetPacket * packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet3);

						string text = "action|play_sfx\nfile|audio/metal_destroy.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
						memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

						ENetPacket * packetsou = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						ENetPeer* currentPeer;


						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								enet_peer_send(currentPeer, 0, packetsou);
							}

						}

					}
					world->items[x + (y*world->width)].foreground = 0;

					((PlayerInfo*)(peer->data))->xp = ((PlayerInfo*)(peer->data))->xp + 1;
					if (((PlayerInfo*)(peer->data))->xp >= 1) {
						((PlayerInfo*)(peer->data))->xp = 0;
						((PlayerInfo*)(peer->data))->level = ((PlayerInfo*)(peer->data))->level + 1;
						//GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " was thrown a bucket of " + (((PlayerInfo*)(peer->data))->addgems)), 0));

						int valgem = rand() % 15;

						std::ifstream ifs("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
						std::string content((std::istreambuf_iterator<char>(ifs)),
							(std::istreambuf_iterator<char>()));

						int gembux = atoi(content.c_str());
						int fingembux = gembux + valgem;

						ofstream myfile;
						myfile.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
						myfile << fingembux;
						myfile.close();

						int gemcalc = gembux + valgem;

						GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), gemcalc));
						ENetPacket * packetpp = enet_packet_create(pp.data,
							pp.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packetpp);
						delete pp.data;










					}
				}
				else {

					((PlayerInfo*)(peer->data))->xp = ((PlayerInfo*)(peer->data))->xp + 1;
					if (((PlayerInfo*)(peer->data))->xp >= 1) {
						((PlayerInfo*)(peer->data))->xp = 0;
						((PlayerInfo*)(peer->data))->level = ((PlayerInfo*)(peer->data))->level + 1;
						//GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " was thrown a bucket of " + (((PlayerInfo*)(peer->data))->addgems)), 0));

						int valgem = rand() % 15;

						std::ifstream ifs("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
						std::string content((std::istreambuf_iterator<char>(ifs)),
							(std::istreambuf_iterator<char>()));

						int gembux = atoi(content.c_str());
						int fingembux = gembux + valgem;

						ofstream myfile;
						myfile.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
						myfile << fingembux;
						myfile.close();

						int gemcalc = gembux + valgem;

						GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), gemcalc));
						ENetPacket * packetpp = enet_packet_create(pp.data,
							pp.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packetpp);
						delete pp.data;


						data.plantingTree = 6864;
						world->items[x + (y*world->width)].background = 6864;
					}
				}

			}
			else
				if (y < world->height)
				{
					world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					world->items[x + (y*world->width)].breakLevel += 4; // TODO
					if (world->items[x + (y*world->width)].foreground == 758)
						sendRoulete(peer, x, y);
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

				if (((PlayerInfo*)(peer->data))->isNicked == true)
				{
					((PlayerInfo*)(peer->data))->isNicked = false;
					((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->displayNamebackup;


					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 && ((PlayerInfo*)(peer->data))->rawName == "playingo")
					{

						((PlayerInfo*)(peer->data))->country = "../rtsoft_logo";
					}
					else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
					{

						((PlayerInfo*)(peer->data))->country = "../flags/ha";
					}
					else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
					{

						((PlayerInfo*)(peer->data))->country = "../atomic_button";
					}
					else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333)
					{


					}

					GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), ((PlayerInfo*)(peer->data))->displayNamebackup));
					memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor

					
					ENetPacket * packet7 = enet_packet_create(p7.data,
						p7.len,
						ENET_PACKET_FLAG_RELIABLE);



					ENetPeer * currentPeer;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer))
						{
							enet_peer_send(currentPeer, 0, packet7);
						}
					}
					delete p7.data;
				}
				world->owner = ((PlayerInfo*)(peer->data))->rawName;
				world->Displayowner = ((PlayerInfo*)(peer->data))->displayName;
				world->isPublic = false;
				ENetPeer * currentPeer;




				if (((PlayerInfo*)(peer->data))->haveGrowId)
				{
					GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`2`2" + ((PlayerInfo*)(peer->data))->tankIDName));
					memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
						((PlayerInfo*)(peer->data))->displayName = "`2" + ((PlayerInfo*)(peer->data))->tankIDName;
					}

					ENetPacket * packet7 = enet_packet_create(p7.data,
						p7.len,
						ENET_PACKET_FLAG_RELIABLE);

					delete p7.data;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer)) {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
								enet_peer_send(currentPeer, 0, packet7);
							}
						}
					}
				}
				else
				{

					
					

				
						


					GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`2`2" + ((PlayerInfo*)(peer->data))->displayName));
					memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
						((PlayerInfo*)(peer->data))->displayName = "`2" + ((PlayerInfo*)(peer->data))->displayName;
					}

					ENetPacket * packet7 = enet_packet_create(p7.data,
						p7.len,
						ENET_PACKET_FLAG_RELIABLE);

					delete p7.data;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer)) {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
								enet_peer_send(currentPeer, 0, packet7);

								/*string text = "action|play_sfx\nfile|audio/use_lock.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packetsou);*/
							}
						}
					}
				}
				


				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer)) {

						string text = "action|play_sfx\nfile|audio/use_lock.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
						memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

						ENetPacket * packetsou = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packetsou);

						if (((PlayerInfo*)(peer->data))->rawName == "playingo" && getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
						{
							world->pIsPlay = true;
						}
						else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 && ((PlayerInfo*)(peer->data))->rawName != "playingo") {
							world->pIsDev = true;
						}
						else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
							world->pIsMod = true;
						}
						else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333) {
							world->pIsVip = true;
						}
						else
						{
							world->pIsPlay = false;
							world->pIsDev = false;
							world->pIsMod = false;
							world->pIsVip = false;
						}
						if (((PlayerInfo*)(peer->data))->rawName == "playingo" && getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3[`w" + world->name + " `ohas been World Locked by `4" + ((PlayerInfo*)(peer->data))->displayName + "`3]"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet);
							delete p.data;
						}
						else
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3[`w" + world->name + " `ohas been World Locked by `6" + ((PlayerInfo*)(peer->data))->displayName + "`3]"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
								delete p.data;
							}
							else
							{
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3[`w" + world->name + " `ohas been World Locked by `#" + ((PlayerInfo*)(peer->data))->displayName + "`3]"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
								else
								{
									if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3[`w" + world->name + " `ohas been World Locked by `e" + ((PlayerInfo*)(peer->data))->displayName + "`3]"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										delete p.data;
									}
									else
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3[`w" + world->name + " `ohas been World Locked by `2" + ((PlayerInfo*)(peer->data))->displayName + "`3]"));
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

void sendPlayerJoin(ENetPeer* peer, PlayerInfo* player)
{
	ENetPeer * currentPeer;
	
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->displayName + "`` `5entered, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld)) + "`` `5others here>```w"));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;

		
	}	
	delete p2.data;
}

void sendPlayerBan(ENetPeer* peer, PlayerInfo* player)
{
	ENetPeer * currentPeer;
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT")
		{
			if (isHere(peer, currentPeer)) {
				{
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet);
				}
			}
		}
		delete p.data;
	}
}


void sendPlayerLeave(ENetPeer* peer, PlayerInfo* player)
{
	ENetPeer * currentPeer;
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->displayName + "`` `5left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`` `5others here>```w"));
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
				enet_peer_send(peer, 0, packet);

				{
					
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
					
				}
				if (((PlayerInfo*)(peer->data))->isinv == false)
				{
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);


					GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5<`w" + player->displayName + "`` `5left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`` `5others here>```w"));
					ENetPacket * packet4 = enet_packet_create(p4.data,
						p4.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet4);
					delete p4.data;
				}

			}
			{
				

			}
		}
	}
	delete p.data;
	delete p2.data;
}

void sendPlayerFakeLeave(ENetPeer* peer, PlayerInfo* player)
{
	ENetPeer * currentPeer;
	//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->displayName + "`` left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld)) + "`` others here>``"));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;

		if (isHere(peer, currentPeer)) {
			{

				/*ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);*/

				{
					/*ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet);*/
				}

			}
			{
				if (((PlayerInfo*)(peer->data))->isinv == false)
				{
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);


					enet_peer_send(currentPeer, 0, packet2);
				}

			}
		}
	}

	delete p2.data;
}

void sendPlayerWBan(ENetPeer* peer, string from, string to)
{
	ENetPeer * currentPeerp;

	for (currentPeerp = server->peers;
		currentPeerp < &server->peers[server->peerCount];
		++currentPeerp)
	{
		if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
			continue;

		if (getAdminLevel(((PlayerInfo*)(currentPeerp->data))->rawName, ((PlayerInfo*)(currentPeerp->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(currentPeerp->data))->rawName, ((PlayerInfo*)(currentPeerp->data))->tankIDPass) == 666) {

		}
		else
		{
			string name = from;
			string kickname = to;
			//string kickname = ((PlayerInfo*)(peer->data))->displayName;
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), name + " `4world bans " + "`o" + kickname));
			string text = "action|play_sfx\nfile|audio/repair.wav\ndelayMS|0\n";
			BYTE* data = new BYTE[5 + text.length()];
			BYTE zero = 0;
			int type = 3;
			memcpy(data, &type, 4);
			memcpy(data + 4, text.c_str(), text.length());
			memcpy(data + 4 + text.length(), &zero, 1);




			if (isHere(peer, currentPeerp))
			{

				ENetPacket * packetsou = enet_packet_create(data,
					5 + text.length(),
					ENET_PACKET_FLAG_RELIABLE);

				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);




				enet_peer_send(currentPeerp, 0, packetsou);
				enet_peer_send(currentPeerp, 0, packet);
				delete data;
				delete p.data;
			}
		}
	}
}

void sendChatMessage(ENetPeer* peer, int netID, string message)
{
	if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
		string ccode;
		if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999) {
			ccode = "5";
		}
		else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
			ccode = "^";
		}


		if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333 && ((PlayerInfo*)(peer->data))->isNicked == false) {
			for (char c : message)
				
				if (c < 0x18 || std::all_of(message.begin(), message.end(), isspace))
				{
					return;
				}

			ENetPeer * currentPeer;
			string name = "";
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->netID == netID)
					name = ((PlayerInfo*)(currentPeer->data))->displayName;

			}
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> `" + ccode + message));
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`" + ccode + message), 0));
			//GamePacket pf2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`" + ccode + message), 0));
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
			for (char c : message)				
			if (c < 0x18 || std::all_of(message.begin(), message.end(), isspace))
			{
				return;
			}

			ENetPeer * currentPeer;
			string name = "";
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->netID == netID)
					name = ((PlayerInfo*)(currentPeer->data))->displayName;

			}
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> " + message));

			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
			GamePacket p2f = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), +"`!" + message), 0));
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

					if (((PlayerInfo*)(peer->data))->isFrozen == false)
					{

						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet2);

					}
					else
					{
						ENetPacket * packet2f = enet_packet_create(p2f.data,
							p2f.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet2f);
					}

					//enet_host_flush(server);
				}
			}
			delete p.data;
			delete p2.data;
			delete p2f.data;
		}
	}
	else {
		if (((PlayerInfo*)(peer->data))->haveGrowId == false) {

			GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oTo prevent abuse, you `4must `obe `2registered `oin order to chat!"));
			ENetPacket * packet0 = enet_packet_create(p0.data,
				p0.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet0);
			delete p0.data;
			GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`oTo prevent abuse, you `4must `obe `2registered `oin order to chat!"));
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
		if (isHere(peer, currentPeer) && ((PlayerInfo*)(currentPeer->data))->isinv == false)
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


void sendWorld(ENetPeer* peer, WorldInfo* worldInfo)
{
#ifdef TOTAL_LOG
	cout << "Entering a world..." << endl;
#endif
	if (worldproperlock == false)
	{

		//testSubServer(peer);
		((PlayerInfo*)(peer->data))->joinClothesUpdated = false;
		string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
		string worldName = worldInfo->name;
		int xSize = worldInfo->width;
		int ySize = worldInfo->height;
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
					type |= 0x04001000; // 0x04000000 // 0x04001000 lock state // 0x04004000 tic tac toe // 0x1 proper lock //0x15000 weird
				if (worldInfo->items[i].glue)
					type |= 0x08000000;
				if (worldInfo->items[i].fire)
					type |= 0x10000000;
				if (worldInfo->items[i].red)
					type |= 0x20000000;
				if (worldInfo->items[i].green)
					type |= 0x40000000;
				if (worldInfo->items[i].blue)
					type |= 0x80000000; // 0x160000000 = yellow // 0x320000000 dark red 0x640000000 // violet 0x1280000000


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


		//cout << enet_socket_get_address(, ipaddr);

		//if (((PlayerInfo*)(peer->data))->isinv)
		//{
		updateInvis(peer);
		//}



		if (((PlayerInfo*)(peer->data))->haveGrowId) {
			if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
			{
				if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
					((PlayerInfo*)(peer->data))->displayName = "`2" + ((PlayerInfo*)(peer->data))->tankIDName;
				}
			}
			else
			{
				if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
					((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->tankIDName;
				}
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
			{
				if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
					((PlayerInfo*)(peer->data))->displayName = "`2" + ((PlayerInfo*)(peer->data))->displayNamebackup;
				}
			}
			else
			{
				if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
					((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->displayNamebackup;
				}
			}
		}

		if (((PlayerInfo*)(peer->data))->haveGrowId) {

			PlayerInfo* p = ((PlayerInfo*)(peer->data));
			std::ifstream ifff("players/" + PlayerDB::getProperName(p->rawName) + ".json");
			json j;
			ifff >> j;

			p->currentWorld = worldInfo->name;

			int bac, han, fac, hai, fee, pan, nec, shi, mas, anc, ban, lgk, lgw, lgb, lgd, lkw, cwd, rfs, cdg;
			bac = j["ClothBack"];
			han = j["ClothHand"];
			fac = j["ClothFace"];
			hai = j["ClothHair"];
			fee = j["ClothFeet"];
			pan = j["ClothPants"];
			nec = j["ClothNeck"];
			shi = j["ClothShirt"];
			mas = j["ClothMask"];
			anc = j["ClothAnces"];
			ban = j["isBanned"];
			lgk = j["boughtLGK"];
			lgw = j["boughtLGW"];
			lgb = j["boughtLGB"];
			lgd = j["boughtLGD"];
			lkw = j["boughtLKW"];
			cwd = j["boughtCWD"];
			rfs = j["boughtRFS"];
			cdg = j["boughtCDG"];
			/*vector <string>frns;
			if (j.count("friends") == 1) {
				for (int i = 0; i < j["friends"].size(); i++) {
					frns.push_back(j["friends"][i]);
				}
			}
			else {
				frns = {};
			}*/



			p->cloth_back = bac;
			p->cloth_hand = han;
			p->cloth_face = fac;
			p->cloth_hair = hai;
			p->cloth_feet = fee;
			p->cloth_pants = pan;
			p->cloth_necklace = nec;
			p->cloth_shirt = shi;
			p->cloth_mask = mas;
			p->boughtLGB = lgb;
			p->boughtLGD = lgd;
			p->boughtLGW = lgw;
			p->boughtLGK = lgk;
			p->boughtLKW = lkw;
			p->boughtCWD = cwd;
			p->boughtRFS = rfs;
			p->boughtCDG = cdg;
			//p->friendinfo = frns;

			//p->cloth_ances = anc;

			sendClothes(peer);

			ifff.close();


			PlayerInventory inventory;
			InventoryItem item;				
			item.itemCount = 1;
			item.itemID = 18;
			inventory.items.push_back(item);
			item.itemCount = 1;
			item.itemID = 32;
			inventory.items.push_back(item);
			sendInventory(peer, inventory);

		}

		delete data;

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


					/*GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;

					int effect = ((PlayerInfo*)(peer->data))->entereffect;*/
					int x = ((PlayerInfo*)(peer->data))->x;
					int y = ((PlayerInfo*)(peer->data))->y;
					/*GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

					ENetPacket * packetd = enet_packet_create(psp.data,
						psp.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packetd);
					delete psp.data;*/
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

		/*if (((PlayerInfo*)(peer->data))->mute == 1) {
			((PlayerInfo*)(peer->data))->cantsay = true;
			sendState(peer);
		}*/
		GamePacket p22 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`` `5entered, `w" + std::to_string(otherpeoples) + "`` others here>``"));


		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			/*if (isHere(peer, currentPeer) && ((PlayerInfo*)(peer->data))->isMod == 0) {
				{

					ENetPacket * packet2 = enet_packet_create(p22.data,
						p22.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);

				}
			}*/
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

void sendWorldCursed(ENetPeer* peer, WorldInfo* worldInfo)
{
#ifdef TOTAL_LOG
	cout << "Entering a world..." << endl;
#endif
	if (worldproperlock == false)
	{
		((PlayerInfo*)(peer->data))->joinClothesUpdated = false;
		string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
		string worldName = "HELL";
		int xSize = worldInfo->width;
		int ySize = worldInfo->height;
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

		//print_ip(peer->address.host);


		if (((PlayerInfo*)(peer->data))->haveGrowId) {

			PlayerInfo* p = ((PlayerInfo*)(peer->data));
			std::ifstream ifff("players/" + PlayerDB::getProperName(p->rawName) + ".json");
			json j;
			ifff >> j;

			p->currentWorld = worldInfo->name;

			int bac, han, fac, hai, fee, pan, nec, shi, mas, anc, ban;
			bac = j["ClothBack"];
			han = j["ClothHand"];
			fac = j["ClothFace"];
			hai = j["ClothHair"];
			fee = j["ClothFeet"];
			pan = j["ClothPants"];
			nec = j["ClothNeck"];
			shi = j["ClothShirt"];
			mas = j["ClothMask"];
			anc = j["ClothAnces"];
			ban = j["isBanned"];
			/*vector <string>frns;
			if (j.count("friends") == 1) {
				for (int i = 0; i < j["friends"].size(); i++) {
					frns.push_back(j["friends"][i]);
				}
			}
			else {
				frns = {};
			}*/

			p->cloth_back = bac;
			p->cloth_hand = han;
			p->cloth_face = fac;
			p->cloth_hair = hai;
			p->cloth_feet = fee;
			p->cloth_pants = pan;
			p->cloth_necklace = nec;
			p->cloth_shirt = shi;
			p->cloth_mask = mas;

			sendClothes(peer);

			ifff.close();

		}

		delete data;

	}
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

void sendTake(ENetPeer* peer, int netID, int x, int y, int item)
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
void sendResetState(ENetPeer* peer)
{
	if (((PlayerInfo*)(peer->data))->isCursed)
	{
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	int netID = info->netID;
	ENetPeer * currentPeer;
	//int state = getState(info);
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
			data.plantingTree = 4096;
			BYTE* raw = packPlayerMoving(&data);
			int var = info->effect; // placing and breking
			memcpy(raw + 1, &var, 3);
			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->isDuctaped)
			{
				PlayerInfo* info = ((PlayerInfo*)(peer->data));
				int netID = info->netID;
				ENetPeer * currentPeer;
				//int state = getState(info);
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
						data.plantingTree = 8192;
						BYTE* raw = packPlayerMoving(&data);
						int var = info->effect; // placing and breking
						memcpy(raw + 1, &var, 3);
						SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
					}
					else
					{
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
						data.plantingTree = 2;
						BYTE* raw = packPlayerMoving(&data);
						int var = info->effect; // placing and breking
						memcpy(raw + 1, &var, 3);
						SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
					}
				}

			}							
		}
		}
	}
}
void sendFrozenState(ENetPeer* peer)
{
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	int netID = info->netID;
	ENetPeer * currentPeer;
	//int state = getState(info);
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
			data.plantingTree = 2048;
			BYTE* raw = packPlayerMoving(&data);
			int var = info->effect; // placing and breking
			memcpy(raw + 1, &var, 3);
			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}
void sendSign(ENetPeer* peer) {
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
			int var = info->effect; // placing and breking
			memcpy(raw + 1, &var, 3);
			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}
void sendState(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->ghostalr == false)
	{
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
				data.characterState = ((PlayerInfo*)(peer->data))->characterState; // animation
				data.x = 1000;
				data.y = 100;
				data.punchX = 0;
				data.punchY = 0;
				data.XSpeed = 300;
				data.YSpeed = 600;
				data.netID = netID;
				data.plantingTree = state;
				BYTE* raw = packPlayerMoving(&data);
				int var = info->effect; // placing and breking
				memcpy(raw + 1, &var, 3);
				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
	else
	{
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
				data.characterState = ((PlayerInfo*)(peer->data))->characterState; // animation //-9269 dope
				data.x = 1100;
				data.y = 100;
				data.punchX = 0;
				data.punchY = 0;
				data.XSpeed = 390;
				data.YSpeed = 760;
				data.netID = netID;
				data.plantingTree = state;
				BYTE* raw = packPlayerMoving(&data);
				int var = info->effect; // placing and breking
				memcpy(raw + 1, &var, 3);
				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
	// TODO
}









void sendfakeState(ENetPeer* peer) {
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
			if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) != 999)
			{
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
				int var = info->effect; // placing and breking
				memcpy(raw + 1, &var, 3);
				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
	// TODO
}

void sendPlayerToPlayer(ENetPeer* peer, ENetPeer* otherpeer)
{
	{
		sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
	}
	WorldInfo info = worldDB.get(((PlayerInfo*)(otherpeer->data))->currentWorld);
	sendWorld(peer, &info);


	int x = ((PlayerInfo*)(otherpeer->data))->x;
	int y = ((PlayerInfo*)(otherpeer->data))->y;


	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));


	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);


	delete p.data;
	((PlayerInfo*)(peer->data))->netID = cId;
	onPeerConnect(peer);
	cId++;


	sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
}


void sendPlayerToWorld(ENetPeer* peer, PlayerInfo* player, string wrldname)
{
	



	toUpperCase(wrldname);
	if (wrldname == "CON" || wrldname == "NUL" || wrldname == "PRN" || wrldname == "AUX" || wrldname == "CLOCK$" || wrldname == "COM0" || wrldname == "COM1" || wrldname == "COM2" || wrldname == "COM3" || wrldname == "COM4" || wrldname == "COM5" || wrldname == "COM6" || wrldname == "COM7" || wrldname == "COM8" || wrldname == "COM9" || wrldname == "LPT0" || wrldname == "LPT1" || wrldname == "LPT2" || wrldname == "LPT3" || wrldname == "LPT4" || wrldname == "LPT5" || wrldname == "LPT6" || wrldname == "LPT7" || wrldname == "LPT8" || wrldname == "LPT9")
	{
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`eWhoops! `wThis `oworld`w can't be warped to, as it is used by `4System`w.``"));
		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);

		delete p.data;
	}
	else
	{
		{
			sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
		}

		WorldInfo info = worldDB.get(wrldname);
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
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));


		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);


		delete p.data;
		((PlayerInfo*)(peer->data))->netID = cId;
		onPeerConnect(peer);
		cId++;


		sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);


		
	}
}

void debugcout()
{
	while (debugcout)
	{
		cout << "debug test 1";
	}
}

void ServerInputPluginByplayingo()
{
	while (ServerInputPluginByplayingo)
	{
		std::string buffer;
		std::cin >> buffer;

		// example:
		if (buffer == "exit") // if exit is typed in server console:
		{
			// do stuff
			exit(0);
		}
		else if (buffer == "online")
		{
			string x;


			ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;

				
					x.append(((PlayerInfo*)(currentPeer->data))->rawName + " (" + to_string(((PlayerInfo*)(currentPeer->data))->adminLevel) + ")" + " (" + ((PlayerInfo*)(currentPeer->data))->charIP + ")" + ", ");
			}
			x = x.substr(0, x.length() - 2);

			cout << "[Console] Peers connected (includes mods) (format: (rawname) (adminlevel) (plainIP): " << x << endl;
		
		}
		else if (buffer == "saveall")
		{
			saveAllWorlds();
		}
		
		else if (buffer == "kickall")
		{
			ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;

				enet_peer_disconnect_later(currentPeer, 0);
				enet_peer_reset(currentPeer);
			}
		}
		if (buffer.find("addrole") != std::string::npos) {
			// todo

		}
		
		
		
		else if (buffer == "help" || buffer == "?")
		{
			cout << "Operator commands: " << "help " << "kickall " << "saveall " << "addrole " << "online " << "delete " << "maintenance " << "exit" << endl;
		}
		
		
		
	}
}

void sendWorldFail(ENetPeer* peer)
{
	if (!((PlayerInfo*)(peer->data))->isIn) return;
	vector<WorldInfo> worlds = worldDB.getRandomWorlds();
	string worldOffers = "default|";
	if (worlds.size() > 0) {
		worldOffers += worlds[0].name;
	}

	worldOffers += "\nadd_button|Showing: `wWorlds``|_catselect_|0.6|3529161471|\n";
	for (int i = 0; i < worlds.size(); i++) {
		worldOffers += "add_floater|" + worlds[i].name + "|" + std::to_string(getPlayersCountInWorld(worlds[i].name)) + "|0.55|3529161471\n";
	}
	//GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";OnFailedToEnterWorld

	GamePacket p3 = packetEnd(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
	ENetPacket * packet3 = enet_packet_create(p3.data,
		p3.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete p3.data;

}

void sendWorldOffers(ENetPeer* peer)
{
	if (!((PlayerInfo*)(peer->data))->isIn) return;
	vector<WorldInfo> worlds = worldDB.getRandomWorlds();
	string worldOffers = "default|";
	if (worlds.size() > 0) {
		worldOffers += worlds[0].name;
	}

	worldOffers += "\nadd_button|Showing: `wWorlds``|_catselect_|0.6|3529161471|\n";
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


void Respawn(ENetPeer* peer) {
	int x = 3040;
	int y = 736;

	WorldInfo* world = getPlyersWorld(peer);
	if (world)
	{


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
			GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 3), x, (y + 8)));

			ENetPacket * packetd = enet_packet_create(psp.data,
				psp.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(currentPeer, 0, packetd);
			delete psp.data;

			string text = "action|play_sfx\nfile|audio/male_scream.wav\ndelayMS|0\n";
			BYTE* data = new BYTE[5 + text.length()];
			BYTE zero = 0;
			int type = 3;
			memcpy(data, &type, 4);
			memcpy(data + 4, text.c_str(), text.length());
			memcpy(data + 4 + text.length(), &zero, 1);

			{
				ENetPacket * packetres = enet_packet_create(data,
					5 + text.length(),
					ENET_PACKET_FLAG_RELIABLE);

				if (isHere(peer, currentPeer)) {
					enet_peer_send(currentPeer, 0, packetres);

				}
			}
		}
	}

	for (int i = 0; i < world->width*world->height; i++)
	{
		if (world->items[i].foreground == 6) {
			x = (i%world->width) * 32;
			y = (i / world->width) * 32;
			//world->items[i].foreground = 8;
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
		data.plantingTree = 0x0; // 0x0
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
				//world->items[i].foreground = 8;
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
				//world->items[i].foreground = 8;
			}
		}
		GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
		memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
		ENetPacket * packet2 = enet_packet_create(p2.data,
			p2.len,
			ENET_PACKET_FLAG_RELIABLE);


		enet_peer_send(peer, 0, packet2);
		delete p2.data;
		enet_host_flush(server);
	}
	}
}






BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
	saveAllWorlds();
	return FALSE;
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
	{
		// 999 = owner/dev/admin 666 = mod/supermod 333 = vip 166 = influencer
		
		

		
		std::thread first(ServerInputPluginByplayingo);
		first.detach();
		
		loadConfig();


	}
	cout << "Growtopia private server (c) playingohd always exit with CTRL+C!" << endl;
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
			cout << "Updating item data success!" << endl;


		}
		else {
			cout << "Updating item data failed!" << endl;
		}
	}



	//world = generateWorld();


	worldDB.get("TEST");
	worldDB.get("MAIN");
	worldDB.get("NEW");
	worldDB.get("ADMIN");
	ENetAddress address;
	/* Bind the server to the default localhost.     */
	/* A specific host address can be specified by   */
	enet_address_set_host(&address, "0.0.0.0");
	//address.host = ENET_HOST_ANY;
	/* Bind the server to port 1234. */
	address.port = serverport; // any port serverport
	server = enet_host_create(&address /* the address to bind the server host to */,
		1024      /* allow up to 32 clients and/or outgoing connections */,
		2      /* allow up to 2 channels to be used, 0 and 1 */,
		4096      /* assume any amount of incoming bandwidth */,
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


				//char clientConnection[32];
				//((PlayerInfo*)(peer->data))->charIP = enet_address_get_host_ip(&peer->address, clientConnection, 32);

				event.peer->data = new PlayerInfo;

				

				/* Get the string ip from peer */
				char clientConnection[16];
				enet_address_get_host_ip(&peer->address, clientConnection, 16);
				((PlayerInfo*)(peer->data))->charIP = clientConnection;


				if (count > 3)
				{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rToo many accounts are logged on from this IP. Log off one account before playing please.``"));
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

				if (((PlayerInfo*)(peer->data))->forcegemUpdate)
				{
					/*((PlayerInfo*)(peer->data))->forcegemUpdate = false;

					std::ifstream ifszx("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
					std::string contentix((std::istreambuf_iterator<char>(ifszx)),
						(std::istreambuf_iterator<char>()));

					int updvgem = atoi(contentix.c_str());

					GamePacket ppx = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), updvgem));
					ENetPacket * packetppx = enet_packet_create(ppx.data,
						ppx.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packetppx);
					delete ppx.data;


					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`8You have received some `4gems`8, pal!"));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;*/

				}
				if (((PlayerInfo*)(event.peer->data))->wrongpass == true)
				{
					if (((PlayerInfo*)(peer->data))->isIn) {
						enet_peer_disconnect_later(peer, 0);

					}
					else
					{
						string text = "action|log\nmsg|`4GrowID or password is wrong! `7Incase you want to recover/change your account/password, contact DiruX#4989.``";
						string text3 = "action|logon_fail\n";
						string dc = "https://discord.gg/zW25ynC";
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

						enet_peer_disconnect_later(peer, 0);
					}
				}
				

				if (((PlayerInfo*)(event.peer->data))->player_age == "")
				{
					enet_peer_disconnect_now(peer, 0);
					enet_peer_reset(peer);
				}

				ENetPeer * currentPeer;
				int count = 0;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;



					std::string mac(((PlayerInfo*)(currentPeer->data))->mac);
					Remove(mac, ":");
					std::string currentip = std::to_string(currentPeer->address.host);
					//((PlayerInfo*)(event.peer->data))->player_age
					bool exist = false;
					if(std::experimental::filesystem::exists("devicebans/" + currentip + ".txt") || std::experimental::filesystem::exists("ridbans/" + ((PlayerInfo*)(event.peer->data))->rid + ".txt") || std::experimental::filesystem::exists("sidbans/" + ((PlayerInfo*)(event.peer->data))->wkid + ".txt") || std::experimental::filesystem::exists("aidbans/" + ((PlayerInfo*)(event.peer->data))->aid + ".txt") || std::experimental::filesystem::exists("vidbans/" + ((PlayerInfo*)(event.peer->data))->vid + ".txt") || std::experimental::filesystem::exists("gidbans/" + ((PlayerInfo*)(event.peer->data))->gid + ".txt") || std::experimental::filesystem::exists("macbans/" + mac + ".txt"))
					{
						
						exist = true;
					}
					else
					{
						exist = false;
					}

					
					if (exist == true)
					{
						if (peer->address.host == currentPeer->address.host)
						{
							
							if (((PlayerInfo*)(peer->data))->isIn) {
								enet_peer_disconnect_later(peer, 0);

							}
							else
							{

								string text = "action|log\nmsg|`4Sorry, this device or location has been suspended. `5Contact DiruX#4989 on discord``! `wPlease do not request an unban if you know that you have done something wrong.";
								string text3 = "action|logon_fail\n";
								string dc = "https://discord.gg/zW25ynC";
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

								enet_peer_disconnect_later(peer, 0);
							}
						}
					}
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


					if (cch.find("action|wrench") == 0) {
						vector<string> ex = explode("|", cch);
						

						stringstream ss;

						
						ss << ex[3];

						
						string temp;
						int found;
						while (!ss.eof()) {

							
							ss >> temp;

							
							if (stringstream(temp) >> found)
								//cout << found;
							((PlayerInfo*)(peer->data))->wrenchsession = found;
							
						
							temp = "";
						}


						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;


							if (isHere(peer, currentPeer)) {
								if (((PlayerInfo*)(currentPeer->data))->netID == ((PlayerInfo*)(peer->data))->wrenchsession) {

									((PlayerInfo*)(peer->data))->lastInfo = ((PlayerInfo*)(currentPeer->data))->rawName;
									((PlayerInfo*)(peer->data))->lastInfoname = ((PlayerInfo*)(currentPeer->data))->displayName;

									string name = ((PlayerInfo*)(currentPeer->data))->displayName;
									string rawnam = ((PlayerInfo*)(peer->data))->rawName;
									string rawnamofwrench = ((PlayerInfo*)(currentPeer->data))->rawName;
									if (rawnamofwrench != rawnam)
									{

										if (rawnamofwrench != "")
										{
											std::ifstream ifszsx("gemdb/" + ((PlayerInfo*)(peer->data))->lastInfo + ".txt");
											std::string contentch2x((std::istreambuf_iterator<char>(ifszsx)),
												(std::istreambuf_iterator<char>()));

											if (world->owner == ((PlayerInfo*)(peer->data))->rawName && ((PlayerInfo*)(peer->data))->haveGrowId || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333)
											{
												if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333)
												{
													GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + contentch2x + "|left|4|\nadd_button|chc0|Close|noflags|0|0|\nadd_button|trade|`wTrade!``|noflags|\n\nadd_button|starttrd|Trade World for `4Gems`w|noflags|\n\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_button|punishview|`!Punish/View|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
													ENetPacket * packet = enet_packet_create(p.data,
														p.len,
														ENET_PACKET_FLAG_RELIABLE);
													enet_peer_send(peer, 0, packet);
													delete p.data;
												}
												else
												{
													GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + contentch2x + "|left|4|\nadd_button|chc0|Close|noflags|0|0|\nadd_button|trade|`wTrade!``|noflags|\n\\nadd_button|starttrd|Trade World for `4Gems`w|noflags|\n\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
													ENetPacket * packet = enet_packet_create(p.data,
														p.len,
														ENET_PACKET_FLAG_RELIABLE);
													enet_peer_send(peer, 0, packet);
													delete p.data;
												}
											}
											else
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + contentch2x + "|left|4|\nadd_button|chc0|Close|noflags|0|0|\nadd_button|trade|`wTrade!``|noflags|\n\\nadd_button|starttrd|Trade World for `4Gems`w|noflags|\n\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
										}
										else
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + "|left|18|\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
											delete p.data;
										}
									}
									else
									{
										std::ifstream ifszs("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										std::string contentch2((std::istreambuf_iterator<char>(ifszs)),
											(std::istreambuf_iterator<char>()));
										if (((PlayerInfo*)(peer->data))->isAAP == true)
										{
											if (((PlayerInfo*)(peer->data))->haveGrowId == true)
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + contentch2 + "|left|4|\nadd_button|disableaap|`5Disable AAP`w``|noflags|0|0|\nadd_button|chc0|Close|noflags|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
											else
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + contentch2 + "|left|4|\nadd_button|chc0|Close|noflags|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
										}
										else
										{
											if (((PlayerInfo*)(peer->data))->haveGrowId == true)
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + "        |left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + contentch2 + "|left|4|\nadd_button|enableaap|`5Enable AAP`w``|noflags|0|0|\n\nadd_button|chc0|Close|noflags|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
											else
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + "        |left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + contentch2 + "|left|4|\nadd_button|chc0|Close|noflags|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
										}
									}

									ofstream myfile;
									myfile.open("wrenchsessions/" + rawnam + ".txt");
									myfile << rawnamofwrench;
									myfile.close();

								}


							}


						}
					}
					if (cch.find("action|respawn") == 0 && !cch.find("action|respawn_spike") == 0)
					{
						Respawn(peer);
					}
					if (cch.find("action|respawn_spike") == 0)
					{
						//cout << "hey";
						//((PlayerInfo*)(peer->data))->canLeave = false;
						int x = 3040;
						int y = 736;


						if (!world) continue;


						for (int i = 0; i < world->width*world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i%world->width) * 32;
								y = (i / world->width) * 32;
								//world->items[i].foreground = 8;
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
							data.plantingTree = 0x0; // 0x0
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
									//world->items[i].foreground = 8;
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
									//world->items[i].foreground = 8;
								}
							}
							GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);


							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							enet_host_flush(server);


						}
#ifdef TOTAL_LOG		
						cout << "Respawning... " << endl;
#endif
					}
					if (cch.find("action|friends") == 0)
					{
						//if (((PlayerInfo*)(peer->data))->joinguild == true) {
						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
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
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGet a GrowID``|left|206|\n\nadd_spacer|small|\nadd_textbox|A `wGrowID `wmeans `oyou can use a name and password to logon from any device.|\nadd_spacer|small|\nadd_textbox|This `wname `owill be reserved for you and `wshown to other players`o, so choose carefully!|\nadd_text_input|username|GrowID||30|\nadd_text_input|password|Password||100|\nadd_text_input|passwordverify|Password Verify||100|\nadd_textbox|Your `wemail `owill only be used for double verification, discord is enough though. Dont worry, they won't be spammed or shared. |\nadd_text_input|email|Email||100|\nadd_textbox|Your `bPIN `owill be used to recover your account incase the players data have reset and you need to recreate it or so. This is VERY important and you `5should `owrite down the `bPIN`o somewhere!|\nadd_text_input|pin|PIN||4|\nend_dialog|register|Cancel|Get My GrowID!|\n"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
#endif
					}
					if (cch.find("action|store") == 0) // to do and sound (for example breaking when no access is to do) and accessing on wls.
					{
						if (((PlayerInfo*)(peer->data))->haveGrowId == true)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_ele_icon|big|`wGTOG Shop|left|5956|\nadd_label_with_icon|small|`9Legendary items``|left|1790|\n\nadd_button_with_icon|lgb||staticBlueFrame|1780|20000|\nadd_button_with_icon|lgw||staticBlueFrame|1784|20000|\nadd_button_with_icon|lgd||staticBlueFrame|1782|20000|\nadd_button_with_icon|lgk||staticBlueFrame|2592|20000|\nadd_button_with_icon|lkw||staticBlueFrame|7734|20000|\nadd_button_with_icon||END_LIST|noflags|0|0||\nadd_spacer|small|\nadd_label_with_icon|small|`7Special items``|left|1900|\nadd_button_with_icon|cwd||staticBlueFrame|1956|7000|\nadd_button_with_icon|rfs||staticBlueFrame|5480|60000|\nadd_button_with_icon|cdg||staticBlueFrame|7762|15000|\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
#ifdef REGISTRATION
							//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							GamePacket pss = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGet a GrowID``|left|206|\n\nadd_spacer|small|\nadd_textbox|A `wGrowID `wmeans `oyou can use a name and password to logon from any device.|\nadd_spacer|small|\nadd_textbox|This `wname `owill be reserved for you and `wshown to other players`o, so choose carefully!|\nadd_text_input|username|GrowID||30|\nadd_text_input|password|Password||100|\nadd_text_input|passwordverify|Password Verify||100|\nadd_textbox|Your `wemail `owill only be used for double verification, discord is enough though. Dont worry, they won't be spammed or shared. |\nadd_text_input|email|Email||100|\nadd_textbox|Your `bPIN `owill be used to recover your account incase the players data have reset and you need to recreate it or so. This is VERY important and you `5should `owrite down the `bPIN`o somewhere!|\nadd_text_input|pin|PIN||4|\nend_dialog|register|Cancel|Get My GrowID!|\n"));
							ENetPacket * packetss = enet_packet_create(pss.data,
								pss.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetss);
							delete pss.data;
#endif


							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`7Create a GrowID to access the store, it's free!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						//enet_host_flush(server);
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
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);


						//enet_host_flush(server);
						delete p.data;
					}
					if (cch.find("action|dialog_return") == 0)
					{
						std::stringstream ss(cch);
						std::string to;
						string btn = "";
						bool isRegisterDialog = false;
						string username = "";
						string restrictedname = "";
						string password = "";
						string passwordverify = "";
						//string email = "";
						string discord = "";
						string pin;	
						bool isDropDialog = false;
						string dropitemcount = "";
						string netid = "";
						bool isFindDialog = false;
						bool isTradeDialog = false;
						bool isBotDialog = false;
						string itemFind = "";
						string strBuyOffer = "";
						string strResult = "";
						int Result = 68662362;
						int buyOffer;
						string dialog_name = "";
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							{
								PlayerInfo* pData = ((PlayerInfo*)(peer->data));
								if (infoDat[0] == "buttonClicked") btn = infoDat[1];
								if (infoDat[0] == "dialog_name" && infoDat[1] == "searchitem1337")
								{
									isFindDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "findid")
								{
									isFindDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "reqoffer")
								{
									isTradeDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "antibotres")
								{
									isBotDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "dropdialog")
								{
									isDropDialog = true;
								}								
								if (isDropDialog) {
									if (infoDat[0] == "dropitemcount") dropitemcount = infoDat[1];
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
								if (isBotDialog)
								{
									if (infoDat[0] == "antibot")
									{
										strResult = infoDat[1];

										bool contains_non_int
											= !std::regex_match(strBuyOffer, std::regex("^[0-9]+$"));

										if (contains_non_int == true)
										{
											Result = atoi(strResult.c_str());
											((PlayerInfo*)(peer->data))->Endresult = Result;
										}

										if (((PlayerInfo*)(peer->data))->resultnbr1 + ((PlayerInfo*)(peer->data))->resultnbr2 != Result)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4[PLAY-Captcha]: Captcha failed."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;

											((PlayerInfo*)(peer->data))->Endresult = Result;

											enet_peer_disconnect_later(peer, 0);
											cout << "[CAPTCHA FAIL] user typed: " << Result << endl;
											cout << "[CAPTCHA FAIL] answer was: " << ((PlayerInfo*)(peer->data))->resultnbr1 + ((PlayerInfo*)(peer->data))->resultnbr2 << endl;
										}
										else
										{
											((PlayerInfo*)(peer->data))->passedCaptcha2 = true;
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|GrowtopiaOG Gazette``|left|5016|\n\nadd_spacer|small|\n\nadd_spacer|small|\nadd_label|small|`6Welcome To GrowtopiaOG!|left|4|\nadd_spacer|small||\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\n\nadd_textbox|`3GTOG V3.0|left|4|\nadd_label_with_icon|small|\nadd_button|crash|`2Press Here`w if you are `4Crashing`w! (removes set&disconnect)|noflags|0|0|\nadd_label_with_icon|big|`5GTOG Summer Update!``|left|836|\n\nadd_textbox|`33.0: 1. Fixed MANY bugs! 2. Added World-Trade! 3. Added PVP (in pvp server, do /server and click battle royale) 4. Added full shop system! 5. Added more commands! - Checkout all yourself, added much more than that :D.|left|4|\n\nadd_textbox|`3To find items, use /find.|left|4|\n\nadd_spacer|small|\n\nadd_textbox|`2Join our Discord for more information!|left|4|\nadd_spacer|small|\nadd_label|small|`$- This Server developed by `6playingo`$ & `6ashley`$.|left|4|\nadd_spacer|small|\nadd_label|small|`4Make sure to Join Our discord server!|left|4|\nadd_url_button||``New discord server!``|NOFLAGS|https://discord.gg/zW25ynC| Join discord server?|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											//enet_host_flush(server);
											delete p.data;
										}
									}
								}
								if (isFindDialog) {
									if (infoDat[0] == "item") itemFind = infoDat[1];
								}
								if (isTradeDialog) {
									if (infoDat[0] == "worldoffer")
									{
										strBuyOffer = infoDat[1];

										bool contains_non_int
											= !std::regex_match(strBuyOffer, std::regex("^[0-9]+$"));

										if (contains_non_int == true)
										{
											GamePacket pfi = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Requesting offer failed... You may only use positive numbers to begin a trade!"));
											ENetPacket * packetfi = enet_packet_create(pfi.data,
												pfi.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packetfi);

											delete pfi.data;
										}
										else
										{
											buyOffer = std::atoi(strBuyOffer.c_str());

											GamePacket psu = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Requested`w " + ((PlayerInfo*)(peer->data))->lastInfo + " `9for a world-trade (you sell world for`w " + strBuyOffer + " `4Gems`9)."));
											ENetPacket * packetsu = enet_packet_create(psu.data,
												psu.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packetsu);
											delete psu.data;


											ENetPeer * currentPeerpx;

											for (currentPeerpx = server->peers;
												currentPeerpx < &server->peers[server->peerCount];
												++currentPeerpx)
											{
												if (currentPeerpx->state != ENET_PEER_STATE_CONNECTED)
													continue;

												if (isHere(peer, currentPeerpx))
												{




													if (((PlayerInfo*)(currentPeerpx->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) // if last wrench
													{
														GamePacket psu = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), ((PlayerInfo*)(peer->data))->displayName + " `9requested you for a world-trade (he/she sells world for`w " + strBuyOffer + " `4Gems`9). Do /tradeworld if you want to buy, /decline if you dont accept the trade. [TRADE COMING TOMORROW TODAY ITS ONLY DESIGN NOT WORK!]"));
														ENetPacket * packetsu = enet_packet_create(psu.data,
															psu.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(currentPeerpx, 0, packetsu);
														delete psu.data;

														((PlayerInfo*)(peer->data))->lastBuyer = ((PlayerInfo*)(currentPeerpx->data))->rawName;
														((PlayerInfo*)(currentPeerpx->data))->lastSeller = ((PlayerInfo*)(peer->data))->rawName;
														((PlayerInfo*)(currentPeerpx->data))->lastTradeAmount = buyOffer;
														((PlayerInfo*)(peer->data))->lastTradeAmount = buyOffer;
														((PlayerInfo*)(currentPeerpx->data))->lastSellWorld = getPlyersWorld(currentPeerpx)->name;
														((PlayerInfo*)(peer->data))->lastSellWorld = getPlyersWorld(peer)->name;
													}
												}
											}
										}
									}


								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "register") isRegisterDialog = true;
								if (infoDat[0] == "dialog_name") dialog_name = infoDat[1];
								if (dialog_name == "captcha") {
									if (btn == pData->buttonID) {
										// Captcha passed
										pData->passedCaptcha = true;
										/*GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|Growtopia Gazette``|left|5016|\n\nadd_spacer|small|\n\nadd_spacer|small|\nadd_label|small|`6Welcome To GrowtopiaEUOG!|left|4|\nadd_spacer|small||\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\n\nadd_textbox|`3GTEUOG V2.0|left|4|\nadd_label_with_icon|small|\nadd_button|crash|`2Press Here`w if you are `4Crashing`w! (removes set)|noflags|0|0|\nadd_label_with_icon|big|`3BIG GTEUOG UPDATE!!|left|610|\n\nadd_textbox|`32. V2.0: Big update, fixed alot of stuff and added /effect and trade N MUCH MORE GO CHECKOUT :D!. Checkout all yourself by playing! Have fun in gtEUOG|left|4|\n\nadd_textbox|`33. To find items, use /find.|left|4|\n\nadd_spacer|small|\n\nadd_textbox|`2Join our Discord for more information!|left|4|\nadd_spacer|small|\nadd_label|small|`$- This Server developed by `6playingo`$ & `6ashley`$, and is hosted by `6ESC.|left|4|\nadd_spacer|small|\nadd_label|small|`4Make sure to Join Our discord server!|left|4|\nadd_url_button||``New discord server!``|NOFLAGS|https://discord.gg/zW25ynC| Join discord server?|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);*/

										//enet_host_flush(server);
										//delete p.data;
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_textbox|What's " + ((PlayerInfo*)(peer->data))->firstnbr + "+" + ((PlayerInfo*)(peer->data))->secondnbr + "|\nadd_text_input|antibot|Number: ||4|\nend_dialog|antibotres||Enter Server\n"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p.data;
									}
									else if (btn == "wrongcaptcha") {
										enet_peer_disconnect(peer, 0);
									}


								}
								if (isRegisterDialog) {
									if (infoDat[0] == "username")
									{
										username = infoDat[1];
										restrictedname = username;
										toUpperCase(restrictedname);


										//cout << "user typed: " + restrictedname;
										string cleanrname = std::regex_replace(restrictedname, std::regex("^ +| +$|( ) +"), "$1");

										if (restrictedname == "CON" || restrictedname == "NUL" || restrictedname == "PRN" || restrictedname == "AUX" || restrictedname == "CLOCK$" || restrictedname == "COM0" || restrictedname == "COM1" || restrictedname == "COM2" || restrictedname == "COM3" || restrictedname == "COM4" || restrictedname == "COM5" || restrictedname == "COM6" || restrictedname == "COM7" || restrictedname == "COM8" || restrictedname == "COM9" || restrictedname == "LPT0" || restrictedname == "LPT1" || restrictedname == "LPT2" || restrictedname == "LPT3" || restrictedname == "LPT4" || restrictedname == "LPT5" || restrictedname == "LPT6" || restrictedname == "LPT7" || restrictedname == "LPT8" || restrictedname == "LPT9")
										{
											enet_peer_disconnect_now(peer, 0);
											enet_peer_reset(peer);
										}
										else
										{
											((PlayerInfo*)(peer->data))->canCreate == true;
										}

									}

									if (infoDat[0] == "password") password = infoDat[1];
									if (infoDat[0] == "passwordverify") passwordverify = infoDat[1];
									//if (infoDat[0] == "email") email = infoDat[1];
									if (infoDat[0] == "discord") discord = infoDat[1];
									if (infoDat[0] == "pin") pin = infoDat[1];
								}
							}
						}
						if (btn.substr(0, 5) == "found") {
							PlayerInventory inventory;
							InventoryItem item;
							item.itemID = atoi(btn.substr(5, btn.length()).c_str());
							item.itemCount = 200;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemID = 32;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);
						}





						//enet_host_flush(server);




						int x = ((PlayerMoving*)(peer->data))->punchX;
						int y = ((PlayerMoving*)(peer->data))->punchY;
						int causedBy = ((PlayerMoving*)(peer->data))->netID;
						int tile = ((PlayerMoving*)(peer->data))->plantingTree;




						if (btn == "worldPublic") {

							if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = true;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wWorld properties changed. Set world to: Public!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "betaserver") {
							GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBetaMode"), 1));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;

							GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Beta-mode activated."));
							//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
							ENetPacket * packetto = enet_packet_create(pto.data,
								pto.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetto);
							delete pto.data;
						}
						if (btn == "battleroyaleserver")
						{
							GamePacket p3 = packetEnd(appendInt(appendInt(appendString(appendString(createPacket(), "OnRedirectServer"), "192.168.2.101"), 17091), 1));

							//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket * packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet3);
							delete p3.data;

							GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Coming soon, will warp to normal GTOG server when connect!"));
							//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
							ENetPacket * packetto = enet_packet_create(pto.data,
								pto.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetto);
							delete pto.data;
						}
						if (btn == "vyteserver")
						{
							GamePacket p3 = packetEnd(appendInt(appendInt(appendString(appendString(createPacket(), "OnRedirectServer"), "privategts1.eu"), 17353), 1));

							//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket * packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet3);
							delete p3.data;

							

							GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9You will now warp to Vyte server when connect! `w(to go back restart gt)"));
							//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
							ENetPacket * packetto = enet_packet_create(pto.data,
								pto.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetto);
							delete pto.data;


						}
						if (btn == "advertiseserver") {
							GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You can link your private server to this button. Costs 2 dls."));
							//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
							ENetPacket * packetto = enet_packet_create(pto.data,
								pto.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetto);
							delete pto.data;
						}
						if (btn == "subserver1") {
							GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You can rent server with GTOG Server.exe. Costs 7 dls, contact us!"));
							//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
							ENetPacket * packetto = enet_packet_create(pto.data,
								pto.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetto);
							delete pto.data;
						}
						if (btn == "trade")
						{
							ENetPeer * currentPeerpx;

							for (currentPeerpx = server->peers;
								currentPeerpx < &server->peers[server->peerCount];
								++currentPeerpx)
							{
								if (currentPeerpx->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeerpx->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) // if last wrench
								{
									GamePacket p2 = packetEnd(appendInt(appendInt(appendString(createPacket(), "OnStartTrade"), ((PlayerInfo*)(currentPeerpx->data))->netID), 1));

									//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;

									/*GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnTradeStatus"), "Trader"));

									//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet3);
									delete p3.data;*/
								}
							}
						}
						if (btn == "enableaap")
						{

						}
						if (btn == "dotradedialog")
						{
							//\nadd_button_with_icon|allowMod|Allow Noclip|noflags|1796||

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wTrade Menu``|left|242|\nadd_label|small|\nadd_button_with_icon|dotrade|Do the Trade!|noflags|1424||\nadd_button|decline|`4Cancel/Decline|noflags||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
						if (btn == "dotrade")
						{


							string text = "action|play_sfx\nfile|audio/keypad_hit.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);


							ENetPacket * packettrd = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							ENetPeer * currentPeerp;

							for (currentPeerp = server->peers;
								currentPeerp < &server->peers[server->peerCount];
								++currentPeerp)
							{
								if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeerp))
									enet_peer_send(currentPeerp, 0, packettrd);
							}
						}

						if (btn == "worldPrivate") {
							if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
								if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) {
									getPlyersWorld(peer)->isPublic = false;

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wWorld properties changed. Set world to: Private!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}
						if (btn == "allowMod") {
							if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
								if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner)
								{
									getPlyersWorld(peer)->allowMod = true;

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wWorld properties changed. World flags modified -> ALLOW-MOD = TRUE!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}
						if (btn == "allowMod1")
						{
							if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {

								if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) {
									getPlyersWorld(peer)->allowMod = false;

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wWorld properties changed. World flags modified -> ALLOW-MOD = FALSE!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;


									ENetPeer * currentPeer;


									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;

										if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
											if (((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(currentPeer->data))->currentWorld) {

												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Owner `ohas `4disabled `5Mod-Noclip `oin this world."));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet);
												delete p.data;


												if (((PlayerInfo*)(currentPeer->data))->rawName != getPlyersWorld(peer)->owner)
												{
													((PlayerInfo*)(currentPeer->data))->canWalkInBlocks = false;
													((PlayerInfo*)(currentPeer->data))->skinColor = 0x8295C3FF;
													sendClothes(currentPeer);
													sendState(currentPeer);


													((PlayerInfo*)(currentPeer->data))->canWalkInBlocks = true;
												}

											}
										}
									}
								}
							}
						}
						if (isFindDialog && btn.substr(0, 4) == "tool") {
							int proitem = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
							if (proitem == 1874 || proitem == 1876 || proitem == 1986 || proitem == 2970 || proitem == 1780 || proitem == 1782 || proitem == 1784 || proitem == 7734 || proitem == 5026)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe `9Legendary Wizard`w has invited you to come to `2LEGEND`w!``|left|1790|\n\nadd_spacer|small|\nadd_label_with_icon|small|set_default_color|`o\n\nadd_label_with_icon|big|`wThe `4Ring Master`w has invited you to come to `2CARNIVAL`w!``|left|1900|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								//enet_host_flush(server);
								delete p.data;
							}
							int Id = atoi(btn.substr(4, btn.length() - 4).c_str());

							size_t invsize = 200;
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
							for (const ItemDefinition& item : itemDefs)
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

							for (const ItemDefinition& item : itemDefsfind)
							{
								string kys = item.name;
								std::transform(kys.begin(), kys.end(), kys.begin(), ::tolower);
								string kms = itemFind;
								std::transform(kms.begin(), kms.end(), kms.begin(), ::tolower);
								if (kys.find(kms) != std::string::npos)
									listMiddle += "add_button_with_icon|tool" + to_string(item.id) + "|`$" + item.name + "``|left|" + to_string(item.id) + "||\n";
							}
							if (itemFind.length() < 3) {
								listFull = "add_textbox|`4Word is less than 3 letters!``|\nadd_spacer|small|\n";
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
						if (btn == "crash")
						{
							sendConsoleMsg(peer, "`8Your set was removed in order to fix the crash. You can now continue playing, before that, we will need to disconnect you `3ONCE`8.");							
							((PlayerInfo*)(peer->data))->cloth_hair = 0;
							((PlayerInfo*)(peer->data))->cloth_shirt = 0;
							((PlayerInfo*)(peer->data))->cloth_pants = 0;
							((PlayerInfo*)(peer->data))->cloth_feet = 0;
							((PlayerInfo*)(peer->data))->cloth_face = 0;
							((PlayerInfo*)(peer->data))->cloth_hand = 0;
							((PlayerInfo*)(peer->data))->cloth_back = 0;
							((PlayerInfo*)(peer->data))->cloth_mask = 0;
							((PlayerInfo*)(peer->data))->cloth_necklace = 0;
							((PlayerInfo*)(peer->data))->cloth_ances = 0;

							enet_peer_disconnect_later(peer, 0);
						}
						
						
							if (btn == "effect0")
							{
								((PlayerInfo*)(peer->data))->effect = -1; // punch

							}
							if (btn == "effect1")
							{
								((PlayerInfo*)(peer->data))->effect = -500;	 // death ray	

							}
							if (btn == "effect2")
							{
								((PlayerInfo*)(peer->data))->effect = 8421381; // shotgun
								sendState(peer); //here
								sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
							}
							if (btn == "effect3")
							{
								((PlayerInfo*)(peer->data))->effect = 8420386; // Tank
							}
							if (btn == "effect4")
							{
								((PlayerInfo*)(peer->data))->effect = 8420396; // Silver Bow
							}
							if (btn == "effect5")
							{
								((PlayerInfo*)(peer->data))->effect = 8420389; // Rock Hammer
							}
							if (btn == "effect6")
							{
								((PlayerInfo*)(peer->data))->effect = 8421382; // Dragon
							}
							if (btn == "effect7")
							{
								((PlayerInfo*)(peer->data))->effect = -979; // egg
							}
							if (btn == "effect8")
							{
								((PlayerInfo*)(peer->data))->effect = -1017; // idk
							}
							if (btn == "effect9")
							{
								((PlayerInfo*)(peer->data))->effect = -991; // ice drag
							}
							if (btn == "effect10")
							{
								((PlayerInfo*)(peer->data))->effect = -1002; // Focused Eyes
							}
							if (btn == "effect11")
							{
								((PlayerInfo*)(peer->data))->effect = -991; // icedrag
							}
							if (btn == "effect12")
							{
								((PlayerInfo*)(peer->data))->effect = -997; // chaos curse wand
							}
							if (btn == "effect13")
							{
								((PlayerInfo*)(peer->data))->effect = 8420394;
							}
							if (btn == "effect14")
							{
								((PlayerInfo*)(peer->data))->effect = 8421391;
							}
							if (btn == "effect15")
							{
								((PlayerInfo*)(peer->data))->effect = 8421391; // battle trout
							}
							if (btn == "effect16")
							{
								((PlayerInfo*)(peer->data))->effect = -1008; // fiesta
							}
							if (btn == "effect17")
							{
								((PlayerInfo*)(peer->data))->effect = -1007; // squirt
							}
							if (btn == "effect18")
							{
								((PlayerInfo*)(peer->data))->effect = -1006; // key tar
							}
							if (btn == "effect19")
							{
								((PlayerInfo*)(peer->data))->effect = -940; // drag V2
							}
							if (btn == "effect20")
							{
								((PlayerInfo*)(peer->data))->effect = -1004; // lbot
							}
							if (btn == "effect21")
							{
								((PlayerInfo*)(peer->data))->effect = -1003; // l drag
							}
							if (btn == "effect22")
							{
								((PlayerInfo*)(peer->data))->effect = -950; // fiesta
							}
							if (btn == "effect23")
							{
								((PlayerInfo*)(peer->data))->effect = -996; // Green Swe
							}
							if (btn == "effect24")
							{
								((PlayerInfo*)(peer->data))->effect = -977; // Gungir
							}
							if (btn == "effect25")
							{
								((PlayerInfo*)(peer->data))->effect = -964; // Blue Soul
							}
							if (btn == "effect26")
							{
								((PlayerInfo*)(peer->data))->effect = -1011; //Black Shadow Effect

							}
							if (btn == "effect27")
							{
								((PlayerInfo*)(peer->data))->effect = -992; // Black Crystal
							}
							if (btn == "effect28")
							{
								((PlayerInfo*)(peer->data))->effect = -981; // l katana
							}
							if (btn == "effect29")
							{
								((PlayerInfo*)(peer->data))->effect = -978; // Black Holes
							}
							if (btn == "effect30")
							{
								((PlayerInfo*)(peer->data))->effect = 8420397; // Pineapple Blur Effect
							}
							if (btn == "effect31")
							{
								((PlayerInfo*)(peer->data))->effect = -995; // digger spade
							}
							if (btn == "effect32")
							{
								((PlayerInfo*)(peer->data))->effect = 0; //
							}
							if (btn == "effect33")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect34")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect35")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect36")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect37")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect38")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect39")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect40")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect41")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect42")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect43")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect44")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect45")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect46")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect47")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect48")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect49")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect50")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect51")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect52")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect53")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect54")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect55")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect56")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect57")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect58")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect59")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect60")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect61")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect62")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect63")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect64")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect65")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect66")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect67")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect67")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect68")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect69")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect70")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect71")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect72")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect73")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect74")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect75")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect76")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect77")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect78")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect79")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect80")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect81")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect82")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect83")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect84")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect85")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect86")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect87")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect88")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect89")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect90")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect91")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect92")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect93")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect94")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect95")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect96")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect97")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect98")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect99")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect100")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect101")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect102")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect103")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect104")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect105")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect106")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect107")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect108")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect109")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect110")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect111")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect112")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect113")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							if (btn == "effect114")
							{
								((PlayerInfo*)(peer->data))->effect = 0;
							}
							sendState(peer); //here
							sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
						
						if (btn == "suspend")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {


								ENetPeer * currentPeer;

								
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									

									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) {
										if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;

										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancient Ones `ohave `4banned `2" + ((PlayerInfo*)(currentPeer->data))->displayName + " `#** `o(`4/rules `oto see the rules!)"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);


										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancient Ones `ohave used `#Ban `oon `2" + ((PlayerInfo*)(currentPeer->data))->displayName + "`o! `#**"));
										ENetPacket * packetb = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packetb);

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
										if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

											PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));
											p->ban = 1;
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
											int clothances = p->cloth_ances;
											//int isCursed = p->isCursed;
											//int puncheffect = p->puncheffect;
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
											j["ClothAnces"] = clothances;
											j["ipID"] = currentPeer->address.host;
											//j["displayName"] = ((PlayerInfo*)(currentPeer->data))->displayUsername;
											j["effect"] = 8421376;
											
											j["isBanned"] = 1;

											//j["puncheffect"] = puncheffect;


											j["adminLevel"] = 0;
											j["password"] = hashPassword(password);
											j["username"] = username;
											j["friends"] = ((PlayerInfo*)(currentPeer->data))->friendinfo;
											j["ip"] = ((PlayerInfo*)(currentPeer->data))->charIP;
											j["boughtLGW"] = ((PlayerInfo*)(peer->data))->boughtLGW;
											j["boughtLGK"] = ((PlayerInfo*)(peer->data))->boughtLGK;
											j["boughtLGD"] = ((PlayerInfo*)(peer->data))->boughtLGD;
											j["boughtLGB"] = ((PlayerInfo*)(peer->data))->boughtLGB;
											j["boughtLKW"] = ((PlayerInfo*)(peer->data))->boughtLKW;
											j["boughtCWD"] = ((PlayerInfo*)(peer->data))->boughtCWD;
											j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS;
											j["boughtCDG"] = ((PlayerInfo*)(peer->data))->boughtCDG;
											j["aap"] = ((PlayerInfo*)(currentPeer->data))->isAAP;
											j["receivedwarns"] = ((PlayerInfo*)(currentPeer->data))->warns;
											j["receivedbans"] = ((PlayerInfo*)(currentPeer->data))->bans;


											o << j << std::endl;

											string bannamed = str.substr(5, cch.length() - 5 - 1);
											std::ofstream outfile("bans/" + bannamed + ".txt");

											outfile << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

											outfile.close();
										}
										delete ps.data;

										enet_peer_send(currentPeer, 0, packet);
										delete p.data;


										enet_peer_disconnect_later(currentPeer, 0);
										

									}

									

									//enet_host_flush(server);
								}
							
							}
								
						}
						if (btn == "ban7")
						{
#pragma warning (disable : 4996)
							// current date/time based on current system
							time_t now = time(0);




							cout << now << endl;


							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{


								ENetPeer * currentPeerp;

								for (currentPeerp = server->peers;
									currentPeerp < &server->peers[server->peerCount];
									++currentPeerp)
								{
									if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(peer->data))->lastInfo == ((PlayerInfo*)(currentPeerp->data))->rawName)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wFeature doesnt work yet, in the next update it will work for sure!"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
									}

								}
							}
						}
						if (btn == "disconnect")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{


								ENetPeer * currentPeerp;

								for (currentPeerp = server->peers;
									currentPeerp < &server->peers[server->peerCount];
									++currentPeerp)
								{
									if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(peer->data))->lastInfo == ((PlayerInfo*)(currentPeerp->data))->rawName)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Fake disconnected player from server."));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										enet_peer_disconnect_later(currentPeerp, 0);
									}
								}
							}
						}
						if (btn == "freeze")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{


								ENetPeer * currentPeerp;

								for (currentPeerp = server->peers;
									currentPeerp < &server->peers[server->peerCount];
									++currentPeerp)
								{
									if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(peer->data))->lastInfo == ((PlayerInfo*)(currentPeerp->data))->rawName)
									{
										if (((PlayerInfo*)(currentPeerp->data))->isFrozen == false)
										{
											((PlayerInfo*)(currentPeerp->data))->isFrozen = true;
											
											

											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wUsed `!Freeze`w mod on `w" + ((PlayerInfo*)(currentPeerp->data))->displayName));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
											delete p.data;

											((PlayerInfo*)(currentPeerp->data))->skinColor = -37500;
											sendClothes(currentPeerp);
											sendFrozenState(currentPeerp);

											GamePacket pf = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wSHUSH... pretty cold here. `!(Frozen)`w mod added."));
											ENetPacket * packetf = enet_packet_create(pf.data,
												pf.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeerp, 0, packetf);
											delete pf.data;
										}
										else
										{
											((PlayerInfo*)(currentPeerp->data))->isFrozen = false;
											sendResetState(currentPeerp);

											GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
											memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeerp->data))->netID), 4);
											ENetPacket * packet2 = enet_packet_create(p2.data,
												p2.len,
												ENET_PACKET_FLAG_RELIABLE);


											enet_peer_send(currentPeerp, 0, packet2);
											delete p2.data;

											((PlayerInfo*)(currentPeerp->data))->skinColor = 0x8295C3FF;
											sendClothes(currentPeerp);
											

											GamePacket pf = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wLiking it warm... `!(Frozen)`w mod removed."));
											ENetPacket * packetf = enet_packet_create(pf.data,
												pf.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeerp, 0, packetf);
											delete pf.data;

											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`!Unfrozen `wplayer `w" + ((PlayerInfo*)(currentPeerp->data))->displayName));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
										}

									}

									string text = "action|play_sfx\nfile|audio/freeze.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
									memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

									ENetPacket * packetso = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									if (isHere(peer, currentPeerp))
									{
										enet_peer_send(currentPeerp, 0, packetso);
									}
								}
							}
						}
						if (btn == "tape")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{


								ENetPeer * currentPeerp;

								for (currentPeerp = server->peers;
									currentPeerp < &server->peers[server->peerCount];
									++currentPeerp)
								{
									if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(peer->data))->lastInfo == ((PlayerInfo*)(currentPeerp->data))->rawName)
									{
										if (((PlayerInfo*)(currentPeerp->data))->taped == false)
										{
											((PlayerInfo*)(currentPeerp->data))->taped = true;
											((PlayerInfo*)(currentPeerp->data))->isDuctaped = true;
											((PlayerInfo*)(currentPeerp->data))->cantsay = true;
											sendState(currentPeerp);
												
											

											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wUsed `btape`w mod on `w" + ((PlayerInfo*)(currentPeerp->data))->displayName));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
										}
										else
										{
											((PlayerInfo*)(currentPeerp->data))->taped = false;
											((PlayerInfo*)(currentPeerp->data))->isDuctaped = false;
											((PlayerInfo*)(currentPeerp->data))->cantsay = false;
											sendState(currentPeerp);
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wUn`btaped`w player."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
										}

									}

									string text = "action|play_sfx\nfile|audio/lightning.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
									memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

									ENetPacket * packetso = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									if (isHere(peer, currentPeerp))
									{
										enet_peer_send(currentPeerp, 0, packetso);
									}
								}
							}
						}
						if (btn == "punishview")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{
								ENetPeer * currentPeerpx;

								for (currentPeerpx = server->peers;
									currentPeerpx < &server->peers[server->peerCount];
									++currentPeerpx)
								{
									if (currentPeerpx->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(currentPeerpx->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) // if last wrench
									{

										if (getAdminLevel(((PlayerInfo*)(currentPeerpx->data))->rawName, ((PlayerInfo*)(currentPeerpx->data))->tankIDPass) == 999)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wEditing Player: ``" + ((PlayerInfo*)(currentPeerpx->data))->rawName + "|left|242|\nadd_label|small|`wProper IP / Identification: (?)" + "|left|4|\n\nadd_spacer|small|\nadd_button_with_icon|tape|`bTape``|noflags|408||\nadd_spacer|small|\nadd_button_with_icon|ban7|`4Ban 7 Days``|noflags|732||\nadd_button_with_icon|ban30|`4Ban 30 Days``|noflags|732||\nadd_button_with_icon|ban60|`4Fake auto-ban``|noflags|732||\nadd_button_with_icon|suspend|`5Suspend `4Player``|noflags|732||\nadd_button_with_icon|disconnect|`6Boot (fake dc)``|noflags|732||\nadd_button_with_icon|freeze|`!Freeze``|noflags|274||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											//enet_host_flush(server);
											delete p.data;
										}
										else
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wEditing Player: ``" + ((PlayerInfo*)(currentPeerpx->data))->rawName + "|left|242|\nadd_label|small|`wProper IP / Identification: (" + ((PlayerInfo*)(currentPeerpx->data))->charIP + ")" + "|left|4|\n\nadd_spacer|small|\nadd_button_with_icon|tape|`bTape``|noflags|408||\nadd_spacer|small|\nadd_button_with_icon|ban7|`4Ban 7 Days``|noflags|732||\nadd_button_with_icon|ban30|`4Ban 30 Days``|noflags|732||\nadd_button_with_icon|ban60|`4Fake auto-ban``|noflags|732||\nadd_button_with_icon|suspend|`5Suspend `4Player``|noflags|732||\nadd_button_with_icon|disconnect|`6Boot (fake dc)``|noflags|732||\nadd_button_with_icon|freeze|`!Freeze``|noflags|274||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											//enet_host_flush(server);
											delete p.data;
										}
									}
									
								}
							}
						}
						if (btn == "wban")
						{
							if (((PlayerInfo*)(peer->data))->haveGrowId && ((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{
								ENetPeer * currentPeerp;

								for (currentPeerp = server->peers;
									currentPeerp < &server->peers[server->peerCount];
									++currentPeerp)
								{
									if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
										continue;



									string name = ((PlayerInfo*)(peer->data))->displayName;
									string kickname = ((PlayerInfo*)(peer->data))->lastInfoname;
									//string kickname = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), name + " `4world bans " + "`o" + kickname));
									string text = "action|play_sfx\nfile|audio/repair.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);

									if (isHere(peer, currentPeerp))
									{
										ENetPacket * packetsou = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										

										enet_peer_send(currentPeerp, 0, packetsou);
										enet_peer_send(currentPeerp, 0, packet);
										delete data;
										delete p.data;
										if (((PlayerInfo*)(currentPeerp->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) // if last wrench
										{

											
											namespace fs = std::experimental::filesystem;

											if (!fs::is_directory("worldbans/" + getPlyersWorld(peer)->name) || !fs::exists("worldbans/" + getPlyersWorld(peer)->name)) { 
												fs::create_directory("worldbans/" + getPlyersWorld(peer)->name); 

												std::ofstream outfile("worldbans/" + getPlyersWorld(peer)->name + "/" + ((PlayerInfo*)(currentPeerp->data))->rawName);

												outfile << "worldbanned by: "  + ((PlayerInfo*)(peer->data))->rawName;

												outfile.close();
											}
											else
											{
												std::ofstream outfile("worldbans/" + getPlyersWorld(peer)->name + "/" + ((PlayerInfo*)(currentPeerp->data))->rawName);

												outfile << "worldbanned by: " + ((PlayerInfo*)(peer->data))->rawName;

												outfile.close();
											}

											sendPlayerLeave(currentPeerp, (PlayerInfo*)(currentPeerp->data));
											sendWorldOffers(currentPeerp);


											((PlayerInfo*)(currentPeerp->data))->currentWorld = "EXIT";

										}
									}
									
									
								}

							}
						}
						if (btn == "autoban")
						{
							// Warning from `4System``: You've been `4BANNED`` from `wGrowtopia`` for 60 days``


						}
						if (btn == "kick")
						{
							if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{
								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;



									string name = ((PlayerInfo*)(peer->data))->displayName;
									string kickname = ((PlayerInfo*)(peer->data))->lastInfoname;
									//string kickname = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), name + " `4kicks " + "`w" + kickname));
									string text = "action|play_sfx\nfile|audio/male_scream.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);

									if (isHere(peer, currentPeer))
									{
										ENetPacket * packetsou = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);


										enet_peer_send(currentPeer, 0, packetsou);
										enet_peer_send(currentPeer, 0, packet);


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
										memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
										ENetPacket * packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);

										if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo)
										{
											enet_peer_send(currentPeer, 0, packet2);
										}



										delete p2.data;
										delete p.data;
										delete data;

									}

								}
							}
						}

						if (btn == "pull")
						{
							if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{
								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									string name = ((PlayerInfo*)(currentPeer->data))->rawName;
									int pullX = ((PlayerInfo*)(peer->data))->x;
									int pullY = ((PlayerInfo*)(peer->data))->y;


									if (name == ((PlayerInfo*)(peer->data))->lastInfo)
									{
										if (isHere(peer, currentPeer) && getPlyersWorld(peer)->name != "EXIT")
										{
											string name = ((PlayerInfo*)(peer->data))->displayName;
											string pullname = ((PlayerInfo*)(currentPeer->data))->displayName;
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), name + " `5pulls " + "`w" + pullname));
											string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
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
											enet_peer_send(peer, 0, packet);




											ENetPacket * packetsou = enet_packet_create(data,
												5 + text.length(),
												ENET_PACKET_FLAG_RELIABLE);


											enet_peer_send(currentPeer, 0, packetsou);
											enet_peer_send(peer, 0, packetsou);

											GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), pullX, pullY));
											memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
											ENetPacket * packet2 = enet_packet_create(p2.data,
												p2.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet2);

											GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You have been pulled by " + ((PlayerInfo*)(peer->data))->displayName));
											//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
											ENetPacket * packetto = enet_packet_create(pto.data,
												pto.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packetto);

											delete pto.data;
											delete p2.data;
											delete p.data;

										}
									}
								}
							}
						
						

							
							

						}
						if (btn == "backsocialportal") {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "frnoption") {
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


						if (btn == "starttrd")
						{
							if (world->owner == ((PlayerInfo*)(peer->data))->rawName && world->isPublic == false)
							{
								if (((PlayerInfo*)(peer->data))->haveGrowId == true)
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_button|chc0|Close|noflags|0|0|\nadd_spacer|small|\nadd_textbox|Choose amount of `4Gems`w to sell world for:|\nadd_text_input|worldoffer|World Offer||30|\nend_dialog|disabled111|Cancel|Request Offer!\n"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
									// need also to reset seller/buyer when wl breaks and any exits (door or exit world) declines, or disconnects happen.
								}
								else
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4ERROR! `w >> `7You need a GrowID first to trade worlds! `wCreate one, it's free."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}

							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4ERROR! `w >> `7You are not the `9world `2owner`w or world is Public!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "dwheel")
						{
							
						}
						if (btn == "swheel")
						{

							sendRoulete(peer, x, y);

						}
						if (btn == "lkw")
						{
							if (((PlayerInfo*)(peer->data))->boughtLKW == false)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAre you sure to buy `6Legendary Dragon Knight's Wings`w for `520.000 `4Gems`w?``|left|6128|\nadd_button|yeslkw|Yes!|0|0|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wYou bought this item.``|left|6126|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "cwd")
						{
							if (((PlayerInfo*)(peer->data))->boughtCWD == false)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAre you sure to buy `6Chaos Cursed Wand`w for `57.000 `4Gems`w?``|left|6128|\nadd_button|yescwd|Yes!|0|0|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wYou bought this item.``|left|6126|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "rfs")
						{
							if (((PlayerInfo*)(peer->data))->boughtRFS == false)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAre you sure to buy `6Rayman's Fist`w for `560.000 `4Gems`w?``|left|6128|\nadd_button|yesrfs|Yes!|0|0|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wYou bought this item.``|left|6126|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "cdg")
						{
							if (((PlayerInfo*)(peer->data))->boughtCDG == false)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAre you sure to buy `6Chaos Dragon`w for `515.000 `4Gems`w?``|left|6128|\nadd_button|yescdg|Yes!|0|0|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wYou bought this item.``|left|6126|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "lgk")
						{
							if (((PlayerInfo*)(peer->data))->boughtLGK == false)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAre you sure to buy `6Legendary Katana`w for `520.000 `4Gems`w?``|left|6128|\nadd_button|yeslgk|Yes!|0|0|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wYou bought this item.``|left|6126|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "lgb")
						{
							if (((PlayerInfo*)(peer->data))->boughtLGB == false) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAre you sure to buy `6Legendary Bot`w for `520.000 `4Gems`w?``|left|6128|\nadd_button|yeslgb|Yes!|0|0|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wYou bought this item.``|left|6126|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "lgw")
						{
							if (((PlayerInfo*)(peer->data))->boughtLGW == false) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAre you sure to buy `6Legendary Wings`w for `520.000 `4Gems`w?``|left|6128|\nadd_button|yeslgw|Yes!|0|0|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wYou bought this item.``|left|6126|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "lgd")
						{
							if (((PlayerInfo*)(peer->data))->boughtLGD == false) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAre you sure to buy `6Dragon of Legend`w for `520.000 `4Gems`w?``|left|6128|\nadd_button|yeslgd|Yes!|0|0|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wYou bought this item.``|left|6126|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "no")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_ele_icon|big|`wGTOG Shop|left|5956|\nadd_label_with_icon|small|`9Legendary items``|left|1790|\n\nadd_button_with_icon|lgb||staticBlueFrame|1780|20000|\nadd_button_with_icon|lgw||staticBlueFrame|1784|20000|\nadd_button_with_icon|lgd||staticBlueFrame|1782|20000|\nadd_button_with_icon|lgk||staticBlueFrame|2592|20000|\nadd_button_with_icon|lkw||staticBlueFrame|7734|20000|\nadd_button_with_icon||END_LIST|noflags|0|0||\nadd_spacer|small|\nadd_label_with_icon|small|`7Special items``|left|1900|\nadd_button_with_icon|cwd||staticBlueFrame|1956|7000|\nadd_button_with_icon|rfs||staticBlueFrame|5480|60000|\nadd_button_with_icon|cdg||staticBlueFrame|7762|15000|\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "yeslkw") {
							std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifsz)),
								(std::istreambuf_iterator<char>()));

							int b = atoi(content.c_str());

							if (b > 19999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - You now bought Legendary Dragon Knight's Wings!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								int gemcalc10k = b - 20000;


								ofstream myfile2;
								myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								myfile2 << std::to_string(gemcalc10k);
								myfile2.close();

								std::ifstream ifszi("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string contentx((std::istreambuf_iterator<char>(ifszi)),
									(std::istreambuf_iterator<char>()));


								int updgem = atoi(contentx.c_str());
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), updgem));
								ENetPacket * packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;


								((PlayerInfo*)(peer->data))->boughtLKW = true;

								std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


								if (ifff.fail()) {
									ifff.close();


								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load


								j["boughtLKW"] = ((PlayerInfo*)(peer->data))->boughtLKW; //edit




								std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;

								PlayerInventory inventory;
								InventoryItem item;
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 32;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 7734;
								inventory.items.push_back(item);
								sendInventory(peer, inventory);

								string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsou);

							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							
						}
						if (btn == "yescwd") {
							std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifsz)),
								(std::istreambuf_iterator<char>()));

							int b = atoi(content.c_str());

							if (b > 6999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - You now bought Chaos Cursed Wand!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								int gemcalc10k = b - 7000;


								ofstream myfile2;
								myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								myfile2 << std::to_string(gemcalc10k);
								myfile2.close();

								std::ifstream ifszi("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string contentx((std::istreambuf_iterator<char>(ifszi)),
									(std::istreambuf_iterator<char>()));


								int updgem = atoi(contentx.c_str());
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), updgem));
								ENetPacket * packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;


								((PlayerInfo*)(peer->data))->boughtCWD = true;

								std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


								if (ifff.fail()) {
									ifff.close();


								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load


								j["boughtCWD"] = ((PlayerInfo*)(peer->data))->boughtCWD; //edit




								std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;

								PlayerInventory inventory;
								InventoryItem item;
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 32;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 1956;
								inventory.items.push_back(item);
								sendInventory(peer, inventory);


								string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsou);

							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "yesrfs") {
							std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifsz)),
								(std::istreambuf_iterator<char>()));

							int b = atoi(content.c_str());

							if (b > 59999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - You now bought Rayman's fist (use with Tractor for fast farm!)"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								int gemcalc10k = b - 60000;


								ofstream myfile2;
								myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								myfile2 << std::to_string(gemcalc10k);
								myfile2.close();

								std::ifstream ifszi("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string contentx((std::istreambuf_iterator<char>(ifszi)),
									(std::istreambuf_iterator<char>()));


								int updgem = atoi(contentx.c_str());
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), updgem));
								ENetPacket * packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;


								((PlayerInfo*)(peer->data))->boughtRFS = true;

								std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


								if (ifff.fail()) {
									ifff.close();


								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load


								j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS; //edit




								std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;


								PlayerInventory inventory;
								InventoryItem item;
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 32;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 5480;
								inventory.items.push_back(item);
								sendInventory(peer, inventory);


								string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsou);

							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "yescdg") {
							std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifsz)),
								(std::istreambuf_iterator<char>()));

							int b = atoi(content.c_str());

							if (b > 14999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - You now bought Chaos Dragon!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								int gemcalc10k = b - 15000;


								ofstream myfile2;
								myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								myfile2 << std::to_string(gemcalc10k);
								myfile2.close();

								std::ifstream ifszi("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string contentx((std::istreambuf_iterator<char>(ifszi)),
									(std::istreambuf_iterator<char>()));


								int updgem = atoi(contentx.c_str());
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), updgem));
								ENetPacket * packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;


								((PlayerInfo*)(peer->data))->boughtCDG = true;

								std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


								if (ifff.fail()) {
									ifff.close();


								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load


								j["boughtCDG"] = ((PlayerInfo*)(peer->data))->boughtCDG; //edit




								std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;


								PlayerInventory inventory;
								InventoryItem item;
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 32;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 7762;
								inventory.items.push_back(item);
								sendInventory(peer, inventory);


								string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsou);

							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "yeslgk") {
							std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifsz)),
								(std::istreambuf_iterator<char>()));

							int b = atoi(content.c_str());

							if (b > 19999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - You now bought Legendary Katana!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								int gemcalc10k = b - 20000;


								ofstream myfile2;
								myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								myfile2 << std::to_string(gemcalc10k);
								myfile2.close();

								std::ifstream ifszi("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string contentx((std::istreambuf_iterator<char>(ifszi)),
									(std::istreambuf_iterator<char>()));


								int updgem = atoi(contentx.c_str());
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), updgem));
								ENetPacket * packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;


								((PlayerInfo*)(peer->data))->boughtLGK = true;

								std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


								if (ifff.fail()) {
									ifff.close();


								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load


								j["boughtLGK"] = ((PlayerInfo*)(peer->data))->boughtLGK; //edit




								std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;



								PlayerInventory inventory;
								InventoryItem item;
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 32;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 2592;
								inventory.items.push_back(item);
								sendInventory(peer, inventory);



								string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsou);
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "yeslgb") {
							std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifsz)),
								(std::istreambuf_iterator<char>()));

							int b = atoi(content.c_str());

							if (b > 19999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - You now bought Legendary Bot!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								int gemcalc10k = b - 20000;


								ofstream myfile2;
								myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								myfile2 << std::to_string(gemcalc10k);
								myfile2.close();

								std::ifstream ifszi("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string contentx((std::istreambuf_iterator<char>(ifszi)),
									(std::istreambuf_iterator<char>()));


								int updgem = atoi(contentx.c_str());
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), updgem));
								ENetPacket * packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;


								((PlayerInfo*)(peer->data))->boughtLGB = true;

								

								std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


								if (ifff.fail()) {
									ifff.close();


								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load


								j["boughtLGB"] = ((PlayerInfo*)(peer->data))->boughtLGB; //edit




								std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;


								PlayerInventory inventory;
								InventoryItem item;
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 32;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 1780;
								inventory.items.push_back(item);
								sendInventory(peer, inventory);
								


								string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsou);
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "yeslgw") {
							std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifsz)),
								(std::istreambuf_iterator<char>()));

							int b = atoi(content.c_str());

							if (b > 19999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - You now bought Legendary Wings!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								int gemcalc10k = b - 20000;


								ofstream myfile2;
								myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								myfile2 << std::to_string(gemcalc10k);
								myfile2.close();

								std::ifstream ifszi("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string contentx((std::istreambuf_iterator<char>(ifszi)),
									(std::istreambuf_iterator<char>()));


								int updgem = atoi(contentx.c_str());
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), updgem));
								ENetPacket * packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;


								((PlayerInfo*)(peer->data))->boughtLGW = true;

								

								std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


								if (ifff.fail()) {
									ifff.close();


								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load


								j["boughtLGW"] = ((PlayerInfo*)(peer->data))->boughtLGW; //edit




								std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;


								PlayerInventory inventory;
								InventoryItem item;
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 32;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 1784;
								inventory.items.push_back(item);
								sendInventory(peer, inventory);



								string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsou);
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "yeslgd") {
							std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifsz)),
								(std::istreambuf_iterator<char>()));

							int b = atoi(content.c_str());

							if (b > 19999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - You now bought Dragon of Legend!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								int gemcalc10k = b - 20000;


								ofstream myfile2;
								myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								myfile2 << std::to_string(gemcalc10k);
								myfile2.close();

								std::ifstream ifszi("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string contentx((std::istreambuf_iterator<char>(ifszi)),
									(std::istreambuf_iterator<char>()));


								int updgem = atoi(contentx.c_str());
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), updgem));
								ENetPacket * packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;


								((PlayerInfo*)(peer->data))->boughtLGD = true;

								

								std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


								if (ifff.fail()) {
									ifff.close();


								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load


								j["boughtLGD"] = ((PlayerInfo*)(peer->data))->boughtLGD; //edit




								std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;

								PlayerInventory inventory;
								InventoryItem item;
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 32;
								inventory.items.push_back(item);
								item.itemCount = 1;
								item.itemID = 1782;
								inventory.items.push_back(item);
								sendInventory(peer, inventory);


								string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsou);
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "lwings")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wDisabled shop, need to improve it soon!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							/*std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifsz)),
								(std::istreambuf_iterator<char>()));

							int b = atoi(content.c_str());

							if (b > 9999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - You now have access to legendary wings! do /item 1784 to get them."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								int gemcalc10k = b - 10000;


								ofstream myfile2;
								myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								myfile2 << std::to_string(gemcalc10k);
								myfile2.close();
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems to buy these"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}*/


							if (btn == "pay500gem") {

								/*std::ifstream ifsz("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string content((std::istreambuf_iterator<char>(ifsz)),
									(std::istreambuf_iterator<char>()));

								std::ifstream ifsz2("wrenchsessions/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								std::string contentxx((std::istreambuf_iterator<char>(ifsz2)),
									(std::istreambuf_iterator<char>()));

								std::ifstream ifs3("gemdb/" + contentxx + ".txt");
								std::string contentxxp((std::istreambuf_iterator<char>(ifs3)),
									(std::istreambuf_iterator<char>()));


								int b = atoi(content.c_str());
								int b2 = atoi(contentxxp.c_str());
								if (b > 499)
								{
									if (((PlayerInfo*)(peer->data))->rawName == contentxx)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wExplain me why you wanna pay to yourself first bruh.``"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p.data;

									}
									else
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2TRANSACTION SUCCESS! - Sent `4Gems `wto " + contentxx + ", may need to reenter to take effect.``"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p.data;

										int gemcalc500 = b - 500;
										int gemcalc500add = b2 + 500;

										ofstream myfile2;
										myfile2.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										myfile2 << std::to_string(gemcalc500);
										myfile2.close();

										ofstream myfile4;
										myfile4.open("gemdb/" + contentxx + ".txt");
										myfile4 << std::to_string(gemcalc500add);
										myfile4.close();
									}



								}
								else
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rYou don't have enough `4Gems `w to pay.``"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								if (btn == "pay5000gem")
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#Feature coming soon!``"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}*/

							}

						}



#ifdef REGISTRATION
						if (isRegisterDialog) {


							int regState = PlayerDB::playerRegister(peer, username, password, passwordverify, discord, pin);
							if (regState == 1) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rYour account has been created!``"));
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
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rAccount creation has failed, because it already exists!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -2) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rAccount creation has failed, because the name is too short!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -3) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Passwords mismatch!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -4) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Account creation has failed, because email address is invalid!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -5) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Account creation has failed, because Discord ID is invalid!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -6) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Account creation has failed due to account name that is being used by system!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -7) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Oops! `9Looks like players data have been resetted, `wmake sure to use your `bPIN `wthat you used when creating your account. `2For help, message `wDirux#4989 on Discord!`w``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -8) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Oops! `9Looks like `wPIN `9is not in a range of 1000-9999. Choose a `wPIN `9from 1000-9999!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -9) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Oops! `9Looks like `wPIN `9contains text, only numbers. Choose a `wPIN `9from 1000-9999!``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -10) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wPlayer name contains illegal characters.``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
#endif
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
					if (cch.find("text|") != std::string::npos) {
						bool canchat = true;
						PlayerInfo* pData = ((PlayerInfo*)(peer->data));
						if (str.length() && str[0] == '/')
						{
							sendConsoleMsg(peer, "`6" + str);
							sendAction(peer, ((PlayerInfo*)(peer->data))->netID, str);

						}
						
					    else if (((PlayerInfo*)(peer->data))->taped == false) {

							sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, str);		

							}
						else {
							for (char c : str)

								if (c < 0x18 || std::all_of(str.begin(), str.end(), isspace))
								{
									canchat = false;
								}
								if (canchat)
								{
									sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, "mfmfmmfmfmff");

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Can't talk properly while you're duct-taped!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							
						}

					
						if (str == "/mod")
						{
							

							//if (getPlyersWorld(peer)->allowMod == false && world->owner != ((PlayerInfo*)(currentPeer->data))->rawName)





							if (getPlyersWorld(peer)->allowMod == false && ((PlayerInfo*)(peer->data))->rawName != world->owner) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7You are not allowed to enable the /mod command in this world cause it is deactivated by owner."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								((PlayerInfo*)(peer->data))->skinColor = -155;
								((PlayerInfo*)(peer->data))->isModState = true;
								((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
								sendState(peer);
								sendClothes(peer);
							}

							/*PlayerMoving data;
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
							SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
						}
						else if (str == "/news")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|GrowtopiaOG Gazette``|left|5016|\n\nadd_spacer|small|\n\nadd_spacer|small|\nadd_label|small|`6Welcome To GrowtopiaOG!|left|4|\nadd_spacer|small||\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\n\nadd_textbox|`3V3.0|left|4|\nadd_label_with_icon|small|\nadd_button|crash|`2Press Here`w if you are `4Crashing`w! (removes set&disconnect)|noflags|0|0|\nadd_label_with_icon|big|`5GTOG Summer Update!``|left|836|\n\nadd_textbox|`33.0: 1. Fixed MANY bugs! 2. Added World-Trade! 3. Added PVP (in pvp server, do /server and click battle royale) 4. Added full shop system! 5. Added more commands! - Checkout all yourself, added much more than that :D.|left|4|\n\nadd_textbox|`3To find items, use /find.|left|4|\n\nadd_spacer|small|\n\nadd_textbox|`2Join our Discord for more information!|left|4|\nadd_spacer|small|\nadd_label|small|`$- This Server developed by `6playingo`$ & `6ashley`$.|left|4|\nadd_spacer|small|\nadd_label|small|`4Make sure to Join Our discord server!|left|4|\nadd_url_button||``New discord server!``|NOFLAGS|https://discord.gg/zW25ynC| Join discord server?|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
						else if (str == "/ghost")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{
								if (pData->ghostalr == true)
								{

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;



									pData->ghostalr = false;
									((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
									sendClothes(peer);
									((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
									sendState(peer);
									sendConsoleMsg(peer, "`oYour body stops shimmering and returns to normal. (Ghost in the shell mod removed)");



								}
								else
								{




									pData->ghostalr = true;

									((PlayerInfo*)(peer->data))->skinColor = atoi("-155");
									sendClothes(peer);
									((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
									sendState(peer);
									sendConsoleMsg(peer, "`oYour atoms are suddenly aware of quantum tunneling. (Ghost in the shell mod added)");




								}


							}
						}
						else if (str == "/mods") {
							string x = "";


							ENetPeer* currentPeer;


							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;


								if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 333) {

									string name = ((PlayerInfo*)(currentPeer->data))->displayName;

									if ((((PlayerInfo*)(currentPeer->data))->isNicked == true))
									{



									}
									else
									{

										if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 999) {

											if (((PlayerInfo*)(currentPeer->data))->rawName == "playingo")
											{
												x.append("`4@" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "``, ");
											}
											else
											{
												x.append("`6@" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "``, ");
											}
										}
										else
										{
											x.append("`#@" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "``, ");
										}
									}









								}


							}
							x = x.substr(0, x.length() - 2);


							if (x == "")
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "``Moderators online: None visible."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "``Moderators online: " + x));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete p.data;
							}

						}
						else if (str == "/nicked") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333) {
								string x = "";


								ENetPeer* currentPeer;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;


									if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 333) {

										string name = ((PlayerInfo*)(currentPeer->data))->displayName;

										if ((((PlayerInfo*)(currentPeer->data))->isNicked == true))
										{

											x.append("`w'" + ((PlayerInfo*)(currentPeer->data))->displayName + "'" + "->" + ((PlayerInfo*)(currentPeer->data))->rawName + "``, ");

										}











									}


								}
								x = x.substr(0, x.length() - 2);


								if (x == "")
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "``Nicked vips/mods/devs: None visible."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								else
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "``Nicked vips/mods/devs: " + x));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}

							}
						}
						else if (str == "/find")
					{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wItem Finder``|left|6016|\nadd_textbox|Enter a word below and click Find!|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find!|\nadd_quick_exit|\n"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);

					//enet_host_flush(server);
					delete p.data;
					}
						else if (str == "/online") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								string x;


								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) < 666)





									{
										x.append(((PlayerInfo*)(currentPeer->data))->rawName + "``, ");
									}


								}
								x = x.substr(0, x.length() - 2);


								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "``Players online (does not include mods): " + x));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
						}
						else if (str == "/wizard")
						{
					
						((PlayerInfo*)(peer->data))->cloth_back = 1790;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noEyes = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noBody = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noHands = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->isInvisible = true;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are the `9Legendary Wizard`o!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), 0.0f, 0.0f, 0.0f));
						memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
						ENetPacket* packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								enet_peer_send(currentPeer, 0, packet3);
							}
						}
						delete p3.data;
						}

						else if (str.substr(0, 10) == "/particle ")
						{   //NiteSpicy
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							GamePacket p3 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), atoi(str.substr(10).c_str())), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
							ENetPacket* packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet3);
							delete p3.data;
						}
						}

						else if (str.substr(0, 8) == "/summon ") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								string name = str.substr(8, str.length());


								ENetPeer* currentPeer;


								bool found = false;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;


									string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


									std::transform(name.begin(), name.end(), name.begin(), ::tolower);
									std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


									if (name == name2) {
										GamePacket pox = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You were summoned by a mod."));
										ENetPacket* packetpox = enet_packet_create(pox.data,
											pox.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packetpox);

										sendPlayerToPlayer(currentPeer, peer);
										found = true;
									}


								}
								if (found) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Summoning " + name));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Player not found!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
								}
							}


						}

						else if (str.substr(0, 6) == "/disablemodinworld ") {

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Player not found!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)



								if (((PlayerInfo*)(peer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {


								}
						}
						else if (str.substr(0, 6) == "/pull ")
						{
						cout << "/pull from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						WorldInfo* world = getPlyersWorld(peer);
						if (((PlayerInfo*)(peer->data))->rawName == world->owner)
						{
							ENetPeer* currentPeer;
							string imie = str.substr(6, cch.length() - 6 - 1);
							int x = ((PlayerInfo*)(peer->data))->x;
							int y = ((PlayerInfo*)(peer->data))->y;
							string dupa;
							GamePacket pmsg = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o" + ((PlayerInfo*)(peer->data))->displayName + " `5pulls " + imie));
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
									{
										dupa = ((PlayerInfo*)(currentPeer->data))->rawName;
										PlayerMoving data;
										data.packetType = 0x0;
										data.characterState = 0x924; // animation
										data.x = x;
										data.y = y;
										data.punchX = -1;
										data.punchY = -1;
										data.XSpeed = 0;
										data.YSpeed = 0;
										data.netID = ((PlayerInfo*)(currentPeer->data))->netID;
										data.plantingTree = 0x0;
										SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
										GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
										memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
										ENetPacket* packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet2);
										delete p2.data;
									}
								}
							}
							ENetPacket* packetmsg = enet_packet_create(pmsg.data,
								pmsg.len,
								ENET_PACKET_FLAG_RELIABLE);
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									enet_peer_send(currentPeer, 0, packetmsg);
								}
							}
							delete pmsg.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You need to be world owner to use that command."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

						}
						}
						else if (str == "/cry")
						{
						GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ":'("), 0));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								enet_peer_send(currentPeer, 0, packet2);
							}
						}
						delete p2.data;
						continue;
						}

						else if (str.substr(0, 4) == "/me ")
						{
						if (((PlayerInfo*)(peer->data))->isDuctaped == false && ((PlayerInfo*)(peer->data))->haveGrowId == true)
						{
							string namer = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`#<`w" + namer + " `#" + str.substr(3, cch.length() - 3 - 1).c_str() + "`5>"), 0));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w<" + namer + " `#" + str.substr(3, cch.length() - 3 - 1).c_str() + "`w>"));
							ENetPacket* packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									enet_peer_send(currentPeer, 0, packet2);
									enet_peer_send(currentPeer, 0, packet3);
								}
							}
							delete p2.data;
							delete p3.data;
							continue;
						}
						}

						else if (str == "/rules") {
						//cout << "/rules from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket pzr = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`2GTOG Rules!``|left|5956|\n\nadd_spacer|small|\nadd_label_with_icon|small|Selling/buying unofficial gems is `wNOT `oillegal. But once we catch a scammer, he/she'll be `5banned`o.|left|1432|\nadd_label_with_icon|small|Don't ask for free staff.|left|1432|\nadd_label_with_icon|small|Don't sb/bc about rude stuffs.|left|1432|\nadd_label_with_icon|small|Don't try to scam.|left|1432|\nadd_label_with_icon|small|Don't be Rude or Racist etc. to other players.|left|1432|\nadd_label_with_icon|small|Don't try to be a Moderator if you aren't one.|left|1432|\nadd_label_with_icon|small|Don't talk about sexual things.|left|1432|\nadd_label_with_icon|small|\nadd_textbox|Breaking these rules will lead you to consequences!|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small||\nadd_quick_exit|\nadd_button|chc0|I accept the rules.|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packetzr = enet_packet_create(pzr.data,
							pzr.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packetzr);
						//enet_host_flush(server);
						delete pzr.data;
						}

						else if (str.substr(0, 3) == "/r ") {
						if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
							GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oTo prevent abuse, you `4must `obe `2registered `oin order to use this command!"));
							ENetPacket* packet0 = enet_packet_create(p0.data,
								p0.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet0);
							delete p0.data;
							continue;
						}


						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastMsger) {

								((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
								GamePacket ps2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6/r " + ((PlayerInfo*)(peer->data))->lastMsger + " " + str.substr(3, cch.length() - 3 - 1)));

								ENetPacket* packet23 = enet_packet_create(ps2.data,
									ps2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet23);
								delete ps2.data;
								sendConsoleMsg(peer, "`6" + str);
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `2" + ((PlayerInfo*)(peer->data))->lastMsger + "`6)"));
								ENetPacket* packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet0);
								delete p0.data;
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `2" + ((PlayerInfo*)(peer->data))->displayName + "`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + str.substr(3, cch.length() - 3 - 1) + "`o"));
								string text = "action|play_sfx\nfile|audio/pay_time.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);
								delete data;
								ENetPacket* packet = enet_packet_create(ps.data,
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
							GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Unable to track down the location of the message."));
							ENetPacket* packet = enet_packet_create(po.data,
								po.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
						}
						else if (act == ((PlayerInfo*)(peer->data))->currentWorld) {
							GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Sorry, but you are already in the world!"));
							ENetPacket* packet = enet_packet_create(po.data,
								po.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
						}
						else {
							sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
							joinWorld(peer, act, 0, 0);
						}
						}

						else if (str.substr(0, 8) == "/report ")
						{
						string imie = str.substr(8, cch.length() - 8 - 1);
						string dupa;
						string worldlocate;
						ENetPeer* currentPeer;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `w" + imie + "`o has been reported."));
						ENetPacket* packet = enet_packet_create(p.data,
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
							if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
							{
								dupa = ((PlayerInfo*)(currentPeer->data))->rawName;
								worldlocate = " (In world: " + ((PlayerInfo*)(peer->data))->currentWorld + ")";


								
							}

							if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 666) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "[MOD LOGS]: Suspect `w" + dupa + "`o has been reported by " + ((PlayerInfo*)(peer->data))->rawName + worldlocate));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
								delete p.data;
							}
						}
						cout << "Report from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << std::dec << " reported -> " << dupa << endl;

						

						}


						else if (str.substr(0, 8) == "/warpto ") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								string name = str.substr(8, str.length());


								ENetPeer* currentPeer;


								bool found = false;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;


									string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


									std::transform(name.begin(), name.end(), name.begin(), ::tolower);
									std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


									if (name == name2) {
										if (((PlayerInfo*)(currentPeer->data))->currentWorld == "EXIT" || ((PlayerInfo*)(currentPeer->data))->passedCaptcha == false)
										{
											//std::this_thread::sleep_for(std::chrono::milliseconds(200));
										}
										else
										{
											sendPlayerToPlayer(peer, currentPeer);
											found = true;
										}

									}
								}
								if (found) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Magically warped to player " + name + "."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Player not found or is currently in EXIT."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
							}


						}
						else if (str.substr(0, 6) == "/warp ") {

							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 166) {
								string world = str.substr(6, str.length());
								std::transform(world.begin(), world.end(), world.begin(), ::toupper);


								if (world == "EXIT")
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`8I know the World Menu is cool etc., but you just cannot warp to it because it will crash the server."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
								}
								else
								{
									bool contains_non_alpha
										= !std::regex_match(world, std::regex("^[A-Za-z0-9]+$"));

									if (contains_non_alpha == true)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Warping failed. Only letters / numbers!"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
									}
									else
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Magically warped to " + world + "."));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										sendPlayerToWorld(peer, (PlayerInfo*)(peer->data), world);


									}



								}


							}

						}
						else if (str == "/banworld")
						{

						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
						((PlayerInfo*)(peer->data))->canExit = false;


						

						ENetPeer * currentPeerp;

						for (currentPeerp = server->peers;
							currentPeerp < &server->peers[server->peerCount];
							++currentPeerp)
						{
							if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (getAdminLevel(((PlayerInfo*)(currentPeerp->data))->rawName, ((PlayerInfo*)(currentPeerp->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(currentPeerp->data))->rawName, ((PlayerInfo*)(currentPeerp->data))->tankIDPass) == 666) {

							}
							else
							{
								


								if (isHere(peer, currentPeerp))
								{

									string name = ((PlayerInfo*)(peer->data))->displayName;
									string kickname = ((PlayerInfo*)(currentPeerp->data))->displayName;
									//string kickname = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), name + " `4world bans " + "`o" + kickname));
									string text = "action|play_sfx\nfile|audio/repair.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);


									ENetPacket * packetsou = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);



									enet_peer_send(peer, 0, packetsou);
									enet_peer_send(peer, 0, packet);
									delete data;
									delete p.data;


									sendPlayerWBan(currentPeerp, ((PlayerInfo*)(peer->data))->displayName, ((PlayerInfo*)(currentPeerp->data))->displayName);


									namespace fs = std::experimental::filesystem;

									if (!fs::is_directory("worldbans/" + getPlyersWorld(peer)->name) || !fs::exists("worldbans/" + getPlyersWorld(peer)->name)) {
										fs::create_directory("worldbans/" + getPlyersWorld(peer)->name);

										std::ofstream outfile("worldbans/" + getPlyersWorld(peer)->name + "/" + ((PlayerInfo*)(currentPeerp->data))->rawName);

										outfile << "worldbanned by: " + ((PlayerInfo*)(peer->data))->rawName;

										outfile.close();
									}
									else
									{
										std::ofstream outfile("worldbans/" + getPlyersWorld(peer)->name + "/" + ((PlayerInfo*)(currentPeerp->data))->rawName);

										outfile << "worldbanned by: " + ((PlayerInfo*)(peer->data))->rawName;

										outfile.close();
									}

									sendPlayerLeave(currentPeerp, (PlayerInfo*)(currentPeerp->data));
									sendWorldOffers(currentPeerp);


									((PlayerInfo*)(currentPeerp->data))->currentWorld = "EXIT";


								}
							}
						}
						((PlayerInfo*)(peer->data))->canExit = true;

						}
						}
						else if (str == "/nuke") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								((PlayerInfo*)(peer->data))->canExit = false;

								WorldInfo *world = getPlyersWorld(peer);
								if (world->nuked) {
									world->nuked = false;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You have un-nuked the world"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
								}
								else {
									world->nuked = true;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You have nuked the world!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);


									ENetPeer* currentPeer;


									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;


										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4" + world->name + " has been nuked from orbit. `w>> It's the only way to be sure. Play safe, everybody!"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);

										string text = "action|play_sfx\nfile|audio/bigboom.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);

										
											ENetPacket * packetnuk = enet_packet_create(data,
												5 + text.length(),
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packetnuk);

										
											if (isHere(peer, currentPeer)) {
												if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) < 666) {

													//((PlayerInfo*)(currentPeer->data))->currentWorld = "EXIT";
													sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
													sendWorldOffers(currentPeer);


													((PlayerInfo*)(currentPeer->data))->currentWorld = "EXIT";
												}
												
											}
										}
										((PlayerInfo*)(peer->data))->canExit = true;
									}
								}
							




						}
						else if (str == "/ban")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oUsage: /ban <user>"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
						}
						else if (str == "/curse")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oUsage: /curse <user>"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
						}
						else if (str == "/ducttape")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 332) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oUsage: /ducttape <user>"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
						}
						else if (str == "/tban")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oUsage: /tban <user> <minutes>"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
						}
						else if (str.substr(0, 6) == "/tban ") {
						string ban_info = str;

						size_t extra_space = ban_info.find("  ");
						if (extra_space != std::string::npos) {
							ban_info.replace(extra_space, 2, " ");
						}

						string delimiter = " ";
						size_t pos = 0;
						string ban_user;
						string ban_time;
						if ((pos = ban_info.find(delimiter)) != std::string::npos) {
							ban_info.erase(0, pos + delimiter.length());
						}
						else {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oUsage: /tban <user> <minutes>"));
							ENetPacket * packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
						}

						if ((pos = ban_info.find(delimiter)) != std::string::npos) {
							ban_user = ban_info.substr(0, pos);
							ban_info.erase(0, pos + delimiter.length());
						}
						else {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oUsage: /tban <user> <minutes>"));
							ENetPacket * packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
						}

						ban_time = ban_info;
						cout << "/tban " << ban_user << " " << ban_time;
						}
						else if (str.substr(0, 7) == "/block ")
						{
							string blox = str.substr(6, str.length());


							bool contains_non_alpha
								= !std::regex_match(blox, std::regex("^[0-9]+$"));

							if (contains_non_alpha)
							{
								int bloxint = atoi(str.substr(7).c_str());
								if (bloxint < 7559)
								{
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
								else
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Please only numbers from 0-7558!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Please only numbers!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}

						
						else if (str.substr(0, 5) == "/eff ") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {

								int effect = atoi(str.substr(5).c_str());
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
						}
						else if (str.substr(0, 9) == "/leaveall") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {





							}
						}
						else if (str.substr(0, 6) == "/warn ") {

						}

						else if (str.substr(0, 5) == "/ban ") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								if (str.substr(5, cch.length() - 5 - 1) == "") continue;
								if (((PlayerInfo*)(peer->data))->rawName == str.substr(5, cch.length() - 5 - 1)) continue;
								if ((str.substr(5, cch.length() - 5 - 1) == "timesimple") || (str.substr(5, cch.length() - 5 - 1) == "j3xxx")) continue;

								cout << "Server operator " << ((PlayerInfo*)(peer->data))->rawName << " has banned " << str.substr(5, cch.length() - 5 - 1) << "." << endl;

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

									if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(str.substr(5, cch.length() - 5 - 1))) {
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
										//j["receivedwarns"] = ((PlayerInfo*)(peer->data))->warns;
										((PlayerInfo*)(currentPeer->data))->bans = ((PlayerInfo*)(peer->data))->bans + 1;
										if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

											PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));
											p->ban = 1;
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
											int clothances = p->cloth_ances;
											//int isCursed = p->isCursed;
											//int puncheffect = p->puncheffect;
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
											j["ClothAnces"] = clothances;
											j["ipID"] = currentPeer->address.host;
											j["effect"] = 0;
											
											j["isBanned"] = 1;

											//j["puncheffect"] = puncheffect;


											j["adminLevel"] = 0;
											j["password"] = hashPassword(password);
											j["username"] = username;
											j["friends"] = ((PlayerInfo*)(currentPeer->data))->friendinfo;
											j["ip"] = ((PlayerInfo*)(currentPeer->data))->charIP;
											j["boughtLGW"] = ((PlayerInfo*)(peer->data))->boughtLGW;
											j["boughtLGK"] = ((PlayerInfo*)(peer->data))->boughtLGK;
											j["boughtLGD"] = ((PlayerInfo*)(peer->data))->boughtLGD;
											j["boughtLGB"] = ((PlayerInfo*)(peer->data))->boughtLGB;
											j["boughtLKW"] = ((PlayerInfo*)(peer->data))->boughtLKW;
											j["boughtCWD"] = ((PlayerInfo*)(peer->data))->boughtCWD;
											j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS;
											j["boughtCDG"] = ((PlayerInfo*)(peer->data))->boughtCDG;
											j["aap"] = ((PlayerInfo*)(currentPeer->data))->isAAP;
											j["receivedwarns"] = ((PlayerInfo*)(currentPeer->data))->warns;
											j["receivedbans"] = ((PlayerInfo*)(currentPeer->data))->bans;


											o << j << std::endl;

											string bannamed = str.substr(5, cch.length() - 5 - 1);
											std::ofstream outfile("bans/" + bannamed + ".txt");

											outfile << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

											outfile.close();
										}
										delete ps.data;

										enet_peer_disconnect_later(currentPeer, 0);


									}

									enet_peer_send(currentPeer, 0, packet);

									//enet_host_flush(server);
								}
								string bannamed = str.substr(5, cch.length() - 5 - 1);
								std::ifstream ifff("players/" + PlayerDB::getProperName(bannamed) + ".json");
								

								if (ifff.fail()) {
									ifff.close();

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Player not found, `4ban `waborted!"));

									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
									continue;
								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load


								j["isBanned"] = 1; //edit

								GamePacket px = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w`4Banned `wplayer " + PlayerDB::getProperName(str.substr(5, cch.length() - 5 - 1))));

								ENetPacket * packetx = enet_packet_create(px.data,
									px.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packetx);
								delete px.data;


								std::ofstream o("players/" + PlayerDB::getProperName(bannamed) + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;
						
								delete p.data;
							}
						}
						else if (str.substr(0, 10) == "/ducttape ") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333) {
								string name = str.substr(10, str.length());


								ENetPeer* currentPeer;


								bool found = false;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;


									if (((PlayerInfo*)(currentPeer->data))->rawName == name) {
										found = true;
										if (((PlayerInfo*)(currentPeer->data))->taped) {
											((PlayerInfo*)(currentPeer->data))->taped = false;
											((PlayerInfo*)(currentPeer->data))->isDuctaped = false;
											((PlayerInfo*)(currentPeer->data))->cantsay = false;
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You are no longer duct-taped!"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet);
											sendClothes(currentPeer);
											sendState(currentPeer);
											
											delete p.data;
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You have un duct-taped the player!"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
											}
										}
										else {
											((PlayerInfo*)(currentPeer->data))->taped = true;
											((PlayerInfo*)(currentPeer->data))->isDuctaped = true;
											((PlayerInfo*)(currentPeer->data))->cantsay = true;
											sendState(currentPeer);

											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You have been duct-taped!"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet);
											sendClothes(currentPeer);
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You have duct-taped the player!"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
											}
										}
									}
								}
								if (!found) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Player not found!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
								}
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You need to have a higher admin-level to do that!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
						}
						else if (str.substr(0, 7) == "/curse ") { // code by playingohd gaming
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								if (str.substr(7, cch.length() - 7 - 1) == "") continue;
								if (((PlayerInfo*)(peer->data))->rawName == str.substr(7, cch.length() - 7 - 1)) continue;
								if ((str.substr(7, cch.length() - 7 - 1) == "timesimple") || (str.substr(7, cch.length() - 7 - 1) == "j3xxx")) continue;
								string cursename = PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1));

								cout << "Server operator " << ((PlayerInfo*)(peer->data))->rawName << " has cursed " << str.substr(7, cch.length() - 7 - 1) << "." << endl;

								ENetPeer * currentPeer;

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancient Ones `ohave `bcursed `2" + str.substr(7, cch.length() - 7 - 1) + " `#** `o(`4/rules `oto see the rules!)"));
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);

									if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1))) {
										if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false && ((PlayerInfo*)(currentPeer->data))->haveGuestId == false) continue;
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancient Ones `ohave used `#Curse `oon `2" + str.substr(7, cch.length() - 7 - 1) + "`o! `#**"));
										ENetPacket * packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);

										GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/hommel.rttex"), "`0Warning from `4System`0: You've been `bCURSED `0from Private Server."), "audio/explode.wav"), 0));
										ENetPacket * packet2 = enet_packet_create(ps2.data,
											ps2.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet2);
										GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWarning from `4System`o: You've been `bCursed `ofrom Private Server."));
										ENetPacket * packet3 = enet_packet_create(ps3.data,
											ps3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet3);
										if (((PlayerInfo*)(currentPeer->data))->haveGrowId || ((PlayerInfo*)(currentPeer->data))->haveGuestId) {

											PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));

											string username = PlayerDB::getProperName(p->rawName);

											((PlayerInfo*)(currentPeer->data))->isCursed = true;

											std::ofstream outfile("cursedplayers/" + cursename + ".txt");

											outfile << "caused by: " + ((PlayerInfo*)(peer->data))->rawName;

											outfile.close();



										}
										delete ps.data;
										sendPlayerToWorld(currentPeer, (PlayerInfo*)(currentPeer->data), "HELL");


										//((PlayerInfo*)(currentPeer->data))->isCursed = true;
										

										//enet_peer_disconnect_later(currentPeer, 0);
									}
								}
							}
						}
						else if (str == "/unequip")
						{
							((PlayerInfo*)(peer->data))->cloth_hair = 0;
							((PlayerInfo*)(peer->data))->cloth_shirt = 0;
							((PlayerInfo*)(peer->data))->cloth_pants = 0;
							((PlayerInfo*)(peer->data))->cloth_feet = 0;
							((PlayerInfo*)(peer->data))->cloth_face = 0;
							((PlayerInfo*)(peer->data))->cloth_hand = 0;
							((PlayerInfo*)(peer->data))->cloth_back = 0;
							((PlayerInfo*)(peer->data))->cloth_mask = 0;
							((PlayerInfo*)(peer->data))->cloth_necklace = 0;
							sendClothes(peer);
						}
						else if (str.substr(0, 9) == "/uncurse ") { // code by playingohd gaming
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								if (str.substr(9, cch.length() - 9 - 1) == "") continue;
								if (((PlayerInfo*)(peer->data))->rawName == str.substr(7, cch.length() - 9 - 1)) continue;
								if ((str.substr(9, cch.length() - 9 - 1) == "timesimple") || (str.substr(9, cch.length() - 9 - 1) == "j3xxx")) continue;
								string cursename = str.substr(9, cch.length() - 9 - 1);
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4System-Message:`2 " + cursename + " has been uncursed."));
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									remove(("cursedplayers/" + cursename + ".txt").c_str());
									if (((PlayerInfo*)(currentPeer->data))->rawName == cursename)
									{
										((PlayerInfo*)(currentPeer->data))->skinColor = 0x8295C3FF;
										sendClothes(currentPeer);
										((PlayerInfo*)(currentPeer->data))->isCursed = false;
										sendState(currentPeer);

										
									}
								}
							}
						}
						else if (str.substr(0, 7) == "/unban ") {
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) && getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) != 666 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) != 999)break;
							std::ifstream ifff("players/" + PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1)) + ".json");
							string ubaname = PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1));

							if (ifff.fail()) {
								ifff.close();

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Player not found, unban aborted!"));

								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								continue;
							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["isBanned"] = 0; //edit

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wBan of player " + PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1)) + " set to 0."));

							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							

							std::ofstream o("players/" + PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1)) + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;
						}

						else if (str == "/saveall")
						{
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

							saveAllWorlds();

						}
						else if (str.substr(0, 7) == "/spawn ")
						{

							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
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
						}
						else if (str == "/pullall")
						{

						}
						else if (str.substr(0, 3) == "/p ") {

						((PlayerInfo*)(peer->data))->peffect = atoi(str.substr(3).c_str());
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
								int var = atoi(str.substr(3).c_str()); // placing and breking
								memcpy(raw + 1, &var, 3);
								SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);

							}
						}
						}
						else if (str == "/effect") {
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333)
						{
							//cout << "current effect: " + ((PlayerInfo*)(peer->data))->effect;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wPunch Effects :|left|18|\n\nadd_spacer|small|\nadd_button_with_icon|effect0|`wPunch|noflags|18|\nadd_button_with_icon|effect1|`wDeath Ray|noflags|930|\nadd_button_with_icon|effect2|`wSawed-Off Shotgun|noflags|768|\nadd_button_with_icon|effect3|`wTommy Gun|noflags|472|\nadd_button_with_icon|effect4|`wSilver Bow|noflags|5456|\nadd_button_with_icon|effect5|`wRock Hammer|noflags|3932|\nadd_button_with_icon|effect6|`wDragon Hand|noflags|900|\nadd_button_with_icon|effect7|`wPineapple Effect|noflags|2734|\nadd_button_with_icon|effect8|`wSkull Explode|noflags|1976|\nadd_button_with_icon|effect9|`wIce Dragon Hand|noflags|1378|\nadd_button_with_icon|effect10|`wFocused Eyes/Zeus|noflags|1204|\nadd_button_with_icon|effect11|`wFocused Eyes|noflags|1956|\nadd_button_with_icon|effect12|`wChaos Cursed Wand|noflags|1956|\nadd_button_with_icon|effect13|`wFlaming Scythe|noflags|1484|\nadd_button_with_icon|effect14|`wPet Leprechaun|noflags|1512|\nadd_button_with_icon|effect15|`wBattle Trout|noflags|1542|\nadd_button_with_icon|effect16|`wFiesta Dragon|noflags|1576|\nadd_button_with_icon|effect17|`wSquirt Gun|noflags|1676|\nadd_button_with_icon|effect18|`wKeytar|noflags|1710|\nadd_button_with_icon|effect19|`wUNKNOWN|noflags|1|\nadd_button_with_icon|effect20|`wLegendbot-009|noflags|1780|\nadd_button_with_icon|effect21|`wDragon of Legend|noflags|1782|\nadd_button_with_icon|effect22|`wDope Effect|noflags|1|\nadd_button_with_icon|effect23|`wGreen Dragon Mask|noflags|1228|\nadd_button_with_icon|effect24|`wThe Gungnir|noflags|2756|\nadd_button_with_icon|effect25|`wBlue Soul|noflags|1|\nadd_button_with_icon|effect26|`wBlack Shadows|noflags|1|\nadd_button_with_icon|effect27|`wBlack Crystal Dragon|noflags|2212|\nadd_button_with_icon|effect28|`wLegendary Katana|noflags|2592|\nadd_button_with_icon|effect29|`wBlack Holes Shooter|noflags|1|\nadd_button_with_icon|effect30|`wPineapple Launcher|noflags|2752|\nadd_button_with_icon|effect31|`wDigger's Spade|noflags|2952|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
						}
						else if (str.substr(0, 5) == "/msg ") {
						bool found = false;
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
								if (((PlayerInfo*)(currentPeer->data))->msgName == PlayerDB::getProperName(pm_user)) {

									((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
									((PlayerInfo*)(currentPeer->data))->lastMsgerTrue = ((PlayerInfo*)(currentPeer->data))->displayName;
									((PlayerInfo*)(currentPeer->data))->lastMsgWorld = ((PlayerInfo*)(peer->data))->currentWorld;

									//sendConsoleMsg(peer, "`6" + str);
									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `w" + ((PlayerInfo*)(currentPeer->data))->displayName + "`6)"));
									ENetPacket * packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									found = true;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `w" + ((PlayerInfo*)(peer->data))->displayName + "`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + pm_message + "`o"));
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
							if (found == false)
							{
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6Player " + PlayerDB::getProperName(pm_user) + " not found, remember to type all letters small."));
								ENetPacket * packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet0);
								delete p0.data;
							}
						}
						else if (str == "/trade")
						{
						GamePacket p2t = packetEnd(appendInt(appendInt(appendString(createPacket(), "OnStartTrade"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->netID));

						//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2t = enet_packet_create(p2t.data,
							p2t.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2t);
						delete p2t.data;

						GamePacket p3 = packetEnd(appendInt(appendString(createPacket(), "OnTradeStatus"), 1));

						//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet3);
						delete p3.data;
						}
						else if (str == "/tradeworld")
						{
						if (getPlyersWorld(peer)->owner == ((PlayerInfo*)(peer->data))->rawName)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oCannot buy your own world!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (getPlyersWorld(peer)->isPublic)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oCannot buy world because it's public!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							ENetPeer * currentPeerpx;

							for (currentPeerpx = server->peers;
								currentPeerpx < &server->peers[server->peerCount];
								++currentPeerpx)
							{
								if (currentPeerpx->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(peer->data))->lastSellWorld == getPlyersWorld(peer)->name)
								{
									if (((PlayerInfo*)(peer->data))->lastSeller == getPlyersWorld(peer)->owner)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wTrade Menu``|left|242|\nadd_label|small|\nadd_button_with_icon|dotrade|Do the Trade!|noflags|1424||\nadd_button|decline|`4Cancel/Decline|noflags||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										//enet_host_flush(server);
										delete p.data;
									}
									else
									{
										cout << "last player sell / buy not true";
									}
								}
								else
								{
									cout << "last sell world not true";
								}
							}
						}
						}
						else if (str == "/boot")
						{
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Attempted everyone to disconnect who was in this world!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								ENetPeer* currentPeer;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 666) {

									}
									else
									{
										enet_peer_disconnect_later(currentPeer, 0);
									}
								}
							}
						}
						}
						else if (str == "/battleroyale")
						{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBetaMode"), 1));
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
						}
						else if (str == "/uba") {
						if (((PlayerInfo*)(peer->data))->haveGrowId && ((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
						{
							namespace fs = std::experimental::filesystem;
							fs::remove_all("worldbans/" + getPlyersWorld(peer)->name);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYou unbanned everyone from the world!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}						
						}
						else if (str == "/forceexit") {

						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						sendWorldOffers(peer);


						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";


						}
						else if (str == "/bluename") {
						
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0)
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
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(peer->data))->country + "|showGuild|maxLevel"));
								memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);
								delete p2.data;
							}
							}
						}
						}
						else if (str == "/hide") {

						GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnDisguiseChanged"), 8));

						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;


						}
						
						else if (str.substr(0, 6) == "/mode ") // 9921116 blue fire mode // -529858286286 98156
						{
							string modestr = str.substr(6, cch.length() - 6 - 1);


							((PlayerInfo*)(peer->data))->characterState = atoi(modestr.c_str());
							sendState(peer);
						}
						else if (str == "/testbuystore") {

						/*GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|Welcome to the `2Growtopia Store``!|\nadd_button|lol|Buy!|0|4|0|0||\n"));
						ENetPacket * packets = enet_packet_create(ps.data,
							ps.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packets);
						delete ps.data;*/


						/*GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnStoreBuyConfirm"), 1));

						//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;*/

						GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnStorePurchaseResult"), "`9Bought `6Legendary Katana`w."));

						//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet3);
						delete p3.data;
						}
						else if (str == "/accesslist") {
						
						}
						else if (str.substr(0, 5) == "/vsb ") {
						if (((PlayerInfo*)(peer->data))->isDuctaped == true)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7Not allowed to VSB while ducttaped!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);


							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{



							using namespace std::chrono;
							if (((PlayerInfo*)(peer->data))->lastSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
							{
								((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Cooldown >> Wait 15 seconds to throw another Super-Broadcast!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);


								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
								continue;
							}


							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`` `# " + str.substr(5, cch.length() - 5 - 1)));
							string text = "action|play_sfx\nfile|audio/double_chance.wav\ndelayMS|0\n";
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


								GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`w** `5VIP-SB`` from `$`2" + name + "``) ** :`` `# " + str.substr(5, cch.length() - 5 - 1)));
								//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
								ENetPacket * packetto = enet_packet_create(pto.data,
									pto.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packetto);
								delete pto.data;

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
						else if (str == "/help") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Help >> /help, /dance, /furious, /love, /cry, /mad, /sleep, /yes, /no, /troll, /cheer, /fp, /omg, /fa, /rolleyes, /dab, /idk, /shrug, /love, /mods, /pull, /rgo, /r, /rules, /news, /report <name>, /mod, /unmod, /inventory, /item id, /team id, /color number, /who, /count, /sb message, /alt, /radio, /find, /pay (user) (amount), /cleaninv, /unequip, /msg, /block, /uba, /effect, /jsb, /nick, /ban, /deviceban <name>, /remove <name>, /eff (id), /ducttape, /nuke, /summon (name), /warp (world), /warpto (player), /online, /info (name), /offlineinfo (name), /ghost, /invis, /curse (name), /uncurse (name), /unban (name), /spawn (id), /asb, /ssclearworld (faster but reloads world), /superclearworld, /magic, /boot, /ipcheck <name>, /nicked, /server, /banworld, /breakroulette, /vsb"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Help >> /help, /dance, /furious, /love, /cry, /mad, /sleep, /yes, /no, /troll, /cheer, /fp, /omg, /fa, /rolleyes, /dab, /idk, /shrug, /love, /mods, /pull, /rgo, /r, /rules, /news, /report <name>, /mod, /unmod, /inventory, /item id, /team id, /color number, /who, /count, /sb message, /alt, /radio, /find, /pay (user) (amount), /cleaninv, /unequip, /msg, /block, /uba, /jsb, /ghost, /nick (need atleast 5 characters), /warp, /spawn (id), /eff (id), /ducttape, /magic, /server, /breakroulette, /vsb"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Help >> /help, /dance, /furious, /love, /cry, /mad, /sleep, /yes, /no, /troll, /cheer, /fp, /omg, /fa, /rolleyes, /dab, /idk, /shrug, /love, /mods, /pull, /rgo, /r, /rules, /news, /report <name>, /mod, /unmod, /inventory, /item id, /team id, /color number, /who, /count, /sb message, /alt, /radio, /find, /pay (user) (amount), /cleaninv, /unequip, /msg, /block, /effect, /uba, /jsb, /nick, /ban, /deviceban (ipID), /remove (ipID), /eff (id), /ducttape, /nuke, /summon (name), /warp (world), /warpto (player), /online, /offlineinfo (name), /ghost, /invis, /curse (name), /uncurse (name), /unban (name), /spawn (id), /asb, /magic, /boot, /ipcheck <name>, /nicked, /server, /banworld, /breakroulette, /vsb"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Help >> /help, /dance, /furious, /love, /cry, /mad, /sleep, /yes, /no, /troll, /cheer, /fp, /omg, /fa, /rolleyes, /dab, /idk, /shrug, /love, /mods, /pull, /rgo, /r, /rules, /news, /report <name>, /mod, /unmod, /inventory, /item id, /team id, /color number, /who, /count, /sb message, /alt, /radio, /find, /pay (user) (amount), /cleaninv, /unequip, /msg, /block, /uba, /server, /breakroulette"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}

						}
						else if (str == "/breakroulette") {
						if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333 || getPlyersWorld(peer)->owner == ((PlayerInfo*)(peer->data))->rawName) {
								if (((PlayerInfo*)(peer->data))->unwheel == false)
								{
									((PlayerInfo*)(peer->data))->unwheel = true;

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wYou can now break roulette wheels, to disable just do /breakroulette again."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								else
								{
									((PlayerInfo*)(peer->data))->unwheel = false;

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wDisabled roulette-breaking. To enable, type /roulettewheel."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
							else
							{
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYou are not the world-owner!"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}
						}
						}
						else if (str == "/magic")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {

								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYou cast a magic spell!"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete ps.data;

								string text = "action|play_sfx\nfile|audio/magic.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket * packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								ENetPeer* currentPeer;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										enet_peer_send(currentPeer, 0, packetsou);
									}

								}


							}
						}
						else if (str.substr(0, 5) == "/pay ") //todo
						{
							if (((PlayerInfo*)(peer->data))->haveGrowId)
							{
								
							}									

							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7Cannot use pay command, create a GrowID first! It's free."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}

						else if (str.substr(0, 13) == "/offlineinfo ") { //this is coded by playingohd gaming special code for nabzgt.

							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 333)
							{
								string playerCalled = PlayerDB::getProperName(str.substr(13, cch.length() - 13 - 1));
								string wrldname = PlayerDB::getProperName(str.substr(6, cch.length() - 6 - 1));
								

								if (playerCalled == "playingo" || playerCalled == "random" || playerCalled == "raiterjaki" || playerCalled == "esc") {

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wCannot view player-info of cool guys!``"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);


									continue;
									break;
								}
								toUpperCase(wrldname);
								if (wrldname == "CON" || wrldname == "NUL" || wrldname == "PRN" || wrldname == "AUX" || wrldname == "CLOCK$" || wrldname == "COM0" || wrldname == "COM1" || wrldname == "COM2" || wrldname == "COM3" || wrldname == "COM4" || wrldname == "COM5" || wrldname == "COM6" || wrldname == "COM7" || wrldname == "COM8" || wrldname == "COM9" || wrldname == "LPT0" || wrldname == "LPT1" || wrldname == "LPT2" || wrldname == "LPT3" || wrldname == "LPT4" || wrldname == "LPT5" || wrldname == "LPT6" || wrldname == "LPT7" || wrldname == "LPT8" || wrldname == "LPT9")
								{
									continue;
									break;
								}

								std::ifstream ifs("players/" + playerCalled + ".json");
								std::string content((std::istreambuf_iterator<char>(ifs)),
									(std::istreambuf_iterator<char>()));


								std::ifstream ifs7("gemdb/" + playerCalled + ".txt");
								std::string contentp((std::istreambuf_iterator<char>(ifs7)),
									(std::istreambuf_iterator<char>()));
								ifs7.close();



								string x;
								x.append(content);

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "``Player infos (offline mode): " + x + "Gems: " + contentp));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								x = x.substr(0, x.length() - 2);

							}
						}
						else if (str.substr(0, 6) == "/info ") { //this is coded by playingohd gaming special code for nabzgt.
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
							{
								string wrldname = PlayerDB::getProperName(str.substr(6, cch.length() - 6 - 1));
								toUpperCase(wrldname);
								if (wrldname == "CON" || wrldname == "NUL" || wrldname == "PRN" || wrldname == "AUX" || wrldname == "CLOCK$" || wrldname == "COM0" || wrldname == "COM1" || wrldname == "COM2" || wrldname == "COM3" || wrldname == "COM4" || wrldname == "COM5" || wrldname == "COM6" || wrldname == "COM7" || wrldname == "COM8" || wrldname == "COM9" || wrldname == "LPT0" || wrldname == "LPT1" || wrldname == "LPT2" || wrldname == "LPT3" || wrldname == "LPT4" || wrldname == "LPT5" || wrldname == "LPT6" || wrldname == "LPT7" || wrldname == "LPT8" || wrldname == "LPT9")
								{

								}
								else
								{
								string playerCalled = PlayerDB::getProperName(str.substr(6, cch.length() - 6 - 1));

								std::ifstream ifs("players/" + playerCalled + ".json");
								std::string content((std::istreambuf_iterator<char>(ifs)),
									(std::istreambuf_iterator<char>()));


								std::ifstream ifs7("gemdb/" + playerCalled + ".txt");
								std::string contentp((std::istreambuf_iterator<char>(ifs7)),
									(std::istreambuf_iterator<char>()));
								ifs7.close();



								string x;
								x.append(content);

								ENetPeer * currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(currentPeer->data))->rawName == playerCalled)
									{

										string showcountry = ((PlayerInfo*)(currentPeer->data))->country;
										string showgameversion = ((PlayerInfo*)(currentPeer->data))->gameversion;
										string showrid = ((PlayerInfo*)(currentPeer->data))->rid;
										string showwk = ((PlayerInfo*)(currentPeer->data))->wkid;
										string showmeta = ((PlayerInfo*)(currentPeer->data))->metaip;
										string showmac = ((PlayerInfo*)(currentPeer->data))->mac;
										string showhash2 = ((PlayerInfo*)(currentPeer->data))->hash2;
										string showplatid = ((PlayerInfo*)(currentPeer->data))->platformID;
										string showage = ((PlayerInfo*)(currentPeer->data))->player_age;
										string showaid = ((PlayerInfo*)(currentPeer->data))->aid;
										string showgid = ((PlayerInfo*)(currentPeer->data))->gid;
										string showvid = ((PlayerInfo*)(currentPeer->data))->vid;
										string showworld = ((PlayerInfo*)(currentPeer->data))->currentWorld;
										string showplainip = ((PlayerInfo*)(currentPeer->data))->charIP;
										string showdeviceversion = ((PlayerInfo*)(currentPeer->data))->deviceversion;
										string showlmode = ((PlayerInfo*)(currentPeer->data))->lmode;
										string showgdpr = ((PlayerInfo*)(currentPeer->data))->gdpr;
										string showuser = ((PlayerInfo*)(currentPeer->data))->user;
										string showtoken = ((PlayerInfo*)(currentPeer->data))->token;
										string showf = ((PlayerInfo*)(currentPeer->data))->f;
										string showfz = ((PlayerInfo*)(currentPeer->data))->fz;
										string showfhash = ((PlayerInfo*)(currentPeer->data))->fhash;
										//string showhid = ((PlayerInfo*)(currentPeer->data))->hpid;
										string showplatidplain;


										if (showplatid == "4")
										{
											showplatidplain = " mobile (android) ";
										}
										else if (showplatid == "0")
										{
											showplatidplain = " PC (Windows) ";
										}
										else if (showplatid == "6")
										{
											showplatidplain = " Mac (OS X) ";
										}
										else
										{
											showplatidplain = " UNIX (Linux, iOS (most likely), FreeBSD etc.) ";
										}
										if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 999 && ((PlayerInfo*)(peer->data))->rawName != "playingo")
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "``Cannot use /info on Developers or Admins or Server creators. Instead you are still able to use /offlineinfo on them."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
										}
										else
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "``Player infos: " + x + "Gems: " + contentp + " " + "Current world: " + showworld + " country: " + showcountry + " gameversion: " + showgameversion + " rid: " + showrid + " aid: " + showaid + " gid: " + showgid + " vid: " + showvid + " wk identity (SID): " + showwk + " meta: " + showmeta + " mac: " + showmac + " hash2: " + showhash2 + " platform:" + showplatidplain + "device-version: " + showdeviceversion + " L-mode: " + showlmode + " GDPR: " + showgdpr + " User:" + showuser + " Token: " + showtoken + " F-Identity: " + showf + " FZ-Identity: " + showfz + +" fhash: " + showfhash + " age: " + showage));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
										}

										x = x.substr(0, x.length() - 2);


									}
								}

								}
							}
						}
						else if (str.substr(0, 9) == "/ipcheck ") {
							
							
							string playerCalled = str.substr(9, cch.length() - 9 - 1);
							cout << "/ipcheck from " + ((PlayerInfo*)(peer->data))->rawName + " on: " + playerCalled << endl;
							std::thread second((Fctor()), peer, playerCalled);
							second.detach();
						}
						else if (str.substr(0, 9) == "/hardban ") { //This is a special code by PlayIngoHD Gaming extra for NabzGT!
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
						{
							ENetPeer * currentPeer;
							string playerCalled = str.substr(9, cch.length() - 9 - 1);
							bool existh = std::experimental::filesystem::exists("players/" + PlayerDB::getProperName(playerCalled) + ".json");

							if (existh)
							{

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(currentPeer->data))->rawName == playerCalled)
									{
										//((PlayerInfo*)(currentPeer->data))->rid

										std::ofstream outfile("ridbans/" + ((PlayerInfo*)(currentPeer->data))->rid + ".txt");

										outfile << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

										outfile.close();

										string checkaid = ((PlayerInfo*)(currentPeer->data))->aid;
										if (checkaid.length() > 4)
										{
											std::ofstream outfile2("aidbans/" + ((PlayerInfo*)(currentPeer->data))->aid + ".txt");

											outfile2 << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

											outfile2.close();
										}

										string checkgid = ((PlayerInfo*)(currentPeer->data))->gid;
										if (checkgid.length() > 4)
										{
											std::ofstream outfile3("gidbans/" + ((PlayerInfo*)(currentPeer->data))->gid + ".txt");

											outfile3 << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

											outfile3.close();
										}

										string checkvid = ((PlayerInfo*)(currentPeer->data))->vid;
										if (checkvid.length() > 4)
										{
											std::ofstream outfile4("vidbans/" + ((PlayerInfo*)(currentPeer->data))->vid + ".txt");

											outfile4 << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

											outfile4.close();
										}

										string checksid = ((PlayerInfo*)(currentPeer->data))->wkid;
										if (checksid.length() > 8)
										{
											std::ofstream outfile5("sidbans/" + ((PlayerInfo*)(currentPeer->data))->wkid + ".txt");

											outfile5 << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

											outfile5.close();
										}

										if (((PlayerInfo*)(currentPeer->data))->mac != "02:00:00:00:00:00" && ((PlayerInfo*)(currentPeer->data))->mac != "00:00:00:00:00:00")
										{
											std::string mac(((PlayerInfo*)(currentPeer->data))->mac);
											Remove(mac, ":");

											std::ofstream outfile6("macbans/" + mac + ".txt"); // c = filteredmac

											outfile6 << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

											outfile6.close();
										}
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5HARD `4BANNED `w" + ((PlayerInfo*)(currentPeer->data))->rawName + " !! (hardbans cannot be removed from the game, only from server itself)"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										delete p.data;

									}
								}
							}
						}

						}
						else if (str.substr(0, 11) == "/deviceban ") { //This is a special code by PlayIngoHD Gaming extra for NabzGT!
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
							{
								string playerCalled = str.substr(11, cch.length() - 11 - 1);
								bool exist = std::experimental::filesystem::exists("players/" + PlayerDB::getProperName(playerCalled) + ".json");
								
								if (exist)
								{


									std::ifstream ifs("players/" + PlayerDB::getProperName(playerCalled) + ".json");
									if (ifs.is_open()) {
										json j;
										ifs >> j;

										int ipID = j["ipID"];
										string ipIDstr = to_string(ipID);

										if (ipIDstr.length() < 4)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4ERROR`` >> `4Banning ``aborted, error while fetching proper IP. Please try again!"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;
										}
										else
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Device of player with ID:\n " + ipIDstr + " added to ban list. Abusing this command will lead into ban and demote!\n"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;

											std::ofstream outfile("devicebans/" + ipIDstr + ".txt");

											outfile << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

											outfile.close();
										}
									}
									else
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Banning`` aborted, player was not found. If you are sure this player exists, please try again!"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										delete p.data;
									}
								}
								else
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Banning`` aborted, player was not found. If you are sure this player exists, please try again!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}


								/*std::ofstream outfile("devicebans/" + playerCalled + ".txt");

								outfile << "user who banned this ID: " + ((PlayerInfo*)(peer->data))->rawName;

								outfile.close();




								string x;
								x.append(playerCalled);


								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Device of player with ID:\n " + x + " added to ban list. Abusing this command will lead into ban and demote!\n"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								

								x = x.substr(0, x.length() - 2);
								delete p.data;*/
							}


						}
						else if (str == "/nick")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								string name2;
								string namemsg = ((PlayerInfo*)(peer->data))->rawName;
								((PlayerInfo*)(peer->data))->isNicked = false;

								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 && ((PlayerInfo*)(peer->data))->rawName == "playingo")
								{
									name2 = "`4@" + ((PlayerInfo*)(peer->data))->tankIDName;
									((PlayerInfo*)(event.peer->data))->country = "../rtsoft_logo";
								}
								else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
								{
									name2 = "`6@" + ((PlayerInfo*)(peer->data))->tankIDName;
									((PlayerInfo*)(event.peer->data))->country = "../flags/ha";
								}
								else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
								{
									name2 = "`#@" + ((PlayerInfo*)(peer->data))->tankIDName;
									((PlayerInfo*)(event.peer->data))->country = "../atomic_button";
								}
								else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333)
								{
									name2 = "`e" + ((PlayerInfo*)(peer->data))->tankIDName;

								}

								((PlayerInfo*)(peer->data))->displayName = name2;
								((PlayerInfo*)(peer->data))->msgName = namemsg;
								GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), name2));
								memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor

								((PlayerInfo*)(peer->data))->displayName = name2;
								ENetPacket * packet7 = enet_packet_create(p7.data,
									p7.len,
									ENET_PACKET_FLAG_RELIABLE);



								ENetPeer * currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										enet_peer_send(currentPeer, 0, packet7);
									}
								}
								delete p7.data;

								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYour nickname has been reverted!"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}
						}


						else if (str.substr(0, 6) == "/nick ") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								string name2 = "`w`w" + str.substr(6, cch.length() - 6 - 1);
								((PlayerInfo*)(peer->data))->msgName = PlayerDB::getProperName(str.substr(6, cch.length() - 6 - 1));

								string lognickname = str.substr(6, cch.length() - 6 - 1);
								if (name2.length() < 5 && getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333)
								{
									GamePacket psa = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9VIP's`w cannot nick to nothing."));
									ENetPacket * packetsa = enet_packet_create(psa.data,
										psa.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packetsa);
									delete psa.data;
								}
								else
								{

									cout << ((PlayerInfo*)(peer->data))->rawName << " nicked into " << lognickname << endl;




									((PlayerInfo*)(peer->data))->displayName = str.substr(6, cch.length() - 6 - 1);
									((PlayerInfo*)(peer->data))->country = "us";
									((PlayerInfo*)(peer->data))->isNicked = true;




									GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), name2));
									memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor

									((PlayerInfo*)(peer->data))->displayName = name2;
									ENetPacket * packet7 = enet_packet_create(p7.data,
										p7.len,
										ENET_PACKET_FLAG_RELIABLE);



									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											enet_peer_send(currentPeer, 0, packet7);
										}
									}
									delete p7.data;

									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your nickname has been changed to `2" + str.substr(6, cch.length() - 6 - 1) + "`o! Type /nick (only /nick, to get default name back!)"));
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet);
									delete ps.data;
								}
							}





							//enet_host_flush(server);
						}
						else if (str == "/levelbro") {
							{
								//((PlayerInfo*)(peer->data))->level = ((PlayerInfo*)(peer->data))->level + 100;
							}
						}
						else if (str.substr(0, 8) == "/remove ") { //This is a special code by PlayIngoHD Gaming extra for NabzGT!

						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
							string ipidx = str.substr(8, cch.length() - 8 - 1);

							bool existx = std::experimental::filesystem::exists("players/" + PlayerDB::getProperName(ipidx) + ".json");
							if (existx)
							{
								std::ifstream ifs("players/" + PlayerDB::getProperName(ipidx) + ".json");
								if (ifs.is_open()) {
									json j;
									ifs >> j;

									int ipID = j["ipID"];
									string ipIDstr = to_string(ipID);

									


								bool exist = std::experimental::filesystem::exists("devicebans/" + ipIDstr + ".txt");
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Working..."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete ps.data;

								if (exist == true)
								{
									string remipid = "devicebans/" + ipIDstr + ".txt";
									remove(remipid.c_str());
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully removed ipID from ban list."));
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet);
									delete ps.data;
								}
								else
								{
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4ipID (" + ipIDstr + ") of player not found in ban list`w, aborting."));
									ENetPacket * packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet);
									delete ps.data;
								}
								}
								}
							else
							{
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Player (" + ipidx + ") not found`w, aborting."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}
							}
						}						
						else if (str.substr(0, 9) == "/weather ") {
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
												GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlayer `2" + ((PlayerInfo*)(peer->data))->displayName + "`o has just changed the world's weather!"));
												ENetPacket * packet1 = enet_packet_create(p1.data,
													p1.len,
													ENET_PACKET_FLAG_RELIABLE);


												enet_peer_send(currentPeer, 0, packet1);
												delete p1.data;

												if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT")
												{
													getPlyersWorld(peer)->weather = atoi(str.substr(9).c_str());
												}
												GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), atoi(str.substr(9).c_str())));
												ENetPacket * packet2 = enet_packet_create(p2.data,
													p2.len,
													ENET_PACKET_FLAG_RELIABLE);


												enet_peer_send(currentPeer, 0, packet2);
												delete p2.data;
												continue; /*CODE UPDATE /WEATHER FOR EVERYONE!*/
											}
										}
									}
								}
							}
						}
						else if (str == "/count") {
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
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
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "There are " + std::to_string(count) + " people online out of 1024 limit."));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}
						}
						else if (str.substr(0, 5) == "/asb ") {
							if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							cout << "ASB from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << " with IP " << ((PlayerInfo*)(peer->data))->charIP << " with message: " << str.substr(5, cch.length() - 5 - 1) << endl;
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
						else if (str == "/realinvis")
						{
							/*GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 1));
							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);


							enet_peer_send(peer, 0, packet2);
							delete p2.data;*/
						}
						else if (str.substr(0, 7) == "/state ")
						{
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
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
							SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
						}
						}
						else if (str == "/invis" || str == "/invisible") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
								//sendConsoleMsg(peer, "`6" + str);
								if (pData->isinv == false) {

									pData->isinv = true;
									sendConsoleMsg(peer, "`oYou are now ninja, invisible to all.");

									GamePacket p0 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 1));

									memcpy(p0.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet0);
									delete p0.data;

									ENetPeer* currentPeer;

									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{


											((PlayerInfo*)(peer->data))->isinv = 1;
											GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 1));

											memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
											ENetPacket * packet2 = enet_packet_create(p2.data,
												p2.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet2);
											delete p2.data;




										}
									}

								}
								else {
									sendConsoleMsg(peer, "`oYou are once again visible to mortals.");
									((PlayerInfo*)(peer->data))->skinColor = atoi("-155");

									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 0));
									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet2);
									delete p2.data;



									pData->isinv = false;

									GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), ((PlayerInfo*)(peer->data))->displayName));
									memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
									ENetPacket * packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);


									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											GamePacket pis = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 0));

											memcpy(pis.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
											ENetPacket * packetpis = enet_packet_create(pis.data,
												pis.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packetpis);
											delete pis.data;


											if (((PlayerInfo*)(peer->data))->rawName != ((PlayerInfo*)(currentPeer->data))->rawName)
											{
												enet_peer_send(currentPeer, 0, packet3);
											}
										}
									}

									sendState(peer);
									sendClothes(peer);



									/*GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), pData->x1, pData->y1));
									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);


									enet_peer_send(peer, 0, packet2);
									delete p2.data;
									((PlayerInfo*)(peer->data))->isInvisible = false;
									sendState(peer);
									sendClothes(peer);
									pData->isGhost = false;*/
								}
							}
						}
						else if (str == "/max")
						{
						/*GamePacket p2ww = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(peer->data))->country + "|maxLevel"));
						memcpy(p2ww.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2ww = enet_packet_create(p2ww.data,
							p2ww.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2ww);
						delete p2ww.data;
						GamePacket p2wwee = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(currentPeer->data))->country + "|maxLevel"));
						memcpy(p2wwee.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
						ENetPacket * packet2wwee = enet_packet_create(p2wwee.data,
							p2wwee.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2wwee);
						delete p2wwee.data;

						((PlayerInfo*)(peer->data))->country = ((PlayerInfo*)(peer->data))->country + "|maxLevel";*/
						}
						else if (str == "/server")
						{
						//cout << "Player entered subserver" << endl;

						/*GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSendToServer"), 17091));

						//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;*/



						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wServer Selection``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|`4WARNING:`` `5If you try to connect back to real GT server, please restart GT first!``|left|4|\n\nadd_button|betaserver|Beta/Alt Server|\nadd_button|battleroyaleserver|Battle Royale (coming soon working on queue!)|\nadd_button|subserver1|Sub-Server/Server spot for sale dm DiruX#4989 7 DLS! (VPS+GTOG Server.exe)|\nadd_button|advertiseserver|Advertise your server here (2 DLS) dm DiruX#4989|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;

						

					
						}
						else if (str.substr(0, 5) == "/jsb ")
						{
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {
							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` in (`$`4JAMMED!``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1)));
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
						}
						else if (str.substr(0, 4) == "/sb ") {
							if (((PlayerInfo*)(peer->data))->isDuctaped == true)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7Not allowed to SB while ducttaped!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);


								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{



								using namespace std::chrono;
								if (((PlayerInfo*)(peer->data))->lastSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
								{
									((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Cooldown >> Wait 15 seconds to throw another Super-Broadcast!"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);


									enet_peer_send(peer, 0, packet);
									delete p.data;
									//enet_host_flush(server);
									continue;
								}


								string name = ((PlayerInfo*)(peer->data))->displayName;
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
						else if (str.substr(0, 6) == "/radio") {
							GamePacket p;
							if (((PlayerInfo*)(peer->data))->radio) {
								p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You won't see broadcasts anymore."));
								((PlayerInfo*)(peer->data))->radio = false;
							}
							else {
								p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You will now see broadcasts again."));
								((PlayerInfo*)(peer->data))->radio = true;
							}


							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);


							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}
						else if (str.substr(0, 6) == "/reset") {
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							cout << "Restart from " << ((PlayerInfo*)(peer->data))->displayName << endl;
							GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Restarting soon!"), "audio/mp3/suspended.mp3"), 0));
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
							delete p.data;
							//enet_host_flush(server);
						}


						/*else if (str.substr(0, 7) == "/clear "){
						if (!canClear(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						cout << "World cleared by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
						WorldInfo* wrld = getPlyersWorld(peer);
						string wName = str.substr(4, cch.length() - 4 - 1);
						for (auto & c : wName) c = toupper(c);
						for (int i = 0; i < worlds.size(); i++)
						{
						if (wrld == NULL) continue;
						if (wName == wrld->name)
						{
						worlds.at(i) = generateWorld(wrld->name, wrld->width, wrld->height);
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
						if (((PlayerInfo*)(currentPeer->data))->currentWorld == wrld->name)
						{
						sendWorld(currentPeer, &worlds.at(i));


						int x = 3040;
						int y = 736;


						for (int j = 0; j < worlds.at(i).width*worlds.at(i).height; j++)
						{
						if (worlds.at(i).items[j].foreground == 6) {
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

						enet_host_flush(server);
						delete p.data;
						((PlayerInfo*)(currentPeer->data))->netID = cId;
						onPeerConnect(currentPeer);
						cId++;


						sendInventory(((PlayerInfo*)(event.peer->data))->inventory);
						}


						}
						enet_host_flush(server);
						}
						}
						}*/
						else if (str.substr(0, 15) == "/sseditworldbg ")
						{

						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999) {
							if (((PlayerInfo*)(peer->data))->rawName == "playingo" || ((PlayerInfo*)(peer->data))->rawName == "esc" || ((PlayerInfo*)(peer->data))->rawName == "random")
							{
								string editforeg = str.substr(15, cch.length() - 15 - 1);


								int editforegint = atoi(editforeg.c_str());
								if (editforegint == 0 || editforegint > 0 && editforegint < 7000) {



									vector<WorldInfo> worlds;

									cout << "World edited by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
									WorldInfo* wrld = getPlyersWorld(peer);

									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										//if (((PlayerInfo*)(currentPeer->data))->currentWorld == wrld->name)
										//{
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
													world->items[i].background = editforegint;

												}



											//}
										}


										//ENetPeer* currentPeer;


										bool found = false;


										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;

											if (((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(currentPeer->data))->currentWorld)
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#[ `$Used edit mod on world`0! `6No abuse, please. `#] `oSupported item ids: 0-7000"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
												sendPlayerToWorld(currentPeer, (PlayerInfo*)(peer->data), ((PlayerInfo*)(peer->data))->currentWorld);
											}


										}
									}
								}
							}
						}
						}
						else if (str.substr(0, 15) == "/sseditworldfg ")
						{
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999) {
							if (((PlayerInfo*)(peer->data))->rawName == "playingo" || ((PlayerInfo*)(peer->data))->rawName == "esc" || ((PlayerInfo*)(peer->data))->rawName == "random")
							{
								string editforeg = str.substr(15, cch.length() - 15 - 1);


								int editforegint = atoi(editforeg.c_str());
								if (editforegint == 0 || editforegint > 0 && editforegint < 7000) {




									vector<WorldInfo> worlds;

									cout << "World edited by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
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
													world->items[i].foreground = editforegint;

												}



											}
										}


										//ENetPeer* currentPeer;


										bool found = false;


										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;

											if (((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(currentPeer->data))->currentWorld)
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#[ `$Used edit mod on world`0! `6No abuse, please. `#] `oSupported item ids: 0-7000"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
												sendPlayerToWorld(currentPeer, (PlayerInfo*)(peer->data), ((PlayerInfo*)(peer->data))->currentWorld);
											}


										}
									}
								}
							}
						}
						}
						else if (str.substr(0, 16) == "/superclearworld") {
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999) {

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#[ `$Used clear mod on world`0! `6No abuse, please. `#]"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							int x = 3040;
							int y = 736;





							vector<WorldInfo> worlds;

							cout << "World cleared by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
							WorldInfo* wrld = getPlyersWorld(peer);

							PlayerMoving data2;
							data2.packetType = 0x3;
							data2.characterState = 0x0; // animation
							data2.x = 3040;
							data2.y = 736;
							data2.punchX = 0;
							data2.punchY = 0;
							data2.XSpeed = 0;
							data2.YSpeed = 0;
							data2.netID = ((PlayerInfo*)(peer->data))->netID;
							data2.plantingTree = 0;

							PlayerMoving data;
							data.packetType = 0x3;
							data.characterState = 0x0; // animation
							data.x = 3040;
							data.y = 736;
							data.punchX = 0;
							data.punchY = 0;
							data.XSpeed = 0;
							data.YSpeed = 0;
							data.netID = ((PlayerInfo*)(peer->data))->netID;
							data.plantingTree = 6864;

							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->currentWorld == wrld->name)
								{

									/*for (int x = 0; x < world->width; x++)
									{
										sendTileUpdate(x, x, 758, ((PlayerInfo*)(peer->data))->netID, peer);
									}

									for (int y = 0; y < world->width; y++)
									{
										sendTileUpdate(y, y, 758, ((PlayerInfo*)(peer->data))->netID, peer);
									}*/

									

									for (int i = 0; i < world->width*world->height; i++)
									{
										//sendTileUpdate(i, i, 758, ((PlayerInfo*)(peer->data))->netID, peer);

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
											
											data.x = (i%world->width) * 32;
											data.y = (i / world->width) * 32;
											data2.x = (i%world->width) * 32;
											data2.y = (i / world->width) * 32;
											data.punchX = (i%world->width) * 1;
											data.punchY = (i / world->width) * 1;
											data2.punchX = (i%world->width) * 1;
											data2.punchY = (i / world->width) * 1;
											

											if (isHere(peer, currentPeer)) {
												SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
												SendPacketRaw(4, packPlayerMoving(&data2), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
											//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
										}

										}
									}
								}
							}
						}
						}


							
						
						else if (str.substr(0, 13) == "/ssclearworld") {
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999) {



								vector<WorldInfo> worlds;

								cout << "World cleared by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
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
									}



								}
								//ENetPeer* currentPeer;


								bool found = false;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(currentPeer->data))->currentWorld)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#[ `$Used Beta-clear mod on world`0! `6No abuse, please. `#]"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p.data;
										sendPlayerToWorld(currentPeer, (PlayerInfo*)(peer->data), ((PlayerInfo*)(peer->data))->currentWorld);
									}


								}
							}
						}
						else if (str == "/unmod")
						{
							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							((PlayerInfo*)(peer->data))->isModState = false;
							((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
							sendState(peer);
							sendClothes(peer);
							/*PlayerMoving data;
							data.packetType = 0x14;
							data.characterState = 0x0; // animation
							data.x = 1000;
							data.y = 1;
							data.punchX = 0;
							data.punchY = 0;
							data.XSpeed = 300;
							data.YSpeed = 600;
							data.netID = ((PlayerInfo*)(peer->data))->netID;
							data.plantingTree = 0x0;
							SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
						}
						/*else if (str == "/clearworld")
						{
						cout << "World cleared by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;

						int x = 3040;
						int y = 736;
						generateWorld("CLEARZ", x, y);


						enet_host_flush;

						}
						else if (str == "/alt") {
							GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBetaMode"), 1));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							//enet_host_flush(server);
						}*/



						else
							if (str == "/inventory")
							{
								sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
							}
							else
								if (str.substr(0, 6) == "/item ")
								{
									//((PlayerInfo*)(peer->data))->invcount


									PlayerInventory inventory;
									InventoryItem item;

									if (((PlayerInfo*)(peer->data))->invcount == 0)
									{
										((PlayerInfo*)(peer->data))->invitem1 = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										((PlayerInfo*)(peer->data))->invcount = 1;
									}
									else if (((PlayerInfo*)(peer->data))->invcount == 1)
									{
										((PlayerInfo*)(peer->data))->invitem2 = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										((PlayerInfo*)(peer->data))->invcount = 2;
									}
									else if (((PlayerInfo*)(peer->data))->invcount == 2)
									{
										((PlayerInfo*)(peer->data))->invitem3 = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										((PlayerInfo*)(peer->data))->invcount = 3;
									}
									else if (((PlayerInfo*)(peer->data))->invcount == 3)
									{
										((PlayerInfo*)(peer->data))->invitem4 = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										((PlayerInfo*)(peer->data))->invcount = 4;
									}
									else if (((PlayerInfo*)(peer->data))->invcount == 4)
									{
										((PlayerInfo*)(peer->data))->invitem5 = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										((PlayerInfo*)(peer->data))->invcount = 5;
									}
									else if (((PlayerInfo*)(peer->data))->invcount == 5)
									{
										((PlayerInfo*)(peer->data))->invitem6 = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										((PlayerInfo*)(peer->data))->invcount = 6;
									}
									else if (((PlayerInfo*)(peer->data))->invcount == 6)
									{
										((PlayerInfo*)(peer->data))->invitem7 = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										((PlayerInfo*)(peer->data))->invcount = 7;
									}
									else if (((PlayerInfo*)(peer->data))->invcount == 7)
									{
										((PlayerInfo*)(peer->data))->invitem8 = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										((PlayerInfo*)(peer->data))->invcount = 8;
									}
									else if (((PlayerInfo*)(peer->data))->invcount == 8)
									{
										((PlayerInfo*)(peer->data))->invitem9 = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
										((PlayerInfo*)(peer->data))->invcount = 9;
									}


									item.itemID = ((PlayerInfo*)(peer->data))->invitem1;
									item.itemCount = 200;
									inventory.items.push_back(item);

									item.itemID = ((PlayerInfo*)(peer->data))->invitem2;
									item.itemCount = 200;
									inventory.items.push_back(item);

									item.itemID = ((PlayerInfo*)(peer->data))->invitem3;
									item.itemCount = 200;
									inventory.items.push_back(item);

									item.itemID = ((PlayerInfo*)(peer->data))->invitem4;
									item.itemCount = 200;
									inventory.items.push_back(item);

									item.itemID = ((PlayerInfo*)(peer->data))->invitem5;
									item.itemCount = 200;
									inventory.items.push_back(item);

									item.itemID = ((PlayerInfo*)(peer->data))->invitem6;
									item.itemCount = 200;
									inventory.items.push_back(item);

									item.itemID = ((PlayerInfo*)(peer->data))->invitem7;
									item.itemCount = 200;
									inventory.items.push_back(item);

									item.itemID = ((PlayerInfo*)(peer->data))->invitem8;
									item.itemCount = 200;
									inventory.items.push_back(item);

									item.itemID = ((PlayerInfo*)(peer->data))->invitem9;
									item.itemCount = 200;
									inventory.items.push_back(item);


									item.itemCount = 1;
									item.itemID = 18;
									inventory.items.push_back(item);
									item.itemID = 32;
									inventory.items.push_back(item);
									sendInventory(peer, inventory);
								}
								else
									if (str.substr(0, 9) == "/cleaninv")
									{
										PlayerInventory inventory;
										InventoryItem item;

										((PlayerInfo*)(peer->data))->invcount = 0;

										((PlayerInfo*)(peer->data))->invitem1 = 0;
										((PlayerInfo*)(peer->data))->invitem2 = 0;
										((PlayerInfo*)(peer->data))->invitem3 = 0;
										((PlayerInfo*)(peer->data))->invitem4 = 0;
										((PlayerInfo*)(peer->data))->invitem5 = 0;
										((PlayerInfo*)(peer->data))->invitem6 = 0;
										((PlayerInfo*)(peer->data))->invitem7 = 0;
										((PlayerInfo*)(peer->data))->invitem8 = 0;
										((PlayerInfo*)(peer->data))->invitem9 = 0;

										item.itemID = ((PlayerInfo*)(peer->data))->invitem1;
										item.itemCount = 200;
										inventory.items.push_back(item);

										item.itemID = ((PlayerInfo*)(peer->data))->invitem2;
										item.itemCount = 200;
										inventory.items.push_back(item);

										item.itemID = ((PlayerInfo*)(peer->data))->invitem3;
										item.itemCount = 200;
										inventory.items.push_back(item);

										item.itemID = ((PlayerInfo*)(peer->data))->invitem4;
										item.itemCount = 200;
										inventory.items.push_back(item);

										item.itemID = ((PlayerInfo*)(peer->data))->invitem5;
										item.itemCount = 200;
										inventory.items.push_back(item);

										item.itemID = ((PlayerInfo*)(peer->data))->invitem6;
										item.itemCount = 200;
										inventory.items.push_back(item);

										item.itemID = ((PlayerInfo*)(peer->data))->invitem7;
										item.itemCount = 200;
										inventory.items.push_back(item);

										item.itemID = ((PlayerInfo*)(peer->data))->invitem8;
										item.itemCount = 200;
										inventory.items.push_back(item);

										item.itemID = ((PlayerInfo*)(peer->data))->invitem9;
										item.itemCount = 200;
										inventory.items.push_back(item);


										item.itemCount = 1;
										item.itemID = 18;
										inventory.items.push_back(item);
										item.itemID = 32;
										inventory.items.push_back(item);
										sendInventory(peer, inventory);

									}
									else
										if (str.substr(0, 6) == "/team ")
										{
											int val = 0;
											val = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
											PlayerMoving data;
											//data.packetType = 0x14;
											data.packetType = 0x1B;
											//data.characterState = 0x924; // animation
											data.characterState = 0x0; // animation
											data.x = 0;
											data.y = 0;
											data.punchX = val;
											data.punchY = 0;
											data.XSpeed = 0;
											data.YSpeed = 0;
											data.netID = ((PlayerInfo*)(peer->data))->netID;
											data.plantingTree = 0;
											SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);


										}
										else
											if (str.substr(0, 7) == "/color ")
											{
												((PlayerInfo*)(peer->data))->skinColor = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
												sendClothes(peer);
											}
						if (str.substr(0, 4) == "/who")
						{
							sendWho(peer);


						}
						
						}
						
					if (!((PlayerInfo*)(event.peer->data))->isIn)
					{
						/*std::ifstream ifs("hash.txt");
						std::string contentha((std::istreambuf_iterator<char>(ifs)),
							(std::istreambuf_iterator<char>()));

						int serverhash = std::atoi(contentha.c_str());
						cout << "client connected successfuly, server hash: " + serverhash;*/
						// current hash: 926425180
						GamePacket p = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(), "OnSuperMainStartAcceptLogonHrdxs47254722215a"), serverhash), "ubistatic-a.akamaihd.net"), "0098/CDNContent3/cache/"), "cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"), "proto=13|choosemusic=audio/mp3/tsirhc.mp3|active_holiday=4"));
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
							else if (id == "game_version")
							{

								((PlayerInfo*)(event.peer->data))->gameversion = act;
							}
							else if (id == "rid")
							{


								((PlayerInfo*)(event.peer->data))->rid = act;
							}
							else if (id == "wk")
							{


								((PlayerInfo*)(event.peer->data))->wkid = act;
							}
							else if (id == "meta")
							{

								((PlayerInfo*)(event.peer->data))->metaip = act;
							}
							else if (id == "hash2")
							{

								((PlayerInfo*)(event.peer->data))->hash2 = act;
							}
							else if (id == "mac")
							{


								((PlayerInfo*)(event.peer->data))->mac = act;
							}
							else if (id == "platformID")
							{
								((PlayerInfo*)(event.peer->data))->platformID = act;
							}
							else if (id == "player_age")
							{
								((PlayerInfo*)(event.peer->data))->player_age = act;
							}
							else if (id == "fhash")
							{
								((PlayerInfo*)(event.peer->data))->fhash = act;
							}
							else if (id == "aid")
							{
								((PlayerInfo*)(event.peer->data))->aid = act;
							}
							else if (id == "houstonProductID")
							{
								((PlayerInfo*)(event.peer->data))->hpid = act;
							}
							else if (id == "gid")
							{
								((PlayerInfo*)(event.peer->data))->gid = act;
							}
							else if (id == "vid")
							{
								((PlayerInfo*)(event.peer->data))->vid = act;
							}
							else if (id == "f")
							{
								((PlayerInfo*)(event.peer->data))->f = act;
							}
							else if (id == "fz")
							{
								((PlayerInfo*)(event.peer->data))->fz = act;
							}
							else if (id == "lmode")
							{
								((PlayerInfo*)(event.peer->data))->lmode = act;
							}
							else if (id == "user")
							{
								((PlayerInfo*)(event.peer->data))->user = act;
							}
							else if (id == "token")
							{
								((PlayerInfo*)(event.peer->data))->token = act;
							}
							else if (id == "GDPR")
							{
								((PlayerInfo*)(event.peer->data))->gdpr = act;
							}
							else if (id == "deviceVersion")
							{
							((PlayerInfo*)(event.peer->data))->deviceversion = act;
							}
							

						}
						if (((PlayerInfo*)(event.peer->data))->mac == "" || ((PlayerInfo*)(event.peer->data))->rid == "" || ((PlayerInfo*)(event.peer->data))->player_age == "")
						{
							enet_peer_disconnect_now(peer, 0);
							enet_peer_reset(peer);
						}

						if (!((PlayerInfo*)(event.peer->data))->haveGrowId)
						{
							((PlayerInfo*)(event.peer->data))->rawName = std::to_string(event.peer->address.host);
							((PlayerInfo*)(event.peer->data))->haveGuestId = true;
							((PlayerInfo*)(event.peer->data))->msgName = std::to_string(event.peer->address.host);
							((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length() > 15 ? 15 : ((PlayerInfo*)(event.peer->data))->requestedName.length()) + "_" + std::to_string(event.peer->address.host));
							((PlayerInfo*)(event.peer->data))->displayNamebackup = ((PlayerInfo*)(event.peer->data))->displayName;
						}
						else {
							((PlayerInfo*)(event.peer->data))->rawName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
							((PlayerInfo*)(event.peer->data))->msgName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
#ifdef REGISTRATION
							int logStatus = PlayerDB::playerLogin(peer, ((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass);
							if (logStatus == -3) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Sorry, this account (`5" + ((PlayerInfo*)(event.peer->data))->rawName + "`4) has been suspended. Contact DiruX#4989 On Discord"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_peer_disconnect_later(peer, 0);
							}
							else if (logStatus == 1) {								
								int level = ((PlayerInfo*)(peer->data))->level;
								((PlayerInfo*)(event.peer->data))->displayName = ((PlayerInfo*)(event.peer->data))->tankIDName;
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999) {
									if (((PlayerInfo*)(peer->data))->rawName == "playingo")
									{
										((PlayerInfo*)(event.peer->data))->displayName = "`4@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
										((PlayerInfo*)(event.peer->data))->displayNamebackup = "`4@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
									}
									else
									{
										((PlayerInfo*)(event.peer->data))->displayName = "`6@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
										((PlayerInfo*)(event.peer->data))->displayNamebackup = "`6@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
									}
								}
								else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333) {
									((PlayerInfo*)(event.peer->data))->displayName = "`e" + ((PlayerInfo*)(event.peer->data))->tankIDName;
									((PlayerInfo*)(event.peer->data))->displayNamebackup = "`e" + ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
								else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
									((PlayerInfo*)(event.peer->data))->displayName = "`#@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
									((PlayerInfo*)(event.peer->data))->displayNamebackup = "`#@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
								else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 166) {
									((PlayerInfo*)(event.peer->data))->displayName = "`1" + ((PlayerInfo*)(event.peer->data))->tankIDName;
									((PlayerInfo*)(event.peer->data))->displayNamebackup = "`1" + ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
								
							}
							else {
								((PlayerInfo*)(event.peer->data))->wrongpass = true;
								
							}
#else

							((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->tankIDName.substr(0, ((PlayerInfo*)(event.peer->data))->tankIDName.length() > 18 ? 18 : ((PlayerInfo*)(event.peer->data))->tankIDName.length()));
							if (((PlayerInfo*)(event.peer->data))->displayName.length() < 3) ((PlayerInfo*)(event.peer->data))->displayName = "Person that doesn't know how the name looks!";
#endif
						}
						for (char c : ((PlayerInfo*)(event.peer->data))->displayName) if (c < 0x20 || c>0x7A) ((PlayerInfo*)(event.peer->data))->displayName = "Bad characters in name, remove them!";

						if (((PlayerInfo*)(event.peer->data))->country.length() > 4)
						{
							((PlayerInfo*)(event.peer->data))->country = "us";
						}
						if (getAdminLevel(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) == 999)
						{
							if (((PlayerInfo*)(peer->data))->rawName == "playingo")
							{
								((PlayerInfo*)(event.peer->data))->country = "../rtsoft_logo";
								
								
							}
							else
							{
								((PlayerInfo*)(event.peer->data))->country = "../flags/ha";
							}
						}
						if (getAdminLevel(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) == 666)
						{
							((PlayerInfo*)(event.peer->data))->country = "../atomic_button";
						}
						if (getAdminLevel(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) == 333)
						{
							
						}
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
						if (((PlayerInfo*)(event.peer->data))->rawName == "")
						{
							enet_peer_disconnect_now(event.peer, 0);
							enet_peer_reset(event.peer);
						}
						else
						{
							((PlayerInfo*)(event.peer->data))->isIn = true;
						}
						
						if (std::experimental::filesystem::exists("cursedplayers/" + ((PlayerInfo*)(peer->data))->rawName + ".txt"))
						{
							((PlayerInfo*)(peer->data))->isCursed = true;
						}
						/*for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;


						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just entered the game..."));
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
						cout << ((PlayerInfo*)(peer->data))->displayName << "(" << ((PlayerInfo*)(peer->data))->rawName << ")" << " joined this server. " << counts << " people are online." << endl;
						
						cout << "IP: " + ((PlayerInfo*)(peer->data))->charIP << endl;
						cout << "MAC: " + ((PlayerInfo*)(peer->data))->mac << endl;						
						cout << "PLATFORM ID: " + ((PlayerInfo*)(peer->data))->platformID << endl;


						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Welcome back `w" + name + "`w, `w" + std::to_string(counts) + " `wplayers online!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
						PlayerInventory inventory;
						for (int i = 0; i < 200; i++)
						{
							InventoryItem it;
							it.itemID = (i * 2) + 2;
							it.itemCount = 200;
							inventory.items.push_back(it);
						}
						((PlayerInfo*)(event.peer->data))->inventory = inventory;
						
						if (((PlayerInfo*)(peer->data))->haveGrowId) {

							PlayerInfo* p = ((PlayerInfo*)(peer->data));
							std::ifstream ifff("players/" + PlayerDB::getProperName(p->rawName) + ".json");
							json j;
							ifff >> j;

							//p->currentWorld = worldInfo->name;



							vector <string>frns;
							if (j.count("friends") == 1) {
								for (int i = 0; i < j["friends"].size(); i++) {
									frns.push_back(j["friends"][i]);
								}
							}
							else {
								frns = {};
							}

							((PlayerInfo*)(peer->data))->effect = j["effect"];


							p->friendinfo = frns;
							ifff.close();
						}

						{
							PlayerInfo* pData = ((PlayerInfo*)(peer->data));
							//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe Growtopia Gazette``|left|5016|\n\nadd_spacer|small|\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\nadd_spacer|small|\n\nadd_textbox|`wSeptember 10:`` `5Surgery Stars end!``|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Hello Growtopians,|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Surgery Stars is over! We hope you enjoyed it and claimed all your well-earned Summer Tokens!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|As we announced earlier, this month we are releasing the feature update a bit later, as we're working on something really cool for the monthly update and we're convinced that the wait will be worth it!|left|\n\nadd_spacer|small|\n\nadd_textbox|Check the Forum here for more information!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wSeptember Updates Delay``|noflags|https://www.growtopiagame.com/forums/showthread.php?510657-September-Update-Delay&p=3747656|Open September Update Delay Announcement?|0|0|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|Also, we're glad to invite you to take part in our official Growtopia survey!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wTake Survey!``|noflags|https://ubisoft.ca1.qualtrics.com/jfe/form/SV_1UrCEhjMO7TKXpr?GID=26674|Open the browser to take the survey?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Click on the button above and complete the survey to contribute your opinion to the game and make Growtopia even better! Thanks in advance for taking the time, we're looking forward to reading your feedback!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|And for those who missed PAW, we made a special video sneak peek from the latest PAW fashion show, check it out on our official YouTube channel! Yay!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wPAW 2018 Fashion Show``|noflags|https://www.youtube.com/watch?v=5i0IcqwD3MI&feature=youtu.be|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Lastly, check out other September updates:|left|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|IOTM: The Sorcerer's Tunic of Mystery|left|24|\n\nadd_label_with_icon|small|New Legendary Summer Clash Branch|left|24|\n\nadd_spacer|small|\n\nadd_textbox|`$- The Growtopia Team``|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\n\n\n\n\nadd_url_button|comment|`wOfficial YouTube Channel``|noflags|https://www.youtube.com/c/GrowtopiaOfficial|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_url_button|comment|`wSeptember's IOTM: `8Sorcerer's Tunic of Mystery!````|noflags|https://www.growtopiagame.com/forums/showthread.php?450065-Item-of-the-Month&p=3392991&viewfull=1#post3392991|Open the Growtopia website to see item of the month info?|0|0|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|`4WARNING:`` `5Drop games/trust tests`` and betting games (like `5Casinos``) are not allowed and will result in a ban!|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` Using any kind of `5hacked client``, `5spamming/text pasting``, or `5bots`` (even with an alt) will likely result in losing `5ALL`` your accounts. Seriously.|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` `5NEVER enter your GT password on a website (fake moderator apps, free gemz, etc) - it doesn't work and you'll lose all your stuff!|left|24|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wGrowtopia on Facebook``|noflags|http://growtopiagame.com/facebook|Open the Growtopia Facebook page in your browser?|0|0|\n\nadd_spacer|small|\n\nadd_button|rules|`wHelp - Rules - Privacy Policy``|noflags|0|0|\n\n\nadd_quick_exit|\n\nadd_spacer|small|\nadd_url_button|comment|`wVisit Growtopia Forums``|noflags|http://www.growtopiagame.com/forums|Visit the Growtopia forums?|0|0|\nadd_spacer|small|\nadd_url_button||`wWOTD: `1THELOSTGOLD`` by `#iWasToD````|NOFLAGS|OPENWORLD|THELOSTGOLD|0|0|\nadd_spacer|small|\nadd_url_button||`wVOTW: `1Yodeling Kid - Growtopia Animation``|NOFLAGS|https://www.youtube.com/watch?v=UMoGmnFvc58|Watch 'Yodeling Kid - Growtopia Animation' by HyerS on YouTube?|0|0|\nend_dialog|gazette||OK|"));

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`wPlease pass this captcha``|left|18|\nadd_spacer|small\nadd_textbox|`wPlease choose `2Dog `wbutton.|left|\nadd_spacer|small|\nadd_button|" + pData->buttonID + "|`2Dog|noflags|0|\nadd_button|wrongcaptcha|`4Cat|noflags|0|\nend_dialog|captcha|||"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);


							//enet_host_flush(server);
							delete p.data;
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
						{
#ifdef TOTAL_LOG
							cout << "Entering some world..." << endl;
#endif
							try {
								toUpperCase(act);
								if (act == "CON" || act == "NUL" || act == "PRN" || act == "AUX" || act == "CLOCK$" || act == "COM0" || act == "COM1" || act == "COM2" || act == "COM3" || act == "COM4" || act == "COM5" || act == "COM6" || act == "COM7" || act == "COM8" || act == "COM9" || act == "LPT0" || act == "LPT1" || act == "LPT2" || act == "LPT3" || act == "LPT4" || act == "LPT5" || act == "LPT6" || act == "LPT7" || act == "LPT8" || act == "LPT9")
								{
									enet_peer_disconnect_now(peer, 0);
									enet_peer_reset(peer);
								}
								else
								{
									WorldInfo info = worldDB.get(act);
									WorldInfo info2 = worldDB.get("HELL");
									WorldInfo info3 = worldDB.get("START");
									bool existsban = std::experimental::filesystem::exists("worldbans/" + info.name + "/" + ((PlayerInfo*)(peer->data))->rawName);
									if (existsban)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wYou have been `4banned `wfrom the world `9owner`w! Kindly ask him to /uba you if you did nothing wrong.``"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p.data;

										GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
										ENetPacket * packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet3);
										delete p3.data;

										continue;
										break;
									}




									if (((PlayerInfo*)(peer->data))->isCursed == true)
									{
										((PlayerInfo*)(peer->data))->currentWorld = "HELL";
										sendWorldCursed(peer, &info2);
										ofstream myfile;

										std::ifstream ifs("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										std::string content((std::istreambuf_iterator<char>(ifs)),
											(std::istreambuf_iterator<char>()));


										ofstream myfilet;
										myfilet.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										myfilet << content;
										myfilet.close();

										int gembuxc = std::atoi(content.c_str());
										GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), gembuxc));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet);
										delete p.data;

										((PlayerInfo*)(peer->data))->isInWorld = true;

										


										int x = 3040;
										int y = 736;


										for (int j = 0; j < info2.width*info2.height; j++)
										{
											if (info2.items[j].foreground == 6) {
												x = (j%info2.width) * 32;
												y = (j / info2.width) * 32;
											}
										}

										if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
											if (((PlayerInfo*)(peer->data))->isinv == true)
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|1\nmstate|1\nsmstate|0\ntype|local\n"));
												//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												//enet_host_flush(server);
												delete p.data;
												((PlayerInfo*)(event.peer->data))->netID = cId;
												onPeerConnect(peer);
												cId++;
											}
											else
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|1\nsmstate|0\ntype|local\n"));
												//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												//enet_host_flush(server);
												delete p.data;
												((PlayerInfo*)(event.peer->data))->netID = cId;
												onPeerConnect(peer);
												cId++;

											}

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


											int countx = 0;
											//ENetPeer * currentPeer;
											string namex = "";
											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												countx++;
											}


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
											string ownerworld = info.Displayowner;
											string nameworld = info.name;

											GamePacket p2x = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWorld `0" + nameworld + " `oentered. There are `0" + std::to_string(otherpeoples) + " `oother people here`7, `0" + std::to_string(countx) + " `oonline."));
											ENetPacket * packet2x = enet_packet_create(p2x.data,
												p2x.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet2x);
											delete p2x.data;
											if (ownerworld != "") {
												GamePacket p3x = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`0" + nameworld + " `$World Locked `oby " + ownerworld + "`5]"));
												ENetPacket * packet3x = enet_packet_create(p3x.data,
													p3x.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet3x);
												delete p3x.data;
											}


											
										}

										else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
										{
											if (((PlayerInfo*)(peer->data))->isinv == true)
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|1\nmstate|0\nsmstate|1\ntype|local\n"));
												//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												//enet_host_flush(server);
												delete p.data;
												((PlayerInfo*)(event.peer->data))->netID = cId;
												onPeerConnect(peer);
												cId++;
											}
											else
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|1\ntype|local\n"));
												//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												//enet_host_flush(server);
												delete p.data;
												((PlayerInfo*)(event.peer->data))->netID = cId;
												onPeerConnect(peer);
												cId++;
											}

										}
										else
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
											//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
											//enet_host_flush(server);
											delete p.data;
											((PlayerInfo*)(event.peer->data))->netID = cId;
											onPeerConnect(peer);
											cId++;
										}


										if (((PlayerInfo*)(peer->data))->haveGrowId == false)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7[`4PROGRESS WON'T BE SAVED!`7] You can still join other worlds but it's recommended to create a `2GrowID, in order to save your account progress`7, `0it's free!"));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
											delete p.data;
										}
									
									}																								
									else
									{
										if (((PlayerInfo*)(peer->data))->haveGrowId == false && ((PlayerInfo*)(peer->data))->haveGuestId == false)
										{
											sendWorld(peer, &info);

											string cworld = act;
											std::transform(cworld.begin(), cworld.end(), cworld.begin(), ::toupper);

											((PlayerInfo*)(peer->data))->currentWorld = cworld;


											((PlayerInfo*)(peer->data))->isInWorld = true;

										
										}
										else
										{
											

											if (act.length() < 16) {

												if (info.nuked)
												{
													if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) < 334)
													{
														
														
															GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wThis world is inaccessible.``"));
															ENetPacket * packet = enet_packet_create(p.data,
																p.len,
																ENET_PACKET_FLAG_RELIABLE);
															enet_peer_send(peer, 0, packet);
															delete p.data;

															GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
															ENetPacket * packet3 = enet_packet_create(p3.data,
																p3.len,
																ENET_PACKET_FLAG_RELIABLE);
															enet_peer_send(peer, 0, packet3);
															delete p3.data;
														
													}
													
													else
													{						
														{
															std::ifstream ifs("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
															std::string content((std::istreambuf_iterator<char>(ifs)),
																(std::istreambuf_iterator<char>()));

															sendWorld(peer, &info);

															string cworld = act;
															std::transform(cworld.begin(), cworld.end(), cworld.begin(), ::toupper);

															((PlayerInfo*)(peer->data))->currentWorld = cworld;



															ofstream myfile;
															myfile.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
															myfile << content;
															myfile.close();
															int gembux = std::atoi(content.c_str());
															GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), gembux));
															ENetPacket * packet = enet_packet_create(p.data,
																p.len,
																ENET_PACKET_FLAG_RELIABLE);

															enet_peer_send(peer, 0, packet);
															delete p.data;


															((PlayerInfo*)(peer->data))->isInWorld = true;

															int x = 3040;
															int y = 736;


															for (int j = 0; j < info.width*info.height; j++)
															{
																if (info.items[j].foreground == 6) {
																	x = (j%info.width) * 32;
																	y = (j / info.width) * 32;
																}
															}

															if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
																if (((PlayerInfo*)(peer->data))->isinv == true)
																{
																	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|1\nmstate|1\nsmstate|0\ntype|local\n"));
																	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
																	ENetPacket * packet = enet_packet_create(p.data,
																		p.len,
																		ENET_PACKET_FLAG_RELIABLE);
																	enet_peer_send(peer, 0, packet);
																	//enet_host_flush(server);
																	delete p.data;
																	((PlayerInfo*)(event.peer->data))->netID = cId;
																	onPeerConnect(peer);
																	cId++;

																	
																}
																else
																{
																	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|1\nsmstate|0\ntype|local\n"));
																	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
																	ENetPacket * packet = enet_packet_create(p.data,
																		p.len,
																		ENET_PACKET_FLAG_RELIABLE);
																	enet_peer_send(peer, 0, packet);
																	//enet_host_flush(server);
																	delete p.data;
																	((PlayerInfo*)(event.peer->data))->netID = cId;
																	onPeerConnect(peer);
																	cId++;

																	
																}
															}

															else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
															{
																if (((PlayerInfo*)(peer->data))->isinv == true)
																{
																	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|1\nmstate|0\nsmstate|1\ntype|local\n"));
																	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
																	ENetPacket * packet = enet_packet_create(p.data,
																		p.len,
																		ENET_PACKET_FLAG_RELIABLE);
																	enet_peer_send(peer, 0, packet);
																	//enet_host_flush(server);
																	delete p.data;
																	((PlayerInfo*)(event.peer->data))->netID = cId;
																	onPeerConnect(peer);
																	cId++;

																	
																}
																else
																{
																	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|1\ntype|local\n"));
																	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
																	ENetPacket * packet = enet_packet_create(p.data,
																		p.len,
																		ENET_PACKET_FLAG_RELIABLE);
																	enet_peer_send(peer, 0, packet);
																	//enet_host_flush(server);
																	delete p.data;
																	((PlayerInfo*)(event.peer->data))->netID = cId;
																	onPeerConnect(peer);
																	cId++;

																	
																}

															}
															else
															{
																GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
																//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
																ENetPacket * packet = enet_packet_create(p.data,
																	p.len,
																	ENET_PACKET_FLAG_RELIABLE);
																enet_peer_send(peer, 0, packet);
																//enet_host_flush(server);
																delete p.data;
																((PlayerInfo*)(event.peer->data))->netID = cId;
																onPeerConnect(peer);
																cId++;

																
															}


															if (((PlayerInfo*)(peer->data))->haveGrowId == false)
															{
																GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7[`4PROGRESS WON'T BE SAVED!`7] You can still join other worlds but it's recommended to create a `2GrowID, in order to save your account progress`7, `0it's free!"));
																ENetPacket * packet = enet_packet_create(p.data,
																	p.len,
																	ENET_PACKET_FLAG_RELIABLE);
																enet_peer_send(peer, 0, packet);
																delete p.data;
															}

															int countx = 0;
															ENetPeer * currentPeer;
															string namex = "";
															for (currentPeer = server->peers;
																currentPeer < &server->peers[server->peerCount];
																++currentPeer)
															{
																if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
																	continue;
																countx++;
															}


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
															string ownerworld = info.Displayowner;
															string nameworld = info.name;

															GamePacket p2x = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWorld `0" + nameworld + " `oentered. There are `0" + std::to_string(otherpeoples) + " `oother people here`7, `0" + std::to_string(countx) + " `oonline."));
															ENetPacket * packet2x = enet_packet_create(p2x.data,
																p2x.len,
																ENET_PACKET_FLAG_RELIABLE);
															enet_peer_send(peer, 0, packet2x);
															delete p2x.data;
															if (ownerworld != "") {
																GamePacket p3x = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`0" + nameworld + " `$World Locked `oby " + ownerworld + "`5]"));
																ENetPacket * packet3x = enet_packet_create(p3x.data,
																	p3x.len,
																	ENET_PACKET_FLAG_RELIABLE);
																enet_peer_send(peer, 0, packet3x);
																delete p3x.data;
															}
														}
													}

												}
												
												
												else
												{
													std::ifstream ifs("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
													std::string content((std::istreambuf_iterator<char>(ifs)),
														(std::istreambuf_iterator<char>()));

													sendWorld(peer, &info);

													string cworld = act;
													std::transform(cworld.begin(), cworld.end(), cworld.begin(), ::toupper);

													((PlayerInfo*)(peer->data))->currentWorld = cworld;



													ofstream myfile;
													myfile.open("gemdb/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
													myfile << content;
													myfile.close();
													int gembux = std::atoi(content.c_str());
													GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), gembux));
													ENetPacket * packet = enet_packet_create(p.data,
														p.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packet);
													delete p.data;


													((PlayerInfo*)(peer->data))->isInWorld = true;

													int x = 3040;
													int y = 736;


													for (int j = 0; j < info.width*info.height; j++)
													{
														if (info.items[j].foreground == 6) {
															x = (j%info.width) * 32;
															y = (j / info.width) * 32;
														}
													}

													if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
														if (((PlayerInfo*)(peer->data))->isinv == true)
														{
															GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|1\nmstate|1\nsmstate|0\ntype|local\n"));
															//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
															ENetPacket * packet = enet_packet_create(p.data,
																p.len,
																ENET_PACKET_FLAG_RELIABLE);
															enet_peer_send(peer, 0, packet);
															//enet_host_flush(server);
															delete p.data;
															((PlayerInfo*)(event.peer->data))->netID = cId;
															onPeerConnect(peer);
															cId++;
														}
														else
														{
															GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|1\nsmstate|0\ntype|local\n"));
															//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
															ENetPacket * packet = enet_packet_create(p.data,
																p.len,
																ENET_PACKET_FLAG_RELIABLE);
															enet_peer_send(peer, 0, packet);
															//enet_host_flush(server);
															delete p.data;
															((PlayerInfo*)(event.peer->data))->netID = cId;
															onPeerConnect(peer);
															cId++;
														}
													}
													else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
													{
														if (((PlayerInfo*)(peer->data))->isinv == true)
														{
															GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|1\nmstate|0\nsmstate|1\ntype|local\n"));
															//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
															ENetPacket * packet = enet_packet_create(p.data,
																p.len,
																ENET_PACKET_FLAG_RELIABLE);
															enet_peer_send(peer, 0, packet);
															//enet_host_flush(server);
															delete p.data;
															((PlayerInfo*)(event.peer->data))->netID = cId;
															onPeerConnect(peer);
															cId++;
														}
														else
														{
															GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|1\ntype|local\n"));
															//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
															ENetPacket * packet = enet_packet_create(p.data,
																p.len,
																ENET_PACKET_FLAG_RELIABLE);
															enet_peer_send(peer, 0, packet);
															//enet_host_flush(server);
															delete p.data;
															((PlayerInfo*)(event.peer->data))->netID = cId;
															onPeerConnect(peer);
															cId++;
														}

													}
													else
													{
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
														//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
														ENetPacket * packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														//enet_host_flush(server);
														delete p.data;
														((PlayerInfo*)(event.peer->data))->netID = cId;
														onPeerConnect(peer);
														cId++;
													}


													if (((PlayerInfo*)(peer->data))->haveGrowId == false)
													{
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7[`4PROGRESS WON'T BE SAVED!`7] You can still join other worlds but it's recommended to create a `2GrowID, in order to save your account progress`7, `0it's free!"));
														ENetPacket * packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}

													int countx = 0;
													ENetPeer * currentPeer;
													string namex = "";
													for (currentPeer = server->peers;
														currentPeer < &server->peers[server->peerCount];
														++currentPeer)
													{
														if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
															continue;
														countx++;
													}


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
													string ownerworld = info.Displayowner;
													string nameworld = info.name;

													GamePacket p2x = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWorld `0" + nameworld + " `oentered. There are `0" + std::to_string(otherpeoples) + " `oother people here`7, `0" + std::to_string(countx) + " `oonline."));
													ENetPacket * packet2x = enet_packet_create(p2x.data,
														p2x.len,
														ENET_PACKET_FLAG_RELIABLE);
													enet_peer_send(peer, 0, packet2x);
													delete p2x.data;
													if (ownerworld != "") {
														GamePacket p3x = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`0" + nameworld + " `$World Locked `oby " + ownerworld + "`5]"));
														ENetPacket * packet3x = enet_packet_create(p3x.data,
															p3x.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet3x);
														delete p3x.data;
													}

													
												}
												
												
											}
											else
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wWorld name cannot be longer than 15 characters."));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
												enet_peer_disconnect_now(peer, 0);
												enet_peer_reset(peer);
												

												GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
												ENetPacket * packet3 = enet_packet_create(p3.data,
													p3.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet3);
												delete p3.data;


												continue;
												//enet_peer_disconnect_later(peer, 0);
											}

										}


									}

									sendState(peer); //here
									sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
									
									
									


									if (info.allowMod == false && ((PlayerInfo*)(peer->data))->ghostalr == false && info.owner != ((PlayerInfo*)(peer->data))->rawName)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oNoclipping `wis disabled in here!"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p.data;

										((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
										((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
										
										sendClothes(peer);
										sendState(peer); //here
									}
									else
									{
										if (((PlayerInfo*)(peer->data))->isModState == true || ((PlayerInfo*)(peer->data))->ghostalr == true)
										{
											((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
											((PlayerInfo*)(peer->data))->canDoubleJump = true; //here
											
											((PlayerInfo*)(peer->data))->skinColor = -155;
											sendClothes(peer);
											
											//sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->puncheffect);
											//sendState(peer); //here

										}
									}

									if (info.weather != 0) {
										GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBaseWeather"), info.weather));
										ENetPacket * packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);


										enet_peer_send(peer, 0, packet2);
										delete p2.data;
									}
									

									/*int resx = 95;
									int resy = 23;*/


									/*for (int i = 0; i < world.width*world.height; i++)
									{
									if (world.items[i].foreground == 6) {
									resx = i%world.width;
									resy = i / world.width;
									}
									}


									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "SetRespawnPos"), resx + (world.width*resy)));
									memcpy(p2.data + 8, &(((PlayerInfo*)(event.peer->data))->netID), 4);
									ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									enet_host_flush(server);*/

									sendState(peer); //here
									sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
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

										GamePacket pj = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(((PlayerInfo*)(event.peer->data))->netID) + "\n"));
										ENetPacket * packetj = enet_packet_create(pj.data,
											pj.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetj);

										((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
										sendWorldOffers(peer);

										GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
										ENetPacket * packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet3);
										delete p3.data;

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
						
						if (id == "action")
						{


							if (act == "join_request")
							{
								isJoinReq = true;
							}
							if (act == "quit_to_exit")
							{

								if (((PlayerInfo*)(event.peer->data))->canExit)
								{
									


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


										string password = ((PlayerInfo*)(peer->data))->tankIDPass;
										j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
										j["username"] = username;
										j["password"] = hashPassword(password);
										j["adminLevel"] = 0;
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
									

										int ban = ((PlayerInfo*)(peer->data))->ban;
										j["isBanned"] = ban;

										int ip;
										j["ipID"] = peer->address.host;
										j["effect"] = ((PlayerInfo*)(peer->data))->effect;
										j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
										j["ip"] = ((PlayerInfo*)(peer->data))->charIP;
										j["boughtLGW"] = ((PlayerInfo*)(peer->data))->boughtLGW;
										j["boughtLGK"] = ((PlayerInfo*)(peer->data))->boughtLGK;
										j["boughtLGD"] = ((PlayerInfo*)(peer->data))->boughtLGD;
										j["boughtLGB"] = ((PlayerInfo*)(peer->data))->boughtLGB;
										j["boughtLKW"] = ((PlayerInfo*)(peer->data))->boughtLKW;
										j["boughtCWD"] = ((PlayerInfo*)(peer->data))->boughtCWD;
										j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS;
										j["boughtCDG"] = ((PlayerInfo*)(peer->data))->boughtCDG;
										j["aap"] = ((PlayerInfo*)(peer->data))->isAAP;
										j["receivedwarns"] = ((PlayerInfo*)(peer->data))->warns;
										j["receivedbans"] = ((PlayerInfo*)(peer->data))->bans;
										o << j << std::endl;

										o.close();
										
									
									


									sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
									sendWorldOffers(peer);


									((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								}
							}



							if (act == "quit")
							{
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

								if (((PlayerInfo*)(event.peer->data))->isInWorld)
								{

									

									((PlayerInfo*)(event.peer->data))->posXY = (int)pMov->x + (int)pMov->y;
									sendPuncheffect(peer, ((PlayerInfo*)(event.peer->data))->effect);
									//((PlayerInfo*)(peer->data))->canDoubleJump = true; //here
									//sendState(peer); //here

									
								}


								switch (pMov->packetType)
								{
								case 0:

									((PlayerInfo*)(event.peer->data))->x = pMov->x;
									((PlayerInfo*)(event.peer->data))->y = pMov->y;
									((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10;
									sendPData(peer, pMov);

									
									if (((PlayerInfo*)(peer->data))->resultnbr1 + ((PlayerInfo*)(peer->data))->resultnbr2 != ((PlayerInfo*)(peer->data))->Endresult)
									{
										cout << "Bot detected? Attempting player to disconnect from server... (IP: " << peer->address.host << ")";
										enet_peer_disconnect_now(peer, 0);
										enet_peer_reset(peer);
										
									}


									if (!((PlayerInfo*)(peer->data))->joinClothesUpdated)
									{
										((PlayerInfo*)(peer->data))->joinClothesUpdated = true;
										updateAllClothes(peer);
										updateInvis(peer);
										sendState(peer); //here
										sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
										sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->effect);

										if (((PlayerInfo*)(peer->data))->ghostalr)
										{
											((PlayerInfo*)(peer->data))->canDoubleJump = true; //here
											
											sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->effect);
										}

										
										//sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->effect);
										/*GamePacket p222 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
										ENetPacket * packet222 = enet_packet_create(p222.data,
											p222.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet222);*/



										if (((PlayerInfo*)(peer->data))->isinv == 1) {
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`^You are in invisibility mode, no one can see you!``"));
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

										
									}

									break;


								default:
									break;
								}
							
							PlayerMoving *data2 = unpackPlayerMoving(tankUpdatePacket);
							//cout << data2->packetType << endl;
							if (data2->packetType == 11)
							{
								//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << endl;
								//sendDrop(((PlayerInfo*)(event.peer->data))->netID, ((PlayerInfo*)(event.peer->data))->x, ((PlayerInfo*)(event.peer->data))->y, pMov->punchX, 1, 0);
								// lets take item
								//cout << "item was tried to be taken!";
								sendTake(peer, ((PlayerInfo*)(event.peer->data))->netID, ((PlayerInfo*)(event.peer->data))->x, ((PlayerInfo*)(event.peer->data))->y, data2->plantingTree);
									
							}
							if (data2->packetType == 7)
							{
								GamePacket pz = packetEnd(appendInt(appendString(createPacket(), "OnZoomCamera"), 0));
								//memcpy(p2.data + 8, &(((PlayerInfo*)(event.peer->data))->netID), 4);
								ENetPacket * packetz = enet_packet_create(pz.data,
									pz.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(event.peer, 0, packetz);
								delete pz.data;



								GamePacket ppp = packetEnd(appendInt(appendInt(appendInt(appendInt(appendInt(appendString(createPacket(), "OnPlayPositioned"), 1), 1), 1), 1), 1));
								//memcpy(ppp.data + 8, &(((PlayerInfo*)(event.peer->data))->netID), 4);
								
								ENetPacket * packetppp = enet_packet_create(ppp.data,
									ppp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetppp);
								delete ppp.data;

								GamePacket p3 = packetEnd(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
								ENetPacket * packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;

								GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
								memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);


								enet_peer_send(peer, 0, packet2);
								delete p2.data;

								/*PlayerInfo* p = ((PlayerInfo*)(peer->data));

								string username = PlayerDB::getProperName(p->rawName);
								{


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


									string password = ((PlayerInfo*)(peer->data))->tankIDPass;
									j["username"] = username;
									j["password"] = hashPassword(password);
									j["adminLevel"] = 0;
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
								
									int ban = p->ban;
									j["isBanned"] = ban;


									int ip;
									j["ipID"] = peer->address.host;
									j["effect"] = ((PlayerInfo*)(peer->data))->effect;
									j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;



									o << j << std::endl;


								}

								sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
								sendWorldOffers(peer);
							
								// lets take item>*/
							//}
							/*else
							{

								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`7Error while leaving a world. Try again or instead use the Exit World button in Menu please (safer)."));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete ps.data;



								((PlayerInfo*)(peer->data))->canLeave = true;

								PlayerInfo* p = ((PlayerInfo*)(peer->data));

								string username = PlayerDB::getProperName(p->rawName);
								{


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




									string password = ((PlayerInfo*)(peer->data))->tankIDPass;
									j["username"] = username;
									j["password"] = hashPassword(password);
									j["adminLevel"] = 0;
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
									
									if (j["isBanned"] == 1)
									{
										int ban = 1;
										j["isBanned"] = ban;
									}
									else
									{
										int ban = 0;
										j["isBanned"] = ban;
									}

									int ip;
									j["ipID"] = peer->address.host;

									vector <string>frns;
									if (j.count("friends") == 1) {
										for (int i = 0; i < j["friends"].size(); i++) {
											frns.push_back(j["friends"][i]);
										}
									}
									else {
										frns = {};
									}

									o << j << std::endl;


								}
							}*/
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

									if (pMov->plantingTree == 1780) {
										if (((PlayerInfo*)(event.peer->data))->boughtLGB == false)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item has to be `2purchased`o."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;


											break;
											((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										}
									}
									

									if (((PlayerInfo*)(event.peer->data))->cloth1 == pMov->plantingTree)
									{
										((PlayerInfo*)(peer->data))->effect = 8421376;
										sendState(peer); //here
										sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
										((PlayerInfo*)(event.peer->data))->cloth1 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth1 = pMov->plantingTree;
									if (pMov->plantingTree = 1780) {
										((PlayerInfo*)(peer->data))->effect = -1004;
										sendState(peer); //here
										sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
									}
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

									if (pMov->plantingTree == 7762) {
										if (((PlayerInfo*)(event.peer->data))->boughtCDG == false)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item has to be `2purchased`o."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;


											break;
											//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										}
									}


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
								case 5:

									

									if (pMov->plantingTree == 2592) {
										if (((PlayerInfo*)(event.peer->data))->boughtLGK == false)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item has to be `2purchased`o."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;


											break;
											//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										}
									}

									else if (pMov->plantingTree == 1782) {
										if (((PlayerInfo*)(event.peer->data))->boughtLGD == false)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item has to be `2purchased`o."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;


											break;
											//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										}										
									}									
									else if (pMov->plantingTree == 1956) {
										if (((PlayerInfo*)(event.peer->data))->boughtCWD == false)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item has to be `2purchased`o."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;


											break;
											//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										}
									}
									else if (pMov->plantingTree == 5480) {
										if (((PlayerInfo*)(event.peer->data))->boughtRFS == false)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item has to be `2purchased`o."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;


											break;
											//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										}
									}
									
									

									if (((PlayerInfo*)(event.peer->data))->cloth5 == pMov->plantingTree)
									{
										((PlayerInfo*)(peer->data))->effect = 8421376;
										sendState(peer); //here
										sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
										((PlayerInfo*)(event.peer->data))->cloth5 = 0;
										break;
									}
									if (pMov->plantingTree == 1782) {
										((PlayerInfo*)(peer->data))->effect = -1003;
										sendState(peer); //here
										sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
									}
									else if (pMov->plantingTree == 2592) {
										((PlayerInfo*)(peer->data))->effect = -981;
										sendState(peer); //here
										sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
									}
									else if (pMov->plantingTree == 2592) {
										((PlayerInfo*)(peer->data))->effect = -981;
										sendState(peer); //here
										sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
									}
									else if (pMov->plantingTree == 1956) {
										((PlayerInfo*)(peer->data))->effect = -997;
										sendState(peer); //here
										sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
									}
									((PlayerInfo*)(event.peer->data))->cloth5 = pMov->plantingTree;
									break;
								case 6:
									

									if (pMov->plantingTree == 1784) {
										if (((PlayerInfo*)(event.peer->data))->boughtLGW == false)
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item has to be `2purchased`o."));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;


											break;
											//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										}
									}
										
									else if (pMov->plantingTree == 7734) {
											if (((PlayerInfo*)(event.peer->data))->boughtLKW == false)
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item has to be `2purchased`o."));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);

												delete p.data;


												break;
												//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
											}
										}
									
									

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
										if (item == 156 || item == 362 || item == 678 || item == 736 || item == 7734 || item == 7762 || item == 818 || item == 1206 || item == 1460 || item == 1550 || item == 1574 || item == 1668 || item == 1672 || item == 1674 || item == 1784 || item == 1824 || item == 1936 || item == 1938 || item == 1970 || item == 2254 || item == 2256 || item == 2258 || item == 2260 || item == 2262 || item == 2264 || item == 2390 || item == 2392 || item == 3120 || item == 3308 || item == 3512 || item == 4534 || item == 4986 || item == 5754 || item == 6144 || item == 6334 || item == 6694 || item == 6818 || item == 6842 || item == 1934 || item == 3134 || item == 6004 || item == 1780 || item == 2158 || item == 2160 || item == 2162 || item == 2164 || item == 2166 || item == 2168 || item == 2438 || item == 2538 || item == 2778 || item == 3858 || item == 350 || item == 998 || item == 1738 || item == 2642 || item == 2982 || item == 3104 || item == 3144 || item == 5738 || item == 3112 || item == 2722 || item == 3114 || item == 4970 || item == 4972 || item == 5020 || item == 6284 || item == 4184 || item == 4628 || item == 5322 || item == 4112 || item == 4114 || item == 3442 || item == 8286) {
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

									
								
										if (((PlayerInfo*)(event.peer->data))->cloth_back == pMov->plantingTree) { //editz here

											((PlayerInfo*)(event.peer->data))->cloth_back = 0;
											break;
										}

										((PlayerInfo*)(event.peer->data))->cloth_back = pMov->plantingTree;

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
								sendPData(peer, pMov);
								// add talk buble
							}
							if (data2->punchX != -1 && data2->punchY != -1) {
								//cout << data2->packetType << endl;
								if (data2->packetType == 3)
								{
									sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);



									if (data2->plantingTree == 410) // checkpoint system playingohd gaming
									{
										if (getPlyersWorld(peer)->owner == ((PlayerInfo*)(peer->data))->rawName)
										{
											int checkposXY = data2->punchX + data2->punchY;
											std::string checkposXYstr = to_string(checkposXY);
											bool exist = std::experimental::filesystem::exists("checkpoints/" + getPlyersWorld(peer)->name + "/" + checkposXYstr);
											if (!exist)
											{

												
												// save file with coordinates to checkpoints folder.
											}
										}
									}
								}
								else {


								}
								/*Playerrmoving data;
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
			 // changeis was made here
			case ENET_EVENT_TYPE_DISCONNECT:
#ifdef TOTAL_LOG
				printf("Peer disconnected.\n");
#endif
				/* Reset the peer's client information. */
				/*ENetPeer* currentPeer;
				for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
				{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;


				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just left the game..."));
				ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet);
				enet_host_flush(server);
				}*/


				if (((PlayerInfo*)(peer->data))->passedCaptcha2 == true)
				{
					if (((PlayerInfo*)(peer->data))->haveGrowId) {


						PlayerInfo* p = ((PlayerInfo*)(peer->data));

						string username = PlayerDB::getProperName(p->rawName);
						{


							std::ofstream o("players/" + username + ".json");
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							json j;

							int ban = p->ban;
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



							string password = ((PlayerInfo*)(peer->data))->tankIDPass;
							j["username"] = username;
							j["password"] = hashPassword(password);
							j["adminLevel"] = 0;
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
						

							j["isBanned"] = ban;

							int ip;
							j["ipID"] = peer->address.host;
							j["effect"] = ((PlayerInfo*)(peer->data))->effect;
							j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;
							j["ip"] = ((PlayerInfo*)(peer->data))->charIP;
							j["boughtLGW"] = ((PlayerInfo*)(peer->data))->boughtLGW;
							j["boughtLGK"] = ((PlayerInfo*)(peer->data))->boughtLGK;
							j["boughtLGD"] = ((PlayerInfo*)(peer->data))->boughtLGD;
							j["boughtLGB"] = ((PlayerInfo*)(peer->data))->boughtLGB;
							j["boughtLKW"] = ((PlayerInfo*)(peer->data))->boughtLKW;
							j["boughtCWD"] = ((PlayerInfo*)(peer->data))->boughtCWD;
							j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS;
							j["boughtCDG"] = ((PlayerInfo*)(peer->data))->boughtCDG;
							j["aap"] = ((PlayerInfo*)(peer->data))->isAAP;
							j["receivedwarns"] = ((PlayerInfo*)(peer->data))->warns;
							j["receivedbans"] = ((PlayerInfo*)(peer->data))->bans;


							o << j << std::endl;

						}
					}
				}

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