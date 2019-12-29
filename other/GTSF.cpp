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
vector<string> bannedlist;
vector<string> nukedworlds;
vector<string> xwhitelist;
int effect = 1;
using json = nlohmann::json;

//#define TOTAL_LOG
#define REGISTRATION

ENetHost * server;
int cId = 1;
BYTE* itemsDat = 0;
bool whitelisted = false;
bool xwhitelisted = false;
int itemsDatSize = 0;
void  toUpperCase(std::string& str)
{
	std::transform(str.begin(), str.end(), str.begin(), ::toupper);
}

void findAndReplaceAll(std::string& data, std::string toSearch, std::string replaceStr)
{
	size_t pos = data.find(toSearch);

	while (pos != std::string::npos)
	{
		data.replace(pos, toSearch.size(), replaceStr);
		pos = data.find(toSearch, pos + replaceStr.size());
	}
}

/***bcrypt***/
std::vector<std::string> split(std::string strToSplit, char delimeter)
{
	std::stringstream ss(strToSplit);
	std::string item;
	std::vector<std::string> splittedStrings;
	while (std::getline(ss, item, delimeter))
	{
		splittedStrings.push_back(item);
	}
	return splittedStrings;
}

std::vector<std::string> split(std::string stringToBeSplitted, std::string delimeter)
{
	std::vector<std::string> splittedString;
	int startIndex = 0;
	int  endIndex = 0;
	while ((endIndex = stringToBeSplitted.find(delimeter, startIndex)) < stringToBeSplitted.size())
	{

		std::string val = stringToBeSplitted.substr(startIndex, endIndex - startIndex);
		splittedString.push_back(val);
		startIndex = endIndex + delimeter.size();

	}
	if (startIndex < stringToBeSplitted.size())
	{
		std::string val = stringToBeSplitted.substr(startIndex);
		splittedString.push_back(val);
	}
	return splittedString;

}

void ReplaceString(std::string & target, std::string var) {
	size_t pos = 0;
	while ((pos = target.find(var)) != std::string::npos) {
		target.erase(pos, var.length());
	}
}


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
		memcpy(packet->data+4, data, len);
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
	while (i<strleng)
	{
		int j = 0;
		while (i + j<strleng && j<delleng && str[i + j] == delimiter[j])
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
	memcpy(n+p.len+2, &sLen, 4);
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
	memcpy(p.data+p.len, &zero, 1);
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
#define cloth9 cloth_ances
struct PlayerInfo {
	bool isIn = false;
	bool fpb = false;
	int netID;
	string lastsbworld = "";
	string Chatname = "";
	string lastMsger = "";
	string lastMsgerTrue = "";
	string lastMsgWorld = "";
	int effect = 0;
	vector<string> worldbans;
	string lastfriend = "";
	vector<string>friendinfo;
	int level_xp = 0;
	int math_level = 300;
	int level = 1;
	bool cantalk = true;
	bool namechange = false;
	string rank = "";
	bool haveGrowId = false;
	string tankIDName = "";
	string tankIDPass = "";
	string requestedName = "";
	string rawName = "";
	string displayName = "";
	string country = "";
	int adminLevel = 0;
	string realcountry = "";
	string currentWorld = "EXIT";
	bool radio = true;
	int x;
	int y;
	int x1;
	int y1;
	unsigned long long gems = 0;
	int totalpunched = 0;
	bool isRotatedLeft = false;
	int lastdropitemcount = 0;
	int lastdropitem = 0;

	bool isUpdating = false;
	bool joinClothesUpdated = false;
	
	bool muted = false;

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

	bool canWalkInBlocks = false; // 1
	bool canDoubleJump = false; // 2
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
	//bool 
	int skinColor = 0x8295C3FF; //normal SKin color like gt!

	PlayerInventory inventory;

	long long int lastSB = 0;
	long long int lastPolice = 0;
	long long int lastVirtual = 0;
	long long int lastPrince = 0;
	long long int lastCat = 0;
	long long int lastFire = 0;
	long long int lastF = 0;
	long long int lastWan = 0;
	long long int lastSpace = 0;
	long long int lastAss = 0;
	long long int lastBFG = 0;
	long long int lastGus = 0;
	long long int lastWarp = 0;
	long long int lastAlp = 0;
	long long int lastApro = 0;
	long long int lastWaw = 0;
	long long int lastPrin = 0;
	long long int lastZav = 0;
	long long int lastINV = 0;
	long long int lastMSB = 0;
	long long int lastVSB = 0;
	long long int lastP = 0;
	long long int lastCSB = 0;
	long long int lastBC = 0;
	long long int lastNSB = 0;
	long long int lastITS = 0;
	long long int lastGSB = 0;
	long long int lastYSB = 0;
	long long int lastAHH = 0;
	long long int lastMAVSB = 0;
	long long int lastMAGSB = 0;
	long long int lastSHOP = 0;
};


int getState(PlayerInfo* info) {
	int val = 0;
	val |= info->canWalkInBlocks << 0;
	val |= info->canDoubleJump << 1;
	val |= info->isInvisible << 2;
	val |= info->noHands << 3;
	val |= info->noEyes << 4;
	val |= info->noBody << 5;
	val |= info->devilHorns << 6;
	val |= info->goldenHalo << 7;
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
	string admins = "";
	string name = "TEST";
	int weather = 0;
	WorldItem* items;
	string owner = "";
	bool isPublic=false;
};

WorldInfo generateWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width * world.height];
	for (int i = 0; i < world.width * world.height; i++)
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
class PlayerDB {
public:
	static string getProperName(string name);
	static string PlayerDB::fixColors(string text);
	static int playerLogin(ENetPeer* peer, string username, string password);
	static int saveplayerinfo(ENetPeer* username);
	static int playerRegister(string username, string password, string passwordverify, string email, string discord);
	static int saveset(string username, int cloth_hair, int cloth_shirt, int cloth_pants, int cloth_feet, int cloth_face, int cloth_hand, int cloth_back, int cloth_mask, int cloth_neck, int cloth_ances, int gems, int level, int skinColor);
};
int PlayerDB::saveplayerinfo(ENetPeer* peer) {
	ofstream outfile;
	outfile.open("players/EXTERNAL/" + ((PlayerInfo*)(peer->data))->tankIDName + ".dat");
	outfile.clear();
	outfile << ((PlayerInfo*)(peer->data))->tankIDName + "|" + to_string(((PlayerInfo*)(peer->data))->level) + "|" + to_string(((PlayerInfo*)(peer->data))->level_xp) + "|" + to_string(((PlayerInfo*)(peer->data))->math_level) + "|" + to_string(((PlayerInfo*)(peer->data))->gems);
	outfile.close();
	return 1;
}
string PlayerDB::getProperName(string name) {
	string newS;
	for (char c : name) newS+=(c >= 'A' && c <= 'Z') ? c-('A'-'a') : c;
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
			
			
			if (i+1 < text.length() && text[i + 1] == '`')
			{
				colorLevel--;
			}
			else {
				colorLevel++;
			}
			i++;
		} else {
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
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete p.data;
					}
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Someone else was logged into this account! He was kicked out now."));
						ENetPacket* packet = enet_packet_create(p.data,
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
int PlayerDB::playerRegister(string username, string password, string passwordverify, string email, string discord) {
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
	o << j << std::endl;
	return 1;
}
int PlayerDB::saveset(string username, int cloth_hair, int cloth_shirt, int cloth_pants, int cloth_feet, int cloth_face, int cloth_hand, int cloth_back, int cloth_mask, int cloth_neck, int cloth_ances, int gems, int level, int skinColor) {
	if (username.length() < 3) return -2;
	std::ifstream ifs("sets/" + username + ".json");

	std::ofstream o("sets/" + username + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	json j;
	j["cloth_hair"] = cloth_hair;
	j["cloth_neck"] = cloth_neck;
	j["cloth_shirt"] = cloth_shirt;
	j["cloth_pants"] = cloth_pants;
	j["cloth_feet"] = cloth_feet;
	j["cloth_face"] = cloth_face;
	j["cloth_hand"] = cloth_hand;
	j["cloth_back"] = cloth_back;
	j["cloth_mask"] = cloth_mask;
	j["cloth_ances"] = cloth_ances;
	j["level"] = level;
	j["gems"] = gems;
	j["skinColor"] = skinColor;
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
		info.height = j["height"];
		info.owner = j["owner"].get<string>();
		info.isPublic = j["isPublic"];
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
		ENetPeer* currentPeer;

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

void saveAllWorlds() // atexit hack plz fix
{
	cout << "Saving worlds..." << endl;
	worldDB.saveAll();
	cout << "Worlds saved!" << endl;
}

WorldInfo* getPlyersWorld(ENetPeer* peer)
{
	try {
		return worldDB.get2(((PlayerInfo*)(peer->data))->currentWorld).ptr;
	} catch(int e) {
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
			else if(bt == "Seed") {
				def.blockType = BlockTypes::SEED;
			}
			else if(bt == "Consummable") {
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
			else if(cl == "Hat") {
				def.clothType = ClothTypes::HAIR;
			}
			else if(cl == "Shirt") {
				def.clothType = ClothTypes::SHIRT;
			}
			else if(cl == "Pants") {
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
				cout << "Critical error! Unordered database at item "<< std::to_string(current) <<"/"<< std::to_string(def.id) <<"!" << endl;
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
		if (admin.username == username && admin.password == password && admin.level>1) {
			using namespace std::chrono;
			if (admin.lastSB + 900000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level == 999)
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
			return admin.level > 0;
		}
	}
	return false;
}
string getRankText(string username, string password) {
	int lvl = 0;
	lvl = getAdminLevel(username, password);
	if (lvl == 0) {
		return "NONE";
	}
	if (lvl == 10) {
		return "`1VIP";
	}
	else if (lvl == 5) {
		return "`^Moderator";
	}
	else if (lvl == 999) {
		return "`9Owner";
	}
}
bool isSuperAdmin(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 999) {
			return true;
		}
	}
	return false;
}
bool isPolice(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 980) {
			return true;
		}
	}
	return false;
}
bool isVirtual(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 981) {
			return true;
		}
	}
	return false;
}
bool isPrince(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 982) {
			return true;
		}
	}
	return false;
}
bool isCat(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 983) {
			return true;
		}
	}
	return false;
}
bool isFire(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 984) {
			return true;
		}
	}
	return false;
}
bool isF(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 985) {
			return true;
		}
	}
	return false;
}
bool isWan(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 986) {
			return true;
		}
	}
	return false;
}
bool isSpace(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 987) {
			return true;
		}
	}
	return false;
}
bool isAss(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 988) {
			return true;
		}
	}
	return false;
}
bool isBFG(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 989) {
			return true;
		}
	}
	return false;
}
bool isBro(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 990) {
			return true;
		}
	}
	return false;
}
bool isAlp(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 994) {
			return true;
		}
	}
	return false;
}
bool isApro(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 995) {
			return true;
		}
	}
	return false;
}
bool isWaw(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 996) {
			return true;
		}
	}
	return false;
}
bool isPrin(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 997) {
			return true;
		}
	}
	return false;
}
bool isCole(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 998) {
			return true;
		}
	}
	return false;
}
bool isChaos(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 993) {
			return true;
		}
	}
	return false;
}
bool isManager(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 992) {
			return true;
		}
	}
	return false;
}
bool isGuard(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 991) {
			return true;
		}
	}
	return false;
}
bool isZav(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 500) {
			return true;
		}
	}
	return false;
}
bool isChicken(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 400) {
			return true;
		}
	}
	return false;
}
bool isMarius(string username, string password) {
	bool haveSuperSupporterName = true;
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 200) {
			return true;
		}
	}
	return false;
}
bool isLegend(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 100) {
			return true;
		}
	}
	return false;
}
bool isMod(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1) {
			return true;
		}
	}
	return false;
}
bool isDev(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 300) {
			return true;
		}
	}
	return false;
}
bool Mod(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 5) {
			return true;
		}
	}
	return false;
}
bool isVIP(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 2) {
			return true;
		}
	}
	return false;
}
bool VIP(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 10) {
			return true;
		}
	}
	return false;
}
bool isSci(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1000) {
			return true;
		}
	}
	return false;
}
bool isYuz(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1001) {
			return true;
		}
	}
	return false;
}
bool isUsed(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1002) {
			return true;
		}
	}
	return false;
}
bool isAh(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1003) {
			return true;
		}
	}
	return false;
}
bool isShop(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1004) {
			return true;
		}
	}
	return false;
}
bool isRare(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1005) {
			return true;
		}
	}
	return false;
}
bool isHere(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}
bool checkNetIDs(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->netID == ((PlayerInfo*)(peer2->data))->netID;
}

bool checkNetIDs2(ENetPeer* peer, string nid)
{
	return ((PlayerInfo*)(peer->data))->netID == stoi(nid);
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
		memcpy(data2 + (i*4) + (asdf2.length() / 2), &val, 4);
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

		if (((PlayerInfo*)(peer->data))->haveGrowId) {

			PlayerInfo* p = ((PlayerInfo*)(peer->data));

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
			int skinColor = p->skinColor;
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
			j["skinColor"] = skinColor;
			j["ClothShirt"] = clothshirt;
			j["ClothPants"] = clothpants;
			j["ClothNeck"] = clothneck;
			j["ClothHair"] = clothhair;
			j["ClothFeet"] = clothfeet;
			j["ClothMask"] = clothmask;

			o << j << std::endl;
		}

		//enet_host_flush(server);
		delete p3.data;
		string username1;
		int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
		username1 = ((PlayerInfo*)(peer->data))->rawName;
		cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
		skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
		cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
		cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
		cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
		cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
		cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
		cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
		cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
		cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
		cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
		level1 = ((PlayerInfo*)(peer->data))->level;
		gems1 = ((PlayerInfo*)(peer->data))->gems;
		PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
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
	void sendWizard(ENetPeer* peer, int x, int y)
	{
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Legendary Wizard``|left|1790|\nadd_textbox|`oGreetings, Traveler! I am the Legendary Wizard. Should to embark on a Legendary Quest, Simply choose one below.|left|\nadd_spacer|small|\nadd_button|ltitle|Quest for Honor|noflags|0|0|\nadd_button|lsky|Quest Of The Sky|noflags|0|0|\nadd_button|ldrag|Quest for Fire|noflags|0|0|\nadd_button|lbot|Quest Of Steel|noflags|0|0|\nadd_button|lwings|Quest Of The Heavens|noflags|0|0|\nadd_button|lkat|Quest of Blade|noflags|0|0|\nadd_button|lwhip|Quest for Condour|noflags|0|0|\nadd_spacer|small|\nadd_button|c0co|Close|noflags|0|0|\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);

		//enet_host_flush(server);
		delete p.data;
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
	void sendRing(ENetPeer* peer, int x, int y)
	{
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wI am the Ring Master please choose a Ring below :|left|1900|\n\nadd_spacer|small|\nadd_button_with_icon|ringf|Ring of Force|noflags|1874|\nadd_button_with_icon|ringw|Ring of Winds|noflags|1876|\nadd_button_with_icon|ringg|Gemini Ring|noflags|1986|\nadd_button_with_icon|ringwat|Ring of Water|noflags|2970||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);

		//enet_host_flush(server);
		delete p.data;
	}
	void sendRoulete(ENetPeer* peer, int x, int y)
	{
		using namespace std::chrono;
		if (((PlayerInfo*)(peer->data))->lastSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
		{
			((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
		}
		else {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Please wait `25`o Seconds till you spin again!"));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet);
			delete p.data;
		}
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
				GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`0[" + name + " `0spun the wheel and got `4" + std::to_string(val) + "`0]"));
				ENetPacket * packet1 = enet_packet_create(p1.data,
					p1.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet1);
				delete p1.data;
			}
			string name = ((PlayerInfo*)(peer->data))->displayName;
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0[" + name + " `0spun the wheel and got `4" + std::to_string(val) + "`0]"), 0));
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(currentPeer, 0, packet2);
			delete p2.data;

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

		WorldInfo* world = getPlyersWorld(peer);

		if (getItemDef(tile).blockType == BlockTypes::CONSUMABLE) return;

		if (world == NULL) return;
		if (x<0 || y<0 || x>world->width || y>world->height) return;
		sendNothingHappened(peer, x, y);
		if (world->items[x + (y * world->width)].foreground == 758)
			sendRoulete(peer, x, y);
		if (world->items[x + (y * world->width)].foreground == 1790)
			sendWizard(peer, x, y);
		if (world->items[x + (y * world->width)].foreground == 1900)
			sendRing(peer, x, y);
		if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			if (world->items[x + (y * world->width)].foreground == 6 || world->items[x + (y * world->width)].foreground == 8 || world->items[x + (y * world->width)].foreground == 3760)
				return;
			if (tile == 6 || tile == 8 || tile == 3760 || tile == 6864)
				return;
		}
		if (!isDev(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			if (world->items[x + (y * world->width)].foreground == 394 || world->items[x + (y * world->width)].foreground == 396 || world->items[x + (y * world->width)].foreground == 1614 || world->items[x + (y * world->width)].foreground == 1790 || world->items[x + (y * world->width)].foreground == 1900)
				return;
			if (tile == 394 || tile == 396 || tile == 1614 || tile == 1790 || tile == 1900)
				return;
		}
		if (world->name == "ADMIN" && !getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			if (world->items[x + (y * world->width)].foreground == 758)
				sendRoulete(peer, x, y);
			return;
		}
		if (world->name == "ADMIN" && !getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			if (world->items[x + (y * world->width)].foreground == 1900)
				sendRing(peer, x, y);
			return;
		}
		if (world->name == "ADMIN" && !getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			if (world->items[x + (y * world->width)].foreground == 1790)
				sendWizard(peer, x, y);
			return;
		}
		if (world->name != "ADMIN") {
			if (world->owner != "") {
				if (((PlayerInfo*)(peer->data))->rawName == world->owner || isDev(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {
					// WE ARE GOOD TO GO
					if (tile == 32) {
						if (world->items[x + (y * world->width)].foreground == 242 or world->items[x + (y * world->width)].foreground == 202 or world->items[x + (y * world->width)].foreground == 204 or world->items[x + (y * world->width)].foreground == 206 or world->items[x + (y * world->width)].foreground == 2408 or world->items[x + (y * world->width)].foreground == 5980 or world->items[x + (y * world->width)].foreground == 2950 or world->items[x + (y * world->width)].foreground == 5814 or world->items[x + (y * world->width)].foreground == 4428 or world->items[x + (y * world->width)].foreground == 1796 or world->items[x + (y * world->width)].foreground == 4802 or world->items[x + (y * world->width)].foreground == 4994 or world->items[x + (y * world->width)].foreground == 5260 or world->items[x + (y * world->width)].foreground == 7188)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wShould this world be publicly breakable?``|left|242|\n\nadd_spacer|small|\nadd_button_with_icon|worldPublic|Public|noflags|2408||\nadd_button_with_icon|worldPrivate|Private|noflags|202||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
					}
				}
				else if (world->isPublic)
				{
					if (world->items[x + (y * world->width)].foreground == 242)
					{
						return;
					}
				}
				else {
					return;
				}
				if (tile == 242) {
					return;
				}
			}
		}
		// WE ARE GOOD TO GO
		if (tile == 32)
		{
			if (world->items[x + (y * world->width)].foreground == 4856)
			{
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wLevel Leaderboard``|left|1488|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_textbox|`wThis Event will only appear once a month, this Leaderboard will be updated once a day, after the Event ends the player that has the `2Highest Level`w will get `2100 Million Gems`w so what are you waiting for? Get up to `$20 Levels`w to Join!|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`91.`w Marius, with `2512 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`s2.`w Yaocat, with `2288 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`63.`w King, with `2138 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w4.`w Today, with `2137 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w5.`w Devil, with `290 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w6.`w Boss, with `285 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w7.`w Zav, with `276 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w8.`w BluePanda, with `241 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w9.`w LaYellow, with `240 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w10.`w ItsRare, with `224 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w11.`w Quiambao of Legend, with `220 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`wLast Date Updated: `$May 4, 2019|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				//enet_host_flush(server);
				delete p.data;
			}
		}
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 1490)
				{
					world->weather = 10;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			if (tile == 32)
			{
				if (world->items[x + (y * world->width)].foreground == 2978)
				{
					string x = "set_default_color|`3\n";

					x.append("\nadd_label_with_icon|big|`wVending Machine|left|2978|");
					x.append("\nadd_spacer|small|");
					x.append("\nadd_label|small|`oThis `2Vending Machine`o looks empty.|left|");
					x.append("\nadd_spacer|small|");
					//x.append("\nadd_button|finditem|`9Find!|noflags|0|0|");
					x.append("\nend_dialog|buyitem|Close|");
					x.append("\nadd_quick_exit|");

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), x));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
				}
			}
		}
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 934)
				{
					world->weather = 2;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 946)
				{
					world->weather = 3;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 1490)
				{
					world->weather = 10;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 932)
				{
					world->weather = 4;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 984)
				{
					world->weather = 5;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 1210)
				{
					world->weather = 8;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 1364)
				{
					world->weather = 11;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 1750)
				{
					world->weather = 15;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 2046)
				{
					world->weather = 17;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 2284)
				{
					world->weather = 18;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 2744)
				{
					world->weather = 19;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 3252)
				{
					world->weather = 20;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 3446)
				{
					world->weather = 21;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 3534)
				{
					world->weather = 22;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 3694)
				{
					world->weather = 25;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 3832)
				{
					world->weather = 29;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 1490)
				{
					world->weather = 10;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 4242)
				{
					world->weather = 30;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 4486)
				{
					world->weather = 31;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 4776)
				{
					world->weather = 32;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 4892)
				{
					world->weather = 33;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 5000)
				{
					world->weather = 34;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 5112)
				{
					world->weather = 35;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 5654)
				{
					world->weather = 36;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 5716)
				{
					world->weather = 37;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 5958)
				{
					world->weather = 38;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 6854)
				{
					world->weather = 42;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
		{
			// WE ARE GOOD TO GO
			if (tile == 18)
			{
				if (world->items[x + (y * world->width)].foreground == 7644)
				{
					world->weather = 44;
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
							ENetPacket* packet2 = enet_packet_create(p2.data,
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
			def.breakHits = 3;
			def.blockType = BlockTypes::UNKNOWN;
#ifdef TOTAL_LOG
			cout << "Ugh, unsupported item " << tile << endl;
#endif
		}

		if (tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 4520 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
		if (tile == 5708 || tile == 5709 || tile == 5780 || tile == 5781 || tile == 5782 || tile == 5783 || tile == 5784 || tile == 5785 || tile == 5710 || tile == 5711 || tile == 5786 || tile == 5787 || tile == 5788 || tile == 5789 || tile == 5790 || tile == 5791 || tile == 6146 || tile == 6147 || tile == 6148 || tile == 6149 || tile == 6150 || tile == 6151 || tile == 6152 || tile == 6153 || tile == 5670 || tile == 5671 || tile == 5798 || tile == 5799 || tile == 5800 || tile == 5801 || tile == 5802 || tile == 5803 || tile == 5668 || tile == 5669 || tile == 5792 || tile == 5793 || tile == 5794 || tile == 5795 || tile == 5796 || tile == 5797 || tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
		if (tile == 1902 || tile == 1508 || tile == 428) return;
		if (tile == 410 || tile == 1770 || tile == 4720 || tile == 4882 || tile == 3808 || tile == 6392 || tile == 3212 || tile == 1832 || tile == 4742 || tile == 3496 || tile == 3270 || tile == 4722) return;
		if (tile >= 7068) return;
		if (tile == 18) {
			if (world->items[x + (y * world->width)].background == 6864 && world->items[x + (y * world->width)].foreground == 0) return;
			if (world->items[x + (y * world->width)].background == 0 && world->items[x + (y * world->width)].foreground == 0) return;
			//data.netID = -1;
			data.packetType = 0x8;
			data.plantingTree = 4;
			using namespace std::chrono;
			//if (world->items[x + (y*world->width)].foreground == 0) return;
			if ((duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() - world->items[x + (y * world->width)].breakTime >= 4000)
			{
				world->items[x + (y * world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				world->items[x + (y * world->width)].breakLevel = 4; // TODO
				if (world->items[x + (y * world->width)].foreground == 758)
					sendRoulete(peer, x, y);
				if (world->items[x + (y * world->width)].foreground == 1790)
					sendWizard(peer, x, y);
				if (world->items[x + (y * world->width)].foreground == 1900)
					sendRing(peer, x, y);
			}
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
				if (world->items[x + (y * world->width)].foreground == 1790)
					sendWizard(peer, x, y);
				if (world->items[x + (y * world->width)].foreground == 1900)
					sendRing(peer, x, y);
			}
			else {
				if (y < world->height && world->items[x + (y * world->width)].breakLevel + 3 >= def.breakHits * 3) { // TODO
					data.packetType = 0x3;// 0xC; // 0xF // World::HandlePacketTileChangeRequest
					data.netID = -1;
					data.plantingTree = tile;
					world->items[x + (y * world->width)].breakLevel = 0;
					if (world->items[x + (y * world->width)].foreground != 0)
					{
						if (world->items[x + (y * world->width)].foreground == 242 or world->items[x + (y * world->width)].foreground == 202 or world->items[x + (y * world->width)].foreground == 204 or world->items[x + (y * world->width)].foreground == 206 or world->items[x + (y * world->width)].foreground == 2408 or world->items[x + (y * world->width)].foreground == 5980 or world->items[x + (y * world->width)].foreground == 2950 or world->items[x + (y * world->width)].foreground == 5814 or world->items[x + (y * world->width)].foreground == 4428 or world->items[x + (y * world->width)].foreground == 1796)
						{
							world->owner = "";
							world->admins = "";
							world->isPublic = false;

							WorldInfo* world = getPlyersWorld(peer);
							string nameworld = world->name;
							GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`w" + nameworld + " `ohas had its `$World Lock `oremoved!`5]"));
							ENetPacket * packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet3);


						}

						world->items[x + (y * world->width)].foreground = 0;

						int randomGem = (rand() % 50) + 1;
						((PlayerInfo*)peer->data)->gems = ((PlayerInfo*)peer->data)->gems + randomGem;
						GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)peer->data)->gems));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						
						((PlayerInfo*)peer->data)->totalpunched = ((PlayerInfo*)peer->data)->totalpunched + 1;
						((PlayerInfo*)peer->data)->level_xp = ((PlayerInfo*)peer->data)->level_xp + 1;
						if (((PlayerInfo*)peer->data)->level_xp == ((PlayerInfo*)peer->data)->math_level) {
							((PlayerInfo*)peer->data)->math_level = ((PlayerInfo*)peer->data)->math_level * 4;
							((PlayerInfo*)peer->data)->level = ((PlayerInfo*)peer->data)->level + 1;
							((PlayerInfo*)peer->data)->level_xp = 0;
							ENetPeer* currentPeer;
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), ((PlayerInfo*)peer->data)->displayName + " `ois now level `o" + std::to_string(((PlayerInfo*)peer->data)->level) + "!"));
							GamePacket p = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 46), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
							GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)peer->data)->displayName + " is now level " + std::to_string(((PlayerInfo*)peer->data)->level) + "!"), 0));

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);

									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);

									ENetPacket* packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
								}
							}
							delete p2.data;

						}
						
					}
					else {
						int randomGem = (rand() % 50) + 1;
						((PlayerInfo*)peer->data)->gems = ((PlayerInfo*)peer->data)->gems + randomGem;
						GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)peer->data)->gems));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						world->items[x + (y * world->width)].background = 0;
						((PlayerInfo*)peer->data)->totalpunched = ((PlayerInfo*)peer->data)->totalpunched + 1;
						((PlayerInfo*)peer->data)->level_xp = ((PlayerInfo*)peer->data)->level_xp + 1;
						if (((PlayerInfo*)peer->data)->level_xp == ((PlayerInfo*)peer->data)->math_level) {
							((PlayerInfo*)peer->data)->math_level = ((PlayerInfo*)peer->data)->math_level * 4;
							((PlayerInfo*)peer->data)->level = ((PlayerInfo*)peer->data)->level + 1;
							((PlayerInfo*)peer->data)->level_xp = 0;
							ENetPeer* currentPeer;
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), ((PlayerInfo*)peer->data)->displayName + " `wis now level " + std::to_string(((PlayerInfo*)peer->data)->level) + "!"));
							GamePacket p = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 46), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
							GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)peer->data)->displayName + " is now level " + std::to_string(((PlayerInfo*)peer->data)->level) + "!"), 0));

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);

									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);

									ENetPacket* packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
								}
							}
							delete p2.data;

						}
					}
				}
				else {
				if (y < world->height)
				{
					world->items[x + (y * world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					world->items[x + (y * world->width)].breakLevel += 4; // TODO
					if (world->items[x + (y * world->width)].foreground == 758)
						sendRoulete(peer, x, y);
					if (world->items[x + (y * world->width)].foreground == 1790)
						sendWizard(peer, x, y);
					if (world->items[x + (y * world->width)].foreground == 1900)
						sendRing(peer, x, y);
				}
			}
		}

	}
		else {
			for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
			{
				if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == tile)
				{
					if ((unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount>1)
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
				world->items[x + (y * world->width)].background = tile;
			}
			else {
				world->items[x + (y * world->width)].foreground = tile;
				if (tile == 242) {
					world->owner = ((PlayerInfo*)(peer->data))->rawName;
					world->isPublic = false;
					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer)) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`w" + world->name + " `ohas been World Locked by " + ((PlayerInfo*)(peer->data))->displayName + "`5]"));
							string text = "action|play_sfx\nfile|audio/use_lock.wav\ndelayMS|0\n";
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
							delete p.data;


							ENetPacket* packet4 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet4);

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
			if (isHere(peer, currentPeer)) {
				SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);

				//cout << "Tile update at: " << data.punchX << "x" << data.punchY << endl;
			}
		}
	}

	void sendPlayerLeave(ENetPeer* peer, PlayerInfo* player)
	{
		sendConsoleMsg(peer, "Event : `2Raining Gems");
		ENetPeer* currentPeer;
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
		GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->displayName + "`5 left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) -1) + "`5 others here>``"));
		GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5<`w" + player->displayName + "`5 left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`5 others here>``"), 0));
		string text = "action|play_sfx\nfile|audio/door_shut.wav\ndelayMS|0\n";
		BYTE * data = new BYTE[5 + text.length()];
		BYTE zero = 0;
		int type = 3;
		memcpy(data, &type, 4);
		memcpy(data + 4, text.c_str(), text.length());
		memcpy(data + 4 + text.length(), &zero, 1);

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				{
					ENetPacket* packet1 = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet1);

					if (!((PlayerInfo*)(peer->data))->isGhost) {
						ENetPacket* packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet3);
					}

					if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						if (!((PlayerInfo*)(peer->data))->isGhost) {

							ENetPacket* packet4 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet4);

						}
					}
				}
			}
		}
		delete p.data;
		delete p2.data;
		delete p3.data;
		delete data;
	}

	void sendLogonFail(ENetPeer* peer, string texts)
	{
		string text = "action|log\nmsg|" + texts + "\n";
		string text3 = "action|logon_fail\n";
		BYTE* data = new BYTE[5 + text.length()];
		BYTE* data3 = new BYTE[5 + text3.length()];
		BYTE zero = 0;
		int type = 3;
		memcpy(data, &type, 4);
		memcpy(data + 4, text.c_str(), text.length());
		memcpy(data + 4 + text.length(), &zero, 1);
		memcpy(data3, &type, 4);
		memcpy(data3 + 4, text3.c_str(), text3.length());
		memcpy(data3 + 4 + text3.length(), &zero, 1);

		ENetPacket* p = enet_packet_create(data,
			5 + text.length(),
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, p);
		ENetPacket* p2 = enet_packet_create(data3,
			5 + text3.length(),
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, p2);

		delete data;
		delete data3;
	}

	void sendLogonFail(ENetPeer* peer, string texts, string buttontext, string buttonurl)
	{
		string text = "action|log\nmsg|" + texts + "\n";
		string text2 = "action|set_url\nurl|" + buttonurl + "\nlabel|" + buttontext + "\n";
		string text3 = "action|logon_fail\n";
		BYTE* data = new BYTE[5 + text.length()];
		BYTE* data2 = new BYTE[5 + text2.length()];
		BYTE* data3 = new BYTE[5 + text3.length()];
		BYTE zero = 0;
		int type = 3;
		memcpy(data, &type, 4);
		memcpy(data + 4, text.c_str(), text.length());
		memcpy(data + 4 + text.length(), &zero, 1);

		memcpy(data2, &type, 4);
		memcpy(data2 + 4, text2.c_str(), text2.length());
		memcpy(data2 + 4 + text2.length(), &zero, 1);

		memcpy(data3, &type, 4);
		memcpy(data3 + 4, text3.c_str(), text3.length());
		memcpy(data3 + 4 + text3.length(), &zero, 1);

		ENetPacket* packet4 = enet_packet_create(data,
			5 + text.length(),
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet4);


		ENetPacket* packet5 = enet_packet_create(data2,
			5 + text2.length(),
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet5);

		ENetPacket* packet6 = enet_packet_create(data3,
			5 + text3.length(),
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet6);

		delete data;
		delete data2;
		delete data3;
	}

	void sendPlayerEnter(ENetPeer* peer, PlayerInfo* player)
	{
		sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
		ENetPeer* currentPeer;
		int count = 0;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			count++;
		}
		if (((PlayerInfo*)(peer->data))->haveGrowId)
		{
		}
		WorldInfo* world = getPlyersWorld(peer);
		string nameworld = world->name;
		GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->displayName + "`5 entered, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`5 others here>``"));
		GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5<`w" + player->displayName + "`5 entered, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld)) + "`5 others here>``"), 0));
		GamePacket p5 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWorld `w" + nameworld + " `oentered. There are `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + " `oother people here, `w" + std::to_string(count) + " `oonline."));
		ENetPacket * packet5 = enet_packet_create(p5.data,
			p5.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet5);
		delete p5.data;
		string text = "action|play_sfx\nfile|audio/door_open.wav\ndelayMS|0\n";
		BYTE * data = new BYTE[5 + text.length()];
		BYTE zero = 0;
		int type = 3;
		memcpy(data, &type, 4);
		memcpy(data + 4, text.c_str(), text.length());
		memcpy(data + 4 + text.length(), &zero, 1);

		if (isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass));
		{
			GamePacket penter1 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
				{
					if (!((PlayerInfo*)(peer->data))->isGhost)
					{
						ENetPacket* packet3 = enet_packet_create(penter1.data,
							penter1.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet3);
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
			if (isHere(peer, currentPeer))
			{


				GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				continue;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer)) {
						if (!((PlayerInfo*)(peer->data))->isGhost) {
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet2);

							ENetPacket* packet4 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet4);
							if (!((PlayerInfo*)(peer->data))->isGhost) {
								ENetPacket* packet = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
							}
						}
					}
				}
				delete data;
				delete p2.data;
				delete p3.data;

			}
		}
	}
	void sendChatMessage(ENetPeer* peer, int netID, string message)
	{

		if (!((PlayerInfo*)(peer->data))->haveGrowId) {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Register first in able to talk."));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet);
			delete p.data;
		}
		else {
			if (message.length() != 0) {
				ENetPeer* currentPeer;
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
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o>`^ " + message));
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID),"`^"+ message), 0));
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{

						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);

						//enet_host_flush(server);

						ENetPacket* packet2 = enet_packet_create(p2.data,
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
			if (isHere(peer, currentPeer))
			{
				if(((PlayerInfo*)(currentPeer->data))->isGhost)
					continue;
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
		((PlayerInfo*)(peer->data))->joinClothesUpdated = false;
		string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
		string worldName = worldInfo->name;
		int xSize = worldInfo->width;
		int ySize = worldInfo->height;
		int weather = worldInfo->weather; //weather
		int square = xSize*ySize;
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
				data.x = i%worldInfo->width;
				data.y = i/worldInfo->height;
				data.punchX = i%worldInfo->width;
				data.punchY = i / worldInfo->width;
				data.XSpeed = 0;
				data.YSpeed = 0;
				data.netID = -1;
				data.plantingTree = worldInfo->items[i].foreground;
				SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
		((PlayerInfo*)(peer->data))->currentWorld = worldInfo->name;
		delete data;

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
		if (item >= 7068) return;
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

	void sendState(ENetPeer* peer) {
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
				int var = 0x808000; // placing and breking
				memcpy(raw+1, &var, 3);
				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
		// TODO
	}

	void joinWorld(ENetPeer* peer, string act, int x2, int y2)
	{
		try {
			WorldInfo info = worldDB.get(act);
			sendWorld(peer, &info);


			int x = 3040;
			int y = 736;

			for (int j = 0; j < info.width * info.height; j++)
			{
				if (info.items[j].foreground == 6) {
					x = (j % info.width) * 32;
					y = (j / info.width) * 32;
				}
			}
			if (x2 != 0 && y2 != 0)
			{
				x = x2;
				y = y2;
			}

			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
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


			WorldInfo * world = getPlyersWorld(peer);
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
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
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


			GamePacket p22 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`` `5entered, `w" + std::to_string(otherpeoples) + "`` others here>``"));


			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer)) {
					{

						ENetPacket* packet2 = enet_packet_create(p22.data,
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
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
			}
			else if (e == 2) {
				((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have entered bad characters in the world name!"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
			}
			else if (e == 3) {
				((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Exit from what? Click back if you're done playing."));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
			}
			else {
				((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "I know this menu is magical and all, but it has its limitations! You can't visit this world!"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
			}
		}
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
	void sendPlayerTP(ENetPeer* peer, ENetPeer* otherpeer)
	{
		{
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
	void sendPlayerToWorld(ENetPeer * peer, PlayerInfo * player, string wrldname)
	{
		{
			sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
		}
		WorldInfo info = worldDB.get(wrldname);
		sendWorld(peer, &info);


		int x = 3040;
		int y = 736;


		for (int j = 0; j < info.width * info.height; j++)
		{
			if (info.items[j].foreground == 6) {
				x = (j % info.width) * 32;
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
			worldOffers += "add_floater|"+worlds[i].name+"|"+std::to_string(getPlayersCountInWorld(worlds[i].name))+"|0.55|3529161471\n";
		}
		//G0amePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
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

	/*
	action|log
msg|`4UPDATE REQUIRED!`` : The `$V2.981`` update is now available for your device.  Go get it!  You'll need to install it before you can play online.
[DBG] Some text is here: action|set_url
url|http://ubistatic-a.akamaihd.net/0098/20180909/GrowtopiaInstaller.exe
label|Download Latest Version
	*/
	int _tmain(int argc, _TCHAR* argv[])
	{
		cout << "Growtopia private server (c) Growtopia Noobs" << endl;
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
	addAdmin("sureking", "123132213", 100);
	addAdmin("sureking", "123132213", 981);
	addAdmin("sureking", "123132213", 989);
	addAdmin("sureking", "123132213", 994);
	addAdmin("sureking", "123132213", 992);
	addAdmin("sureking", "123132213", 982);
	addAdmin("sureking", "123132213", 988);
	addAdmin("sureking", "123132213", 987);
	addAdmin("sureking", "123132213", 991);
	addAdmin("sureking", "123132213", 990);
	addAdmin("sureking", "123132213", 980);
	addAdmin("sureking", "123132213", 500);
	addAdmin("sureking", "123132213", 1005);
	addAdmin("sureking", "123132213", 985);
	addAdmin("sureking", "123132213", 1002);
	addAdmin("sureking", "123132213", 1003);
	addAdmin("sureking", "123132213", 986);
	addAdmin("sureking", "123132213", 1004);
	addAdmin("sureking", "123132213", 1001);
	addAdmin("sureking", "123132213", 999);
	addAdmin("sureking", "123132213", 984);
	addAdmin("sureking", "123132213", 996);
	addAdmin("sureking", "123132213", 983);
	addAdmin("sureking", "123132213", 995);
	addAdmin("sureking", "123132213", 2);
	addAdmin("sureking", "123132213", 1);
	addAdmin("sureking", "123132213", 300);
	addAdmin("sureking", "123132213", 993);
	addAdmin("sureking", "123132213", 400);
	addAdmin("sureking", "123132213", 998);
	addAdmin("donate", "donate", 1);
	addAdmin("ibad", "kiyomi", 2);
	addAdmin("goldoflegend", "lineesh", 1000);
	addAdmin("deadshot", "Lancette", 1);
	addAdmin("2xvs", "dlngeri", 1);
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
	address.port = 17091;
	server = enet_host_create(&address /* the address to bind the server host to */,
		1024      /* allow up to 32 clients and/or outgoing connections */,
		10      /* allow up to 2 channels to be used, 0 and 1 */,
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
				ENetPeer* currentPeer;
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
				if (count > 3)
				{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rToo many accounts are logged on from this IP. Log off one account before playing please.``"));
					ENetPacket* packet = enet_packet_create(p.data,
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
			if (std::find(bannedlist.begin(), bannedlist.end(), ((PlayerInfo*)(peer->data))->tankIDName) != bannedlist.end())
			{
				sendLogonFail(peer, "`oSorry, but`w " + ((PlayerInfo*)(peer->data))->tankIDName + "`o account is `4Banned`o! If you have some questions please Contact Us at Discord!");
				enet_peer_disconnect_later(peer, 0);
			}
			if (std::find(xwhitelist.begin(), xwhitelist.end(), ((PlayerInfo*)(peer->data))->tankIDName) != xwhitelist.end())
			{
				sendLogonFail(peer, "Server is currently `4Down`o, Server might be under Maintenance, fixing some issues,  or adding some commands.");
				enet_peer_disconnect_later(peer, 0);
			}
			/*
			((PlayerInfo*)(peer->data))->xstring = genstring(10);
			GamePacket p = packetEnd(appendInt(appendInt(appendString(appendString(createPacket(), "onShowCaptcha"), "set_default_color|\n\nadd_label_with_icon|big|`wBot confirmation``|left|20|\nadd_textbox|What is 14?|left|\nadd_text_input|ccc_text|||128|\nend_dialog|" + ((PlayerInfo*)(peer->data))->xstring + "|Cancel|OK|"), 10), 11));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;

			int cmessageType = GetMessageTypeFromPacket(event.packet);
			switch (cmessageType) {
			case 2:
			{
				string ccch = GetTextPointerFromPacket(event.packet);
				if (ccch == "") {}
				cout << ccch << endl;
				if (ccch.find("action|dialog_return") == 0)
				{

					std::stringstream ss(ccch);
					std::string to;
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat.size() == 2) {
						}
					}
				}
			}
			}
			*/
			//if (peer->state == ENET_PEER_STATE_CONNECTED) {
			//if (((PlayerInfo*)(peer->data))->verified)
			//{
			if (((PlayerInfo*)(peer->data))->isUpdating)
			{
				continue;
			}
			int messageType = GetMessageTypeFromPacket(event.packet);
			WorldInfo* world = getPlyersWorld(peer);
			switch (messageType) {
			case 2:
			{

				//cout << GetTextPointerFromPacket(event.packet) << endl;
				string cch = GetTextPointerFromPacket(event.packet);
				if (cch == "") {}
				string str = cch.substr(cch.find("text|") + 5, cch.length() - cch.find("text|") - 1);
				if (cch.find("action|mod_trade") == 0) {
					GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFocreTradeEnd"), 1));
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet2);
					delete p2.data;
				}
				if (cch.find("action|help") == 0)
				{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wSome things to Help :``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_button|help10|`wWhere is our `2Discord Invite Link`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help1|`wWhere can I see the `4Rules`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|helps|`wWhere can I see my Commands?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help|`wHow to get `2Gems`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help2|`wHow to get `2Levels`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help3|`wHow to get the `eBlue Name`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help4|`wHow to add colors on my `2Name`w?|noflags|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					//enet_host_flush(server);
					delete p.data;
				}
				if (cch.find("action|respawn") == 0)
				{
					int x = 3040;
					int y = 736;

					if (!world) continue;

					for (int i = 0; i < world->width * world->height; i++)
					{
						if (world->items[i].foreground == 6) {
							x = (i % world->width) * 32;
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

						for (int i = 0; i < world->width * world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i % world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}
					{
						int x = 3040;
						int y = 736;

						for (int i = 0; i < world->width * world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i % world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket* packet2 = enet_packet_create(p2.data,
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
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
#endif
#ifdef REGISTRATION
					//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wCreating an Account``|left|1280|\n\nadd_spacer|small|\nadd_textbox|Welcome to `wGTSF Server`o by creating your Account you will have full access on some of our features!|\nadd_spacer|small|\nadd_textbox|Please kindly make your Username! Reminder : Badwords/Sexual Content words on your name is Illegal!|\nadd_text_input|username|Username :||30|\nadd_text_input|password|Password :||100|\nadd_text_input|passwordverify|Re-Enter Password :||100|\nend_dialog|register|Cancel|Create my Account!|\n"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
#endif
				}
				string wrenchText = "action|wrench\n|netid|";
				if (cch.find("action|wrench") == 0)
				{
					if (!((PlayerInfo*)(peer->data))->haveGrowId) {
						continue;
					}

					std::vector<std::string> id = split(str, '|');
					string lols = "";
					string gay = id[3];
					//add_player_info|" + name + "|" + levels + "|" + std::to_string(blocksbroken) + "|150|
					if (checkNetIDs2(peer, gay)) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_player_info|" + ((PlayerInfo*)(peer->data))->displayName + "|" + to_string(((PlayerInfo*)peer->data)->level) + "|" + to_string(((PlayerInfo*)peer->data)->level_xp) + "|" + to_string(((PlayerInfo*)peer->data)->math_level) + " |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_button|account|`wCreate New Account|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|helped|`2HELP!|noflags|0|0| |left|6746|\nadd_label_with_icon|small|`2Longpunch`w and `2Modzoom`w Activated!|left|2072|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wIf you are at Level 125 please contact a `2Moderator`w or an `9Owner`w to get the `eBlue Name`w!|left|1280|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Continue|noflags|0|0|\n"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}

					{
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (currentPeer == peer)
								continue;
							if (checkNetIDs2(currentPeer, gay)) {
								if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), ((PlayerInfo*)(currentPeer->data))->rawName) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {

									if (isSuperAdmin(((PlayerInfo*)(peer->data))->tankIDName, ((PlayerInfo*)(peer->data))->tankIDPass)) {
										ENetPeer* currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (currentPeer == peer)
												continue;
											if (isHere(peer, currentPeer))
											{
												if (checkNetIDs2(currentPeer, gay)) {

													WorldInfo info = worldDB.get(((PlayerInfo*)(peer->data))->currentWorld);
													if (info.owner == ((PlayerInfo*)(peer->data))->tankIDName) {
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `o(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`o)``|left|18|\n\nadd_spacer|small|\nadd_textbox|`2Player Gems`w: " + to_string(((PlayerInfo*)(currentPeer->data))->gems) + "|left| |left|6746|\nadd_label_with_icon|small|\nadd_button|report|`wReport Player|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nend_dialog|dialogWrenchMenu||Continue|"));
														ENetPacket * packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
													else {

														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `o(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`o)``|left|18|\n\nadd_spacer|small|\nadd_textbox|`2Player Gems`w: " + to_string(((PlayerInfo*)(currentPeer->data))->gems) + "|left| |left|6746|\nadd_label_with_icon|small|\nadd_button|report|`wReport Player|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nend_dialog|dialogWrenchMenu||Continue|"));
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
									else {
										ENetPeer* currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (currentPeer == peer)
												continue;
											if (isHere(peer, currentPeer))
											{
												if (checkNetIDs2(currentPeer, gay)) {

													WorldInfo info = worldDB.get(((PlayerInfo*)(peer->data))->currentWorld);
													if (info.owner == ((PlayerInfo*)(peer->data))->tankIDName) {
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `o(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`o)``|left|18|\n\nadd_spacer|small|\nadd_textbox|`2Player Gems`w: " + to_string(((PlayerInfo*)(currentPeer->data))->gems) + "|left| |left|6746|\nadd_label_with_icon|small|\nadd_button|report|`wReport Player|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nend_dialog|dialogWrenchMenu||Continue|"));
														ENetPacket * packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
													else {

														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `o(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`o)``|left|18|\n\nadd_spacer|small|\nadd_textbox|`2Player Gems`w: " + to_string(((PlayerInfo*)(currentPeer->data))->gems) + "|left| |left|6746|\nadd_label_with_icon|small|\nadd_button|report|`wReport Player|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nend_dialog|dialogWrenchMenu||Continue|"));
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
								}
								else {
									if (getAdminLevel(((PlayerInfo*)(peer->data))->tankIDName, ((PlayerInfo*)(peer->data))->tankIDPass) > 5) {
										ENetPeer* currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (currentPeer == peer)
												continue;
											if (isHere(peer, currentPeer))
											{
												if (checkNetIDs2(currentPeer, gay)) {

													WorldInfo info = worldDB.get(((PlayerInfo*)(peer->data))->currentWorld);
													if (info.owner == ((PlayerInfo*)(peer->data))->tankIDName) {
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `o(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`o)``|left|18|\n\nadd_spacer|small|\nadd_textbox|`2Player Gems`w: " + to_string(((PlayerInfo*)(currentPeer->data))->gems) + "|left| |left|6746|\nadd_label_with_icon|small|\nadd_button|report|`wReport Player|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nend_dialog|dialogWrenchMenu||Continue|"));
														ENetPacket * packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
													else {

														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `o(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`o)``|left|18|\n\nadd_spacer|small|\nadd_textbox|`2Player Gems`w: " + to_string(((PlayerInfo*)(currentPeer->data))->gems) + "|left| |left|6746|\nadd_label_with_icon|small|\nadd_button|report|`wReport Player|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nend_dialog|dialogWrenchMenu||Continue|"));
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
									else {
										ENetPeer* currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (currentPeer == peer)
												continue;
											if (isHere(peer, currentPeer))
											{
												if (checkNetIDs2(currentPeer, gay)) {

													WorldInfo info = worldDB.get(((PlayerInfo*)(peer->data))->currentWorld);
													if (info.owner == ((PlayerInfo*)(peer->data))->tankIDName) {
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `o(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`o)``|left|18|\n\nadd_spacer|small|\nadd_textbox|`2Player Gems`w: " + to_string(((PlayerInfo*)(currentPeer->data))->gems) + "|left| |left|6746|\nadd_label_with_icon|small|\nadd_button|report|`wReport Player|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nend_dialog|dialogWrenchMenu||Continue|"));
														ENetPacket * packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
													else {

														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `o(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`o)``|left|18|\n\nadd_spacer|small|\nadd_textbox|`2Player Gems`w: " + to_string(((PlayerInfo*)(currentPeer->data))->gems) + "|left| |left|6746|\nadd_label_with_icon|small|\nadd_button|report|`wReport Player|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nend_dialog|dialogWrenchMenu||Continue|"));
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
								}
							}
						}// for
					}

				}
				if (cch.find("action|friends") == 0)
				{
					GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|leader|Show Leaderboard``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet2);
					delete p2.data;

				}
				if (cch.find("action|leader") == 0)
				{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wLevel Leaderboard``|left|1488|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_textbox|`wThis Event will only appear once a month, this Leaderboard will be updated once a day, after the Event ends the player that has the `2Highest Level`w will get `2100 Million Gems`w so what are you waiting for? Get up to `$20 Levels`w to Join!|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`91.`w Marius, with `2512 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`s2.`w Yaocat, with `2288 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`63.`w King, with `2138 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w4.`w Today, with `2137 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w5.`w Devil, with `290 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w6.`w Boss, with `285 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w7.`w Zav, with `276 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w8.`w BluePanda, with `241 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w9.`w LaYellow, with `240 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w10.`w ItsRare, with `224 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w11.`w Quiambao of Legend, with `220 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`wLast Date Updated: `$May 4, 2019|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);

					//enet_host_flush(server);
					delete p.data;

				}
				if (cch.find("action|store") == 0)
				{
					/*GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|Welcome to the `2Growtopia Store``!  Tap the item you'd like more info on.`o  `wWant to get `5Supporter`` status? Any Gem purchase (or `57,000`` Gems earned with free `5Tapjoy`` offers) will make you one. You'll get new skin colors, the `5Recycle`` tool to convert unwanted items into Gems, and more bonuses!\nadd_button|iap_menu|Buy Gems|interface/large/store_buttons5.rttex||0|2|0|0||\nadd_button|subs_menu|Subscriptions|interface/large/store_buttons22.rttex||0|1|0|0||\nadd_button|token_menu|Growtoken Items|interface/large/store_buttons9.rttex||0|0|0|0||\nadd_button|pristine_forceps|`oAnomalizing Pristine Bonesaw``|interface/large/store_buttons20.rttex|Built to exacting specifications by GrowTech engineers to find and remove temporal anomalies from infected patients, and with even more power than Delicate versions! Note : The fragile anomaly - seeking circuitry in these devices is prone to failure and may break (though with less of a chance than a Delicate version)! Use with care!|0|3|3500|0||\nadd_button|itemomonth|`oItem Of The Month``|interface/large/store_buttons16.rttex|`2September 2018:`` `9Sorcerer's Tunic of Mystery!`` Capable of reflecting the true colors of the world around it, this rare tunic is made of captured starlight and aether. If you think knitting with thread is hard, just try doing it with moonbeams and magic! The result is worth it though, as these clothes won't just make you look amazing - you'll be able to channel their inherent power into blasts of cosmic energy!``|0|3|200000|0||\nadd_button|contact_lenses|`oContact Lens Pack``|interface/large/store_buttons22.rttex|Need a colorful new look? This pack includes 10 random Contact Lens colors (and may include Contact Lens Cleaning Solution, to return to your natural eye color)!|0|7|15000|0||\nadd_button|locks_menu|Locks And Stuff|interface/large/store_buttons3.rttex||0|4|0|0||\nadd_button|itempack_menu|Item Packs|interface/large/store_buttons3.rttex||0|3|0|0||\nadd_button|bigitems_menu|Awesome Items|interface/large/store_buttons4.rttex||0|6|0|0||\nadd_button|weather_menu|Weather Machines|interface/large/store_buttons5.rttex|Tired of the same sunny sky?  We offer alternatives within...|0|4|0|0||\n"));
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet2);
					delete p2.data;
					//enet_host_flush(server);*/
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`2GTSF Server Store|left|242|\n\nadd_spacer|small|\nadd_button_with_icon|worldPublic|`^Mod Role`o -`25`1 Dls|noflags|408|\nadd_button_with_icon|worldPublic|`1VIP Role`o -`21`1 Dl|noflags|1486|\nadd_button_with_icon|worldPrgiva|`wCustom SB`o - `250`9 Wls|noflags|2480|\nadd_button_with_icon|worldPublic|`wGems`o -`25000`w/`9Wl|noflags|112|\nadd_button_with_icon|worldPublic|`wLevels`o -`25`w/`9Wl|noflags|1488||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
					ENetPacket* packet = enet_packet_create(p.data,
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
						ENetPacket* packet = enet_packet_create(ps.data,
							ps.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
						continue;
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wDrop " + itemDefs.at(idx).name + "``|left|" + std::to_string(idx) + "|\nadd_textbox|`oHow many to drop?|\nadd_text_input|dropitemcount|||3|\nend_dialog|dropdialog|Cancel|OK|\n"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
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
					if (id == 18) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_textbox|You've punched : `w" + std::to_string(((PlayerInfo*)peer->data)->totalpunched) + "`` times.|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
					}
					if (itemDefs.size() < id || id < 0) continue;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);


					delete p.data;
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
					string password = "";
					string passwordverify = "";
					string email = "";
					string discord = "";
					bool isFindDialog = false;
					bool isDropDialog = false;
					string dropitemcount = "";
					string itemFind = "";
					bool isMSGDialog = false;
					string message = "";
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat.size() == 2) {
							if (infoDat[0] == "buttonClicked") btn = infoDat[1];
							if (infoDat[0] == "dialog_name" && infoDat[1] == "register")
							{
								isRegisterDialog = true;
							}
							if (infoDat[0] == "dialog_name" && infoDat[1] == "searchitem1337")
							{
								isFindDialog = true;
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
							if (infoDat[0] == "dialog_name" && infoDat[1] == "msg")
							{
								isMSGDialog = true;
							}
							if (isMSGDialog) {
								if (infoDat[0] == "username") username = infoDat[1];
								if (infoDat[0] == "message") message = infoDat[1];
							}
							if (isRegisterDialog) {
								if (infoDat[0] == "username") username = infoDat[1];
								if (infoDat[0] == "password") password = infoDat[1];
								if (infoDat[0] == "passwordverify") passwordverify = infoDat[1];
								if (infoDat[0] == "email") email = infoDat[1];
								if (infoDat[0] == "discord") discord = infoDat[1];
							}
						}
					}
					if (btn == "worldPublic") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = true;
					if (btn == "worldPrivate") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = false;
#ifdef REGISTRATION
					if (isMSGDialog) {
						string worldname = ((PlayerInfo*)(peer->data))->currentWorld;
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (((PlayerInfo*)(currentPeer->data))->rawName == username) {
								if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `0" + ((PlayerInfo*)(peer->data))->rawName + "`6 (`$in " + worldname + "`6) : " + message));
								GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6/msg " + username + " " + message));
								GamePacket ps2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `$" + username + "`6)"));
								ENetPacket * packetmsg13 = enet_packet_create(ps3.data,
									ps3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packetmsg13);
								ENetPacket * packet23 = enet_packet_create(ps2.data,
									ps2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet23);

								ENetPacket * packetdd = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packetdd);
								delete ps2.data;
								delete ps.data;
							}
						}
					}
					if (isDropDialog) {
						int x;

						try {
							x = stoi(dropitemcount);
						}
						catch (std::invalid_argument & e) {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Sorry but we can't drop that!"));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
							continue;
						}
						if (x < 0 || x >200) {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4That is too many/less to drop!"));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
							continue;
						}

						else {

							sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y, ((PlayerInfo*)(peer->data))->lastdropitem, x, 0);
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
					if (btn == "Off")
					{
						((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
						((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
						sendState(peer);
					}
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat.size() == 0) {
						}
						else if (infoDat[0] == "buttonClicked" && infoDat[1].rfind("grantMod", 0) == 0)
						{
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (peer == currentPeer)
									continue;
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								string lol = infoDat[1];
								std::vector<std::string> ids = split(lol, "grantMod");
								toUpperCase(ids[1]);
								string real = ((PlayerInfo*)(currentPeer->data))->rawName;
								toUpperCase(real);
								if (real == ids[1])
								{
									addAdmin(((PlayerInfo*)(currentPeer->data))->tankIDName, ((PlayerInfo*)(currentPeer->data))->tankIDPass, 7);
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYou changed rank of" + ((PlayerInfo*)(currentPeer->data))->rawName + "``"));
									ENetPacket * packet = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p2.data;
									if (currentPeer->state == ENET_PEER_STATE_CONNECTED) {
										GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYour rank has been changed!``"));
										ENetPacket* packet = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p3.data;
										GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/handle_up.rttex"), "You have beed promoted! Redirecting again..."), "audio/secret.wav"), 0));
										ENetPacket* packet1 = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet1);
										enet_peer_disconnect_later(currentPeer, 0);
										delete p.data;
									}
								}
							}
						}
					}
					if (btn == "buyitem") {
						string x = "set_default_color|`3\n";

						x.append("\nadd_label_with_icon|big|`wPurchase Confirmation|left|1366|");
						x.append("\nadd_spacer|small|");
						x.append("\nadd_label|small|`4You'll give:|left|");
						x.append("\nadd_label|small|`o (`w1`o)`7 World Lock|left|242|\nadd_label_with_icon|small|");
						x.append("\nadd_spacer|small|");
						x.append("\nadd_label|small|`2You'll get:|left|");
						x.append("\nadd_label|small|`o (`w10`o)`2 Dirt|left|2|\nadd_label_with_icon|small|");
						x.append("\nadd_spacer|small|");
						x.append("\nadd_label|small|`oAre you sure you want to make this purchase?|left|");
						//x.append("\nadd_button|finditem|`9Find!|noflags|0|0|");
						x.append("\nend_dialog|finditem|Cancel|`wOK|");
						x.append("\nadd_quick_exit|");

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), x));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (btn == "showoffline") {
						string onlinelist = "";
						string offlinelist = "";
						string offname = "";
						int onlinecount = 0;
						int totalcount = ((PlayerInfo*)(peer->data))->friendinfo.size();
						vector<string>offliness = ((PlayerInfo*)(peer->data))->friendinfo;

						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							string name = ((PlayerInfo*)(currentPeer->data))->rawName;

							if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
								onlinelist += "\nadd_button|f_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + "``|0|0|";
								onlinecount++;

								offliness.erase(std::remove(offliness.begin(), offliness.end(), name), offliness.end());
							}
						}
						for (std::vector<string>::const_iterator i = offliness.begin(); i != offliness.end(); ++i) {
							offname = *i;
							offlinelist += "\nadd_button|f_" + offname + "|`4OFFLINE: `o" + offname + "``|0|0|";
						}
						if (offlinelist == "") {
							offlinelist += "\nadd_textbox|All of your friends are online!|left|";
						}

						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\nadd_spacer|small|" + offlinelist + "\nadd_spacer|small|\n\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backonlinelist|Back``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;

					}
					if (btn.rfind("sendFriendRequest", 0) == 0) {
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 0) {
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									string lol = infoDat[1];
									std::vector<std::string> ids = split(lol, "sendFriendRequest");
									toUpperCase(ids[1]);
									if (checkNetIDs2(currentPeer, ids[1])) {

										if (((PlayerInfo*)(peer->data))->lastfriend == ((PlayerInfo*)(currentPeer->data))->rawName) {

											((PlayerInfo*)(peer->data))->friendinfo.push_back(((PlayerInfo*)(currentPeer->data))->rawName); //add


											((PlayerInfo*)(currentPeer->data))->friendinfo.push_back(((PlayerInfo*)(peer->data))->rawName);

											string text = "action|play_sfx\nfile|audio/love_in.wav\ndelayMS|0\n";
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
											BYTE * data = new BYTE[5 + text.length()];
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
						}
					}
					if (btn.rfind("f_spm_", 0) == 0) {
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 0) {
								string lol = infoDat[1];
								ENetPeer* currentPeer;
								std::vector<std::string> ids = split(lol, "f_spm_");
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->rawName != ids[1])
										continue;

									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`5Message to " + ((PlayerInfo*)(currentPeer->data))->displayName + "|left|660|\nadd_spacer|small|\nadd_text_input|spm_t_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|||128|\nadd_spacer|small|\nadd_button|spm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`5Send|0|0|\nadd_button|backonlinelist|`wBack|0|0|\nadd_quick_exit|"));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;
								}
							}
						}
					}
					if (btn.rfind("f_", 0) == 0) {
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 0) {
								string lol = infoDat[1];
								ENetPeer* currentPeer;
								std::vector<std::string> ids = split(lol, "f_");
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->rawName != ids[1])
										continue;

									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + "|left|1366|\n\nadd_spacer|small|\nadd_textbox|" + ((PlayerInfo*)(currentPeer->data))->displayName + " is `2online `onow in the world `w" + ((PlayerInfo*)(currentPeer->data))->currentWorld + "`o.|left|\nadd_spacer|small|\nadd_button|f_wt_" + ((PlayerInfo*)(currentPeer->data))->currentWorld + " |`oWarp to `5" + ((PlayerInfo*)(currentPeer->data))->currentWorld + "|0|0|\nadd_button|f_spm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`5Send Message|0|0|\nadd_spacer|small|\nadd_button|f_rf_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`oRemove as friend|0|0|\nadd_button|backonlinelist|`oBack|0|0|\nadd_quick_exit|"));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;
								}
							}
						}
					}
					if (btn.rfind("showModMenu", 0) == 0) {
						if (getAdminLevel(((PlayerInfo*)(peer->data))->tankIDName, ((PlayerInfo*)(peer->data))->tankIDPass) > 5) {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_textbox|Editing TEST (test)|left|\nadd_spacer|small|\nadd_textbox|Total Warnings:|left|\nadd_textbox|Currently, player don't have any warnings.|left|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `o2 week DGH||276|name|\nadd_label_with_icon_button||`w<-- `o4 week DGH||276|name|\nadd_label_with_icon_button||`w<-- `o8 week DGH||276|name|\nadd_label_with_icon_button||`w<-- `oPerma ban DGH||276|name|\nadd_label_with_icon_button||`w<-- `oPerma ban for hacking||276|name|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oFake auto-ban (use for hackers confuses them, online only)||4922|name|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
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

						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							string name = ((PlayerInfo*)(currentPeer->data))->rawName;

							if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
								onlinelist += "\nadd_button|f_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + "``|0|0|";
								onlinecount++;

								offliness.erase(std::remove(offliness.begin(), offliness.end(), name), offliness.end());
							}
						}
						for (std::vector<string>::const_iterator i = offliness.begin(); i != offliness.end(); ++i) {
							offname = *i;
							offlinelist += "\nadd_button|f_" + offname + "|`4OFFLINE: `o" + offname + "``|0|0|";
						}
						if (offlinelist == "") {
							offlinelist += "\nadd_textbox|All of your friends are online!|left|";
						}

						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\nadd_spacer|small|" + offlinelist + "\nadd_spacer|small|\n\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backonlinelist|Back``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;

					}
					if (btn.rfind("f_rf_", 0) == 0) {
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 0) {
								ENetPeer* currentPeer;
								string lol = infoDat[1];
								std::vector<std::string> ids = split(lol, "f_rf_");
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->rawName == ids[1]) {


										((PlayerInfo*)(peer->data))->friendinfo.erase(std::remove(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), ids[1]), ((PlayerInfo*)(peer->data))->friendinfo.end());


										((PlayerInfo*)(currentPeer->data))->friendinfo.erase(std::remove(((PlayerInfo*)(currentPeer->data))->friendinfo.begin(), ((PlayerInfo*)(currentPeer->data))->friendinfo.end(), ((PlayerInfo*)(peer->data))->rawName), ((PlayerInfo*)(currentPeer->data))->friendinfo.end());


										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND ALERT: `2" + ((PlayerInfo*)(peer->data))->displayName + " `ohas removed you as a friend."));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet);
										delete p.data;
									}
								}
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`4Friend removed``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`oOk, you are no longer friends with `o" + ids[1] + ".``|\n\nadd_spacer|small|\nadd_button||`oOK``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
					}
					if (btn == "backonlinelist") {

						string onlinefrnlist = "";
						int onlinecount = 0;
						int totalcount = ((PlayerInfo*)(peer->data))->friendinfo.size();
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							string name = ((PlayerInfo*)(currentPeer->data))->rawName;
							if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
								onlinefrnlist += "\nadd_button|f_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + "``|0|0|";
								onlinecount++;
								for (int i = 0; i < totalcount; i++) {
									cout << ((PlayerInfo*)(peer->data))->friendinfo[i] << endl;
								}
							}

						}

						if (totalcount == 0) {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_label|small|`oYou currently have no friends.  That's just sad.  To make some, click a person's wrench icon, then choose `5Add as friend`o.``|left|4|\n\nadd_spacer|small|\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						else if (onlinecount == 0) {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\nadd_label|small|`oNone of your friends are currently online.``|left|4|\n\nadd_spacer|small|\nadd_button|showoffline|`oShow offline too``|0|0|\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}

						else {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|" + onlinefrnlist + "\n\nadd_spacer|small|\nadd_button|showoffline|`oShow offline too``|0|0|\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
					}
					if (btn == "1")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wIf you are sure to`4GAMEBAN`w this Player please do /gameban (the player name).``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "2")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wIf you are sure to`4KICK`w this Player please do /kick (the player name).``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "3")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wIf you are sure to`4MUTE`w this Player please do /mute (the player name).``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "4")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wIf you want to `2Summon`w this Player please do /summon (the player name).``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "5")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wIf you want to Teleport to this player please do /warpto (the player name).``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "account")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wCreate New Account``|left|206|\n\nadd_spacer|small|\nadd_textbox|`2TIP `w: Creating a new account is like getting a GrowID but way easier.|\nadd_spacer|small|\nadd_textbox|Creating a new Account requires a `wnew name`o so choose carefully!|\nadd_text_input|username|Username||30|\nadd_text_input|password|Password||100|\nadd_text_input|passwordverify|Re-enter Password||100|\nend_dialog|register|Cancel|`wCreate My New Account!|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (btn == "helped")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wSome things to Help :``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_button|help10|`wWhere is our `2Discord Invite Link`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help1|`wWhere can I see the `4Rules`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|helps|`wWhere can I see my Commands?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help|`wHow to get `2Gems`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help2|`wHow to get `2Levels`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help3|`wHow to get the `eBlue Name`w?|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_button|help4|`wHow to add colors on my `2Name`w?|noflags|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "ldrag")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 1782;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						int netID = info->netID;
						ENetPeer* currentPeer;
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
								data.x = 1000;
								data.y = 1000;
								data.punchX = 0;
								data.punchY = 0;
								data.XSpeed = 300;
								data.YSpeed = 600;
								data.netID = netID;
								data.plantingTree = state;
								BYTE* raw = packPlayerMoving(&data);
								int var = 21; // placing and breking
								memcpy(raw + 1, &var, 3);
								SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 90), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (btn == "lsky")
					{
						((PlayerInfo*)(peer->data))->cloth_back = 7734;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						((PlayerInfo*)(peer->data))->canDoubleJump = true;
						int netID = info->netID;
						ENetPeer* currentPeer;
						int state = getState(info);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 90), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (btn == "help1")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wYou can see the `2GTSF Server Rules`w by doing /rules.``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "help")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wYou can get gems by `2Breaking Blocks`w, breaking a block will give you 1-50 gems when `2Raining Gems`w Event is here, on the regular day it will give you 1-5 Gems when breaking a block.``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "help2")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wYou can get `2Levels`w by breaking blocks, you can see your progress by wrenching your self.``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "leader")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wLevel Leaderboard``|left|1488|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_textbox|`wThis Event will only appear once a month, this Leaderboard will be updated once a day, after the Event ends the player that has the `2Highest Level`w will get `2100 Million Gems`w so what are you waiting for? Get up to `$20 Levels`w to Join!|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`91.`w Marius, with `2512 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`s2.`w Yaocat, with `2288 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`63.`w King, with `2138 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w4.`w Today, with `2137 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w5.`w Devil, with `290 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w6.`w Boss, with `285 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w7.`w Zav, with `276 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w8.`w BluePanda, with `241 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w9.`w LaYellow, with `240 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w10.`w ItsRare, with `224 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`w11.`w Quiambao of Legend, with `220 Levels`w.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`wLast Date Updated: `$May 4, 2019|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "help10")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wDiscord Invite Link :``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_url_button||``Discord: `2Join our Discord Server!``|NOFLAGS|https://discord.gg/yGsQDjA|Open link?|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "helps")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wYou can see the available commands by doing /help.``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "help3")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wYou can get the `eBlue Name`w by leveling up to 125, if you are at `2Level 125`w contact a `2Moderator`w as fast as you can!``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "help4")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wIn order to put colors on your name you need to go to the log in section and add ` and put any number or letter example ` e put it without any space.``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "help5")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wYou can get `2Levels`w by breaking blocks, you can see your progress by wrenching your self.``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "reportp")
					{
						string imie = str.substr(8, cch.length() - 8 - 1);
						string dupa;
						ENetPeer * currentPeer;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `w" + imie + "`o has been reported."));
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
							if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
							{
								dupa = ((PlayerInfo*)(currentPeer->data))->rawName;
							}
						}
						cout << "Report from " << ((PlayerInfo*)(peer->data))->rawName << "in world " << ((PlayerInfo*)(peer->data))->currentWorld << std::dec << "reported " << dupa << endl;
					}
					if (btn == "report")
					{
						string x = "set_default_color|`3\n";

						x.append("\nadd_label_with_icon|big|`wReport this player|left|1432|");
						x.append("\nadd_text_input|itemname|`oReason:||33|");
						x.append("\nadd_label|small|`1If you really want to report this player, click Report below!|left|");
						//x.append("\nadd_button|finditem|`9Find!|noflags|0|0|");
						x.append("\nend_dialog|reportp|Cancel|`wReport|");
						x.append("\nadd_quick_exit|");

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), x));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (btn == "lwings")
					{
						((PlayerInfo*)(peer->data))->cloth_back = 1784;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						((PlayerInfo*)(peer->data))->canDoubleJump = true;
						int netID = info->netID;
						ENetPeer* currentPeer;
						int state = getState(info);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 90), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (btn == "ringw")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 1876;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						((PlayerInfo*)(peer->data))->canDoubleJump = true;
						int netID = info->netID;
						ENetPeer* currentPeer;
						int state = getState(info);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 73), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (btn == "ringwat")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 2970;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						((PlayerInfo*)(peer->data))->canDoubleJump = true;
						int netID = info->netID;
						ENetPeer* currentPeer;
						int state = getState(info);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 73), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (btn == "ringg")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 1986;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						((PlayerInfo*)(peer->data))->canDoubleJump = true;
						int netID = info->netID;
						ENetPeer* currentPeer;
						int state = getState(info);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 73), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (btn == "ringf")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 1874;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						((PlayerInfo*)(peer->data))->canDoubleJump = true;
						int netID = info->netID;
						ENetPeer* currentPeer;
						int state = getState(info);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 73), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (btn == "lbot")
					{
						((PlayerInfo*)(peer->data))->cloth_shirt = 1780;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						int netID = info->netID;
						ENetPeer* currentPeer;
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
								data.x = 1000;
								data.y = 1000;
								data.punchX = 0;
								data.punchY = 0;
								data.XSpeed = 300;
								data.YSpeed = 600;
								data.netID = netID;
								data.plantingTree = state;
								BYTE* raw = packPlayerMoving(&data);
								int var = 20; // placing and breking
								memcpy(raw + 1, &var, 3);
								SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 90), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (btn == "effect0")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 0; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect1")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 1; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect2")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 2; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect3")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 3; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect4")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 4; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect5")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 5; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect6")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 6; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect7")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 7; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect8")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 8; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect9")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 9; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect10")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 10; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect11")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 11; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect12")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 12; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect13")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 13; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect14")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 14; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect15")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 15; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect16")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 16; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect17")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 17; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect18")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 18; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect19")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 19; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect20")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 20; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect21")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 21; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect22")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 22; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect23")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 23; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect24")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 24; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect25")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 25; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect26")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 26; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect27")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 27; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect28")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 28; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect29")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 29; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect30")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 30; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect31")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 31; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect32")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 32; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect33")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 33; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect34")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 34; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect35")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 35; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect36")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 36; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect37")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 37; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect38")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 38; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect39")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 39; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect40")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 40; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect41")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 41; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect42")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 42; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect43")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 43; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect44")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 44; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect45")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 45; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect46")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 46; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect47")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 47; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect48")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 48; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect49")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 49; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect50")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 50; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect51")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 51; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect52")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 52; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect53")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 53; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect54")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 54; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect55")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 55; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect56")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 56; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect57")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 57; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect58")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 58; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect59")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 59; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect60")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 60; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect61")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 61; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect62")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 62; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect63")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 63; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect64")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 64; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect65")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 65; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect66")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 66; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect67")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 67; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect67")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 67; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect68")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 68; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect69")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 69; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect70")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 70; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect71")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 71; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect72")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 72; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect73")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 73; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect74")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 74; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect75")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 75; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect76")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 76; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect77")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 77; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect78")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 78; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect79")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 79; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect80")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 80; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect81")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 81; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect82")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 82; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect83")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 83; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect84")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 84; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect85")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 85; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect86")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 86; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect87")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 87; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect88")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 88; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect89")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 89; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect90")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 90; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect91")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 91; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect92")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 92; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect93")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 93; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect94")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 94; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect95")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 95; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect96")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 96; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect97")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 97; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect98")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 98; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect99")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 99; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect100")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 100; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect101")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 101; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect102")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 102; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect103")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 103; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect104")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 104; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect105")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 105; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect106")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 106; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect107")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 107; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect108")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 108; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect109")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 109; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect110")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 110; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect111")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 111; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect112")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 112; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect113")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 113; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "effect114")
					{
						int effect = atoi(str.substr(8).c_str());
						if (effect != 40)
						{
							PlayerInfo* info = ((PlayerInfo*)(peer->data));
							int netID = info->netID;
							ENetPeer* currentPeer;
							int state = getState(info);
							info->effect = atoi(str.substr(8).c_str());
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
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									data.netID = netID;
									data.plantingTree = state;
									BYTE* raw = packPlayerMoving(&data);
									int var = 114; // placing and breking
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), effect));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}
						}
					}
					if (btn == "searchitems") {

						//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Search item``|left|2398|\nadd_label|small|`4Sorry, this feature is not working :( ``|left|4|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|cancel||gazette||"));


						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFind item``|left|6016|\nadd_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\nadd_quick_exit|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "mod")
					{
						((PlayerInfo*)(peer->data))->skinColor = -150;
						sendClothes(peer);
						cout << "/mod from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
						sendState(peer);
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
						sendConsoleMsg(peer, "You can now walk through `2blocks`o!");
					}
					if (btn == "unmod")
					{
						((PlayerInfo*)(peer->data))->skinColor = -2104114177;
						sendClothes(peer);
						cout << "/unmod from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
						sendState(peer);
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
						sendConsoleMsg(peer, "You `4can not`o walk through blocks anymore.");
						string text = "action|play_sfx\nfile|audio/dialog_cancel.wav\ndelayMS|0\n";
					}
					if (btn == "crash")
					{
						sendConsoleMsg(peer, "`4Your set has been Removed!");
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);
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
					}
					if (btn == "sendfriendreq")
					{
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 0) {
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									string lol = infoDat[1];
									std::vector<std::string> ids = split(lol, "sendFriendRequest");
									toUpperCase(ids[1]);
									if (checkNetIDs2(currentPeer, ids[1])) {

										if (((PlayerInfo*)(peer->data))->lastfriend == ((PlayerInfo*)(currentPeer->data))->rawName) {

											((PlayerInfo*)(peer->data))->friendinfo.push_back(((PlayerInfo*)(currentPeer->data))->rawName); //add


											((PlayerInfo*)(currentPeer->data))->friendinfo.push_back(((PlayerInfo*)(peer->data))->rawName);

											string text = "action|play_sfx\nfile|audio/love_in.wav\ndelayMS|0\n";
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
											BYTE * data = new BYTE[5 + text.length()];
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
						}
					}
					if (btn.rfind("f_spm_", 0) == 0) {
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 0) {
								string lol = infoDat[1];
								ENetPeer* currentPeer;
								std::vector<std::string> ids = split(lol, "f_spm_");
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->rawName != ids[1])
										continue;

									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`5Message to " + ((PlayerInfo*)(currentPeer->data))->displayName + "|left|660|\nadd_spacer|small|\nadd_text_input|spm_t_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|||128|\nadd_spacer|small|\nadd_button|spm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`5Send|0|0|\nadd_button|backonlinelist|`wBack|0|0|\nadd_quick_exit|"));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;
								}
							}
						}
					}
					if (btn.rfind("f_", 0) == 0) {
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 0) {
								string lol = infoDat[1];
								ENetPeer* currentPeer;
								std::vector<std::string> ids = split(lol, "f_");
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->rawName != ids[1])
										continue;

									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(currentPeer->data))->displayName + "|left|1366|\n\nadd_spacer|small|\nadd_textbox|" + ((PlayerInfo*)(currentPeer->data))->displayName + " is `2online `onow in the world `w" + ((PlayerInfo*)(currentPeer->data))->currentWorld + "`o.|left|\nadd_spacer|small|\nadd_button|f_wt_" + ((PlayerInfo*)(currentPeer->data))->currentWorld + " |`oWarp to `5" + ((PlayerInfo*)(currentPeer->data))->currentWorld + "|0|0|\nadd_button|f_spm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`5Send Message|0|0|\nadd_spacer|small|\nadd_button|f_rf_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`oRemove as friend|0|0|\nadd_button|backonlinelist|`oBack|0|0|\nadd_quick_exit|"));
									ENetPacket * packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;
								}
							}
						}
					}
					if (btn == "lwhip")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 6026;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						int netID = info->netID;
						ENetPeer* currentPeer;
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
								data.x = 1000;
								data.y = 1000;
								data.punchX = 0;
								data.punchY = 0;
								data.XSpeed = 300;
								data.YSpeed = 600;
								data.netID = netID;
								data.plantingTree = state;
								BYTE* raw = packPlayerMoving(&data);
								int var = 76; // placing and breking
								memcpy(raw + 1, &var, 3);
								SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 90), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (btn == "lkat")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 2592;
						sendClothes(peer);
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						int netID = info->netID;
						ENetPeer* currentPeer;
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
								data.x = 1000;
								data.y = 1000;
								data.punchX = 0;
								data.punchY = 0;
								data.XSpeed = 300;
								data.YSpeed = 600;
								data.netID = netID;
								data.plantingTree = state;
								BYTE* raw = packPlayerMoving(&data);
								int var = 43; // placing and breking
								memcpy(raw + 1, &var, 3);
								SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
								GamePacket p6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 90), ((PlayerInfo*)peer->data)->x + 10, ((PlayerInfo*)peer->data)->y + 15));
								ENetPacket * packet6 = enet_packet_create(p6.data,
									p6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);
								delete p6.data;
							}
						}
					}
					if (isRegisterDialog) {

						int regState = PlayerDB::playerRegister(username, password, passwordverify, email, discord);
						if (regState == 1) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Your new account has been Created!``"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							GamePacket p2 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), 1), username), password));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);

							//enet_host_flush(server);
							delete p2.data;
							enet_peer_disconnect_later(peer, 0);
						}
						else if (regState == -1) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rAccount creation has failed, because it already exists!``"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (regState == -2) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rAccount creation has failed, because the name is too short!``"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (regState == -3) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Passwords mismatch!``"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (regState == -4) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Account creation has failed, because email address is invalid!``"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (regState == -5) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Account creation has failed, because Discord ID is invalid!``"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
#endif
				}
				if (cch.find("text|") != std::string::npos) {
					PlayerInfo* pData = ((PlayerInfo*)(peer->data));
					if (str == "/mod")
					{
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						((PlayerInfo*)(peer->data))->skinColor = -150;
						sendClothes(peer);
						cout << "/mod from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
						sendState(peer);
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
						sendConsoleMsg(peer, "You can now walk through `2blocks`o!");
						string text = "action|play_sfx\nfile|audio/secret.wav\ndelayMS|0\n";
					}
					else if (str.substr(0, 7) == "/state ")
					{
						cout << "/state from " << ((PlayerInfo*)(peer->data))->displayName << endl;
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
					else if (str.substr(0, 5) == "/gsm ")
					{
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Only Owner can use this command."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							break;
						}
						GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oGlobal System Message`o: " + str.substr(4, cch.length() - 4 - 1)));
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


						delete ban.data;
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
					else if (str == "/find ")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wItem Finder``|left|6016|\nadd_textbox|Enter a word below and click Find!|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find!|\nadd_quick_exit|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
					else if (str.substr(0, 8) == "/unmute ")
					{
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						ENetPeer* currentPeer;
						string dupa;
						string pa;
						string imie = str.substr(8, cch.length() - 8 - 1);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
							{
								((PlayerInfo*)(currentPeer->data))->cantalk = true;
								dupa = ((PlayerInfo*)(currentPeer->data))->rawName;
								pa = ((PlayerInfo*)(currentPeer->data))->displayName;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You got `2Unmuted`o by `4ADMIN`o!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
								delete p.data;
							}
						}

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#**`oThe Ancient Ones have `2Unmuted`w " + pa + "`#**"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packet);
						}
						delete p.data;
						continue;
					}
					else if (str.substr(0, 5) == "/mav ") {
						using namespace std::chrono;
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `1L`2a`3T`4e`5r`6-`7S`B`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/kas ") {
						using namespace std::chrono;
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `1K`2a`3s`4s`5y`6-`7S`8B`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 6) == "/item ")
					{

						PlayerInventory inventory;
						InventoryItem item;
						int proitem = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						if (proitem == 1874 || proitem == 1876 || proitem == 1986 || proitem == 2970 || proitem == 1780 || proitem == 1782 || proitem == 1784 || proitem == 7734 || proitem == 5026)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe `9Legendary Wizard`w has invited you to come to `2LEGEND`w!``|left|1790|\n\nadd_spacer|small|\nadd_label_with_icon|small|set_default_color|`o\n\nadd_label_with_icon|big|`wThe `4Ring Master`w has invited you to come to `2CARNIVAL`w!``|left|1900|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							//enet_host_flush(server);
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

							size_t invsize = 200;
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
								item.itemCount = 200;
								((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
							}
							sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
						}
					}
					else if (str.substr(0, 5) == "/bfs ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastBFG + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastBFG = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isBFG(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `9BFG-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/vas ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastAss + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastAss = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isAss(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `bAsade-`4SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/hsb ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastWan + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastWan = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isWan(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `1H`2e`3r`4o`5-`6S`7B`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/sps ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastSpace + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastSpace = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isSpace(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `9Vnya-`4SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/prs ") {
						using namespace std::chrono;
						if (!isChaos(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `1R`2a`3i`4n`5b`6o`7w`8-`9S`#B`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/fls ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastF + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastF = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isF(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `eF-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/fis ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastFire + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastFire = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isFire(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4Fire-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/fes ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastPrince + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastPrince = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isPrince(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `#Felecia-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/ycs ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastCat + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastCat = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isCat(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `#YaoCat-`bSB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 6) == "/clear") {
						if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {

							WorldInfo* wrld = getPlyersWorld(peer);

							ENetPeer* currentPeer;
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



									for (int i = 0; i < world->width * world->height; i++)
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
					else if (str.substr(0, 5) == "/pes ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastPrince + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastPrince = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isPrince(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4Prince-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 6) == "/warp ") {
						using namespace std::chrono;





						if (((PlayerInfo*)(peer->data))->lastWarp + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastWarp = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Please wait `515`o seconds you can warp to another world!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;

							continue;
						}
						string act = str.substr(6, cch.length() - 6 - 1);

						joinWorld(peer, act, 0, 0);

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Warping to world..."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					else if (str.substr(0, 8) == "/warpto ") {
					cout << "/warpto from " << ((PlayerInfo*)(peer->data))->displayName << endl;
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(8, cch.length() - 8 - 1)) {

								string act = ((PlayerInfo*)(currentPeer->data))->currentWorld;

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
					}
					else if (str.substr(0, 5) == "/vls ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastVirtual + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastVirtual = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isVirtual(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4V`ei`4r`et`4u`ea`4l`e-`4S`eB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 6) == "/warn ") {
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;

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
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Please enter the player name."));
						ENetPacket* packet = enet_packet_create(ps.data,
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
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Please enter your reason."));
						ENetPacket* packet = enet_packet_create(ps.data,
							ps.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
					}

					warn_message = warn_info;
					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (((PlayerInfo*)(currentPeer->data))->rawName == warn_user) {

							GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully`o warned`w " + warn_user + "`o!"));
							ENetPacket * packet0 = enet_packet_create(p0.data,
								p0.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet0);
							delete p0.data;
							GamePacket ps = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`4Warning`w from `4ADMIN`0: " + warn_message), "audio/hub_open.wav"), 0));

							ENetPacket * packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet);
							delete ps.data;
							break;
						}
					}
					}
					else if (str.substr(0, 3) == "/go") {
					string act = ((PlayerInfo*)(peer->data))->lastsbworld;
					if (act == "") {
						GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Sorry but we can't track the last sb."));
						ENetPacket* packet = enet_packet_create(po.data,
							po.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
					}
					else if (act == ((PlayerInfo*)(peer->data))->currentWorld) {
						GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Sorry but you are already in the world!"));
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
					else if (str.substr(0, 5) == "/pos ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastPolice + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastPolice = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isPolice(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `wPolice-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str == "/news") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe GrowtopiaSF News``|left|5016|\n\nadd_spacer|small|\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\nadd_spacer|small|\n\nadd_textbox|`wMay 27:`` `5Big Updates!``|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Hello GrowtopiaSF players,|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|We have got new UPDATE! : do /mhelp for mods and /ahelp for admin and /vhelp for vip and /help for member and add friend system and etc! |left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|Thanks to ESC, we got new updates!|left|\n\nadd_spacer|small|\n\nadd_textbox|We have working of big update and we're convinced that the wait will be worth it!|0|0|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|Also, we're getting in every day one new update or so.|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|And for those who missed our new updates, we have our Discord, check it out on!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wDiscord Server``|noflags|https://discord.gg/uBAAVZW|Wanna check our Discord Server?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Lastly, check out other May updates:|left|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|New Commands: /thanos, /owner, /oset and improving Gazette, /ban for mods and above|left|24|\n\nadd_label_with_icon|small|Personal roles, custom broadcasts|left|24|\n\nadd_spacer|small|\n\nadd_textbox|`$- The GrowtopiaSF Team``|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\n\n\n\n\nadd_url_button|comment|`wESCSF/VerkaSF Channel``|noflags|https://www.youtube.com/c/DeveloperNGPS|Open our developer ESCSF YouTube channel?|0|0|\n\nadd_url_button|comment|`wSurekingSF Channel````|noflags|https://www.youtube.com/channel/UCaN2c7xI1nJi7h2-wjtvdbQ|Open our developer SurekingSF YouTube channel?|0|0|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|`4WARNING:`` `5Drop games/trust tests`` and betting games (like `5Casinos``) are not allowed and will result in a ban!|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` Using any kind of `5hacked client``, `5spamming/text pasting``, or `5bots`` (even with an alt) will likely result in losing `5ALL`` your accounts. Seriously.|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` `5NEVER enter your GT password on a website (fake moderator apps, free gemz, etc) - it doesn't work and you'll lose all your stuff!|left|24|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wGrowtopiaSF website``|noflags|https://5cbae5bde102c.site123.me/|Open the GrowtopiaSF page in your browser?|0|0|\n\nadd_spacer|small|\n\nadd_button|rules|`wHelp - Rules - Privacy Policy``|noflags|0|0|\n\n\nadd_quick_exit|\n\nadd_spacer|small|\nadd_url_button|comment|`wVisit Growtopia Forums``|noflags|http://www.growtopiagame.com/forums|Visit the Growtopia forums?|0|0|\nadd_spacer|small|\nadd_url_button||`wWOTW: `1STEAM`` by `#Ahha````|NOFLAGS|OPENWORLD|STEAM|0|0|\nadd_spacer|small|\nadd_url_button||`wVOTW: `1New Growtopia private server My own GTPS!``|NOFLAGS|https://www.youtube.com/watch?v=hVExXxKAm2w|Watch 'New Growtopia private server My own GTPS!' by Sureking on YouTube?|0|0|\nend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					else if (str == "/cole") {
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					sendConsoleMsg(peer, "Welcome back `2Cole`o!");
					sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
					((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
					sendWorldOffers(peer);
					((PlayerInfo*)(peer->data))->cloth_hair = 3138;
					((PlayerInfo*)(peer->data))->cloth_shirt = 3370;
					((PlayerInfo*)(peer->data))->cloth_pants = 344;
					((PlayerInfo*)(peer->data))->cloth_feet = 1822;
					((PlayerInfo*)(peer->data))->cloth_face = 1204;
					((PlayerInfo*)(peer->data))->cloth_hand = 1438;
					((PlayerInfo*)(peer->data))->cloth_back = 1784;
					((PlayerInfo*)(peer->data))->cloth_mask = 2972;
					((PlayerInfo*)(peer->data))->cloth_necklace = 1968;
					((PlayerInfo*)(peer->data))->cloth_ances = 5132;
					}
					else if (str == "/unequip") {
						cout << "/unequip from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wAre you sure you want to `4Remove`w all of your clothes?``|left|1432|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_button|crash|`4REMOVE!|noflags|0|0|\nadd_button|nothing|`2No thank you!|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
						string text = "action|play_sfx\nfile|audio/change_clothes.wav\ndelayMS|0\n";
					}
					else if (str == "/noclip") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`2Noclip`w Options :``|left|1432|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_button|mod|`2TURN ON!|noflags|0|0|\nadd_button|unmod|`4TURN OFF!|noflags|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
						string text = "action|play_sfx\nfile|audio/change_clothes.wav\ndelayMS|0\n";
					}
					else if (str == "/roles") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`2Informations``|left|1432|\n\nadd_spacer|small|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wBakemono#5721`o/`^Myth`o - `^Moderator|left|408|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wItsRare#8528`o/`4Its`^Rare`o - `4Legend`o/`^Moderator|left|408|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wYuzed#8226`o/`^Yuzed`o - `^Moderator|left|408|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wAHHA#9669`o/`^AHHA`o - `^Moderator|left|408|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wKrat0s#1101`o/`^kratos1`o - `^Moderator|left|408|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wKinater#7917`o/`^Kinater`o - `^Moderator|left|408|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wBull#4591`o/`^Bull`o - `^Moderator|left|408|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`^Light Green`w text color for Moderator, `4Red`w text color for Legend.|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					else if (str.substr(0, 6) == "/mute ")
					{
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						ENetPeer* currentPeer;
						string dupa;
						string pa;
						string imie = str.substr(6, cch.length() - 6 - 1);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
							{
								((PlayerInfo*)(currentPeer->data))->cantalk = false;
								dupa = ((PlayerInfo*)(currentPeer->data))->rawName;
								pa = ((PlayerInfo*)(currentPeer->data))->displayName;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You got `4Muted`o by `4ADMIN`o!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
								delete p.data;
							}
						}
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#**`w" + ((PlayerInfo*)(peer->data))->rawName + "`o has `4Muted`o player`w " + imie + "`#**"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packet);
						}
						delete p.data;
						continue;
					}
					else if (str == "/store") {
						cout << "/store from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`2GTSF Server Store``|left|5956|\n\nadd_spacer|small|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|This is the `2GTSF Server Store`o you can check what kind of stuffs we sell here.|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`^Moderator Role`o - `25`1 Diamond Lock|left|408|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`1VIP Role`o - `21`1 Diamond Lock|left|1486|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wCustom SB`o - `250`9 World Locks|left|2480|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wGems`o - 5000 per `9World Lock|left|112|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wLevels`o - 5 per `9World Lock|left|1488|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|For more informations please join our Discord Server!|left|\nadd_url_button||``Discord: `1Join our Discord Server!``|NOFLAGS|https://discord.gg/QaqB8bJ|Open link?|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}


					else if (str.substr(0, 9) == "/showlvl") {

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
							GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`oPlayer`w " + name + "`o has`2 " + std::to_string(level) + "`o levels!"), 0));
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player`w " + name + "`o has`2 " + std::to_string(level) + "`o levels!"));
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

					else if (str.substr(0, 9) == "/showgem") {

					ENetPeer* currentPeer;
					int gem = ((PlayerInfo*)(peer->data))->gems;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer))
						{
							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`oPlayer`w " + name + "`o has`2 " + std::to_string(gem) + "`o Gems!"), 0));
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player`w " + name + "`o has`2 " + std::to_string(gem) + "`o Gems!"));
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
					else if (str == "/save") {
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, level1, gems1, skinColor1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
						sendState(peer);
						level1 = ((PlayerInfo*)(peer->data))->level;
						sendState(peer);
						gems1 = ((PlayerInfo*)(peer->data))->gems;
						sendState(peer);
						skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
						sendState(peer);
						PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
						sendConsoleMsg(peer, "`2Successfully`o Saved!");
					}
					else if (str.substr(0, 7) == "/online") {

					string online = "";

					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
						if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) >= 0) {
							online += ((PlayerInfo*)(currentPeer->data))->displayName + "`o, `w";
						}
					}
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5Players online: `w" + online));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					}
					else if (str == "/mhelp") {
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`^Moderator Commands Are`o: /news, /mods, /help, /noclip, /inventory, /item (id), /team (id), /color (number), /who, /state (number), /count, /sb (message), /alt, /radio, /gem (amount), /find, /unequip, /weather (id), /owners, /rules, /effect, /ban (player name), /pull (player name), /vips, /me (message), /cry, /invis, /vis, /warpto (player name), /summon (player name), /msb (message), /kick (player name), /nick (nickname), /unnick, /gameban, /report (player name), /store, /mute (player name), /unmute (player name), /invite (player name), /bc (message), /growformer, /sss, /pay (player name) (amount), /?, /hide, /unhide, /drop (ID), /block (ID), /showgem, /showlvl, /save, /warp (world name), /clear, /msg (player name) (message), /r (message), /rgo, /freeze (player name), /warn (player name) (reason), /online, /go."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str.substr(0, 7) == "/spawn ")
						{

						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
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

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Successfully spawned `2" + std::to_string(block) + "`o!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;

						}
					else if (str == "/saveworlds") {
						{
							if (!isDev(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							cout << "Saving worlds..." << endl;
							worldDB.saveAll();
							cout << "Worlds saved!" << endl;
						}
					}
					if (str == "/sss")
					{
						((PlayerInfo*)(peer->data))->skinColor = 120999;
						sendClothes(peer);
						sendConsoleMsg(peer, "Super Supporter Skin was `2Added`o!");
					}
					else if (str == "/lhelp") {
						cout << "/lhelp from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Legend Commands Are`o: /news, /mods, /help, /noclip, /inventory, /item (id), /team (id), /color (number), /who, /state (number), /count, /sb (message), /alt, /radio, /gem (amount), /find, /unequip, /weather (id), /owners, /rules, /effect, /ban (player name), /pull (player name), /vips, /invis, /vis, /warpto (player name), /summon (player name), /msb (message), /kick (player name), /nick (nickname), /unnick, /gameban, /report (player name), /store, /mute (player name), /unmute (player name), /invite (player name), /legend, /unlegend, /lsb (message), /drop, /bedrock, /maindoor, /wizard, /dirt, /ringmaster, /lava, /door, /lock, /growformer, /sss, /pay (player name) (amount), /?, /hide, /unhide, /spawn (ID), /block (ID), /showgem, /showlvl, /save, /warp (world name), /clear, /msg (player name) (message), /r (message), /rgo, /freeze (player name), /warn (player name) (reason), /online, /go."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str == "/maindoor")
					{
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						((PlayerInfo*)(peer->data))->cloth_back = 6;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noEyes = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noBody = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noHands = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->isInvisible = true;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are a now the `wMain Door`o!"));
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
					else if (str == "/bedrock")
					{
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						((PlayerInfo*)(peer->data))->cloth_back = 8;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noEyes = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noBody = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noHands = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->isInvisible = true;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are a now a `wBedrock`o!"));
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
					else if (str == "/growformer")
					{
					((PlayerInfo*)(peer->data))->cloth_back = 7480;
					sendState(peer);
					((PlayerInfo*)(peer->data))->noEyes = true;
					sendState(peer);
					((PlayerInfo*)(peer->data))->noBody = true;
					sendState(peer);
					((PlayerInfo*)(peer->data))->noHands = true;
					sendState(peer);
					((PlayerInfo*)(peer->data))->isInvisible = true;
					sendState(peer);
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are now a Robot!"));
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
					else if (str == "/dirt")
					{
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						((PlayerInfo*)(peer->data))->cloth_back = 2;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noEyes = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noBody = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noHands = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->isInvisible = true;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are a now a `2Dirt`o!"));
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
					else if (str == "/wizard")
					{
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
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
					else if (str == "/lock")
					{
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						((PlayerInfo*)(peer->data))->cloth_back = 242;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noEyes = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noBody = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noHands = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->isInvisible = true;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are a now a `9World Lock`o!"));
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
					else if (str == "/door")
					{
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						((PlayerInfo*)(peer->data))->cloth_back = 12;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noEyes = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noBody = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noHands = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->isInvisible = true;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are a now a `9Door`o!"));
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
					else if (str == "/lava")
					{
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						((PlayerInfo*)(peer->data))->cloth_back = 4;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noEyes = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noBody = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noHands = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->isInvisible = true;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are a now a `4Lava`o!"));
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
					else if (str == "/ringmaster")
					{
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						((PlayerInfo*)(peer->data))->cloth_back = 1900;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noEyes = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noBody = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->noHands = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->isInvisible = true;
						sendState(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are a now the`4 Ring Master`o!"));
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
					else if (str == "/whitelist")
					{
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
						sendState(peer);
						level1 = ((PlayerInfo*)(peer->data))->level;
						sendState(peer);
						gems1 = ((PlayerInfo*)(peer->data))->gems;
						sendState(peer);

						whitelisted = true;
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), ""), "`4Server will be Down!"), ""), 0));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet);
							delete p.data;

							GamePacket pban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Server will be under `4Maintenance`o!"));
							ENetPacket * packet45 = enet_packet_create(pban.data, pban.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet45);
							enet_peer_disconnect_later(currentPeer, 0);
							delete pban.data;

							xwhitelist.push_back(((PlayerInfo*)(currentPeer->data))->tankIDName);
							enet_peer_disconnect_later(currentPeer, 0);
						}

					}
					else if (str == "/fakeban") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "Fake Ban from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "Warning from `4System`w: You've been `4BANNED `wfrom GTSF Server`w for `4730`w days!"), "audio/hub_open.wav"), 0));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer* currentPeer;
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
					else if (str.substr(0, 9) == "/gameban ")
					{
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
						sendState(peer);
						level1 = ((PlayerInfo*)(peer->data))->level;
						sendState(peer);
						gems1 = ((PlayerInfo*)(peer->data))->gems;
						sendState(peer);
						//if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						ENetPeer* currentPeer;
						string real = "";
						string imie = str.substr(9, cch.length() - 9 - 1);
						toUpperCase(imie);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							string lolzzz = ((PlayerInfo*)(currentPeer->data))->rawName;
							toUpperCase(lolzzz);
							if (lolzzz == imie) {

								string nick = ((PlayerInfo*)(currentPeer->data))->rawName;
								real = nick;

								sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
								GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "You got `4BANNED`w from `2GTSF Server`w!"), "audio/hub_open.wav"), 0));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
								delete p.data;
								enet_peer_disconnect_later(currentPeer, 0);

								GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#**`w" + ((PlayerInfo*)(peer->data))->rawName + "`o has `4Banned`o player`w " + imie + "`#**"));
								ENetPacket * packetba = enet_packet_create(ban.data,
									ban.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packetba);
								delete ban.data;

								bannedlist.push_back(((PlayerInfo*)(currentPeer->data))->tankIDName);
								enet_peer_disconnect_later(currentPeer, 0);
							}
							else {
								bannedlist.push_back(imie);

							}

						}
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							GamePacket pban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#**`w" + ((PlayerInfo*)(peer->data))->rawName + "`o has `4Banned`o player`w " + imie + "`#**"));
							ENetPacket * packet45 = enet_packet_create(pban.data, pban.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet45);
							delete pban.data;
						}

					}
					else if (str.substr(0, 9) == "/gameban LaTer")
					{
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `4Gameban`o an `9Owner`o!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);

					}
					else if (str.substr(0, 9) == "/gameban developer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `4Gameban`o an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/kick LaTer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `4Kick`o an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/kick developer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `4Kick`o an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/summon LaTer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `2Summon`o an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/summon developer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `2Summon`o an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/mute LaTer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `4Mute`o an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/mute developer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `4Mute`o an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 8) == "/freeze ") {
					cout << "/freeze from " << ((PlayerInfo*)(peer->data))->displayName << endl;
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer))
						{

							if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(8, cch.length() - 8 - 1)) {
								if (((PlayerInfo*)(currentPeer->data))->rawName == "123456789123456780123139861982391023") {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `1freeze`o an `9Owner`o!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet);
									delete p.data;
									continue;
								}

								GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 1));
								memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);
								delete p2.data;
								{
									string name = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#Moderator`w " + name + " `1Froze`o you!"));
									string text = "action|play_sfx\nfile|audio/freeze.wav\ndelayMS|0\n";
									BYTE * data = new BYTE[5 + text.length()];
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
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `ohas been `1Freezed`o!"));
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
					else if (str.substr(0, 9) == "/warpto LaTer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "An `9Owner`o is to powerfull to warp in."));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/nick LaTer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `2Nick`o in to an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/nick LaTer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `2Nick`o in to an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/nick developer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `2Nick`o in to an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/nick LaTer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't `2Nick`o in to an `9Owner`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 9) == "/warpto developer")
					{
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "An `9Owner`o is to powerfull to warp in."));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 6) == "/vip") {
						if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);

						string name = ((PlayerInfo*)(peer->data))->displayName;
						((PlayerInfo*)(peer->data))->displayName = "`w[`1VIP`w]`1 " + name + "";

						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Added`1 VIP`o!"));
						ENetPacket* packet = enet_packet_create(ps.data,
							ps.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete ps.data;
						//enet_host_flush(server);
					}
					else if (str.substr(0, 6) == "/imod") {
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);

						string name = ((PlayerInfo*)(peer->data))->displayName;
						((PlayerInfo*)(peer->data))->displayName = "`w[`^MOD`w]`^ " + name + "";

						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Added`^ MOD`o!"));
						ENetPacket* packet = enet_packet_create(ps.data,
							ps.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete ps.data;
						//enet_host_flush(server);
					}
					else if (str.substr(0, 6) == "/legend") {
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);

						string name = ((PlayerInfo*)(peer->data))->displayName;
						((PlayerInfo*)(peer->data))->displayName = "`w[`4Legend`w]`4 " + name + "";

						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Added`4 Legend`o!"));
						ENetPacket* packet = enet_packet_create(ps.data,
							ps.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete ps.data;
						//enet_host_flush(server);
					}
					else if (str == "/unlegend")
					{
						if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						string xd = ((PlayerInfo*)(peer->data))->rank + ((PlayerInfo*)(peer->data))->rawName;
						((PlayerInfo*)(peer->data))->displayName = xd;
						sendState(peer);
						((PlayerInfo*)(peer->data))->namechange = false;
						sendState(peer);
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Removed`4 Legend`o!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					else if (str.substr(0, 6) == "/own") {
						cout << "/own from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);

						string name = ((PlayerInfo*)(peer->data))->displayName;
						((PlayerInfo*)(peer->data))->displayName = "`w[`9OWNER`w]`9 " + name + "";

						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Added`9 Owner`o!"));
						ENetPacket* packet = enet_packet_create(ps.data,
							ps.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete ps.data;
						//enet_host_flush(server);
					}
					else if (str == "/unnick")
					{
						cout << "/unnick from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						string xd = ((PlayerInfo*)(peer->data))->rank + ((PlayerInfo*)(peer->data))->rawName;
						((PlayerInfo*)(peer->data))->displayName = xd;
						sendState(peer);
						((PlayerInfo*)(peer->data))->namechange = false;
						sendState(peer);
						((PlayerInfo*)(event.peer->data))->country = "../ ";
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Your real name has been returned!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					else if (str == "/unown")
					{
						cout << "/unown from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						string xd = ((PlayerInfo*)(peer->data))->rank + ((PlayerInfo*)(peer->data))->rawName;
						((PlayerInfo*)(peer->data))->displayName = xd;
						sendState(peer);
						((PlayerInfo*)(peer->data))->namechange = false;
						sendState(peer);
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Removed`9 Owner`o!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					else if (str == "/unimod")
					{
						cout << "/unimod from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						string xd = ((PlayerInfo*)(peer->data))->rank + ((PlayerInfo*)(peer->data))->rawName;
						((PlayerInfo*)(peer->data))->displayName = xd;
						sendState(peer);
						((PlayerInfo*)(peer->data))->namechange = false;
						sendState(peer);
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Removed`^ MOD`o!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					else if (str == "/unvip")
					{
						cout << "/unvip from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						string xd = ((PlayerInfo*)(peer->data))->rank + ((PlayerInfo*)(peer->data))->rawName;
						((PlayerInfo*)(peer->data))->displayName = xd;
						sendState(peer);
						((PlayerInfo*)(peer->data))->namechange = false;
						sendState(peer);
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Removed`1 VIP`o!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					else if (str == "/vhelp") {
						if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`1VIP Commands Are`o: /news, /mods, /help, /noclip, /inventory, /item (id), /team (id), /color (number), /who, /state (number), /count, /sb (message), /alt, /radio, /gem (amount), /find, /unequip, /weather (id) /owners, /rules, /effect, /ban (player name), /pull (player name), /vips, /warpto, /vsb (message), /vip, /unvip, /bc (message), /growformer, /sss, /pay (player name) (amount), /?, /block (ID), /showgem, /showlvl, /save, /warp (world name), /clear, /msg (player name) (message), /r (message), /rgo, /online, /go."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str == "/effect") {
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wPunch Effects :|left|18|\n\nadd_spacer|small|\nadd_button_with_icon|effect0|`wPunch|noflags|18|\nadd_button_with_icon|effect1|`wCyclopean Visor|noflags|138|\nadd_button_with_icon|effect2|`wHeart Bow|noflags|366|\nadd_button_with_icon|effect3|`wTommy Gun|noflags|472|\nadd_button_with_icon|effect4|`wElvish Longbow|noflags|594|\nadd_button_with_icon|effect5|`wSawed-Off Shotgun|noflags|768|\nadd_button_with_icon|effect6|`wDragon Hand|noflags|900|\nadd_button_with_icon|effect7|`wReanimator Remote|noflags|910|\nadd_button_with_icon|effect8|`wDeath Ray|noflags|930|\nadd_button_with_icon|effect9|`wSix Shooter|noflags|1016|\nadd_button_with_icon|effect10|`wFocused Eyes|noflags|1204|\nadd_button_with_icon|effect11|`wIce Dragon Hand|noflags|1378|\nadd_button_with_icon|effect12|`wUnearthly Synthoid|noflags|4508|\nadd_button_with_icon|effect13|`wAtomic Shadow Scythe|noflags|1484|\nadd_button_with_icon|effect14|`wPet Leprechaun|noflags|1512|\nadd_button_with_icon|effect15|`wBattle Trout|noflags|1542|\nadd_button_with_icon|effect16|`wFiesta Dragon|noflags|1576|\nadd_button_with_icon|effect17|`wSquirt Gun|noflags|1676|\nadd_button_with_icon|effect18|`wKeytar|noflags|1710|\nadd_button_with_icon|effect19|`wFlamethrower|noflags|1748|\nadd_button_with_icon|effect20|`wLegendbot-009|noflags|1780|\nadd_button_with_icon|effect21|`wDragon of Legend|noflags|1782|\nadd_button_with_icon|effect22|`wZeus's Lightning Bolt|noflags|1804|\nadd_button_with_icon|effect23|`wViolet Protodrake Dragon|noflags|1868|\nadd_button_with_icon|effect24|`wRing of Force|noflags|1874|\nadd_button_with_icon|effect25|`wIce Calf Leash|noflags|1946|\nadd_button_with_icon|effect26|`wMagnifying Glass|noflags|1252|\nadd_button_with_icon|effect27|`wCursed Fishing Rod|noflags|3100|\nadd_button_with_icon|effect28|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect29|`wPhoenix Sword|noflags|6312|\nadd_button_with_icon|effect30|`wClaw Glove|noflags|1980|\nadd_button_with_icon|effect31|`wCosmic Unicorn Bracelet|noflags|2066|\nadd_button_with_icon|effect32|`wBlack Crystal Dragon|noflags|2212|\nadd_button_with_icon|effect33|`wMighty Snow Rod|noflags|2218|\nadd_button_with_icon|effect34|`wTiny Tank|noflags|2220|\nadd_button_with_icon|effect35|`wCrystal Glaive|noflags|2266|\nadd_button_with_icon|effect36|`wHeavenly Scythe|noflags|2386|\nadd_button_with_icon|effect37|`wHeartbreaker Hammer|noflags|2388|\nadd_button_with_icon|effect38|`wDiamond Dragon|noflags|2450|\nadd_button_with_icon|effect39|`wBurning Eyes|noflags|2476|\nadd_button_with_icon|effect40|`wDiamond Horns|noflags|4748|\nadd_button_with_icon|effect41|`wMarshmallow Basket|noflags|2512|\nadd_button_with_icon|effect42|`wFlame Scythe|noflags|2572|\nadd_button_with_icon|effect43|`wLegendary Katana|noflags|2592|\nadd_button_with_icon|effect44|`wElectric Bow|noflags|2720|\nadd_button_with_icon|effect45|`wPineapple Launcher|noflags|2752|\nadd_button_with_icon|effect46|`wDemonic Arm|noflags|2754|\nadd_button_with_icon|effect47|`wThe Gungnir|noflags|2756|\nadd_button_with_icon|effect48|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect49|`wPoseidon's Trident|noflags|2802|\nadd_button_with_icon|effect50|`wWizard's Staff|noflags|2866|\nadd_button_with_icon|effect51|`wBLYoshi's Free Dirt|noflags|2876|\nadd_button_with_icon|effect52|`wFC Cleats|noflags|2878|\nadd_button_with_icon|effect53|`wTennis Racquet|noflags|2906|\nadd_button_with_icon|effect54|`wBaseball Glove|noflags|2886|\nadd_button_with_icon|effect55|`wBasketball|noflags|2890|\nadd_button_with_icon|effect56|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect57|`wFire Hose|noflags|3066|\nadd_button_with_icon|effect58|`wSoul Orb|noflags|3124|\nadd_button_with_icon|effect59|`wStrawberry Slime|noflags|3168|\nadd_button_with_icon|effect60|`wAxe of Winter|noflags|3214|\nadd_button_with_icon|effect61|`wMagical Carrot|noflags|3238|\nadd_button_with_icon|effect62|`wGreen T-Shirt Launcher|noflags|3274|\nadd_button_with_icon|effect63|`wBlack T-Shirt Launcher|noflags|3274|\nadd_button_with_icon|effect64|`wParty Blaster|noflags|3300|\nadd_button_with_icon|effect65|`wSerpent Staff|noflags|3418|\nadd_button_with_icon|effect66|`wSpring Bouquet|noflags|3476|\nadd_button_with_icon|effect67|`wLollipop|noflags|352|\nadd_button_with_icon|effect68|`wToy Lock-Bot|noflags|3686|\nadd_button_with_icon|effect69|`wNeutron Gun|noflags|3716|\nadd_button_with_icon|effect70|`wXenoid Claws|noflags|4688|\nadd_button_with_icon|effect71|`wSolsascarf|noflags|4290|\nadd_button_with_icon|effect72|`wSkull Launcher|noflags|4474|\nadd_button_with_icon|effect73|`wAK-8084|noflags|4464|\nadd_button_with_icon|effect74|`wFiesta Dragon|noflags|1576|\nadd_button_with_icon|effect75|`wDiamond Horn|noflags|4746|\nadd_button_with_icon|effect76|`wAdventurer's Whip|noflags|4778|\nadd_button_with_icon|effect77|`wBurning Hands|noflags|4996|\nadd_button_with_icon|effect78|`wBalloon Launcher|noflags|4840|\nadd_button_with_icon|effect79|`wCloak of Falling Waters|noflags|5206|\nadd_button_with_icon|effect80|`wRayman's Fist|noflags|5480|\nadd_button_with_icon|effect81|`wPineapple Spear|noflags|6110|\nadd_button_with_icon|effect82|`wBeach Ball|noflags|6308|\nadd_button_with_icon|effect83|`wWatermelon|noflags|6310|\nadd_button_with_icon|effect84|`wSmoog the Great Dragon|noflags|6298|\nadd_button_with_icon|effect85|`wScepter of Honor Guard|noflags|6756|\nadd_button_with_icon|effect86|`wJade Crescent Axe|noflags|7044|\nadd_button_with_icon|effect87|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect88|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect89|`wEzio's Armguards|noflags|7088|\nadd_button_with_icon|effect90|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect91|`wShadow Spirit of the Underworld|noflags|7192|\nadd_button_with_icon|effect92|`wEthereal Rainbow Dragon|noflags|7136|\nadd_button_with_icon|effect93|`wPet Slime|noflags|3166|\nadd_button_with_icon|effect94|`wMad Hatter|noflags|7216|\nadd_button_with_icon|effect95|`wMonarch Butterfly Wings|noflags|7196|\nadd_button_with_icon|effect96|`wMage's Orb|noflags|7392|\nadd_button_with_icon|effect97|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect98|`wGrowformer Bot|noflags|7384|\nadd_button_with_icon|effect99|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect100|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect101|`wSnowfrost's Candy Cane Blade|noflags|7424|\nadd_button_with_icon|effect102|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect103|`wSLaminator's Boomerang|noflags|7488|\nadd_button_with_icon|effect104|`wSonic Buster Sword|noflags|7586|\nadd_button_with_icon|effect105|`wMjolnir|noflags|7650|\nadd_button_with_icon|effect106|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect107|`wHovernator Drone|noflags|7574|\nadd_button_with_icon|effect108|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect109|`wSuper Party Launcher|noflags|7660|\nadd_button_with_icon|effect110|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect111|`wUNKNOWN|noflags|3308|\nadd_button_with_icon|effect112|`wMorty the Elephant|noflags|7836|\nadd_button_with_icon|effect113|`wIonic Pulse Cannon Tank|noflags|7950|\nadd_button_with_icon|effect114|`wMoney Gun|noflags|8002||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);

					//enet_host_flush(server);
					delete p.data;
					}
					else if (str == "/ohelp") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Owner Commands Are`o: /news, /mods, /help, /noclip, /inventory, /item (id), /team (id), /color (number), /who, /state (number), /count, /sb (message), /alt, /radio, /gem (amount), /find, /unequip, /weather (id), /owners, /rules, /effect, /ban (player name), /pull (world name), /vips, /vhelp, /mhelp, /vsb, /vip, /unvip, /vip, /unvip, /imod, /unimod, /own, /unown, /legend, /invis, /vis /warpto, /summon, /msb, /hide, /unhide, /kick, /nick, /particle, /drop, /osb, /asb, /reset, /unnick, /gsm, /gameban, /report (player name), /store, /whitelist, /grant, /mute (player name), /unmute (player name), /invite (player name), /me (message), /cry, /saveworlds, /bedrock, /maindoor, /wizard, /dirt, /ringmaster, /lava, /door, /lock, /roles, /bc (message), /music, /growformer, /sss, /pay (player name) (amount), /?, /gift, /spawn (ID), /block (ID), /showgem, /showlvl, /save, /warp (world name), /clear, /msg (player name) (message), /r (message), /rgo, /freeze (player name), /warn (player name) (reason), /online, /go."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str.substr(0, 7) == "/grant ")
					{
						//if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

						ENetPeer* currentPeer;
						string imie = str.substr(7, cch.length() - 7);
						toUpperCase(imie);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\n\nadd_label_with_icon|big|`wGrant " + imie + " to:``|left|32|\n\nadd_spacer|small|\ntext_scaling_string|iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii||\nadd_button_with_icon|grantMod" + imie + "|Moderator|noflags|204|\nadd_button|chc0|Close|noflags|0|0|\nadd_spacer|small|\nadd_quick_exit|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
					}
					else if (str.substr(0, 6) == "/drop ")
					{
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						//rl
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);

						//up lr
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);

						//down lr

						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
						sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					}
					else if (str == "/firework")
					{
					using namespace std::chrono;
					cout << "Xmas from " << ((PlayerInfo*)(peer->data))->rawName << "in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << endl;
					if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are spamming fireworks too fast, calm down."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}

					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w" + name + " `olaunches `4fireworks`o to c`2elebrate`o the `2First Month of The Server`o!"));
					string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
							ENetPacket * packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet3);
							delete p3.data;
						}
					}
					else if (str.substr(0, 6) == "/nick ") {
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << ((PlayerInfo*)(peer->data))->displayName << " nicked into " << str.substr(6, cch.length() - 6 - 1) << endl;
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);

						((PlayerInfo*)(event.peer->data))->country = "us";
						((PlayerInfo*)(peer->data))->displayName = str.substr(6, cch.length() - 6 - 1);

						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your nickname has been changed!"));
						ENetPacket * packet = enet_packet_create(ps.data,
							ps.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete ps.data;
						//enet_host_flush(server);
					}
					else if (str.substr(0, 6) == "/kick ")
					{
						cout << "/kick from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						string imie = str.substr(6, cch.length() - 6 - 1);
						ENetPeer * currentPeer;
						string dupa;
						GamePacket plong = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#**`oThe Ancient Ones have `4KICKED`o " + imie + "`o out of the server!`#**"));
						ENetPacket * packetlong = enet_packet_create(plong.data,
							plong.len,
							ENET_PACKET_FLAG_RELIABLE);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packetlong);
						}
						delete plong.data;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
							{
								string username1;
								int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1;
								username1 = ((PlayerInfo*)(peer->data))->rawName;
								sendState(peer);
								cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
								sendState(peer);
								cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
								sendState(peer);
								cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
								sendState(peer);
								cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
								sendState(peer);
								cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
								sendState(peer);
								cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
								sendState(peer);
								cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
								sendState(peer);
								cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
								sendState(peer);
								cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
								sendState(peer);
								cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
								sendState(peer);
								level1 = ((PlayerInfo*)(peer->data))->level;
								sendState(peer);
								gems1 = ((PlayerInfo*)(peer->data))->gems;
								sendState(peer);
								GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "You got `4kicked`w out by `4ADMIN`w!"), "audio/hub_open.wav"), 0));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
								delete p.data;
								enet_peer_disconnect_later(currentPeer, 0);
							}
						}
					}
					else if (str.substr(0, 5) == "/msb ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastMSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastMSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `#Mod-SB`o again."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/msb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `#Mod-SB`` from `$`2" + name + "`w (in `4HIDDEN``) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/getpoint.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					if (((PlayerInfo*)(peer->data))->lastVSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastVSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `#Mod-SB`o again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/vsb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `1VIP-SB`` from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`# " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/gus ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastGus + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastGus = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isGuard(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/gus from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `2Guardian-SB`` from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`# " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/alp ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastAlp + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastAlp = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isAlp(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/apr from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `9Alperen-`4SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/apr ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastApro + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastApro = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}
						if (!isApro(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "/apr from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4AProi-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/wsb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastWaw + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastWaw = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isWaw(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/vsb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4WAW-SB`w from `$`2" + name + "`w (in `4JAMMED `w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/psb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastPrin + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastPrin = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `1VIP-SB`o again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isPrin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/achievement from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `9Princess-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/csu ") {
					if (!isCole(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/csu from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `bCole-`eSB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/chs ") {
					if (!isChaos(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/chs from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `sSpooky-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/csh ") {
					if (!isCole(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/csh from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `bCole-`eSB`w from `$`2" + name + "`w (in `4HIDDEN`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/csb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastCSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastCSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isChicken(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4CHICKENS-`9SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/bsb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastP + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastP = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can `oCustom SB`o again!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isBro(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/csb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `eBro-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/ahh ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastAHH + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastAHH = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can Custom SB again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isAh(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/ahh from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4AH`bHA`6-`2SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/usb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastMSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastMSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can Custom-SB again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isUsed(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/usb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `bUsed-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/yuz ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastMAVSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastMAVSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can Custom-SB again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isYuz(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/ysb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `9Mavsy-`4SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/zsb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastZav + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastZav = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can Custom-SB again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isZav(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/zsb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `2Zav-`bSB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/tsb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastSHOP + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastSHOP = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can Custom-SB again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isShop(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/tsb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4Trash`w-`6SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/isb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastITS + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastITS = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can Custom-SB again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isRare(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/its from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `eItsRare`w-`eSB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/fsb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastMAGSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastMAGSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can Custom-SB again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isYuz(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/ysb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `#Fake-`4SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/ysb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastYSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastYSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can Custom-SB again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isYuz(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/ysb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `#Y`2u`4z`1e`bd`o-SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/nsb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastNSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastNSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait `215`o Seconds before you can Custom-SB again."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					if (!isYuz(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "/nsb from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `bNoob-`1SB`w from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					
					else if (str.substr(0, 8) == "/summon ")
						 {
						 if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;

						 ENetPeer* currentPeer;

						 for (currentPeer = server->peers;
							 currentPeer < &server->peers[server->peerCount];
							 ++currentPeer)
						 {
							 if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								 continue;

							 if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(8, cch.length() - 8 - 1)) {


								 GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully`o summned `w " + ((PlayerInfo*)(currentPeer->data))->displayName + "`o!"));

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




								 GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wYou were summoned by a mod"));
								 string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
								 BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/osb ") {
						using namespace std::chrono;
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `9Owner-SB`` from `$`2" + name + "`w (in `4HIDDEN``) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/launch.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/ksb ") {
					using namespace std::chrono;
					if (!isSci(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `9Gold-`3SB`` from `$`2" + name + "`w (in `bSECRET``) ** :`6" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/launch.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/ssb ") {
					using namespace std::chrono;
					if (!isDev(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `6Special-SB`` from `$`2" + name + "`w (in `4HIDDEN``) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/friend_logon.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/cms ") {
					using namespace std::chrono;
					if (!isManager(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `#Manager-SB`` from `$`2" + name + "`w (in `4HIDDEN``) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/friend_logon.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 5) == "/lsb ") {
					using namespace std::chrono;
					if (!isLegend(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4Legend-SB`` from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`#" + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/double_chance.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 8) == "/tele ") {
						cout << "/tele from " << ((PlayerInfo*)(peer->data))->displayName << endl;
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
								sendPlayerTP(peer, currentPeer);
								found = true;
							}


						}
						if (found) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You have warped to " + name));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4There is no player online named " + name));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
						}
					}
					else if (str == "/mods") {
						cout << "/mods from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						string x;

						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (Mod(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 0) {
								x.append("`^" + ((PlayerInfo*)(currentPeer->data))->rawName + "``, ");
							}

						}
						x = x.substr(0, x.length() - 2);

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`^Moderators online: " + x));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
					}
					else if (str.substr(0, 4) == "/me ")
					{
						if (((PlayerInfo*)(peer->data))->cantalk == true && ((PlayerInfo*)(peer->data))->haveGrowId == true)
						{
							string namer = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`#<`w" + namer + " `#" + str.substr(3, cch.length() - 3 - 1).c_str() + "`5>"), 0));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w<" + namer + " `#" + str.substr(3, cch.length() - 3 - 1).c_str() + "`w>"));
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
									enet_peer_send(currentPeer, 0, packet2);
									enet_peer_send(currentPeer, 0, packet3);
								}
							}
							delete p2.data;
							delete p3.data;
							continue;
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
					else if (str == "/vips") {
						cout << "/vips from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						string x;

						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (VIP(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 0) {
								x.append("`1" + ((PlayerInfo*)(currentPeer->data))->rawName + "``, ");
							}

						}
						x = x.substr(0, x.length() - 2);

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`1VIPS online: " + x));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
					}
					else if (str == "/owners") {
						cout << "/owners from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9GTSF Server Creator :``|left|5956|\n\nadd_spacer|small|\nadd_label_with_icon|small|`1Sureking#4999|left|3138|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|set_default_color|`o\n\nadd_label_with_icon|big|`9GTSF Server Co-Creator :``|left|5956|\n\nadd_spacer|small|\nadd_label_with_icon|small|`1Animez|left|3138|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|set_default_color|`o\n\nadd_label_with_icon|big|`9GTSF Server Creator :``|left|5956|\n\nadd_spacer|small|\nadd_label_with_icon|small|`9iwontstop#8226|left|3138|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small||\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					else if (str == "/rules") {
						cout << "/rules from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`2GTSF Server Rules!``|left|5956|\n\nadd_spacer|small|\nadd_label_with_icon|small|Selling/buying gems is illegal!|left|1432|\nadd_label_with_icon|small|Asking for a mute will cause ban.|left|1432|\nadd_label_with_icon|small|Don't sb/bc about rude stuffs.|left|1432|\nadd_label_with_icon|small|Don't try to scam.|left|1432|\nadd_label_with_icon|small|Don't be Rude, Racist to other players.|left|1432|\nadd_label_with_icon|small|Don't try to be a Moderator if you aren't one.|left|1432|\nadd_label_with_icon|small|Don't talk about sexual things.|left|1432|\nadd_label_with_icon|small|\nadd_textbox|Breaking this rules will lead you to consequences!|small| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small||\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					else if (str.substr(0, 5) == "/pay ")
{
ENetPeer* currentPeer;
string imie = str.substr(5, cch.length() - 5 - 1);
int phm = 0;
if (imie.find(" ") != std::string::npos)
{
	phm = atoi(imie.substr(imie.find(" ") + 1).c_str());
	imie = imie.substr(0, imie.find(" "));
}
else {
	GamePacket p4 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Pay failed"));
	ENetPacket* packet4 = enet_packet_create(p4.data,
		p4.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet4);
	delete p4.data;
}
if (((PlayerInfo*)(peer->data))->gems >= phm)
{
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player`w " + ((PlayerInfo*)(peer->data))->rawName + "`o paid you `2" + std::to_string(phm) + " Gems`o!"));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You paid`w " + imie + "`2 " + std::to_string(phm) + " Gems`o!"));
	ENetPacket * packet2 = enet_packet_create(p2.data,
		p2.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2);
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
		{
			((PlayerInfo*)(peer->data))->gems = ((PlayerInfo*)(peer->data))->gems - phm;
			((PlayerInfo*)(currentPeer->data))->gems = ((PlayerInfo*)(currentPeer->data))->gems + phm;
			GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gems));
			ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packetsa);
			GamePacket psa2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(currentPeer->data))->gems));
			ENetPacket* packetsa2 = enet_packet_create(psa2.data, psa2.len, ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(currentPeer, 0, packetsa2);
			enet_peer_send(currentPeer, 0, packet);
			delete psa.data;
			delete psa2.data;
			string username1;
			int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
			username1 = ((PlayerInfo*)(peer->data))->rawName;
			sendState(peer);
			cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
			sendState(peer);
			cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
			sendState(peer);
			cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
			sendState(peer);
			cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
			sendState(peer);
			cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
			sendState(peer);
			cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
			sendState(peer);
			cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
			sendState(peer);
			cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
			sendState(peer);
			cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
			sendState(peer);
			cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
			sendState(peer);
			level1 = ((PlayerInfo*)(peer->data))->level;
			sendState(peer);
			gems1 = ((PlayerInfo*)(peer->data))->gems;
			sendState(peer);
			skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
			sendState(peer);
			PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
		}
	}
	delete p.data;
	delete p2.data;
}
else if (((PlayerInfo*)(peer->data))->gems < phm)
{
	GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Sorry but you need " + std::to_string(phm) + " gems to pay someone."));
	ENetPacket * packet3 = enet_packet_create(p3.data,
		p3.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete p3.data;
}
}
					else if (str.substr(0, 5) == "/gift")
					{
					if (!isDev(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					if (((PlayerInfo*)(peer->data))->gems > 1)
					{
						ENetPeer* currentPeer;
						string imie = str.substr(5, cch.length() - 5 - 1);
						GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`2Gem Event!`w Everyone will receive `21000 gems`w!"), "audio/pinata_lasso.wav"), 0));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						GamePacket p2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`2Gem Event!`w Everyone will receive `21000 gems`w!"), "audio/pinata_lasso.wav"), 0));
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							{
								((PlayerInfo*)(peer->data))->gems = ((PlayerInfo*)(peer->data))->gems - 0;
								((PlayerInfo*)(currentPeer->data))->gems = ((PlayerInfo*)(currentPeer->data))->gems + 1000;
								GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gems));
								ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packetsa);
								GamePacket psa2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(currentPeer->data))->gems));
								ENetPacket* packetsa2 = enet_packet_create(psa2.data, psa2.len, ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packetsa2);
								enet_peer_send(currentPeer, 0, packet);
								delete psa.data;
								delete psa2.data;
								string username1;
								int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
								username1 = ((PlayerInfo*)(peer->data))->rawName;
								sendState(peer);
								cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
								sendState(peer);
								cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
								sendState(peer);
								cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
								sendState(peer);
								cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
								sendState(peer);
								cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
								sendState(peer);
								cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
								sendState(peer);
								cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
								sendState(peer);
								cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
								sendState(peer);
								cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
								sendState(peer);
								cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
								sendState(peer);
								level1 = ((PlayerInfo*)(peer->data))->level;
								sendState(peer);
								gems1 = ((PlayerInfo*)(peer->data))->gems;
								sendState(peer);
								skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
								sendState(peer);
								PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
							}
						}
						delete p.data;
						delete p2.data;
					}
					else if (((PlayerInfo*)(peer->data))->gems < 0)
					{
						GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Sorry but you need 1000 gems to pay someone."));
						ENetPacket* packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet3);
						delete p3.data;
					}
					}
					else if (str == "/unhide")
					{
					cout << "/unhide from " << ((PlayerInfo*)(peer->data))->displayName << endl;
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					string xd = ((PlayerInfo*)(peer->data))->rank + ((PlayerInfo*)(peer->data))->rawName;
					((PlayerInfo*)(peer->data))->displayName = xd;
					sendState(peer);
					((PlayerInfo*)(peer->data))->namechange = false;
					sendState(peer);
					sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
					((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
					sendWorldOffers(peer);
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your name is now `2back`o!"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					}
					else if (str.substr(0, 6) == "/hide") {
					cout << "/hide from " << ((PlayerInfo*)(peer->data))->displayName << endl;
					if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
					((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
					sendWorldOffers(peer);

					((PlayerInfo*)(peer->data))->displayName = " ";

					GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your nickname has been `2changed!"));
					ENetPacket* packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete ps.data;
					//enet_host_flush(server);
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
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `2" + ((PlayerInfo*)(peer->data))->displayName + "`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + str.substr(3, cch.length() - 3 - 1) + "`o"));
							string text = "action|play_sfx\nfile|audio/pay_time.wav\ndelayMS|0\n";
							BYTE * data = new BYTE[5 + text.length()];
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
						GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Sorry but we can't tract the last message."));
						ENetPacket* packet = enet_packet_create(po.data,
							po.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
					}
					else if (act == ((PlayerInfo*)(peer->data))->currentWorld) {
						GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Sorry but you are already in the world!"));
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
					else if (str.substr(0, 5) == "/msg ") {
					if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
						GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease create an `4Account`o in order to use this Command!"));
						ENetPacket* packet0 = enet_packet_create(p0.data,
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
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlease enter a Player Name."));
						ENetPacket* packet = enet_packet_create(ps.data,
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
						GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "What is your message to this guy?"));
						ENetPacket* packet = enet_packet_create(ps.data,
							ps.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete ps.data;
					}

					pm_message = msg_info;
					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(pm_user)) {

							((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
							((PlayerInfo*)(currentPeer->data))->lastMsgerTrue = ((PlayerInfo*)(peer->data))->displayName;
							((PlayerInfo*)(currentPeer->data))->lastMsgWorld = ((PlayerInfo*)(peer->data))->currentWorld;
							GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> (Sent to `2" + ((PlayerInfo*)(peer->data))->lastMsger + "`6)"));
							ENetPacket * packet0 = enet_packet_create(p0.data,
								p0.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet0);
							delete p0.data;
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Private msg from `2" + ((PlayerInfo*)(peer->data))->displayName +"`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + pm_message + "`o"));
							string text = "action|play_sfx\nfile|audio/pay_time.wav\ndelayMS|0\n";
							BYTE * data = new BYTE[5 + text.length()];
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
					else if (str.substr(0, 7) == "/block ")
						{
						((PlayerInfo*)(peer->data))->cloth_back = atoi(str.substr(7).c_str());
						sendState(peer);
						((PlayerInfo*)(peer->data))->noEyes = true;
						sendState(peer);
						((PlayerInfo*)(peer->data))->skinColor = 2;
						sendClothes(peer);

						int block = atoi(str.substr(7).c_str());

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully`o turned into `w " + std::to_string(block) + "`o!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						}
					else if (str == "/help") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Supported commands are: /news, /mods, /help, /noclip, /inventory, /item (id), /team (id), /color (number), /who, /state (number), /count, /sb (message), /alt, /radio, /gem (amount), /find, /unequip, /weather (id), /owners, /rules, /effect, /ban (player name), /pull (player name), /vips, /report (player name), /store, /invite (player name), /me (message), /cry, /bc (message), /growformer, /sss, /pay (player name) (amount), /?, /block (ID), /showgem, /showlvl, /save, /warp (world name), /clear, /msg (player name) (message), /r (message), /rgo, /online, /go."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
						
					else if (str == "/?") {
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Supported commands are: /news, /mods, /help, /noclip, /inventory, /item (id), /team (id), /color (number), /who, /state (number), /count, /sb (message), /alt, /radio, /gem (amount), /find, /unequip, /weather (id), /owners, /rules, /effect, /ban (player name), /pull (player name), /vips, /report (player name), /store, /invite (player name), /me (message), /cry, /bc (message), /growformer, /sss, /pay (player name) (amount), /?,, /block (ID), /showgem, /showlvl, /save, /warp (world name), /clear, /msg (player name) (message), /r (message), /rgo, /online, /go."));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 8) == "/report ")
					{
					string imie = str.substr(8, cch.length() - 8 - 1);
					string dupa;
					ENetPeer * currentPeer;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `w" + imie + "`o has been reported."));
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
						if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
						{
							dupa = ((PlayerInfo*)(currentPeer->data))->rawName;
						}
					}
					cout << "Report from " << ((PlayerInfo*)(peer->data))->rawName << "in world " << ((PlayerInfo*)(peer->data))->currentWorld << std::dec << "reported " << dupa << endl;
					string username1;
					int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
					username1 = ((PlayerInfo*)(peer->data))->rawName;
					sendState(peer);
					cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
					sendState(peer);
					cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
					sendState(peer);
					cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
					sendState(peer);
					cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
					sendState(peer);
					cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
					sendState(peer);
					cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
					sendState(peer);
					cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
					sendState(peer);
					cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
					sendState(peer);
					cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
					sendState(peer);
					cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
					sendState(peer);
					level1 = ((PlayerInfo*)(peer->data))->level;
					sendState(peer);
					gems1 = ((PlayerInfo*)(peer->data))->gems;
					sendState(peer);
					skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
					sendState(peer);
					PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
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
						GamePacket pmsg = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o" + ((PlayerInfo*)(peer->data))->displayName + " `3pulls `o" + imie));
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
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
						sendState(peer);
						level1 = ((PlayerInfo*)(peer->data))->level;
						sendState(peer);
						gems1 = ((PlayerInfo*)(peer->data))->gems;
						sendState(peer);
						skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
						sendState(peer);
						PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
					}
					}
					else if (str.substr(0, 5) == "/ban ")
					{
					
					WorldInfo* world = getPlyersWorld(peer);
					if (((PlayerInfo*)(peer->data))->rawName == world->owner)
					{
						string imie = str.substr(5, cch.length() - 5 - 1);
						string dupa;
						GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2World-Owner `#" + ((PlayerInfo*)(peer->data))->rawName + " `ohas `4BANNED`o player " + imie + " `ofrom world `2" + ((PlayerInfo*)(peer->data))->currentWorld));
						ENetPeer * currentPeer;
						ENetPacket * packetba = enet_packet_create(ban.data,
							ban.len,
							ENET_PACKET_FLAG_RELIABLE);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								enet_peer_send(currentPeer, 0, packetba);
							}
						}
						delete ban.data;
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
									sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
									((PlayerInfo*)(currentPeer->data))->currentWorld = "EXIT";
									sendWorldOffers(currentPeer);
								}
							}
						}
					}
					//enet_host_flush(server);
					else
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You need to be world owner to use that command."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					continue;
					}
					else if (str.substr(0, 5) == "/gem ") //gem if u want flex with ur gems!
					{
					GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), atoi(str.substr(5).c_str())));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete p.data;
					continue;


					}
					else if (str.substr(0, 8) == "/invite ")
					{
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastINV + 300000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastINV = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Please wait `25 Minutes`o till you can invite someone again!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}
					GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Invitation has been `2Sent`o!"));
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet2);
					GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wPlayer " + ((PlayerInfo*)(peer->data))->displayName + " has invited you to join the world " + ((PlayerInfo*)(peer->data))->currentWorld +"`w!``|left|660|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_button|nothing|`4IGNORE!|noflags|0|0|\nadd_button|nothing|`2I will come later.|noflags|0|0|\nnend_dialog|gazette||OK|"));
					ENetPacket* packet3 = enet_packet_create(p3.data,
						p3.len,
						ENET_PACKET_FLAG_RELIABLE);
					string imie = str.substr(8, cch.length() - 8 - 1);
					ENetPeer * currentPeer;
					string dupa;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
						{
							dupa = ((PlayerInfo*)(currentPeer->data))->rawName;
							enet_peer_send(currentPeer, 0, packet3);
							string username1;
							int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
							username1 = ((PlayerInfo*)(peer->data))->rawName;
							sendState(peer);
							cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
							sendState(peer);
							cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
							sendState(peer);
							cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
							sendState(peer);
							cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
							sendState(peer);
							cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
							sendState(peer);
							cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
							sendState(peer);
							cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
							sendState(peer);
							cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
							sendState(peer);
							cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
							sendState(peer);
							cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
							sendState(peer);
							level1 = ((PlayerInfo*)(peer->data))->level;
							sendState(peer);
							gems1 = ((PlayerInfo*)(peer->data))->gems;
							sendState(peer);
							skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
							sendState(peer);
							PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
						}
					}
					delete p2.data;
					delete p3.data;
					continue;
					}
					else if (str.substr(0, 9) == "/weather ") {
					cout << "/weather from " << ((PlayerInfo*)(peer->data))->displayName << endl;
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

											GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), atoi(str.substr(9).c_str())));
											ENetPacket * packet2 = enet_packet_create(p2.data,
												p2.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet2);
											delete p2.data;
											continue; /*CODE UPDATE /WEATHER FOR EVERYONE!*/
											string username1;
											int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
											username1 = ((PlayerInfo*)(peer->data))->rawName;
											sendState(peer);
											cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
											sendState(peer);
											cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
											sendState(peer);
											cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
											sendState(peer);
											cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
											sendState(peer);
											cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
											sendState(peer);
											cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
											sendState(peer);
											cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
											sendState(peer);
											cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
											sendState(peer);
											cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
											sendState(peer);
											cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
											sendState(peer);
											level1 = ((PlayerInfo*)(peer->data))->level;
											sendState(peer);
											gems1 = ((PlayerInfo*)(peer->data))->gems;
											sendState(peer);
											skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
											sendState(peer);
											PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
										}
									}
								}
							}
						}
					}
					/*else if (str == "/saveset") {
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your set has been saved to database! It will be loaded automatic from now."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}*/
					/*else if (str == "/loadset"){
						string username = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						std::ifstream ifs("sets/" + username + ".json");
						if (ifs.is_open()) {
							json j;
							ifs >> j;
							int cloth_hair = j["cloth_hair"];
							int cloth_shirt = j["cloth_shirt"];
							int cloth_pants = j["cloth_pants"];
							int cloth_feet = j["cloth_feet"];
							int cloth_face = j["cloth_face"];
							int cloth_hand = j["cloth_hand"];
							int cloth_back = j["cloth_back"];
							int cloth_mask = j["cloth_mask"];
							((PlayerInfo*)(peer->data))->cloth_hair = cloth_hair;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_shirt = cloth_shirt;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_pants = cloth_pants;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_feet = cloth_feet;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_face = cloth_face;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_hand = cloth_hand;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_back = cloth_back;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_mask = cloth_mask;
							sendState(peer);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your set has been loaded! Re-enter world! If you want to save your new set to the database use /saveset!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You didn't create your set yet! Create your set and save it using /saveset!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}*/
					else if (str == "/count") {
						int count = 0;
						ENetPeer* currentPeer;
						string name = "";
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							count++;
						}
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wThere are`2 " + std::to_string(count) + "`w people online."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
						sendState(peer);
						level1 = ((PlayerInfo*)(peer->data))->level;
						sendState(peer);
						gems1 = ((PlayerInfo*)(peer->data))->gems;
						sendState(peer);
						skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
						sendState(peer);
						PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
					}
					else if (str == "/vis") {
					cout << "/vis from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						sendConsoleMsg(peer, "`oOthers `2can`o see you now!");

						GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), ((PlayerInfo*)(peer->data))->x1, ((PlayerInfo*)(peer->data))->y1));
						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						((PlayerInfo*)(peer->data))->isInvisible = false;
						sendState(peer);
						sendClothes(peer);
						((PlayerInfo*)(peer->data))->isGhost = false;

						/*GamePacket p = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 89), ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y));
					ENetPacket* packet3 = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet3);*/
						ENetPeer* currentPeer;
						GamePacket penter1 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
						GamePacket penter2 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
						GamePacket penter3 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
						GamePacket penter4 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
						GamePacket penter8 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
						GamePacket penter5 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
						GamePacket penter6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
						GamePacket penter7 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								if (!((PlayerInfo*)(peer->data))->isGhost)
								{
									ENetPacket* packet5 = enet_packet_create(penter1.data,
										penter1.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet5);

									ENetPacket* packet6 = enet_packet_create(penter2.data,
										penter2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet6);

									ENetPacket* packet7 = enet_packet_create(penter3.data,
										penter3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet7);

									ENetPacket* packet8 = enet_packet_create(penter4.data,
										penter4.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet8);

									ENetPacket* packet9 = enet_packet_create(penter5.data,
										penter5.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet9);
									
									ENetPacket* packet10 = enet_packet_create(penter6.data,
										penter6.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet10);

									ENetPacket* packet11 = enet_packet_create(penter7.data,
										penter7.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet11);

									ENetPacket* packet12 = enet_packet_create(penter8.data,
										penter8.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet12);
									string username1;
									int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
									username1 = ((PlayerInfo*)(peer->data))->rawName;
									sendState(peer);
									cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
									sendState(peer);
									cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
									sendState(peer);
									cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
									sendState(peer);
									cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
									sendState(peer);
									cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
									sendState(peer);
									cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
									sendState(peer);
									cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
									sendState(peer);
									cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
									sendState(peer);
									cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
									sendState(peer);
									cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
									sendState(peer);
									level1 = ((PlayerInfo*)(peer->data))->level;
									sendState(peer);
									gems1 = ((PlayerInfo*)(peer->data))->gems;
									sendState(peer);
									skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
									sendState(peer);
									PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
								}
							}
						}
					}
					else if (str == "/magic") {
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					sendConsoleMsg(peer, "`oOthers `2can`o see you now!");

					GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), ((PlayerInfo*)(peer->data))->x1, ((PlayerInfo*)(peer->data))->y1));
					memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet2);
					delete p2.data;
					((PlayerInfo*)(peer->data))->isInvisible = false;
					sendState(peer);
					sendClothes(peer);
					((PlayerInfo*)(peer->data))->isGhost = false;

					/*GamePacket p = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 89), ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y));
				ENetPacket* packet3 = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(peer, 0, packet3);*/
					ENetPeer* currentPeer;
					GamePacket penter1 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
					GamePacket penter2 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
					GamePacket penter3 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
					GamePacket penter4 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
					GamePacket penter8 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
					GamePacket penter5 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
					GamePacket penter6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
					GamePacket penter7 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
					GamePacket penter9 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 - 15));
					GamePacket penter10 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 - 15));
					GamePacket penter11 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 - 15));
					GamePacket penter12 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 - 15));
					GamePacket penter13 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 - 15));
					GamePacket penter14 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 - 15));
					GamePacket penter15 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 40), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 - 15));
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer))
						{
							if (!((PlayerInfo*)(peer->data))->isGhost)
							{
								ENetPacket* packet5 = enet_packet_create(penter1.data,
									penter1.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet5);

								ENetPacket* packet6 = enet_packet_create(penter2.data,
									penter2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet6);

								ENetPacket* packet7 = enet_packet_create(penter3.data,
									penter3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet7);

								ENetPacket* packet8 = enet_packet_create(penter4.data,
									penter4.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet8);

								ENetPacket* packet9 = enet_packet_create(penter5.data,
									penter5.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet9);

								ENetPacket* packet10 = enet_packet_create(penter6.data,
									penter6.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet10);

								ENetPacket* packet11 = enet_packet_create(penter7.data,
									penter7.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet11);

								ENetPacket* packet12 = enet_packet_create(penter8.data,
									penter8.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet12);

								ENetPacket* packet13 = enet_packet_create(penter9.data,
									penter9.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet13);

								ENetPacket* packet14 = enet_packet_create(penter10.data,
									penter10.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet14);

								ENetPacket* packet15 = enet_packet_create(penter11.data,
									penter11.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet15);

								ENetPacket* packet16 = enet_packet_create(penter12.data,
									penter12.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet16);

								ENetPacket* packet17 = enet_packet_create(penter13.data,
									penter13.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet17);

								ENetPacket* packet18 = enet_packet_create(penter14.data,
									penter14.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet18);

								ENetPacket* packet19 = enet_packet_create(penter15.data,
									penter15.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet19);
								string username1;
								int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
								username1 = ((PlayerInfo*)(peer->data))->rawName;
								sendState(peer);
								cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
								sendState(peer);
								cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
								sendState(peer);
								cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
								sendState(peer);
								cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
								sendState(peer);
								cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
								sendState(peer);
								cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
								sendState(peer);
								cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
								sendState(peer);
								cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
								sendState(peer);
								cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
								sendState(peer);
								cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
								sendState(peer);
								level1 = ((PlayerInfo*)(peer->data))->level;
								sendState(peer);
								gems1 = ((PlayerInfo*)(peer->data))->gems;
								sendState(peer);
								skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
								sendState(peer);
								PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
							}
						}
					}
					}
					else if (str == "/invis") {
					if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						sendConsoleMsg(peer, "`6" + str);
						if (!((PlayerInfo*)(peer->data))->isGhost) {

							sendConsoleMsg(peer, "`oOthers can `4not`o see you!");

							GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y));
							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;

							sendState(peer);
							sendClothes(peer);
							((PlayerInfo*)(peer->data))->isGhost = true;
							string username1;
							int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
							username1 = ((PlayerInfo*)(peer->data))->rawName;
							sendState(peer);
							cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
							sendState(peer);
							cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
							sendState(peer);
							cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
							sendState(peer);
							cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
							sendState(peer);
							cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
							sendState(peer);
							cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
							sendState(peer);
							cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
							sendState(peer);
							cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
							sendState(peer);
							cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
							sendState(peer);
							cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
							sendState(peer);
							level1 = ((PlayerInfo*)(peer->data))->level;
							sendState(peer);
							gems1 = ((PlayerInfo*)(peer->data))->gems;
							sendState(peer);
							skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
							sendState(peer);
							PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
						}
					}
					else if (str.substr(0, 5) == "/asb ") {
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "ASB from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`9Owner Message`w from `2 " + name + "`w: " + str.substr(4, cch.length() - 4 - 1).c_str()), "audio/double_chance.wav"), 0));
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
					GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Owner Message`o from " + name + "`o:" + str.substr(4, cch.length() - 4 - 1)));
					ENetPacket * packetba = enet_packet_create(ban.data,
						ban.len,
						ENET_PACKET_FLAG_RELIABLE);
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						enet_peer_send(currentPeer, 0, packetba);
					}
					}

					else if (str.substr(0, 5) == "/dsb ") {
					if (!isDev(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`6Developer Message`w from `2 " + name + "`w: " + str.substr(4, cch.length() - 4 - 1).c_str()), "audio/double_chance.wav"), 0));
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
					GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6Developer Message`o from " + name + "`o:" + str.substr(4, cch.length() - 4 - 1)));
					ENetPacket * packetba = enet_packet_create(ban.data,
						ban.len,
						ENET_PACKET_FLAG_RELIABLE);
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						enet_peer_send(currentPeer, 0, packetba);
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
						sendState(peer);
						level1 = ((PlayerInfo*)(peer->data))->level;
						sendState(peer);
						gems1 = ((PlayerInfo*)(peer->data))->gems;
						sendState(peer);
						skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
						sendState(peer);
						PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
					}


					delete ban.data;
					}
					else if (str.substr(0, 5) == "/cmm ") {
					if (!isManager(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`#Community Manager Message`w from `2 " + name + "`w: " + str.substr(4, cch.length() - 4 - 1).c_str()), "audio/double_chance.wav"), 0));
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
					GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#Community Manager Message`o from " + name + "`o:" + str.substr(4, cch.length() - 4 - 1)));
					ENetPacket * packetba = enet_packet_create(ban.data,
						ban.len,
						ENET_PACKET_FLAG_RELIABLE);
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						enet_peer_send(currentPeer, 0, packetba);
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
						sendState(peer);
						level1 = ((PlayerInfo*)(peer->data))->level;
						sendState(peer);
						gems1 = ((PlayerInfo*)(peer->data))->gems;
						sendState(peer);
						skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
						sendState(peer);
						PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
					}


					delete ban.data;
					}
					else if (str.substr(0, 4) == "/sb ") {
					if (getAdminLevel(((PlayerInfo*)(peer->data))->tankIDName, ((PlayerInfo*)(peer->data))->tankIDPass) < 2)
					{
						if (((PlayerInfo*)(peer->data))->cantalk == true)
						{
							if (((PlayerInfo*)(peer->data))->haveGrowId == true)
							{
								if (((PlayerInfo*)(peer->data))->gems > 1000)
								{
									using namespace std::chrono;
									if (((PlayerInfo*)(peer->data))->lastSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
									{
										((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
									}
									else {
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Please wait `515`o seconds before you can sb another one!"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet);
										delete p.data;

										continue;
									}

									string name = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`# " + str.substr(4, cch.length() - 4 - 1)));
									string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
									BYTE * data = new BYTE[5 + text.length()];
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


									}
									((PlayerInfo*)(peer->data))->gems = ((PlayerInfo*)(peer->data))->gems - 1000;
									GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gems));
									ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packetsa);
									delete data;
									delete p.data;
									delete psa.data;
									continue;
								}
								else if (((PlayerInfo*)(peer->data))->gems < 1000)
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You don't have enough gems to sb!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
							else if (((PlayerInfo*)(peer->data))->haveGrowId == false)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Create an account first to SB!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						else if (((PlayerInfo*)(peer->data))->cantalk == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Can't SB while Muted!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					else {
						if (((PlayerInfo*)(peer->data))->cantalk == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Can't SB while Muted!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							continue;
						}
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are spamming sb too fast, calm down."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;

							continue;
						}
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`# " + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
							string username1;
							int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
							username1 = ((PlayerInfo*)(peer->data))->rawName;
							sendState(peer);
							cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
							sendState(peer);
							cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
							sendState(peer);
							cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
							sendState(peer);
							cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
							sendState(peer);
							cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
							sendState(peer);
							cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
							sendState(peer);
							cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
							sendState(peer);
							cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
							sendState(peer);
							cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
							sendState(peer);
							cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
							sendState(peer);
							level1 = ((PlayerInfo*)(peer->data))->level;
							sendState(peer);
							gems1 = ((PlayerInfo*)(peer->data))->gems;
							sendState(peer);
							skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
							sendState(peer);
							PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);


						}

						delete data;
						delete p.data;
						continue;
					}
				}
					else if (str.substr(0, 4) == "/jsb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait a minute before using the SB command again!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}

					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `4JAMMED``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
					BYTE * data = new BYTE[5 + text.length()];
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
					else if (str == "/invis") {
						sendConsoleMsg(peer, "`6" + str);
						if (!pData->isGhost) {

							sendConsoleMsg(peer, "`oYour atoms are suddenly aware of quantum tunneling. (Ghost in the shell mod added)");

							GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), pData->x, pData->y));
							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;

							sendState(peer);
							sendClothes(peer);
							pData->isGhost = true;
						}
						else {
							sendConsoleMsg(peer, "`oYour body stops shimmering and returns to normal. (Ghost in the shell mod removed)");

							GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), pData->x1, pData->y1));
							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							((PlayerInfo*)(peer->data))->isInvisible = false;
							sendState(peer);
							sendClothes(peer);
							pData->isGhost = false;
						}
					}
					else if (str.substr(0, 4) == "/bc ") {
					if (getAdminLevel(((PlayerInfo*)(peer->data))->tankIDName, ((PlayerInfo*)(peer->data))->tankIDPass) < 2)
					{
						if (((PlayerInfo*)(peer->data))->cantalk == true)
						{
							if (((PlayerInfo*)(peer->data))->haveGrowId == true)
							{
								if (((PlayerInfo*)(peer->data))->gems > 300)
								{
									using namespace std::chrono;
									if (((PlayerInfo*)(peer->data))->lastSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
									{
										((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
									}
									else {
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Please wait `515`o seconds to broadcast again!"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet);
										delete p.data;

										continue;
									}

									string name = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w**`2Broadcast`w from`2 " + name + "`w** :`# " + str.substr(4, cch.length() - 4 - 1)));
									string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
									BYTE * data = new BYTE[5 + text.length()];
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


									}
									((PlayerInfo*)(peer->data))->gems = ((PlayerInfo*)(peer->data))->gems - 300;
									GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gems));
									ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packetsa);
									delete data;
									delete p.data;
									delete psa.data;
									continue;
								}
								else if (((PlayerInfo*)(peer->data))->gems < 300)
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You don't have enough gems to BC!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
							else if (((PlayerInfo*)(peer->data))->haveGrowId == false)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Create an account first to BC!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						else if (((PlayerInfo*)(peer->data))->cantalk == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Can't BC while Muted!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					else {
						if (((PlayerInfo*)(peer->data))->cantalk == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Can't BC while Muted!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							continue;
						}
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are spamming sb too fast, calm down."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;

							continue;
						}
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w**`2Broadcast`w from`2 " + name + "`w** :`# " + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
						BYTE * data = new BYTE[5 + text.length()];
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
							string username1;
							int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
							username1 = ((PlayerInfo*)(peer->data))->rawName;
							sendState(peer);
							cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
							sendState(peer);
							cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
							sendState(peer);
							cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
							sendState(peer);
							cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
							sendState(peer);
							cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
							sendState(peer);
							cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
							sendState(peer);
							cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
							sendState(peer);
							cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
							sendState(peer);
							cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
							sendState(peer);
							cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
							sendState(peer);
							level1 = ((PlayerInfo*)(peer->data))->level;
							sendState(peer);
							gems1 = ((PlayerInfo*)(peer->data))->gems;
							sendState(peer);
							skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
							sendState(peer);
							PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);


						}

						delete data;
						delete p.data;
						continue;
					}
				}
					else if (str.substr(0, 6) == "/radio") {
					cout << "/radio from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p;
						if (((PlayerInfo*)(peer->data))->radio) {
							p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You won't see broadcasts anymore."));
							((PlayerInfo*)(peer->data))->radio = false;
						} else {
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
					else if (str.substr(0, 6) == "/reset"){
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
					else if (str.substr(0, 6) == "/music") {
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Everybody `2DANCE`w!"), "audio/mp3/pauwinako.mp3"), 0));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					ENetPeer* currentPeer;
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
					}
					else if (str.substr(0, 6) == "/clear"){
						if (!canClear(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						cout << "World cleared by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
						WorldInfo* wrld = getPlyersWorld(peer);
						for (int i = 0; i < worlds.size(); i++)
						{
							if (wrld == NULL) continue;
							if (&worlds.at(i) == wrld)
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
					else if (str == "/alt") {
					cout << "/alt from " << ((PlayerInfo*)(peer->data))->displayName << endl;
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
						cout << "/inventory from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
					}
					else
					if (str.substr(0, 6) == "/team ")
					{
						cout << "/team from " << ((PlayerInfo*)(peer->data))->displayName << endl;
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
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
						sendState(peer);
						level1 = ((PlayerInfo*)(peer->data))->level;
						sendState(peer);
						gems1 = ((PlayerInfo*)(peer->data))->gems;
						sendState(peer);
						skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
						sendState(peer);
						PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
					} else 
					if (str.substr(0, 7) == "/color ")
					{
						cout << "/color from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						((PlayerInfo*)(peer->data))->skinColor = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						sendClothes(peer);
						string username1;
						int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
						username1 = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
						sendState(peer);
						cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
						sendState(peer);
						cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
						sendState(peer);
						cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
						sendState(peer);
						cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
						sendState(peer);
						cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
						sendState(peer);
						cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
						sendState(peer);
						cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
						sendState(peer);
						cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
						sendState(peer);
						cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
						sendState(peer);
						level1 = ((PlayerInfo*)(peer->data))->level;
						sendState(peer);
						gems1 = ((PlayerInfo*)(peer->data))->gems;
						sendState(peer);
						skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
						sendState(peer);
						PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
					}
					if (str.substr(0, 4) == "/who")
					{
						cout << "/who from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						sendWho(peer);

					}
					if (str.length() && str[0] == '/')
					{
						sendAction(peer, ((PlayerInfo*)(peer->data))->netID, str);
					} else if (str.length()>0)
					{
						if (((PlayerInfo*)(peer->data))->cantalk == true) {
							sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, str);
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Can't`o talk while`4 Muted`o!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					
			}
			if (!((PlayerInfo*)(event.peer->data))->isIn)
			{



				GamePacket p1 = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(), "OnSuperMainStartAcceptLogonHrdxs47254722215a"), 1385479555), "ubistatic-a.akamaihd.net"), "0098/CDNContent3/cache/"), "cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"), "proto=42|choosemusic=audio/mp3/loonysong.mp3|active_holiday=0|"));
				GamePacket p = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(), "OnSuperMainStartAcceptLogonHrdxs47254722215a"), -1467284934), "ubistatic-a.akamaihd.net"), "0098/CDNContent3/cache/"), "cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"), "proto=42|choosemusic=audio/mp3/loonysong.mp3|active_holiday=0|"));
				//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);


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
						((PlayerInfo*)(event.peer->data))->realcountry = act;
						((PlayerInfo*)(event.peer->data))->country = act;
					}
				}
				if (!((PlayerInfo*)(event.peer->data))->haveGrowId)
				{
					((PlayerInfo*)(event.peer->data))->rawName = "";
					((PlayerInfo*)(event.peer->data))->displayName = "`w[`4GUEST`w] " + PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length() > 15 ? 15 : ((PlayerInfo*)(event.peer->data))->requestedName.length()));
					((PlayerInfo*)(peer->data))->isInvisible = false;
					sendState(peer);
				}
				else {
					((PlayerInfo*)(event.peer->data))->rawName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
#ifdef REGISTRATION
					int logStatus = PlayerDB::playerLogin(peer, ((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass);
					if (logStatus == 1) {
						string username = ((PlayerInfo*)(peer->data))->rawName;
						sendState(peer);
						ifstream file("players/EXTERNAL/friends/" + ((PlayerInfo*)(peer->data))->tankIDName + ".dat");
						if (file && ((PlayerInfo*)(peer->data))->fpb) {
							string content;
							while (file >> content) {
								((PlayerInfo*)(peer->data))->friendinfo.push_back(content);
							}
						}

						ifstream afile("players/EXTERNAL/" + ((PlayerInfo*)(peer->data))->tankIDName + ".dat");
						if (afile && ((PlayerInfo*)(peer->data))->fpb) {
							string acontent;
							while (afile >> acontent) {
								vector<string> info = split(acontent, '|');
								((PlayerInfo*)(peer->data))->level = stoi(info[1]);
								((PlayerInfo*)(peer->data))->level_xp = stoi(info[2]);
								((PlayerInfo*)(peer->data))->math_level = stoi(info[3]);
								((PlayerInfo*)(peer->data))->gems = stoi(info[4]);
								((PlayerInfo*)(peer->data))->level = stoi(info[5]);
							}
						}
						((PlayerInfo*)(peer->data))->fpb = true;
						std::ifstream ifs("sets/" + username + ".json");
						if (ifs.is_open()) { //here
							json j;
							ifs >> j;
							int cloth_hair = j["cloth_hair"];
							int cloth_neck = j["cloth_neck"];
							int cloth_shirt = j["cloth_shirt"];
							int cloth_pants = j["cloth_pants"];
							int cloth_feet = j["cloth_feet"];
							int cloth_face = j["cloth_face"];
							int cloth_hand = j["cloth_hand"];
							int cloth_back = j["cloth_back"];
							int cloth_mask = j["cloth_mask"];
							int cloth_ances = j["cloth_ances"];
							int level = j["level"];
							int gems = j["gems"];
							int skinColor = j["skinColor"];
							((PlayerInfo*)(peer->data))->cloth_hair = cloth_hair;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_necklace = cloth_neck;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_shirt = cloth_shirt;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_pants = cloth_pants;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_feet = cloth_feet;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_face = cloth_face;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_hand = cloth_hand;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_back = cloth_back;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_mask = cloth_mask;
							sendState(peer);
							((PlayerInfo*)(peer->data))->cloth_ances = cloth_ances;
							sendState(peer);
							((PlayerInfo*)(peer->data))->level = level;
							sendState(peer);
							((PlayerInfo*)(peer->data))->gems = gems;
							sendState(peer);
							((PlayerInfo*)(peer->data))->skinColor = skinColor;
							sendState(peer);
							if (((PlayerInfo*)(peer->data))->cloth_back > 0)
							{
								((PlayerInfo*)(peer->data))->canDoubleJump == true;
								sendState(peer);
							}
						}
						((PlayerInfo*)(peer->data))->isInvisible = false;
						sendState(peer);
						((PlayerInfo*)(event.peer->data))->displayName = ((PlayerInfo*)(event.peer->data))->tankIDName;
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Wrong username or password!``"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						enet_peer_disconnect_later(peer, 0);
					}
#else

					((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->tankIDName.substr(0, ((PlayerInfo*)(event.peer->data))->tankIDName.length() > 18 ? 18 : ((PlayerInfo*)(event.peer->data))->tankIDName.length()));
					if (((PlayerInfo*)(event.peer->data))->displayName.length() < 3) ((PlayerInfo*)(event.peer->data))->displayName = "Person that don't know how name looks!";
#endif
				}
				for (char c : ((PlayerInfo*)(event.peer->data))->displayName) if (c < 0x20 || c>0x7A) {
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Bad characters in user name! Change them.``"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					enet_peer_disconnect_later(peer, 0);
				}


				if (((PlayerInfo*)(event.peer->data))->country.length() > 4)
				{
					((PlayerInfo*)(event.peer->data))->country = "us";
				}
					if (isVIP(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "../token_icon_overlay";
					}
					if (isMod(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "../ ";
					}
					if (isMarius(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "us|maxLevel";
					}
					if (isManager(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "|maxLevel";
					}
					if (isSuperAdmin(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "|maxLevel";
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
				if(pStr.substr(0, 17) == "action|enter_game" && !((PlayerInfo*)(event.peer->data))->isIn)
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
					string name = ((PlayerInfo*)(peer->data))->displayName;
					cout << ((PlayerInfo*)(peer->data))->displayName << " joined the server. " << counts << " people are online." << endl;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWelcome back,`w " + name + "`o. `w" + std::to_string(counts) + "`o players are online."));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					counts = 0;
					GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWorld of The Week`o : `2ARI`o Owned by `2ARI`o!"));
					ENetPacket* packet1 = enet_packet_create(p1.data,
						p1.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet1);
					delete p1.data;
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
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe GrowtopiaSF News``|left|5016|\n\nadd_spacer|small|\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\nadd_spacer|small|\n\nadd_textbox|`wMay 28:`` `5Big updates!``|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Hello GrowtopiaSF players,|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|We have got new commands |left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|Thanks to ESC, we got new updates!|left|\n\nadd_spacer|small|\n\nadd_textbox|We have working of big update and we're convinced that the wait will be worth it!|0|0|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|Also, we're getting in every day one new update or so.|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|And for those who missed our new updates, we have our Discord, check it out on!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wDiscord Server``|noflags|https://discord.gg/uBAAVZW|Wanna check our Discord Server?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Lastly, check out other May updates:|left|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|New Commands and feature!:ADD FRIEND SYSTEM, LEVEL SYSTEM, GEMS SYSTEM , SAVE SET SYSTEM /mhelp,/help,/vhelp,/help/thanos, /owner, /oset and improving Gazette, /ban and /mute for mods and above|left|24|\n\nadd_label_with_icon|small|Personal roles, custom broadcasts|left|24|\n\nadd_spacer|small|\n\nadd_textbox|`$- The GrowtopiaSF Team``|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\n\n\n\n\nadd_url_button|comment|`wESCSF/VerkaSF Channel``|noflags|https://www.youtube.com/c/DeveloperNGPS|Open our developer ESCSF YouTube channel?|0|0|\n\nadd_url_button|comment|`wSurekingSF Channel````|noflags|https://www.youtube.com/channel/UCaN2c7xI1nJi7h2-wjtvdbQ|Open our developer SurekingSF YouTube channel?|0|0|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|`4WARNING:`` `5Drop games/trust tests`` and betting games (like `5Casinos``) are not allowed and will result in a ban!|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` Using any kind of `5hacked client``, `5spamming/text pasting``, or `5bots`` (even with an alt) will likely result in losing `5ALL`` your accounts. Seriously.|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` `5NEVER enter your GT password on a website (fake moderator apps, free gemz, etc) - it doesn't work and you'll lose all your stuff!|left|24|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wGrowtopiaSF website``|noflags|https://5cbae5bde102c.site123.me/|Open the GrowtopiaSF page in your browser?|0|0|\n\nadd_spacer|small|\n\nadd_button|rules|`wHelp - Rules - Privacy Policy``|noflags|0|0|\n\n\nadd_quick_exit|\n\nadd_spacer|small|\nadd_url_button|comment|`wVisit Growtopia Forums``|noflags|http://www.growtopiagame.com/forums|Visit the Growtopia forums?|0|0|\nadd_spacer|small|\nadd_url_button||`wWOTW: `1STEAM`` by `#Ahha````|NOFLAGS|OPENWORLD|STEAM|0|0|\nadd_spacer|small|\nadd_url_button||`wVOTW: `1New Growtopia private server My own GTPS!``|NOFLAGS|https://www.youtube.com/watch?v=hVExXxKAm2w|Watch 'New Growtopia private server My own GTPS!' by Sureking on YouTube?|0|0|\nend_dialog|gazette||OK|"));
						//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wMelty's Server``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_button|crash|`2Click Here`w if you are `4Crashing`w!|noflags|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|`wMay 21st: `5New Server|left| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|Dear Players,|left| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|GrowtopiaPH has been destroyed, it's now owned by oioids. Now we have a new server which is called Melty's Server. Melty's Server is owned by MeltyXD.|left| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_url_button||``Discord: `2Join our Discord Server!``|NOFLAGS|https://discord.gg/QaqB8bJ|Open link?|0|0| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|Here are some of the updates :|left| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wAdded `2Dropping System`w.|left|20|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wFixed /warp, added /go.|left|20|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wAdded /online to see who are the players online.|left|20|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wAdded /freeze and /warn for `^Moderators`o.|left|20|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wAdded /rgo,/r, and fixed /msg.|left|20|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wFixed /find, added /msg.|left|20|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`wAdded /warp (World Name).|left|20|\nadd_label_with_icon|small|`wAdded /showgem and /showlvl.|left|20|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|Happy server, for everyone!|left| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_textbox|-MeltyXD|left| |left|6746|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`4WARNING:`w DO NOT share your password to anyone! stolen gems will not be recovered!|left|1432|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`4WARNING:`w Worlds,accounts,levels and gems may be deleted/rollbacked at anytime we are doing our best to prevent this.|left|1432|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|`4WARNING:`w DO NOT download any malicious files because this might be a save.dat stealer that can see your account files!|left|1432|\nadd_label_with_icon|small| |left|6746|\nadd_label_with_icon|small|\nadd_url_button||`4YouTube`w: `1Watch the Video of The Week!``|NOFLAGS|https://youtu.be/yeDebhY9BZ8|Open link?|0|0|\nadd_url_button||``World: `1Check the World of The Week!``|NOFLAGS|https://cdn.discordapp.com/attachments/569666336314359819/577318121275129866/Screenshot_266.png|Open link?|0|0|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
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
				bool isNukedx = false;
				bool isplayebanned = false;
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
							WorldInfo info = worldDB.get(act);

							for (int i = 0; i < nukedworlds.size(); i++)
							{
								if (act == nukedworlds[i])
									isNukedx = true;
								else
									isNukedx = false;
							}
							if (act.length() > 15) {
								sendConsoleMsg(peer, "`wSorry`o, the World Name is too `2Long`o! The name should be `215`o Letters Short.");
								enet_peer_disconnect_later(peer, 0);
							}
							if (!isNukedx) {
								for (int i = 0; i < ((PlayerInfo*)(peer->data))->worldbans.size(); i++)
								{
									if (act == ((PlayerInfo*)(peer->data))->worldbans[i])
										isplayebanned = true;
									else
										isplayebanned = false;
								}
								if (!isplayebanned)
								{
									sendWorld(peer, &info);

									int x = 3040;
									int y = 736;

									for (int j = 0; j < info.width * info.height; j++)
									{
										if (info.items[j].foreground == 6) {
											x = (j % info.width) * 32;
											y = (j / info.width) * 32;
										}
									}

									string invis = "0";
									if (((PlayerInfo*)(peer->data))->isInvisible) {
										invis = "1";
									}
									else {
										invis = "0";
									}
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|" + invis + "\nmstate|0\nsmstate|2\ntype|local\n"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
									((PlayerInfo*)(event.peer->data))->netID = cId;
									onPeerConnect(peer);
									cId++;
									ENetPeer * currentPeer;
									PlayerInventory inventory;
									InventoryItem item;
									item.itemCount = 1;
									item.itemID = 18;
									inventory.items.push_back(item);
									item.itemCount = 1;
									item.itemID = 32;
									inventory.items.push_back(item);
									sendInventory(peer, inventory);
									//sendInventory(peer, ((PlayerInfo*)(event.peer->data))->inventory);
									WorldInfo * world = getPlyersWorld(peer);
									string nameworld = world->name;
									string ownerworld = world->owner;
									int count = 0;
									string name = "";
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										count++;
									}
									sendPlayerEnter(peer, (PlayerInfo*)(event.peer->data));
									if (ownerworld != "") {
										GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#[`o" + nameworld + " `oWorld Locked by " + ownerworld + "`#]"));
										ENetPacket * packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet3);
										delete p3.data;
									}
									WorldInfo * real = getPlyersWorld(peer);
									PlayerInfo* info = ((PlayerInfo*)(peer->data));
									GamePacket paczka = packetEnd(appendInt(appendString(createPacket(), "OnSetBaseWeather"), real->weather));
									ENetPacket* packetpaka = enet_packet_create(paczka.data,
										paczka.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packetpaka);
									delete paczka.data;
									//
									PlayerInfo* playinfo = ((PlayerInfo*)(peer->data));
									int netID = info->netID;
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
											data.x = 1000;
											data.y = 1000;
											data.punchX = 0;
											data.punchY = 0;
											data.XSpeed = 300;
											data.YSpeed = 600;
											data.netID = netID;
											data.plantingTree = state;
											BYTE* raw = packPlayerMoving(&data);
											int var = effect; // placing and breking
											memcpy(raw + 1, &var, 3);
											SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
											GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), playinfo->effect));
											ENetPacket* packet2 = enet_packet_create(p2.data,
												p2.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet2);
											delete p2.data;
											GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), playinfo->effect));
											ENetPacket* packets = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packets);
											delete p.data;
										}
									}
									//
									((PlayerInfo*)(event.peer->data))->haveSuperSupporterName = true;
									sendState(peer);

								}

								else {
									GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Oh no! `oYou've been banned from that world by its owner! Try again later after the world ban wears off."));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}

							else {
								GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "That world is inaccessible."));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;


							}

						}
						catch (int e) {
							if (e == 1) {
								GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are in EXIT!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

							}
							else if (e == 2) {
								GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have entered bad characters to world name!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

							}
							else if (e == 3) {
								GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't go to EXIT!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

							}
							else {
								GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Unknown error while entering world!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

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
							sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
							((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
							sendWorldOffers(peer);
						}
						if (act == "quit")
						{
							string username1;
							int cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1;
							username1 = ((PlayerInfo*)(peer->data))->rawName;
							sendState(peer);
							cloth_hair1 = ((PlayerInfo*)(peer->data))->cloth_hair;
							sendState(peer);
							cloth_necklace1 = ((PlayerInfo*)(peer->data))->cloth_necklace;
							sendState(peer);
							cloth_shirt1 = ((PlayerInfo*)(peer->data))->cloth_shirt;
							sendState(peer);
							cloth_pants1 = ((PlayerInfo*)(peer->data))->cloth_pants;
							sendState(peer);
							cloth_feet1 = ((PlayerInfo*)(peer->data))->cloth_feet;
							sendState(peer);
							cloth_face1 = ((PlayerInfo*)(peer->data))->cloth_face;
							sendState(peer);
							cloth_hand1 = ((PlayerInfo*)(peer->data))->cloth_hand;
							sendState(peer);
							cloth_back1 = ((PlayerInfo*)(peer->data))->cloth_back;
							sendState(peer);
							cloth_mask1 = ((PlayerInfo*)(peer->data))->cloth_mask;
							sendState(peer);
							cloth_ances1 = ((PlayerInfo*)(peer->data))->cloth_ances;
							sendState(peer);
							level1 = ((PlayerInfo*)(peer->data))->level;
							sendState(peer);
							gems1 = ((PlayerInfo*)(peer->data))->gems;
							sendState(peer);
							skinColor1 = ((PlayerInfo*)(peer->data))->skinColor;
							sendState(peer);
							PlayerDB::saveset(username1, cloth_hair1, cloth_shirt1, cloth_pants1, cloth_feet1, cloth_face1, cloth_hand1, cloth_back1, cloth_mask1, cloth_necklace1, cloth_ances1, gems1, level1, skinColor1);
							int count = 0;
							ENetPeer* currentPeer;
							string name = "";
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								count++;
							}
							cout << ((PlayerInfo*)(peer->data))->displayName << " left the server. " << count << " people are online." << endl;
							count = 0;
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
						if (((PlayerInfo*)(event.peer->data))->isGhost) {
							((PlayerInfo*)(event.peer->data))->isInvisible = true;
							((PlayerInfo*)(event.peer->data))->x1 = pMov->x;
							((PlayerInfo*)(event.peer->data))->y1 = pMov->y;
							pMov->x = -1000000;
							pMov->y = -1000000;
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
						}
						if (data2->packetType == 7)
						{
							//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << endl;
							/*GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
							//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
							ENetPacket * packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet3);
							enet_host_flush(server);*/
							sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
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
							case 5:
								if (((PlayerInfo*)(event.peer->data))->cloth5 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth5 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth5 = pMov->plantingTree;
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
#endif
			/* Reset the peer's client information. */
			/*ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;

				GameitPacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just left the game..."));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet);
				enet_host_flush(server);
			}*/
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

