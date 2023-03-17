#include <Windows.h>
#include <stdio.h>

typedef int(WINAPI *t_DownloadFile)(LPCSTR, LPCSTR, int);

void Inseng_DownloadFile()
{
	HMODULE lib = LoadLibraryA("inseng.dll");
	if (lib)
	{
		t_DownloadFile DownloadFile = (t_DownloadFile)GetProcAddress(lib, "DownloadFile");
		if (DownloadFile)
		{
			DownloadFile("https://www.google.com/putty.exe", "putty.exe", 1);
		}
	}
}
int main()
{
	Inseng_DownloadFile();
	return 0;
}
