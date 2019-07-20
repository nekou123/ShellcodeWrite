#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>


int main(int argc , char** argv)
{
	if (argc != 2)
	{
		printf("%s <Shellcode File>", argv[0]);
		return 1;
	}

	FILE* Filein = fopen(argv[1], "rb");
	if(Filein == NULL)
	{
		printf("Could not open file \n");
		return 1;
	}

	
	/*Find the find shellcode size*/
	fseek(Filein, 0L, SEEK_END);
	int ShellcodeSize = ftell(Filein);
	fseek(Filein, 0L, SEEK_SET);

	char* buf = (char*)malloc(ShellcodeSize * sizeof(char));
	fread(buf, 1, ShellcodeSize, Filein);
	/*Get handle of the current process and alloc memory to execute*/
	HANDLE currentProcess = GetCurrentProcess(); 
	void * MemoryShellcode = VirtualAllocEx(currentProcess, NULL, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if(MemoryShellcode == NULL)
	{
		printf("Fail to Alloc memory \n");
		return 1;
	}

	memcpy(MemoryShellcode, buf, ShellcodeSize);
	DWORD threadID;
	HANDLE thHand = CreateThread(NULL, 0,(LPTHREAD_START_ROUTINE) MemoryShellcode, NULL, 0, &threadID);
	
	if (thHand == NULL) {
		printf("CreateThread failed. Error");
		return 1;
	}
	else {
		printf("Createthread successful!");
	}
	
	
	WaitForSingleObject(thHand, INFINITE);

	fclose(Filein);
	CloseHandle(thHand);
	CloseHandle(currentProcess);
	return 0;
}