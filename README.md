# cmd-spoofing

ʹ�øù��߿�ʹ��α��������д���Ŀ����̣��� sysmon �� ETW ����Ľ��̴����¼���־�н���ʾα��������У�������ʵ��ִ�е������У������� CobaltStrike �� argue ָ�

## �÷�

cmd-spoofing.exe "cmd.exe /c xxxxxxx" "cmd.exe /c notepad.exe"

Ч����

![x](screenshot.png)

**ע�⣺����ִ�еĻ���ͬһ������ֻ�����ǲ����Ĳ�ͬ���ѣ�����Ҫ����������ֲ�����`cmd-spoofing.exe cmd.exe notepad.exe`��**

## ����

������Windows + VS2022 + CMake

����ֱ���� VS2022 �д򿪱��룬Ҳ����ʹ�� cmake �������� build.ninja ���б��룺

```powershell
cd cmd-spoofing
cmake -S . --preset=x64-release
ninja -C out\build\x64-release
```