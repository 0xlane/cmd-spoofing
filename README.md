# cmd-spoofing

ʹ�øù��߿�ʹ��α��������д���Ŀ����̣��� sysmon �� ETW ����Ľ��̴����¼���־�н���ʾα��������У�������ʵ��ִ�е������У������� CobaltStrike �� argue ָ�

## �÷�

cmd-spoofing.exe "cmd.exe /c xxxxxxx" "cmd.exe /c notepad.exe"

Ч����

![x](screenshot.png)

## ����

������Windows + VS2022 + CMake

����ֱ���� VS2022 �д򿪱��룬Ҳ����ʹ�� cmake �������� build.ninja ���б��룺

```powershell
cd cmd-spoofing
cmake -S . --preset=x64-release
ninja -C out\build\x64-release
```