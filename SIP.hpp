#ifndef SIP_HPP
#define SIP_HPP
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <openssl/md5.h>
#include <memory>


#define SIP_PORT 15065
#define SIP_PORT_SRC "15065"
#define SIP_SRC_GET "15063"
#define DEF_SIP_PORT "5060"


using namespace std;

struct Channel
{
    string login;
    string password;
    string dst_name;
    string src_name;
    string host;
    string callTo;
    string contactIp;
    friend ostream& operator<< (ostream &out, const struct Channel& ch);
};

class SIP
{
    static string branchForCall;
    static string tagForCall;
    static string idForCall;
    static string line;
    static int Csq;
    public:
    /*void setCsq();*/
    string processResponse(map<string, string>& fields, const char * response);
    void HA1(const char * username, const char * realm, const char * passwd, unsigned char * out);
    void HA2(const char * method, const char * uri, unsigned char * out);
    void countResponse(map<string, string>& fields, struct Channel& channel_);
    string getfield(string& str, const string field);
    static string generateUnique();
    static string getRandSID();
    void generateRegisterHeader(string& header, map<string, string>& fields, struct Channel& channel_);
    void generateAuthHeader(string& header, map<string, string>& fields, struct Channel& channel_);
    void generateInviteRequest(string& header, struct Channel& ch);
};

#endif