#include "SIP.hpp"

string SIP::line;
string SIP::branchForCall;
string SIP::tagForCall;
string SIP::idForCall;
int SIP::Csq = 20;


string SIP::processResponse(map<string, string>& fields, const char * response)
{
    string tmp = response;
    string hdr(tmp.begin(), tmp.begin() + tmp.find("\r\n"));
    if (hdr.find("401") != string::npos)
    {
        fields["nonce"] = getfield(tmp, "nonce");
        fields["opaque"] = getfield(tmp, "opaque");
        fields["realm"] = getfield(tmp, "realm");
        fields["qop"] = getfield(tmp, "qop");
        fields["received"] = getfield(tmp, "received");
        return "";
    } else {
        return hdr;
    }
}

void SIP::HA1(const char * username, const char * realm, const char * passwd, unsigned char * out)
{
    unsigned char str[200] = "";
    strcat((char *)str, username);
    strcat((char *)str, ":");
    strcat((char *)str, realm);
    strcat((char *)str, ":");
    strcat((char *)str, passwd);
    MD5(str, strlen((char *)str), out);
}

void SIP::HA2(const char * method, const char * uri, unsigned char * out)
{
    unsigned char str[200] = "";
    strcat((char *)str, method);
    strcat((char *)str, ":");
    strcat((char *)str, uri);
    MD5(str, strlen((char *)str), out);
}

void SIP::countResponse(map<string, string>& fields, struct Channel& channel_)
{
    fields["cnonce"] = generateUnique();
    fields["nc"] = "00000001";
    unsigned char cHA1[MD5_DIGEST_LENGTH] = "";
    unsigned char cHA2[MD5_DIGEST_LENGTH] = "";
    HA1(channel_.login.c_str(), fields["realm"].c_str(), channel_.password.c_str(), cHA1);
    HA2("REGISTER", channel_.host.c_str(), cHA2);
    char HA1C[33] = "";
    char HA2C[33] = "";
    char buff[3];
    for (int i=0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(buff, "%02x",cHA1[i]);
        strcat(HA1C, buff);
    };
    for (int i=0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(buff, "%02x",cHA2[i]);
        strcat(HA2C, buff);
    };
    HA1C[32] = '\0';
    HA2C[32] = '\0';

    unsigned char tmp[33] = "";

    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, HA1C, strlen(HA1C));
    MD5_Update(&c, ":", 1);
    MD5_Update(&c, fields["nonce"].c_str(), strlen(fields["nonce"].c_str()));
    MD5_Update(&c, ":", 1);
    MD5_Update(&c, fields["nc"].c_str(), strlen(fields["nc"].c_str()));
    MD5_Update(&c, ":", 1);
    MD5_Update(&c, fields["cnonce"].c_str(), strlen(fields["cnonce"].c_str()));
    MD5_Update(&c, ":", 1);
    MD5_Update(&c, fields["qop"].c_str(), strlen(fields["qop"].c_str()));
    MD5_Update(&c, ":", 1);
    MD5_Update(&c, HA2C, strlen(HA2C));
    MD5_Final(tmp, &c);
    char out[33] = "";
    for (int i=0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(buff, "%02x", tmp[i]);
        strcat(out, buff);
    };
    fields["response"] = out;
}

string SIP::getfield(string& str, const string field)
{
    size_t pos;
    pos = str.find(field);
    string::iterator i = str.begin() + pos;
    string out;
    if (field == "received")
    {
        while (*i != '=')
        {
            i++;
        }
        i++;
        while (*i != '\r')
        {
            out.push_back(*i);
            i++;
        }
    }
    else
    {
        while (*i != '"')
        {
            i++;
        }
        i++;
        while (*i != '"')
        {
            out.push_back(*i);
            i++;
        }
    }
    return out;
}

string SIP::generateUnique()
{
    srand(time(NULL) + rand());
    stringstream ss;
    for (int i = 0; i < 8; i++)
    {
        ss << std::hex << rand() % 16;
    }
    return ss.str();
}

void SIP::generateRegisterHeader(string& header, map<string, string>& fields, struct Channel& channel_)
{
    vector<string> fieldsv{
        "REGISTER ",
        "Via: SIP/2.0/UDP ",
        "Max-Forwards: 70\r\n",
        "From: <sip:",
        "To: <sip:",
        "Call-ID: ",
        "CSeq: 1 REGISTER\r\n",
        "User-Agent: Wiprobe\r\n",
        "Contact: <sip:", //
        "Expires: 30\n",
        "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n",
        "Content-Length:  0\r\n\r\n",
        ""
    };
    fields["callid"] = generateUnique();
    fields["tag"] = generateUnique();
    fieldsv[0] += channel_.dst_name + " SIP/2.0\r\n";
    fieldsv[1] += channel_.src_name + ";rport;branch=z9hG4bK" + generateUnique() + "\r\n";
    fieldsv[3] += channel_.login + "@" + channel_.host + ">;tag=" + fields["tag"] + "\r\n";
    fieldsv[4] += channel_.login + "@" + channel_.host + ">\r\n";
    fieldsv[5] += fields["callid"] + "\r\n";
    fieldsv[8] += channel_.login + "@" + channel_.src_name + ";line=" + line + ">\r\n";
    stringstream ss;
    string n = fieldsv[0];
    for (int i = 1; n != ""; i++)
    {
        ss << n;
        n = fieldsv[i];
    }
    header = ss.str();
}

void SIP::generateAuthHeader(string& header, map<string, string>& fields, struct Channel& channel_)
{
    vector<string> fieldsv{
        "REGISTER ",
        "Via: SIP/2.0/UDP ",
        "Max-Forwards: 70\r\n",
        "From: <sip:",
        "To: <sip:",
        "Call-ID: ",
        "CSeq: 2 REGISTER\r\n",
        "User-Agent: Wiprobe\r\n",
        "Contact: <sip:",
        "Expires: 30\r\n",
        "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n",
        "Authorization: Digest username=\"",
        "Content-Length:  0\r\n\r\n",
        ""
    };
    fieldsv[0] += channel_.host + " SIP/2.0\r\n";
    fieldsv[1] += fields["received"] + ";rport;branch=z9hG4bK" + generateUnique() + "\r\n";
    fieldsv[3] += channel_.login + "@" + channel_.host + ">;tag=" + fields["tag"] + "\r\n";
    fieldsv[4] += channel_.login + "@" + channel_.host + ">\r\n";
    fieldsv[5] += fields["callid"] + "\r\n";
    fieldsv[8] += channel_.login + "@" + fields["received"] + ";line=" + line + ">\r\n";
    fieldsv[11] += channel_.login + "\", realm=\"" + fields["realm"] + "\", nonce=\""
                        + fields["nonce"] + "\", uri=\"" + channel_.host + "\", response=\""
                        + fields["response"] + "\", algorithm=MD5, cnonce=\"" + fields["cnonce"]
                        + "\", opaque=\"" + fields["opaque"] + "\", qop=" + fields["qop"]
                        + ", nc=00000001\r\n";
    stringstream ss;
    string n = fieldsv[0];
    for (int i = 1; n != ""; i++)
    {
        ss << n;
        n = fieldsv[i];
    }
    header = ss.str();
}

void SIP::generateInviteRequest(string& header, struct Channel& ch)
{
    header = "";
    vector<string> fieldsv{
        "INVITE ",
        "Via: SIP/2.0/UDP 91.121.209.194;rport;branch=z9hG4bK" + SIP::generateUnique() + "\r\n",
        "Via: SIP/2.0/UDP ",
        "Record-Route: <sip:",
        "From: <sip:",
  /*5*/ "To: <",
        "Call-ID: ",
        "CSeq: ",
        "User-Agent: Wiprobe\r\n",
        "Contact: <sip:",
 /*10*/ "Content-Type: application/sdp\r\n",
        "Max-Forwards: 70\r\n",
        "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n",
        "Subject: Phone call\r\n",
        "Content-Length: ",
        "v=0\r\n",
        "o=wiproberu " + SIP::getRandSID() + " 145 IN IP4 192.168.14.184\r\n",
        "s=Talk\r\n",
        "c=IN IP4 192.168.14.184\r\n",
        "t=0 0\r\n",
        "m=audio 17078 RTP/AVP 99 124\r\n",
        "a=rtpmap:99 G.729/8000\r\n",
        "a=rtpmap:124 opus/48000\r\n",
        // "a=fmtp:124 useinbandfec=1; usedtx=1\r\n",
        ""
    };
    if (line == "")
    {
        line = SIP::generateUnique();
    }
    if (branchForCall == "")
    {
        branchForCall = "z9hG4bK" + SIP::generateUnique();
    }
    if (tagForCall == "")
    {
        tagForCall = SIP::generateUnique();
    }
    if (idForCall == "")
    {
        idForCall = SIP::generateUnique();
    }
    if (Csq == 0)
    {
        Csq = 20;
    }
    fieldsv[0] += "sip:" + ch.callTo + "@5.44.169.206;line=" + line + " SIP/2.0\r\n";
    fieldsv[2] += ch.src_name + ":" + SIP_SRC_GET + ";rport="+ SIP_SRC_GET +";branch=" + branchForCall + ";received=5.44.169.206\r\n";
    fieldsv[3] += ch.dst_name + ":" + DEF_SIP_PORT + ";lr>\r\n";
    fieldsv[4] += ch.login + "@sip.linphone.org>;tag=" + tagForCall + "\r\n";
    fieldsv[5] += "sip:" + ch.callTo + "@sip.linphone.org" + ">\r\n";
    fieldsv[6] += idForCall + "\r\n";
    fieldsv[7] += to_string(Csq) + " INVITE\r\n";
    Csq++;
    fieldsv[9] += ch.login + "@" + ch.src_name + ":" + SIP_SRC_GET +">\r\n";
    int countLen = 0;
    for (auto i = fieldsv.begin() + 15; *i != ""; i++)
    {
        countLen += i->length();
    }
    fieldsv[14] += to_string(countLen) + "\r\n\r\n";
    for (auto i = fieldsv.begin(); i < fieldsv.end(); i++)
    {
        header += *i;
    }
}

string SIP::getRandSID()
{
    srand(time(0));
    return to_string(rand());
}

/*void SIP::setCsq()
{
    Csq = 0;
}*/

ostream& operator<< (ostream &out, const struct Channel& ch)
{
    out << "Login:    " << ch.login << endl;
    out << "Password: " << ch.password << endl;
    out << "Dst_name: " << ch.dst_name << endl;
    out << "Src_name: " << ch.src_name << endl;
    out << "Host:     " << ch.host << endl;
    return out;
}