#include "SIP.hpp"
#define CLR_REQ request = "";

using namespace boost::asio;
using namespace boost::asio::ip;
using namespace std;

static io_service io;

int main(int argc, char ** argv)
{
    /*if (argc != 6)
    {
        cout << "Not enough args." << endl;
        return 1;
    }*/
    struct Channel ch;
    cout << "Input login:" << endl;
    cin >> ch.login;
    cout << "Input password:" << endl;
    cin >> ch.password;
    cout << "Input src_adr:" << endl;
    cin >> ch.dst_name;
    cout << "Input dst_adr:" << endl;
    cin >> ch.src_name;
    cout << "Input host:" << endl;
    cin >> ch.host;

    cout << ch;

	boost::asio::ip::udp::endpoint ep( boost::asio::ip::address::from_string("91.121.209.194"), 5060);
    boost::asio::ip::udp::endpoint sender_ep;

    boost::asio::ip::udp::socket * local_socket = new udp::socket(io);
    local_socket->open(boost::asio::ip::udp::v4());
    try {
        cout << "Trying to bind socket for " << ch.src_name << " port = " << SIP_PORT << endl;
    	local_socket->bind(ip::udp::endpoint(ip::address::from_string(ch.src_name), SIP_PORT));
	}
    catch(std::exception& e)
    {
        cout << "Get exeption " << e.what() << endl;
        cout << "Returning from prog" << endl;
        local_socket->bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0));
    }
	catch(...)
	{
		cout << " Error with binding local socket." << endl;
		return 1;
	}
    cout << "Type address you want to call" << endl;
    cin >> ch.callTo;

    SIP obj;
    string CLR_REQ;
    map<string, string> fields;
    char response[1000];
    /* Block of sending REGISTER request */
    obj.generateRegisterHeader(request, fields, ch);
    int bytes;
    local_socket->send_to(boost::asio::buffer(request), ep);
    local_socket->receive_from(boost::asio::buffer(response), sender_ep);
    obj.processResponse(fields, response);

    obj.countResponse(fields, ch);
    CLR_REQ;
    char secondResponse[1000] = "";
    obj.generateAuthHeader(request, fields, ch);
    bytes = local_socket->send_to(boost::asio::buffer(request), ep);
    bytes = local_socket->receive_from(boost::asio::buffer(secondResponse), sender_ep);

    /* End of sending REGISTER request */
    obj.generateInviteRequest(request, ch);
    // cout << request;

    /* Block of sending INVITE Request */
    bytes = local_socket->send_to(boost::asio::buffer(request), ep);
    cout << "Waiting answer from sip server..." << endl;
    //string response;
    memset(response, 0, 1000);
    bytes = local_socket->receive_from(boost::asio::buffer(response), sender_ep);
    cout << "Answer from server : " << response << endl;
    string str_response = response;

    if (str_response.find("407 Proxy Authentication Required") != string::npos)
    {
        CLR_REQ;
        fields["tag"] = SIP::getfield(str_response, "tag");
        obj.generateAck(request, fields, ch);
        cout << endl << endl << "Ack request = " << endl << request;
        bytes = local_socket->send_to(boost::asio::buffer(request), ep);
    }
    obj.processResponse(fields, str_response.c_str());

    fields["uri"] = "sip:" + ch.callTo + "@" + ch.host;
    obj.countResponse(fields, ch);
    CLR_REQ;
    obj.generateProxyAuthHeader(request, fields, ch);
    cout << "Sending proxy auth request" << endl;
    bytes = local_socket->send_to(boost::asio::buffer(request), ep);

    memset(response, 0, 1000);
    cout << " Trying to get answer from server" << endl;
    bytes = local_socket->receive_from(boost::asio::buffer(response), sender_ep);

    //cout << obj.getfield(response, "");
    /* End of sending INVITE request */
    return 0;
}