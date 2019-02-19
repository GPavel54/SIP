#include "SIP.hpp"
#define SIP_PORT 15065
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
    
    cout << "First response = " << endl << response << endl;
    obj.processResponse(fields, response);

    obj.countResponse(fields, ch);
    CLR_REQ;
    char secondResponse[1000] = "";
    obj.generateAuthHeader(request, fields, ch);
    bytes = local_socket->send_to(boost::asio::buffer(request), ep);
    bytes = local_socket->receive_from(boost::asio::buffer(secondResponse), sender_ep);

    cout << "Second response = " << secondResponse << endl;

    /* End of sending REGISTER request */
    obj.generateInviteRequest(request, ch);
    // cout << request;

    cout << "Generated INVITE request:" << endl << request;

    /* Block of sending INVITE Request */
    bytes = local_socket->send_to(boost::asio::buffer(request), ep);
    cout << "Successfully sent " << bytes << " bytes to " << "91.121.209.194" << endl;
    cout << "Waiting answer from sip server..." << endl;
    //string response;
    bytes = local_socket->receive_from(boost::asio::buffer(response), sender_ep);
    cout << "Recieve " << bytes << " bytes from sip server " << endl;
    cout << "Answer from server : " << response << endl;
    /* End of sending INVITE request */
    return 0;
}