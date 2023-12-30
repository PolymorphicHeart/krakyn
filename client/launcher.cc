#include <krakyn/krakyn.hh>

int32_t main ()
{
    kyn::init_all_modules();

    kyn::tcp_socket_t client;

    if (!client.connect())
    {
        std::cout << "unable to connect!" << std::endl;
    }

    client.send("hello world", 12);

    kyn::shutdown_all_modules();
    return 0;
}