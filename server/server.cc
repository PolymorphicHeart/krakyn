#include <krakyn/krakyn.hh>

int32_t main ()
{
    kyn::init_all_modules();

    kyn::tcp_socket_t server("ANY");

    char msg[12] = {};

    server.bind();
    server.listen();

    while (true)
    {
        auto conn = server.accept();
        conn.recieve(msg, sizeof(msg));
        
        std::cout << msg << "\n";
        std::cout << conn.to_string() << "\n";
    }

    kyn::shutdown_all_modules();
    return 0;
}