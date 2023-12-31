#include <krakyn/krakyn.hh>

int32_t main ()
{
    kyn::init_all_modules();

    auto keypair2 = kyn::load_profile_from_disk("./test.kyn", "test_user_0", "abc");

    if (keypair2.first.size() < 1 || keypair2.second.size() < 1)
    {
        std::cout << "error loading profile!" << std::endl;
    }

    else
    {
        std::cout << kyn::bytes_to_base64(keypair2.first) << "\n" << kyn::bytes_to_base64(keypair2.second) << std::endl;
    }

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