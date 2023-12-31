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

    kyn::tcp_socket_t client;

    if (!client.connect())
    {
        std::cout << "unable to connect!" << std::endl;
    }

    client.send("hello world", 12);

    kyn::shutdown_all_modules();
    return 0;
}