#include <krakyn/krakyn.hh>

int32_t main ()
{
    kyn::init_all_modules();

    auto cprofile = kyn::load_profile_from_disk("./test.kyn", "test_user_0", "abc");
    kyn::tcp_socket_t conn;

    conn.connect();
    auto ret = conn.send(cprofile.m_Keypair.first.data(), cprofile.m_Keypair.first.size());

    while (true) {}

    conn.close();

    kyn::shutdown_all_modules();
    return 0;
}