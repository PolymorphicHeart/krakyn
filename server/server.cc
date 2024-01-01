#include <krakyn/krakyn.hh>

int32_t main ()
{
    kyn::init_all_modules();
    
    auto sprofile = kyn::load_profile_from_disk("./test.kyn", "test_user_0", "abc");

    kyn::server_endp_t server(sprofile);
    server.init();

    kyn::shutdown_all_modules();
    return 0;
}