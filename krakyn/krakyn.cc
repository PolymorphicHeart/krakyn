#include "krakyn.hh"

namespace kyn
{
    bool init_all_modules ()
    {
        return 
            init_auth_module() &&
            init_socket_module();
    }

    bool shutdown_all_modules ()
    {
        return
            shutdown_auth_module() &&
            shutdown_socket_module();
    }
}