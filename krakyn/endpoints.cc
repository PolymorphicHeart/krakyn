#include "krakyn.hh"

namespace kyn
{
    static void handle_server_conn (server_endp_t* server, endp_desc_t conn)
    {
        while (true)
        {
            byte_vec_t buffer(KYN_AUTH_ASYM_KEYBYTES);
            auto ret = conn.m_Socket.recieve(buffer.data(), buffer.size());

            if (ret > 0) 
            {
                std::cout << ret << std::endl;
                std::cout << bytes_to_base64(buffer) << std::endl;
                std::cout << bytes_to_base64(server->m_Profile.m_Keypair.first) << std::endl;
            }

            if (ret == 0)
            {
                std::cout << "shutting down socket: " << conn.m_Socket.m_ID << std::endl;
                break;
            }
        }
    }

    server_endp_t::server_endp_t (const profile_t& profile) : m_ListenerSocket(KYN_SOCK_EMPTY_ADDR, KYN_SOCK_NEW_ID)
    {
        if (profile.m_Keypair.first.size() < KYN_AUTH_ASYM_KEYBYTES || profile.m_Keypair.second.size() < KYN_AUTH_ASYM_KEYBYTES) return;
        if (profile.m_Name.size() == 0) return;

        m_Authenticated = true;
        m_Profile = profile;

        m_ListenerSocket.bind();
        m_ListenerSocket.listen();
    }

    server_endp_t::~server_endp_t () 
    {
        m_ListenerSocket.close();
    }

    void server_endp_t::init ()
    {
        if (m_Running || !m_Authenticated) return;
        m_Running = true;

        while (m_Running)
        {
            auto conn_sock = m_ListenerSocket.accept();
            if (!conn_sock.is_valid()) continue;

            endp_desc_t conn_desc = { .m_Socket = conn_sock, .m_Complete = false };
            std::thread conn_th(handle_server_conn, this, conn_desc);
            conn_th.detach();
        }
    }
}