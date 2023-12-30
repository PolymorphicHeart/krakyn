#include "krakyn.hh"

#if defined(KYN_PLATFORM_UNIX)
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static bool s_SocketModuleInit = false;

namespace kyn
{
    tcp_socket_t::tcp_socket_t (const std::string& addr, int32_t id) : m_ID(id), m_Address(addr) 
    {
        if (m_ID == -2) m_ID = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    }

    tcp_socket_t::~tcp_socket_t ()
    {
        close(m_ID);
    }

    bool tcp_socket_t::bind ()
    {
        sockaddr_in6 saddr = {};
        saddr.sin6_family  = AF_INET6;
	    saddr.sin6_port    = htons(KYN_SOCK_TCP_PORT);

        if (m_Address != "ANY") inet_pton(AF_INET6, m_Address.c_str(), &saddr.sin6_addr);
        else saddr.sin6_addr = in6addr_any;

        auto ret = ::bind(m_ID, reinterpret_cast<struct sockaddr*>(&saddr), sizeof(saddr));
        return (ret == -1) ? false : true;
    }

    bool tcp_socket_t::connect ()
    {
        sockaddr_in6 saddr = {};
        saddr.sin6_family  = AF_INET6;
	    saddr.sin6_port    = htons(KYN_SOCK_TCP_PORT);

        inet_pton(AF_INET6, m_Address.c_str(), &saddr.sin6_addr);

        auto ret = ::connect(m_ID, reinterpret_cast<struct sockaddr*>(&saddr), sizeof(saddr));
        return (ret == -1) ? false : true;
    }

    bool tcp_socket_t::listen ()
    {
        auto ret = ::listen(m_ID, KYN_SOCK_MAX_QUEUE);
        return (ret == -1) ? false : true;
    }

    tcp_socket_t tcp_socket_t::accept ()
    {
        sockaddr_in6 saddr = {};
        saddr.sin6_family  = AF_INET6;
	    saddr.sin6_port    = htons(KYN_SOCK_TCP_PORT);
        socklen_t saddr_size = sizeof(saddr);

        auto id = ::accept(m_ID, reinterpret_cast<struct sockaddr*>(&saddr), &saddr_size);
        char addr[INET_ADDRSTRLEN] = {};

        inet_ntop(AF_INET6, &(saddr.sin6_addr), addr, INET_ADDRSTRLEN);
        return tcp_socket_t(addr, id);
    }

    int32_t tcp_socket_t::recieve (void* buffer, int32_t size)
    {
        return ::recv(m_ID, buffer, size, 0);
    }

    int32_t tcp_socket_t::send (const void* buffer, int32_t size)
    {
        return ::send(m_ID, buffer, size, 0);
    }

    std::string tcp_socket_t::to_string ()
    {
        std::string str = 
            "------ socket ------\naddress: " +
            m_Address + "\nid: " +
            std::to_string(m_ID) +
            "\n------ socket ------";

        return str;
    }

    bool init_socket_module ()
    {
        if (s_SocketModuleInit) return false;
        return s_SocketModuleInit = true;
    }

    bool shutdown_socket_module ()
    {
        if (!s_SocketModuleInit) return false;
        s_SocketModuleInit = false;
        return true;
    }
}

#endif