#ifndef KRAKYN_H
#define KRAKYN_H

#if defined(__cplusplus)

/* -------- Defines & Includes ------------------
 * ----------------------------------------------
*/

#if defined(__linux__)
#   define KYN_PLATFORM_UNIX
#   define KYN_PLATFORM_LINUX
#   define KAPI
#elif defined(__APPLE__)
#   define KYN_PLATFORM_UNIX
#   define KYN_PLATFORM_APPLE
#   define KAPI
#elif defined(_WIN64)
#   define KYN_PLATFORM_WIN
#   if defined(KYN_BUILD_LIB)
#       define KAPI __declspec(dllexport)
#   else
#       define KAPI __declspec(dllimport)
#   endif
#endif // PLATFORMS

#include <string>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <cctype>
#include <algorithm>

/* -------- Core Module -------------------------
 * ----------------------------------------------
*/

namespace kyn
{
    using byte_vec_t = std::vector<uint8_t>;
    using byte_vec_pair_t = std::pair<byte_vec_t, byte_vec_t>;

    KAPI bool init_all_modules ();
    KAPI bool shutdown_all_modules ();
}

/* -------- Socket Module -----------------------
 * ----------------------------------------------
*/

#define KYN_SOCK_LOOPBACK_ADDR "::1"
#define KYN_SOCK_TCP_PORT 14460
#define KYN_SOCK_MAX_QUEUE 100
#define KYN_SOCK_NEW_ID -2

namespace kyn
{
    class KAPI tcp_socket_t
    {
        public:
            int32_t m_ID;
            std::string m_Address;

        public:
            tcp_socket_t (const std::string& addr = "::1", int32_t id = -2);
            ~tcp_socket_t ();

            bool bind ();
            bool connect ();
            bool listen ();
            tcp_socket_t accept ();

            int32_t recieve (void* buffer, int32_t size);
            int32_t send (const void* buffer, int32_t size);

            std::string to_string ();

            inline bool is_valid () { return m_ID != -1; }
    };

    KAPI bool init_socket_module ();
    KAPI bool shutdown_socket_module ();
}

/* -------- Authentication Module ---------------
 * ----------------------------------------------
*/

#define KYN_AUTH_ASYM_MACBYTES 16u

namespace kyn
{
    KAPI uint32_t gen_random_val (uint32_t max);
    KAPI byte_vec_t gen_random_bytes (uint32_t size);
    KAPI byte_vec_pair_t gen_asym_keys ();

    KAPI byte_vec_t asym_encrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& recv_pk, const byte_vec_t& send_sk);
    KAPI byte_vec_t asym_decrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& send_pk, const byte_vec_t& recv_sk);

    KAPI bool init_auth_module ();
    KAPI bool shutdown_auth_module ();
}

/* -------- Transmission Module -----------------
 * ----------------------------------------------
*/

namespace kyn
{
    enum class packet_type_t : uint8_t
    {
        // bi-directional
        UNKNOWN,
        QUIT,
        DATA,

        // client
        CONNECT_ANONYMOUS,
        CONNECT_REQUEST,

        // server
        REPLY_ANONYMOUS,
        CONNECT_ACCEPT,
        CONNECT_DENY
    };

    struct KAPI connect_data_t {};

    struct KAPI packet_t
    {
        public:
            packet_type_t m_Type;
            std::vector<char> m_Data;
    };

    template <class T>
    inline packet_t serialize (const T& data)
    {
        packet_t pkt;
        pkt.m_Type = packet_type_t::UNKNOWN;
        return pkt;
    }

    template <>
    inline packet_t serialize (const connect_data_t& data)
    {

    }
}

/* -------- Endpoint Module ---------------------
 * ----------------------------------------------
*/

namespace kyn
{
    class server_endp_t;
    class KAPI endp_t {};

    class KAPI client_endp_t : public endp_t
    {
        public:
            std::vector<server_endp_t> m_ServerConns;
    };

    class KAPI server_endp_t : public endp_t
    {
        public:
            tcp_socket_t m_ListenerSocket;
            std::vector<client_endp_t> m_ClientConns;
    };
}

#endif // __cplusplus
#endif // KRAKYN_H