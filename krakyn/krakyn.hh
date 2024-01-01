/*  ██╗  ██╗██████╗  █████╗ ██╗  ██╗██╗   ██╗███╗   ██╗
 *  ██║ ██╔╝██╔══██╗██╔══██╗██║ ██╔╝╚██╗ ██╔╝████╗  ██║
 *  █████╔╝ ██████╔╝███████║█████╔╝  ╚████╔╝ ██╔██╗ ██║
 *  ██╔═██╗ ██╔══██╗██╔══██║██╔═██╗   ╚██╔╝  ██║╚██╗██║
 *  ██║  ██╗██║  ██║██║  ██║██║  ██╗   ██║   ██║ ╚████║
 *  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝
 * =====================================================
 *     Decentralized // Encrypted // Chat Protocol
 * =====================================================
 * LICENSE:                                   Apache 2.0
 * FILE:                    core header file (krakyn.hh)
 * =====================================================
*/

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
#include <optional>
#include <vector>
#include <unordered_map>
#include <cctype>
#include <algorithm>
#include <filesystem>
#include <sstream>
#include <fstream>
#include <thread>
#include <mutex>

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

/* -------- Networking Module -------------------
 * ----------------------------------------------
*/

#define KYN_SOCK_LOOPBACK_ADDR "::1"
#define KYN_SOCK_EMPTY_ADDR    ""

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
            tcp_socket_t (const std::string& addr = KYN_SOCK_LOOPBACK_ADDR, int32_t id = KYN_SOCK_NEW_ID);
            ~tcp_socket_t ();

            bool bind ();
            bool connect ();
            bool listen ();
            tcp_socket_t accept ();
            void close ();

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

#define KYN_AUTH_ASYM_MACBYTES   16u
#define KYN_AUTH_ASYM_NONCEBYTES 24u
#define KYN_AUTH_ASYM_KEYBYTES   32u

#define KYN_AUTH_SYM_MACBYTES   16u
#define KYN_AUTH_SYM_NONCEBYTES 24u
#define KYN_AUTH_SYM_KEYBYTES   32u

namespace kyn
{
    struct KAPI profile_t
    {
        public:
            std::string m_Name;
            byte_vec_pair_t m_Keypair;
    };

    KAPI byte_vec_t base64_to_bytes (const std::string& str);
    KAPI std::string bytes_to_base64 (const byte_vec_t& bytes);

    KAPI uint32_t gen_random_val (uint32_t max);
    KAPI byte_vec_t gen_random_bytes (uint32_t size);
    KAPI byte_vec_pair_t gen_asym_keys ();

    KAPI byte_vec_t asym_encrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& recv_pk, const byte_vec_t& send_sk);
    KAPI byte_vec_t asym_decrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& send_pk, const byte_vec_t& recv_sk);

    KAPI byte_vec_t sym_encrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& key);
    KAPI byte_vec_t sym_decrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& key);

    KAPI profile_t gen_new_profile (const std::string& path, const std::string& user, const std::string& pass);
    KAPI profile_t load_profile_from_disk (const std::string& path, const std::string& user, const std::string& pass);

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
            byte_vec_t m_Data;
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
    struct KAPI endp_desc_t
    {
        public:
            tcp_socket_t m_Socket;
            std::string  m_Name;
            byte_vec_t   m_PublicKey;
            byte_vec_t   m_SessionKey;
            bool         m_Complete;
    };

    class KAPI endp_t
    {
        public:
            profile_t m_Profile;
            bool m_Authenticated = false;

        public:
            inline endp_t () = default;
            inline virtual ~endp_t () {}
    };

    class KAPI server_endp_t : public endp_t
    {
        private:
            tcp_socket_t m_ListenerSocket;
            std::vector<endp_desc_t> m_ClientConns;
            bool m_Running;

        public:
            server_endp_t (const profile_t& profile);
            ~server_endp_t ();

            void init ();
    };

    class KAPI client_endp_t : public endp_t
    {
        private:
            std::vector<endp_desc_t> m_ServerConns;

        public:
            client_endp_t ();
            ~client_endp_t ();
    };
}

#endif // __cplusplus
#endif // KRAKYN_H