#include "krakyn.hh"

#define SODIUM_STATIC
#include <sodium.h>

static bool s_AuthModuleInit = false;

namespace kyn
{
    uint32_t gen_random_val (uint32_t max)
    {
        return randombytes_uniform(max);
    }

    byte_vec_t gen_random_bytes (uint32_t size)
    {
        byte_vec_t buffer(size);
        randombytes_buf(buffer.data(), size);
        return buffer;
    }

    byte_vec_pair_t gen_asym_keys ()
    {
        byte_vec_pair_t keypair(byte_vec_t(crypto_box_PUBLICKEYBYTES), byte_vec_t(crypto_box_SECRETKEYBYTES));

        auto ret = crypto_box_keypair
        (
            keypair.first.data(),
            keypair.second.data()
        );

        return keypair;
    }

    byte_vec_t asym_encrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& recv_pk, const byte_vec_t& send_sk)
    {
        byte_vec_t cipher_buffer(msg.size() + KYN_AUTH_ASYM_MACBYTES);

        auto ret = crypto_box_easy
        (
            cipher_buffer.data(),
            msg.data(),
            msg.size(),
            nonce.data(),
            recv_pk.data(),
            send_sk.data()
        );

        if (ret != 0) return byte_vec_t(0);
        return cipher_buffer;
    }

    byte_vec_t asym_decrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& send_pk, const byte_vec_t& recv_sk)
    {
        byte_vec_t plain_buffer(msg.size() - KYN_AUTH_ASYM_MACBYTES);

        auto ret = crypto_box_open_easy
        (
            plain_buffer.data(),
            msg.data(),
            msg.size(),
            nonce.data(),
            send_pk.data(),
            recv_sk.data()
        );

        if (ret != 0) return byte_vec_t(0);
        return plain_buffer;
    }

    bool init_auth_module ()
    {
        if (s_AuthModuleInit) return false;
        if (sodium_init() < 0) return false;
        return s_AuthModuleInit = true;
    }

    bool shutdown_auth_module ()
    {
        if (!s_AuthModuleInit) return false;
        s_AuthModuleInit = false;
        return true;
    }
}