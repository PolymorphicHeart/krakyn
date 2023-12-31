#include "krakyn.hh"

#define SODIUM_STATIC
#include <sodium.h>

static bool s_AuthModuleInit = false;

namespace kyn
{

    byte_vec_t base64_to_bytes (const std::string& str)
    {
        byte_vec_t buffer((str.size() / 4 * 3) + 1);

        size_t len = 0;

        sodium_base642bin
        (
            buffer.data(),
            buffer.size(),
            str.c_str(),
            str.size(),
            nullptr,
            &len,
            nullptr,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        );

        buffer.resize(len);
        return buffer;
    }

    std::string bytes_to_base64 (const byte_vec_t& bytes)
    {
        uint32_t buffer_size = sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        char* buffer = new char[buffer_size];

        sodium_bin2base64(buffer, buffer_size, bytes.data(), bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        std::string str(buffer);

        delete[] buffer;
        return str;
    }

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
        byte_vec_pair_t keypair(byte_vec_t(KYN_AUTH_ASYM_KEYBYTES), byte_vec_t(KYN_AUTH_ASYM_KEYBYTES));

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

    byte_vec_t sym_encrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& key)
    {
        byte_vec_t cipher_buffer(msg.size() + KYN_AUTH_SYM_MACBYTES);

        auto ret = crypto_secretbox_easy
        (
            cipher_buffer.data(),
            msg.data(),
            msg.size(),
            nonce.data(),
            key.data()
        );

        if (ret != 0) return byte_vec_t(0);
        return cipher_buffer;
    }

    byte_vec_t sym_decrypt (const byte_vec_t& msg, const byte_vec_t& nonce, const byte_vec_t& key)
    {
        byte_vec_t plain_buffer(msg.size() - KYN_AUTH_SYM_MACBYTES);

        auto ret = crypto_secretbox_open_easy
        (
            plain_buffer.data(),
            msg.data(),
            msg.size(),
            nonce.data(),
            key.data()
        );

        if (ret != 0) return byte_vec_t(0);
        return plain_buffer;
    }

    byte_vec_pair_t gen_new_profile (const std::string& path, const std::string& user, const std::string& pass)
    {
        std::string masterkey = user + pass;
        auto keypair = gen_asym_keys();

        byte_vec_t key(crypto_box_SEEDBYTES);
        auto salt = gen_random_bytes(crypto_pwhash_SALTBYTES);
        auto nonce = gen_random_bytes(crypto_secretbox_NONCEBYTES);

        auto ret = crypto_pwhash
        (
            key.data(), key.size(), masterkey.c_str(), masterkey.size(), salt.data(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, 
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT
        );
 
        if (ret != 0) return byte_vec_pair_t(byte_vec_t(0), byte_vec_t(0));

        std::ofstream ofs(path);
        if (ofs.bad()) return byte_vec_pair_t(byte_vec_t(0), byte_vec_t(0));

        ofs 
            << user << "\n" 
            << bytes_to_base64(salt) << "\n"
            << bytes_to_base64(nonce) << "\n"
            << bytes_to_base64(sym_encrypt(keypair.first, nonce, key)) << "\n"
            << bytes_to_base64(sym_encrypt(keypair.second, nonce, key));

        return keypair;
    }

    byte_vec_pair_t load_profile_from_disk (const std::string& path, const std::string& user, const std::string& pass)
    {
        std::ifstream ifs(path);
        if (ifs.bad()) return byte_vec_pair_t(byte_vec_t(0), byte_vec_t(0));

        std::string data[5];
        std::string line;

        for (int32_t i = 0; std::getline(ifs, line, '\n'); i++) data[i] = line;

        auto salt  = base64_to_bytes(data[1]);
        auto nonce = base64_to_bytes(data[2]);
        auto en_pk = base64_to_bytes(data[3]);
        auto en_sk = base64_to_bytes(data[4]);

        std::string masterkey = user + pass;
        byte_vec_t key(crypto_box_SEEDBYTES);

        auto ret = crypto_pwhash
        (
            key.data(), key.size(), masterkey.c_str(), masterkey.size(), salt.data(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, 
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT
        );

        if (ret != 0) return byte_vec_pair_t(byte_vec_t(0), byte_vec_t(0));

        auto pk = sym_decrypt(en_pk, nonce, key);
        auto sk = sym_decrypt(en_sk, nonce, key);

        return byte_vec_pair_t(pk, sk);
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