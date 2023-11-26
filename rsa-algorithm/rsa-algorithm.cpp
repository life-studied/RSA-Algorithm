#include "rsa-algorithm.h"
#include <fstream>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/x509cert.h>
#include <botan/botan.h>
#include <botan/pk_keys.h>
#include <botan/auto_rng.h>

#include <botan/data_src.h>
#include <botan/pem.h>

RSA::RSA::RSA() :  public_key_file("public_key.pem"), private_key_file("private_key.pem")
{
    if (!read_keys())  generate_key();
}

void RSA::RSA::generate_key()
{
    Botan::AutoSeeded_RNG rng;
    private_key = std::make_unique<RSA_PrivateKey>(rng, 2048);
    public_key = std::make_unique<RSA_PublicKey>(private_key);
}

bool RSA::RSA::read_keys()
{
    auto read_key = []<typename T>(std::string key_file, std::unique_ptr<T> key) {
        std::ifstream ifs(key_file, std::ios::binary);
        if (!ifs.is_open()) throw std::runtime_error("Failed to load key from file" + key_file);
        ifs.seekg(0, std::ios::end);
        size_t file_size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);
        std::vector<uint8_t> key_bits(file_size);
        ifs.read(reinterpret_cast<char*>(key_bits.data()), file_size);
        Botan::AlgorithmIdentifier alg_id;
        return std::make_unique<T>(alg_id, key_bits);
    };

    private_key = read_key(private_key_file, std::move(private_key));
    public_key = read_key(public_key_file, std::move(public_key));
}

bool RSA::RSA::write_keys()
{
    // 将公钥和私钥编码为 PEM 格式
    std::string public_key_pem = Botan::X509::PEM_encode(*public_key);
    std::string private_key_pem = Botan::PKCS8::PEM_encode(*private_key);

    auto save_key_to_file = [](const std::string& filename, const std::string& key_data) {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << key_data;
            file.close();
        }
        else {
            throw std::runtime_error("Unable to open file for writing: " + filename);
        }
    };
    // 保存公钥和私钥到文件
    save_key_to_file(public_key_file, public_key_pem);
    save_key_to_file(private_key_file, private_key_pem);
}
