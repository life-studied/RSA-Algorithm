#pragma once
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/pem.h>
#include <botan/rsa.h>
#include <memory>
#include <string>

namespace RSA
{
	using namespace Botan;
	class RSA
	{
	public:
		RSA();
		void generate_key();
		bool read_keys();
		bool write_keys();
		std::string encrypt(std::string s);
		std::string decrypt(std::string s);
	private:
		std::unique_ptr<RSA_PrivateKey> private_key;
		std::unique_ptr<RSA_PublicKey> public_key;
		std::string public_key_file;
		std::string private_key_file;

	};
}