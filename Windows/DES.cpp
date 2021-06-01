#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cin;
using std::cout;
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/des.h"
using CryptoPP::DES;
using CryptoPP::byte;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CBC_CTS_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#ifdef _WIN32
	#include <io.h>
	#include <fcntl.h>
#elif __linux__
	#include <stdio_ext.h>
#else
#endif

#include <codecvt>
#include <locale>

#include "assert.h"

void clean_stdin() {
	#ifdef _WIN32
		fflush(stdin);
	#elif __linux__
		__fpurge(stdin);
	#else
	#endif
}

// convert UTF-8 string to wstring
std::wstring utf8_to_wstring (const std::string& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.from_bytes(str);
}

// convert wstring to UTF-8 string
std::string wstring_to_utf8 (const std::wstring& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

double DES_ECB_encrypt(SecByteBlock key, string plain, string& cipher) {
	int start = clock();
	try	{		

		ECB_Mode< DES >::Encryption e;
		e.SetKey(key, key.size());

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_ECB_decrypt(SecByteBlock key, string cipher, string& recovered) {
	int start = clock();
	try	{
		ECB_Mode< DES >::Decryption d;
		d.SetKey(key, key.size());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource		
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_CBC_CTS_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{		

		CBC_CTS_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_CBC_CTS_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		CBC_CTS_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource		
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_CBC_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{		

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_CBC_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		CBC_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource		
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_OFB_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{		

		OFB_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_OFB_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		OFB_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource		
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_CFB_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{		

		CFB_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_CFB_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		CFB_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource		
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_CTR_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{		

		CTR_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double DES_CTR_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		CTR_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource		
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

int main(int argc, char* argv[]) {
	#ifdef __linux__
		setlocale(LC_ALL,"");
	#elif _WIN32
		_setmode(_fileno(stdin), _O_U16TEXT);
		_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

	AutoSeededRandomPool prng;

	SecByteBlock key(DES::DEFAULT_KEYLENGTH);

	SecByteBlock iv(DES::BLOCKSIZE);

	wcout << L"Input plaintext: ";
	wstring utf8plain;
	getline(wcin, utf8plain);
	string plain = wstring_to_utf8(utf8plain);
	string cipher, encoded, recovered;

	//chose mode
	wcout << L"Choose mode:\n";
	wcout << L"1. ECB    2.CBC    3.CBC_CTS    4.OFB    5.CFB    6.CTR\n";
	int mode;
	wcin >> mode;
	if (mode <= 0 || mode > 6) {
		wcout << L"Not valid option\n";
		return 0;
	}
	
	// key genarator or input
	wcout << L"1.Input key from screen    2.Input key from file    3.Random key\n";
	int tmp;
	wcin >> tmp;
	if (tmp == 1) {	
		wstring skey;	
		clean_stdin();
		getline(wcin, skey);
		string tmp = wstring_to_utf8(skey);
		if (tmp.size() < key.size()) {
			wcout << "Not enough length!\n";
			return 0;
		}
		for (int i = 0; i < (int)key.size(); i++) {
			key[i] = tmp[i];
		}
	} else if (tmp == 2) {
		wcout << L"Open DES_key.key...\n";
		try {
			FileSource fs("DES_key.key", false);
			CryptoPP::ArraySink copykey(key, key.size());
			fs.Detach(new Redirector(copykey));
			fs.Pump(key.size());
		} catch(const CryptoPP::Exception& e) {
			wcout << L"File DES_key.key not valid\n";
			return 0;
		}
		
	} else if (tmp == 3) {
		prng.GenerateBlock(key, key.size());
	} else {
		wcout << L"Not valid option\n";
		return 0;
	}	

	// iv genarator or input
	if (mode != 1) {
		wcout << L"1.Input iv from screen    2.Input iv from file    3.Random iv\n";
		wcin >> tmp;
		if (tmp == 1) {
			wstring skey;	
			clean_stdin();
			getline(wcin, skey);	
			string tmp = wstring_to_utf8(skey);
			if (tmp.size() < iv.size()) {
				wcout << "Not enough length!\n";
				return 0;
			}
			for (int i = 0; i < (int)iv.size(); i++) {
				iv[i] = tmp[i];
			}
		} else if (tmp == 2) {
			wcout << L"Open DES_iv.key...\n";
			try {
				FileSource fs("DES_iv.key", false);
				CryptoPP::ArraySink copykey(iv, iv.size());
				fs.Detach(new Redirector(copykey));
				fs.Pump(iv.size());
			} catch(const CryptoPP::Exception& e) {
				wcout << L"File DES_iv.key not valid\n";
				return 0;
			}			
		} else if (tmp == 3) {
			prng.GenerateBlock(iv, iv.size());
		} else {
			wcout << L"Not valid option\n";
			return 0;
		}
	}


	// Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << utf8_to_wstring(encoded) << endl;

	// Pretty print iv
	if (mode != 1) {
		encoded.clear();
		StringSource(iv, iv.size(), true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		wcout << "iv: " << utf8_to_wstring(encoded) << endl;
	}

	double time = 0;

	switch (mode) {
		case 1:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += DES_ECB_encrypt(key, plain, cipher);
			}			
			break;
		case 2:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += DES_CBC_encrypt(key, iv, plain, cipher);
			}			
			break;
		case 3:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += DES_CBC_CTS_encrypt(key, iv, plain, cipher);
			}			
			break;
		case 4:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += DES_OFB_encrypt(key, iv, plain, cipher);
			}			
			break;
		case 5:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += DES_CFB_encrypt(key, iv, plain, cipher);
			}			
			break;
		default: // case 6
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += DES_CTR_encrypt(key, iv, plain, cipher);
			}			
			break;
	}	

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "Cipher text: " << utf8_to_wstring(encoded) << endl;
	wcout << "Time encrypt: " << time / 10000 << "ms\n";

	time = 0;
	
	switch (mode) {
		case 1:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += DES_ECB_decrypt(key, cipher, recovered);
			}			
			break;
		case 2:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += DES_CBC_decrypt(key, iv, cipher, recovered);
			}			
			break;
		case 3:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += DES_CBC_CTS_decrypt(key, iv, cipher, recovered);
			}			
			break;
		case 4:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += DES_OFB_decrypt(key, iv, cipher, recovered);
			}			
			break;
		case 5:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += DES_CFB_decrypt(key, iv, cipher, recovered);
			}			
			break;
		default: // case 6
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += DES_CTR_decrypt(key, iv, cipher, recovered);				
			}			
			break;
	}

	wcout << "Recovered text: " << utf8_to_wstring(recovered) << endl;
	wcout << "Time decrypt: " << time / 10000 << "ms\n";

	wcout << L"1.Save key and iv    2.Exit\n";
	wcin >> tmp;
	if (tmp == 1) {
		StringSource ss1(key, key.size(), true , new FileSink( "DES_key_save.key"));
		if (mode != 1) {
			StringSource ss2(iv, iv.size(), true , new FileSink( "DES_iv_save.key"));
		}		
	}

	return 0;
}
