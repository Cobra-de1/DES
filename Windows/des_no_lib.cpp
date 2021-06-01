/*
                ******
		
        Author: Nguyen Phuc Chuong

                ******
*/

#include <bits/stdc++.h>
#ifdef _WIN32
	#include <io.h>
	#include <fcntl.h>
#else
#endif

#include <codecvt>
#include <locale>

using namespace std;

string subkey[16]; // subkey
unordered_map<char, string> mp1; // hex -> bin hash map
unordered_map<string, string> mp2; // bin -> hex hash map

// user for initial key 64 -> 56 bit
int keyp[56] = { 57, 49, 41, 33, 25, 17, 9,
                 1, 58, 50, 42, 34, 26, 18,
                 10, 2, 59, 51, 43, 35, 27,
                 19, 11, 3, 60, 52, 44, 36,
                 63, 55, 47, 39, 31, 23, 15,
                 7, 62, 54, 46, 38, 30, 22,
                 14, 6, 61, 53, 45, 37, 29,
                 21, 13, 5, 28, 20, 12, 4 };

// Use for plaintext initial permutation stage 
int initial_perm[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
                         60, 52, 44, 36, 28, 20, 12, 4,
                         62, 54, 46, 38, 30, 22, 14, 6,
                         64, 56, 48, 40, 32, 24, 16, 8,
                         57, 49, 41, 33, 25, 17, 9, 1,
                         59, 51, 43, 35, 27, 19, 11, 3,
                         61, 53, 45, 37, 29, 21, 13, 5,
                         63, 55, 47, 39, 31, 23, 15, 7 };

// convert right part 32 -> 48 bit before xor	
int exp_d[48] = { 32, 1, 2, 3, 4, 5, 4, 5,
                  6, 7, 8, 9, 8, 9, 10, 11,
                  12, 13, 12, 13, 14, 15, 16, 17,
                  16, 17, 18, 19, 20, 21, 20, 21,
                  22, 23, 24, 25, 24, 25, 26, 27,
                  28, 29, 28, 29, 30, 31, 32, 1 };
	
// s-box
int s[8][4][16] = { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                      0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                      4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                      15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
                    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                      3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                      13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
  
                    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                      13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                      13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                      1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
                    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                      13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                      10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                      3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
                    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                      14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                      4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                      11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
                    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                      10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                      9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                      4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
                    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                      13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                      1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                      6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
                    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                      1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                      7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                      2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

//permutation after s-box	
int per[32] = { 16, 7, 20, 21,
                29, 12, 28, 17,
                1, 15, 23, 26,
                5, 18, 31, 10,
                2, 8, 24, 14,
                32, 27, 3, 9,
                19, 13, 30, 6,
                22, 11, 4, 25 }; 

// user for final_permutation stage    
int final_perm[64] = { 40, 8, 48, 16, 56, 24, 64, 32,
                       39, 7, 47, 15, 55, 23, 63, 31,
                       38, 6, 46, 14, 54, 22, 62, 30,
                       37, 5, 45, 13, 53, 21, 61, 29,
                       36, 4, 44, 12, 52, 20, 60, 28,
                       35, 3, 43, 11, 51, 19, 59, 27,
                       34, 2, 42, 10, 50, 18, 58, 26,
                       33, 1, 41, 9, 49, 17, 57, 25 };

// user for shift left in key generation
int shift_table[16] = { 1, 1, 2, 2,
                        2, 2, 2, 2,
                        1, 2, 2, 2,
                        2, 2, 2, 1 };

// user for gen roundkey from 56 -> 48 bit                 
int key_comp[48] = { 14, 17, 11, 24, 1, 5,
                     3, 28, 15, 6, 21, 10,
                     23, 19, 12, 4, 26, 8,
                     16, 7, 27, 20, 13, 2,
                     41, 52, 31, 37, 47, 55,
                     30, 40, 51, 45, 33, 48,
                     44, 49, 39, 56, 34, 53,
                     46, 42, 50, 36, 29, 32 };

void setup() { // initalize 2 hash map
	mp1['0'] = "0000";
    mp1['1'] = "0001";
    mp1['2'] = "0010";
    mp1['3'] = "0011";
    mp1['4'] = "0100";
    mp1['5'] = "0101";
    mp1['6'] = "0110";
    mp1['7'] = "0111";
    mp1['8'] = "1000";
    mp1['9'] = "1001";
    mp1['A'] = "1010";
    mp1['B'] = "1011";
    mp1['C'] = "1100";
    mp1['D'] = "1101";
    mp1['E'] = "1110";
    mp1['F'] = "1111";
    mp2["0000"] = "0";
    mp2["0001"] = "1";
    mp2["0010"] = "2";
    mp2["0011"] = "3";
    mp2["0100"] = "4";
    mp2["0101"] = "5";
    mp2["0110"] = "6";
    mp2["0111"] = "7";
    mp2["1000"] = "8";
    mp2["1001"] = "9";
    mp2["1010"] = "A";
    mp2["1011"] = "B";
    mp2["1100"] = "C";
    mp2["1101"] = "D";
    mp2["1110"] = "E";
    mp2["1111"] = "F";
}

// convert hex to int
string inttohex(char num) {
	char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	string inhex = "";
	//inhex += hex_chars[(num & 0xF000) >> 12];
	//inhex += hex_chars[(num & 0x0F00) >> 8];
	inhex += hex_chars[(num & 0xF0) >> 4];
	inhex += hex_chars[(num & 0x0F)];
	return inhex;
}

// convert int to hex
char hextoint(string num) {
	//assert((int)num.size() == 4);
	char dec = (stol(num.substr(0, 1), NULL, 16) << 4) + stol(num.substr(1, 1), NULL, 16);
	return dec;
}

// hex to bin
string hextobin(string s) {  // use hash map hex -> bin 
    string bin = "";
    for (int i = 0; i < (int)s.size(); i++) { 
        bin += mp1[s[i]];
    }
    return bin;
}

// bin to hex
string bintohex(string s) { // use hash map bin -> hex
	//assert((int)s.size() % 4 == 0);    
    string hex = "";
    for (int i = 0; i < (int)s.size(); i += 4) {
        string ch = s.substr(i, 4);
        hex += mp2[ch];
    }
    return hex;
}

// convert string to wstring
wstring string_to_wstring (const std::string& str) {
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str) {
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

void padding(string& a) {
	int cp = ((int)a.size() / 2) % 8; // padding
	if (cp) {
		cp = 8 - cp;
		for (int i = 0; i < cp; i++) {
			a += inttohex(cp);
		}
	} else {
		for (int i = 0; i < 8; i++) {
			a += "08";
		}
	}
}

void unpadding(string& a) {
	int n = hextoint(a.substr((int)a.size() - 2, 2));
	a = a.substr(0, (int)a.size() - n * 2);
}

// conver plain to hex
string plaintohex(wstring input) {	
	string inhex = "";
	string tmp = wstring_to_string(input);
	for (int i = 0; i < (int)tmp.size(); i++) {
		inhex += inttohex(tmp[i]);
	}	
	return inhex;
}

// convert hex to plain
wstring hextoplain(string input) {	
	string toplain = "";	
	for (int i = 0; i < (int)input.size(); i += 2) {
		toplain += hextoint(input.substr(i, 2));
	}
	return string_to_wstring(toplain);
}

// take a string and an array and permutation
string permute(string k, int* arr, int n)
{
    string per = "";
    for (int i = 0; i < n; i++) {
        per += k[arr[i] - 1];
    }
    return per;
}

// shift left
string shift_left(string k, int shifts) {
    string s = "";
    for (int i = 0; i < shifts; i++) {
        for (int j = 1; j < 28; j++) {
            s += k[j];
        }
        s += k[0];
        k = s;
        s = "";
    }
    return k;
}

// xor 2 binary string
string xor_(string a, string b) {
    string ans = "";
    for (int i = 0; i < (int)a.size(); i++) {
        if (a[i] == b[i]) {
            ans += "0";
        }
        else {
            ans += "1";
        }
    }
    return ans;
}

// generate 16 round key
void gensubkey(string key) {	
	string left = key.substr(0, 28); // left part
    string right = key.substr(28, 28); // right part
    for (int i = 0; i < 16; i++) {
        left = shift_left(left, shift_table[i]); // shift left
        right = shift_left(right, shift_table[i]);
  
        string combine = left + right;
  
        string RoundKey = permute(combine, key_comp, 48); // gen 48 bit key
		
		subkey[i] = RoundKey;
    }
}

double encrypt(string plain, string key, string& output, string iv) {
	int start = clock();
	
	output = "";
    
    key = hextobin(key);
    key = permute(key, keyp, 56); // initkey 64 -> 56 bit
    iv = hextobin(iv);
    
    gensubkey(key); // gen round key
    //assert((int)plain.size() % 16 == 0);
                   
	for (int f = 0; f < (int)plain.size(); f += 16) {
		string pt = plain.substr(f, 16); // take block
		pt = hextobin(pt);
		pt = xor_(pt, iv); // xor with iv
		pt = permute(pt, initial_perm, 64); // initial permutation
		string left = pt.substr(0, 32); // left part
		string right = pt.substr(32, 32); // right part
		for (int i = 0; i < 16; i++) {
			string right_expanded = permute(right, exp_d, 48); // exp right part 32->48 bit
			string x = xor_(subkey[i], right_expanded); // xor with round key
			string op = "";
			for (int i = 0; i < 8; i++) { // split 48 bit to 8 6-bit part
				int row = 2 * int(x[i * 6] - '0') + int(x[i * 6 + 5] - '0');
				int col = 8 * int(x[i * 6 + 1] - '0') + 4 * int(x[i * 6 + 2] - '0') + 2 * int(x[i * 6 + 3] - '0') + int(x[i * 6 + 4] - '0');
				int val = s[i][row][col]; // use s-box to convert
				op += char(val / 8 + '0');
				val = val % 8;
				op += char(val / 4 + '0');
				val = val % 4;
				op += char(val / 2 + '0');
				val = val % 2;
				op += char(val + '0');
			}
			op = permute(op, per, 32); // permutation
			x = xor_(op, left);	  // xor with left part 
			left = x;	  
			if (i != 15) {
				swap(left, right);
			}
		}
		string combine = left + right;
		string tmp = permute(combine, final_perm, 64); // final permutation
		output += tmp;
		iv = tmp; // change iv
	}
	
	output = bintohex(output);
	int end = clock();
	return (end - start) / (double)CLOCKS_PER_SEC * 1000;
}

double decrypt(string plain, string key, string& output, string iv) {
	int start = clock();
	
	output = "";
    
    key = hextobin(key);
    key = permute(key, keyp, 56); // initial key 64 -> 56 bit
    iv = hextobin(iv);
    
    gensubkey(key); // gen roundkey
    
    reverse(subkey, subkey + 16); // reverse order key
    
    //assert((int)plain.size() % 16 == 0);
                   
	for (int f = 0; f < (int)plain.size(); f += 16) {
		string pt = plain.substr(f, 16); // take block
		pt = hextobin(pt);
		string save = pt; // use for next iv
		pt = permute(pt, initial_perm, 64); // initial permutation
		string left = pt.substr(0, 32); // left part
		string right = pt.substr(32, 32); // right part
		for (int i = 0; i < 16; i++) {
			string right_expanded = permute(right, exp_d, 48); // exp right part 32 -> 48 bit
			string x = xor_(subkey[i], right_expanded); // xor with round key
			string op = "";
			for (int i = 0; i < 8; i++) { // split 48 bit to 8 6-bit part
				int row = 2 * int(x[i * 6] - '0') + int(x[i * 6 + 5] - '0');
				int col = 8 * int(x[i * 6 + 1] - '0') + 4 * int(x[i * 6 + 2] - '0') + 2 * int(x[i * 6 + 3] - '0') + int(x[i * 6 + 4] - '0');
				int val = s[i][row][col]; // use s-box to convert
				op += char(val / 8 + '0');
				val = val % 8;
				op += char(val / 4 + '0');
				val = val % 4;
				op += char(val / 2 + '0');
				val = val % 2;
				op += char(val + '0');
			}
			op = permute(op, per, 32); // permutation
			x = xor_(op, left);	  // xor with left part
			left = x;	  
			if (i != 15) {
				swap(left, right);
			}
		}
		string combine = left + right;
		string tmp = xor_(permute(combine, final_perm, 64), iv); // final permutation ^ iv 
		output += tmp;
		iv = save;
	}
	
	output = bintohex(output);
	int end = clock();
	return (end - start) / (double)CLOCKS_PER_SEC * 1000;
}

int main() {
	// unicode input
	#ifdef __linux__
		setlocale(LC_ALL,"");
	#elif _WIN32
		_setmode(_fileno(stdin), _O_U16TEXT);
		_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif	
	
	setup(); // setup 2 hash map for converting hex to bin and bin to hex
	
    wcout << "DES CBC mode with out library\n";
    wcout << "Input plain text: ";
    
    // input plain
    wstring input;
    getline(wcin, input);
    
    string plain = plaintohex(input); // plaintext -> hex
    padding(plain); // padding
    wcout << "Plain text in hex: " << string_to_wstring(plain) << '\n';
    
    // input key
    wcout << "Input key: ";
    fflush(stdin);
    getline(wcin, input);
    string key = plaintohex(input);
    if (key.size() < 16) {
		wcout << L"Key not valid\n";
		return 0;
	} else {
		key = key.substr(0, 16);
	}
	
    wcout << "Key(hex): " << string_to_wstring(key) << '\n'; // In ra key
    
    // input iv
    wcout << "Input IV: ";
    fflush(stdin);
    getline(wcin, input);
    string iv = plaintohex(input);
    if (iv.size() < 16) {
		wcout << L"IV no valid\n";
		return 0;
	} else {
		iv = iv.substr(0, 16);
	}
	
    wcout << "IV(hex): " << string_to_wstring(iv) << '\n'; // In ra key
    
    string cipher = "";    
    double timeencrypt = 0;
    for (int i = 0; i < 10000; i++) {
		timeencrypt += encrypt(plain, key, cipher, iv); // run encrypt 10000 and take the avg
	}
	wcout << "Cipher text(hex): " << string_to_wstring(cipher) << '\n'; // In ra cipher text
	wcout << timeencrypt / 10000 << "ms\n"; // Show time encrypt
	
	string recovered = "";    
    double timedecrypt = 0;
    for (int i = 0; i < 10000; i++) {
		timedecrypt += decrypt(cipher, key, recovered, iv); // run decrypt 10000 and take the avg
	}
	wcout << "Plain text after decrypt(hex): " << string_to_wstring(recovered) << '\n'; 
	wcout << timedecrypt / 10000 << "ms\n"; // Show time decrypt
    
    unpadding(recovered); // unpadding
        
    wstring output = hextoplain(recovered);
    wcout << "Plain text after decrypt: "<< output; // print plain text (unicode)
    
	return 0;
}
