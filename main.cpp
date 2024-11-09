#include <iostream>
#include <openssl/evp.h>
#include "RsaTest.h"



using namespace std;
int main() {
	OpenSSL_add_all_algorithms();
	cout << "begin rsa test" << endl;
	auto rsaTest = RsaTest();
	rsaTest.Init("this is a rsaTest");
	rsaTest.DoTest();
	cout << "end rsa test" << endl;
	return 0;
}
