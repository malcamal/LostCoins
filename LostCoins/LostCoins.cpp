#include "LostCoins.h"
#include "Base58.h"
#include "Bech32.h"
#include "hash/sha512.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <cstring>
#include <cmath>
#include <stdexcept>
#include <cassert>
#include <algorithm>
#include <iostream>

#include <string>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha256.cpp"
#include <sstream>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>

#include <vector>
#include <random>
#include <ctime>
#include <iomanip>

#include <atomic>
#include <mutex>
#include <thread>
#include <fstream>
#include <iterator>
#include <regex>

using namespace std;

#ifndef WIN64
#include <pthread.h>
#endif

using namespace std;

Point Gn[CPU_GRP_SIZE / 2];
Point _2Gn;

// ----------------------------------------------------------------------------

LostCoins::LostCoins(string addressFile, string seed, string zez, int diz, int searchMode,
	bool useGpu, string outputFile, bool useSSE, uint32_t maxFound,
	uint64_t rekey, int nbit, int nbit2, bool paranoiacSeed, const std::string& rangeStart1, const std::string& rangeEnd1, bool& should_exit)
{
	this->searchMode = searchMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->addressFile = addressFile;
	this->rekey = rekey;
	this->nbit = nbit;
	this->nbit2 = nbit2;
	this->maxFound = maxFound;
	this->seed = seed;
	this->zez = zez;
	this->diz = diz;
	this->searchType = P2PKH;
	this->rangeStart1;
	this->rangeEnd1;
	this->rangeDiff;
	secp = new Secp256K1();
	secp->Init();

	// load address file
	uint8_t buf[20];
	FILE* wfd;
	uint64_t N = 0;

	wfd = fopen(this->addressFile.c_str(), "rb");
	if (!wfd) {
		printf("%s can not open\n", this->addressFile.c_str());
		exit(1);
	}

	_fseeki64(wfd, 0, SEEK_END);
	N = _ftelli64(wfd);
	N = N / 20;
	rewind(wfd);

	DATA = (uint8_t*)malloc(N * 20);
	memset(DATA, 0, N * 20);

	bloom = new Bloom(2 * N, 0.000001);

	if (N > 100) {
		uint64_t percent = (N - 1) / 100;
		uint64_t i = 0;
		printf("\n");
		while (i < N && !should_exit) {
			memset(buf, 0, 20);
			memset(DATA + (i * 20), 0, 20);
			if (fread(buf, 1, 20, wfd) == 20) {
				bloom->add(buf, 20);
				memcpy(DATA + (i * 20), buf, 20);
				if (i % percent == 0) {
					printf("\r Loading      : %llu %%", (i / percent));
					fflush(stdout);
				}
			}
			i++;
		}
		printf("\n");
		fclose(wfd);

		if (should_exit) {
			delete secp;
			delete bloom;
			if (DATA)
				free(DATA);
			exit(0);
		}

		BLOOM_N = bloom->get_bytes();
		TOTAL_ADDR = N;
		printf(" Loaded       : %s address\n", formatThousands(i).c_str());
		printf("\n");

		bloom->print();
		printf("\n");

		lastRekey = 0;
	
	
	}
	else {
		uint64_t percent = N;
		uint64_t i = 0;
		printf("\n");
		while (i < N && !should_exit) {
			memset(buf, 0, 20);
			memset(DATA + (i * 20), 0, 20);
			if (fread(buf, 1, 20, wfd) == 20) {
				bloom->add(buf, 20);
				memcpy(DATA + (i * 20), buf, 20);
				
				printf("\r Loading      : %d address", N);
				fflush(stdout);
				
			}
			i++;
		}
		printf("\n");
		fclose(wfd);

		if (should_exit) {
			delete secp;
			delete bloom;
			if (DATA)
				free(DATA);
			exit(0);
		}

		BLOOM_N = bloom->get_bytes();
		TOTAL_ADDR = N;
		printf(" Loaded       : %s address\n", formatThousands(i).c_str());
		printf("\n");

		bloom->print();
		printf("\n");

		lastRekey = 0;
	}

	

	// Compute Generator table G[n] = (n+1)*G

	Point g = secp->G;
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g, secp->G);
		Gn[i] = g;
	}
	// _2Gn = CPU_GRP_SIZE*G
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

	// Constant for endomorphism
	// if a is a nth primitive root of unity, a^-1 is also a nth primitive root.
	// beta^3 = 1 mod p implies also beta^2 = beta^-1 mop (by multiplying both side by beta^-1)
	// (beta^3 = 1 mod p),  beta2 = beta^-1 = beta^2
	// (lambda^3 = 1 mod n), lamba2 = lamba^-1 = lamba^2
	beta.SetBase16("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");
	lambda.SetBase16("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
	beta2.SetBase16("851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40");
	lambda2.SetBase16("ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283ce");
	
	char *ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	printf("  Start Time  : %s", ctimeBuff);
	
	if (rekey == 0) {

		if (zez == "keys") {
			printf("\n  Random mode : %.0f \n  Rotor       : Loading private keys from file: %s ... \n", (double)rekey, seed.c_str());
		}
		else {
			printf("\n  Random mode : %.0f \n  Rotor       : Loading passphrases from file: %s ... \n", (double)rekey, seed.c_str());
		}

		ifstream ifs2(seed);
		int n = 0;
		string s;
		while (getline(ifs2, s)) {
			n++;
			if (n > 2147000000) {
				printf("  The file %s has more lines than 2,147,483,647 !!! Split the file into chunks 1,000,000,000 lines in EmEditor https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str());
				exit(1);
			}

		}
		ifs2.close();
		stope += n - 2;
		this->kusok = n / nbit2;

		if (zez == "keys") {
			printf("  Loaded      : %d private keys \n", stope);
		}
		else {
			printf("  Loaded      : %d passphrases \n", stope);
		}

		printf("  Rotor       : Only letters and symbols: А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./? others will be skipped!\n");
		printf("  Rotor       : For large files use -t 11 max (1 core = ~30.000/s, 1 thread = ~5.000/s) Text file max 2,147,483,647 lines!\n");
		if (nbit > 0) {
			printf("  Rotor       : Additional conversion of passphrase to sha256 x%d times. Works on only one core -t 1\n", nbit);
		}
		if (nbit2 > 11) {
			printf("  Rotor CPU   : Only works 11 core !!! You are using (%d) cores!!! It will NOT add speed! Multithreading work is 11 core max! USE max -t 11 \n", nbit2);
		}
		printf("  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");

	}
	if (rekey == 1) {
		char* gyg = &seed[0];
		char* fun = &zez[0];

		this->rangeStart1.SetBase16(gyg);
		this->rangeEnd1.SetBase16(fun);

		if (seed == "") {
			this->rangeStart1.Add(1);
			printf("\n  The START of the range is empty!!! Default: 1\n");
		}

		if (zez == "") {
			this->rangeEnd1.Set(&this->rangeStart1);
			this->rangeEnd1.Add(10000000000000000);
			printf("\n  The END of the range is empty!!! Default: START + 10000000000000000\n");
		}
		
		this->rangeDiff2.Set(&this->rangeEnd1);
		this->rangeDiff2.Sub(&this->rangeStart1);
		printf("\n  Random mode : %.0f \n  Random      : Finding in a range \n", (double)rekey);
	
		printf("  Global start: %064s (%d bit)\n", this->rangeStart1.GetBase16().c_str(), this->rangeStart1.GetBitLength());
		printf("  Global end  : %064s (%d bit)\n", this->rangeEnd1.GetBase16().c_str(), this->rangeEnd1.GetBitLength());
		printf("  Global range: %064s (%d bit)\n", this->rangeDiff2.GetBase16().c_str(), this->rangeDiff2.GetBitLength());
 
		if (nbit2 < 1) {
			if (nbit == 0) {
				printf("  Rotor       : Save checkpoint every (default: 60 minutes) to file LostCoins-Continue.bat Use -n ? (1-1000 minutes)\n");
			}
			else {
				printf("  Rotor       : Save checkpoint every %d minutes to file LostCoins-Continue.bat \n", nbit);
			}
		
		}
		
		printf("  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}


	if (rekey == 2) {

		printf("\n  Random mode : %.0f \n  Random      : Finding in a range \n", (double)rekey);
		printf("  Use range   : %d (bit)\n", nbit);
		printf("  Rotor       : Random generate hex in range %d \n", nbit);
		if (nbit2 > 0) {
			printf("  Rotor CPU   : %d cores constant random generation hashes in %d (bit) range\n", nbit2, nbit);
		}
		else {
			printf("  Rotor GPU   : Reloading starting hashes in range %d (bit) every %d.000.000.000 on the counter\n", nbit, maxFound);
		}
		printf("  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}

	if (rekey == 3) {
		
		printf("\n  Random mode : %.0f \n  Random      : Part+value+part2+value \n", (double)rekey);
		printf("  Part        : %s \n", seed.c_str());
		printf("  Value       : %d x (0-f) \n", nbit);
		printf("  Part 2      : %s \n", zez.c_str());
		printf("  Value 2     : %d x (0-f) \n", maxFound);
		printf("  Example     : %s[<<%d>>]%s[<<%d>>] \n", seed.c_str(), nbit, zez.c_str(), maxFound);
		printf("  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
		
	}
	if (rekey == 4) {

		printf("\n  Random mode : %.0f \n  Random      : Finding in a ranges \n", (double)rekey);

		printf("  Start range : %s (bit)\n", seed.c_str());
		printf("  End range   : %s (bit)\n", zez.c_str());
		printf("  Rotor       : Generate random hex in ranges %s <~> %s \n", seed.c_str(), zez.c_str());
		if (nbit2 > 0) {
			printf("  Rotor CPU   : %d cores constant random generation hashes in ranges\n", nbit2);
		}
		else {
			printf("  Rotor GPU   : Reloading new starting hashes in ranges every %d.000.000.000 on the counter\n", maxFound);
		}
		printf("  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");

	}

	if (rekey == 5) {
		printf("\n  Mode        : %.0f \n  Using       : Brute force Slow algorithm -t 1 USE ONLY 1 CPU CORE\n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~(space) \n  Rotor       : Passphrase %s+%s \n", (double)rekey, seed.c_str(), zez.c_str());
		printf("  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	
	if (rekey == 6) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  ", (double)rekey);
		if (nbit2 > 0) {
			printf("Rotor CPU   : %d cores constant random generation hashes in range %d (bit)", nbit2, nbit);
		}
		else {
			printf("Rotor GPU   : Reloading new starting hashes in range every %d.000.000.000 on the counter", maxFound);
		}
	
		printf("\n  Range bit   : %d (bit) Recommended -n 256 (256 searches in the 252-256 range and below) \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", nbit);
	}
	if (rekey == 8) {
		printf("\n  Random Mode : %.0f \n  Using       : random %d letters  \n", (double)rekey, nbit);
		printf("  Rotor       : %s+<<%d>>+%s \n", seed, nbit, zez);
		printf("  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");

	}
	if (rekey > 8) {
		printf("\n  ERROR!!! \n  Check -r ? \n  Range -r from 1 - 8\n  BYE   \n\n");
		exit(-1);

	}
	

}

LostCoins::~LostCoins()
{
	delete secp;
	delete bloom;
	if (DATA)
		free(DATA);
}

// ----------------------------------------------------------------------------

double log1(double x)
{
	// Use taylor series to approximate log(1-x)
	return -x - (x * x) / 2.0 - (x * x * x) / 3.0 - (x * x * x * x) / 4.0;
}

void LostCoins::output(string addr, string pAddr, string pAddrHex)
{

#ifdef WIN64
	WaitForSingleObject(ghMutex, INFINITE);
#else
	pthread_mutex_lock(&ghMutex);
#endif

	FILE *f = stdout;
	bool needToClose = false;

	if (outputFile.length() > 0) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("Cannot open %s for writing\n", outputFile.c_str());
			f = stdout;
		}
		else {
			needToClose = true;
		}
	}

	if (!needToClose)
		printf("\n");

	fprintf(f, "PubAddress: %s\n", addr.c_str());

	//if (startPubKeySpecified) {

	//	fprintf(f, "PartialPriv: %s\n", pAddr.c_str());

	//}
	//else
	{

		switch (searchType) {
		case P2PKH:
			fprintf(f, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
			break;
		case P2SH:
			fprintf(f, "Priv (WIF): p2wpkh-p2sh:%s\n", pAddr.c_str());
			break;
		case BECH32:
			fprintf(f, "Priv (WIF): p2wpkh:%s\n", pAddr.c_str());
			break;
		}
		fprintf(f, "Priv (HEX): %s\n", pAddrHex.c_str());

	}
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	printf("\n  =================================================================================");  
	printf("\n  * PubAddress: %s                                *", addr.c_str());
	printf("\n  * Priv(WIF) : p2pkh:%s        *", pAddr.c_str());
	printf("\n  * Priv(HEX) : %s  *", pAddrHex.c_str());
	printf("\n  =================================================================================\n");
	if (needToClose)
		fclose(f);

#ifdef WIN64
	ReleaseMutex(ghMutex);
#else
	pthread_mutex_unlock(&ghMutex);
#endif

}

// ----------------------------------------------------------------------------

bool LostCoins::checkPrivKey(string addr, Int &key, int32_t incr, int endomorphism, bool mode)
{

	Int k(&key);
	//Point sp = startPubKey;

	if (incr < 0) {
		k.Add((uint64_t)(-incr));
		k.Neg();
		k.Add(&secp->order);
		//if (startPubKeySpecified)
		//	sp.y.ModNeg();
	}
	else {
		k.Add((uint64_t)incr);
	}

	// Endomorphisms
	switch (endomorphism) {
	case 1:
		k.ModMulK1order(&lambda);
		//if (startPubKeySpecified)
		//	sp.x.ModMulK1(&beta);
		break;
	case 2:
		k.ModMulK1order(&lambda2);
		//if (startPubKeySpecified)
		//	sp.x.ModMulK1(&beta2);
		break;
	}

	// Check addresses
	Point p = secp->ComputePublicKey(&k);
	//if (startPubKeySpecified)
	//	p = secp->AddDirect(p, sp);

	string chkAddr = secp->GetAddress(searchType, mode, p);
	if (chkAddr != addr) {

		//Key may be the opposite one (negative zero or compressed key)
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		//if (startPubKeySpecified) {
		//	sp.y.ModNeg();
		//	p = secp->AddDirect(p, sp);
		//}
		string chkAddr = secp->GetAddress(searchType, mode, p);
		if (chkAddr != addr) {
			printf("\n  Check your text file for junkand scribbles\n");
			printf("  Warning, wrong private key generated !\n");
			printf("  Addr :%s\n", addr.c_str());
			printf("  Check:%s\n", chkAddr.c_str());
			printf("  Endo:%d incr:%d comp:%d\n", endomorphism, incr, mode);
			//return false;
		}

	}

	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16());

	return true;

}

// ----------------------------------------------------------------------------

#ifdef WIN64
DWORD WINAPI _FindKey(LPVOID lpParam)
{
#else
void *_FindKey(void *lpParam)
{
#endif
	TH_PARAM *p = (TH_PARAM *)lpParam;
	p->obj->FindKeyCPU(p);
	return 0;
}

#ifdef WIN64
DWORD WINAPI _FindKeyGPU(LPVOID lpParam)
{
#else
void *_FindKeyGPU(void *lpParam)
{
#endif
	TH_PARAM *p = (TH_PARAM *)lpParam;
	p->obj->FindKeyGPU(p);
	return 0;
}

// ----------------------------------------------------------------------------

void LostCoins::checkAddresses(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[20];
	Point pte1[1];
	Point pte2[1];

	// Point
	secp->GetHash160(searchType, compressed, p1, h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i, 0, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #1
	pte1[0].x.ModMulK1(&p1.x, &beta);
	pte1[0].y.Set(&p1.y);
	secp->GetHash160(searchType, compressed, pte1[0], h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i, 1, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #2
	pte2[0].x.ModMulK1(&p1.x, &beta2);
	pte2[0].y.Set(&p1.y);
	secp->GetHash160(searchType, compressed, pte2[0], h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i, 2, compressed)) {
			nbFoundKey++;
		}
	}

	// Curve symetrie
	// if (x,y) = k*G, then (x, -y) is -k*G
	p1.y.ModNeg();
	secp->GetHash160(searchType, compressed, p1, h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -i, 0, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #1
	pte1[0].y.ModNeg();
	secp->GetHash160(searchType, compressed, pte1[0], h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -i, 1, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #2
	pte2[0].y.ModNeg();
	secp->GetHash160(searchType, compressed, pte2[0], h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -i, 2, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void LostCoins::checkAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4)
{
	unsigned char h0[20];
	unsigned char h1[20];
	unsigned char h2[20];
	unsigned char h3[20];
	Point pte1[4];
	Point pte2[4];

	// Point -------------------------------------------------------------------------
	secp->GetHash160(searchType, compressed, p1, p2, p3, p4, h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i + 0, 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, i + 1, 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, i + 2, 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, i + 3, 0, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #1
	// if (x, y) = k * G, then (beta*x, y) = lambda*k*G
	pte1[0].x.ModMulK1(&p1.x, &beta);
	pte1[0].y.Set(&p1.y);
	pte1[1].x.ModMulK1(&p2.x, &beta);
	pte1[1].y.Set(&p2.y);
	pte1[2].x.ModMulK1(&p3.x, &beta);
	pte1[2].y.Set(&p3.y);
	pte1[3].x.ModMulK1(&p4.x, &beta);
	pte1[3].y.Set(&p4.y);

	secp->GetHash160(searchType, compressed, pte1[0], pte1[1], pte1[2], pte1[3], h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i + 0, 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, i + 1, 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, i + 2, 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, i + 3, 1, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #2
	// if (x, y) = k * G, then (beta2*x, y) = lambda2*k*G
	pte2[0].x.ModMulK1(&p1.x, &beta2);
	pte2[0].y.Set(&p1.y);
	pte2[1].x.ModMulK1(&p2.x, &beta2);
	pte2[1].y.Set(&p2.y);
	pte2[2].x.ModMulK1(&p3.x, &beta2);
	pte2[2].y.Set(&p3.y);
	pte2[3].x.ModMulK1(&p4.x, &beta2);
	pte2[3].y.Set(&p4.y);

	secp->GetHash160(searchType, compressed, pte2[0], pte2[1], pte2[2], pte2[3], h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i + 0, 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, i + 1, 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, i + 2, 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, i + 3, 2, compressed)) {
			nbFoundKey++;
		}
	}

	// Curve symetrie -------------------------------------------------------------------------
	// if (x,y) = k*G, then (x, -y) is -k*G

	p1.y.ModNeg();
	p2.y.ModNeg();
	p3.y.ModNeg();
	p4.y.ModNeg();

	secp->GetHash160(searchType, compressed, p1, p2, p3, p4, h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -(i + 0), 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, -(i + 1), 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, -(i + 2), 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, -(i + 3), 0, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #1
	// if (x, y) = k * G, then (beta*x, y) = lambda*k*G
	pte1[0].y.ModNeg();
	pte1[1].y.ModNeg();
	pte1[2].y.ModNeg();
	pte1[3].y.ModNeg();

	secp->GetHash160(searchType, compressed, pte1[0], pte1[1], pte1[2], pte1[3], h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -(i + 0), 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, -(i + 1), 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, -(i + 2), 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, -(i + 3), 1, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #2
	// if (x, y) = k * G, then (beta2*x, y) = lambda2*k*G
	pte2[0].y.ModNeg();
	pte2[1].y.ModNeg();
	pte2[2].y.ModNeg();
	pte2[3].y.ModNeg();

	secp->GetHash160(searchType, compressed, pte2[0], pte2[1], pte2[2], pte2[3], h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -(i + 0), 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, -(i + 1), 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, -(i + 2), 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, -(i + 3), 2, compressed)) {
			nbFoundKey++;
		}
	}
}


static string const digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~ ";


string increment(string value) {
	string result;
	bool carry = true;
	for (int i = value.size() - 1; i >= 0; --i) {
		int v = digits.find(value.at(i));
		v += carry;
		carry = v >= digits.size();
		v = carry ? 0 : v;
		result.push_back(digits.at(v));
	}
	reverse(begin(result), end(result));
	return result;
}

bool compare_digits(char a, char b) {
	int va = digits.find(a);
	int vb = digits.find(b);
	return va < vb;
}

bool compare(string const& a, string const& b) {
	return lexicographical_compare(begin(a), end(a), begin(b), end(b), compare_digits);
}



const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
enum { base = sizeof(alphabet) - 1, length = 8 };
char number[length + 1];

void print_digits(int pos)
{
	if (length == pos) {
		puts(number);
	}
	else {
		int i = 0;
		for (; i < base; ++i) {
			number[pos] = alphabet[i];
			print_digits(pos + 1);
		}
	}
}



// ----------------------------------------------------------------------------
void LostCoins::getCPUStartingKey(int thId, Int &key, Point &startP)
{
	if (rekey == 1) {

		char* gyg = &seed[0];
		this->rangeStart1.SetBase16(gyg);
		key.Set(&rangeStart1);
	}
	
	if (rekey == 2) {

		if (nbit == 0) {
			int N = 1 + rand() % 65;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit == 1) {
			int N = 10 + rand() % 55;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit == 2) {
			int N = 20 + rand() % 45;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit == 3) {
			int N = 30 + rand() % 35;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit == 4) {
			int N = 40 + rand() % 25;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit == 5) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 6) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 7) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 8) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 9) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 10) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 11) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 12) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 13) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 14) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 15) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 16) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 17) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 18) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 19) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 20) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 21) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 22) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 23) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 24) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 25) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 26) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 27) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 28) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 29) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 30) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 31) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 32) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 33) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 34) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 35) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 36) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 37) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 38) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 39) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 40) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 41) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 42) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 43) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 44) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 45) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 46) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 47) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 48) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 49) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 50) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 51) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 52) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 53) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 54) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 55) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 56) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 57) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 58) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 59) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 60) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 61) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 62) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 63) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 64) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 65) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 66) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 67) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 68) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 69) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 70) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 71) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 72) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 73) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 74) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 75) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 76) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 77) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 78) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 79) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 80) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 81) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 82) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 83) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 84) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 85) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 86) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 87) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 88) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 89) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 90) {
			int N2 = 4;
			char str2[]{ "4567" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 91) {
			int N2 = 4;
			char str2[]{ "89ab" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 92) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 93) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 94) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 95) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 96) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 97) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 33;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 98) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 99) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 100) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 101) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 102) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 103) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 104) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 105) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 106) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 107) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 108) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 109) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 110) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 111) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 112) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 113) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 114) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 115) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 116) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 117) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 118) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 119) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 120) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 121) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 122) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 123) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 124) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 125) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 126) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 127) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 128) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 129) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 130) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 131) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 132) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 133) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 134) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 135) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 136) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 137) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 138) {
			int N2 = 4;
			char str2[]{ "4567" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 139) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 140) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 141) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 142) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 143) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 144) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 145) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 146) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 147) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 148) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 149) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 150) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 151) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 152) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 153) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 154) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 155) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 156) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 157) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 158) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 159) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 160) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 161) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 162) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 163) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 164) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 165) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 166) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 167) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 168) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 169) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 170) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 171) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 172) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 173) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 174) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 175) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 176) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 177) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 178) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 179) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 180) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 181) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 182) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 183) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 184) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 185) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 186) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 187) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 188) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 189) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 190) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 191) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 192) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 193) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 194) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 195) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 196) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 197) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 198) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 199) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 200) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 201) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 202) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 203) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 204) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}



		if (nbit == 205) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 206) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 207) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 208) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 209) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 210) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 211) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 212) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 213) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 214) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 215) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 216) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}



		if (nbit == 217) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 218) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 219) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 220) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 221) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 222) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 223) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 224) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 225) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 226) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 227) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 228) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 229) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 230) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 231) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 232) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 233) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 234) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 235) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 236) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}

		if (nbit == 237) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 238) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 239) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 240) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}

		if (nbit == 241) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 242) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 243) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 244) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 245) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 246) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 247) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 248) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 249) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 250) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 251) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 252) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 253) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 254) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 255) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 256) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
	}

	if (rekey == 3) {

		int N = nbit;
		char str[]{ "0123456789abcdef" };
		int strN = 16; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выделяем память для строки пароля
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставляем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		int N2 = maxFound;
		char str2[]{ "0123456789abcdef" };
		int strN2 = 16; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выделяем память для строки пароля
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставляем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки


		std::stringstream ss;
		ss << seed << pass << zez << pass2;
		std::string input = ss.str();
		//string nos = sha256(input);
		char* cstr = &input[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}

	if (rekey == 4) {
	
		int myint1 = std::stoi(seed);
		int myint2 = std::stoi(zez);
		int myint3 = myint2 - myint1;
		int myint4 = rand() % myint3 + 1;
		int nbit2 = myint2 - myint4;

		if (nbit2 == 0) {
			int N = 1 + rand() % 65;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit2 == 1) {
			int N = 10 + rand() % 55;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit2 == 2) {
			int N = 20 + rand() % 45;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit2 == 3) {
			int N = 30 + rand() % 35;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit2 == 4) {
			int N = 40 + rand() % 25;

			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (nbit2 == 5) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 6) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 7) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 8) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 9) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 10) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 11) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 12) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 13) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 14) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 15) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 16) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 17) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 18) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 19) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 20) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 21) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 22) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 23) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 24) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 25) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 26) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 27) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 28) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 29) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 30) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 31) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 32) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 33) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 34) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 35) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 36) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 37) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 38) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 39) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 40) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 41) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 42) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 43) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 44) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 45) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 46) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 47) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 48) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 49) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 50) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 51) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 52) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 53) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 54) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 55) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 56) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 57) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 58) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 59) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 60) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 61) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 62) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 63) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 64) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 65) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 66) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 67) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 68) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 69) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 70) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 71) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 72) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 73) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 74) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 75) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 76) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 77) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 78) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 79) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 80) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 81) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 82) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 83) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 84) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 85) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 86) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 87) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 88) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 89) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 90) {
			int N2 = 4;
			char str2[]{ "4567" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 91) {
			int N2 = 4;
			char str2[]{ "89ab" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 92) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 93) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 94) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 95) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 96) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 97) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 98) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 99) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 100) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 101) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 102) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 103) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 104) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 105) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 106) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 107) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 108) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 109) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 110) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 111) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 112) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 113) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 114) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 115) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 116) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 117) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 118) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 119) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 120) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 121) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 122) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 123) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 124) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 125) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 126) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 127) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 128) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 129) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 130) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 131) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 132) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 133) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 134) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 135) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 136) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 137) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 138) {
			int N2 = 4;
			char str2[]{ "4567" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 139) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 140) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 141) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 142) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 143) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 144) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 145) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 146) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 147) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 148) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 149) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 150) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 151) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 152) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 153) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 154) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 155) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 156) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 157) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 158) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 159) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 160) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 161) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 162) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 163) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 164) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 165) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 166) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 167) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 168) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 169) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 170) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 171) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 172) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 173) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 174) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 175) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 176) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 177) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 178) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 179) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 180) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 181) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 182) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 183) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 184) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 185) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 186) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 187) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 188) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 189) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 190) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 191) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 192) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 193) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 194) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 195) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 196) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 197) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 198) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 199) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 200) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 201) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 202) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 203) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 204) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 205) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 206) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 207) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 208) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 209) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 210) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 211) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 212) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit2 == 213) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 214) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 215) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 216) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 217) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 218) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 219) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 220) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 221) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 222) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 223) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 224) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 225) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 226) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 227) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 228) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 229) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 230) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 231) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 232) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 233) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 234) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 235) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 236) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}

		if (nbit2 == 237) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 238) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 239) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 240) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}

		if (nbit2 == 241) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 242) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 243) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 244) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit2 == 245) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 246) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 247) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 248) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 249) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 250) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 251) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 252) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit2 == 253) {

			int N2 = 1;
			char str2[]{ "123" };
			int strN2 = 3;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 254) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 255) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit2 == 256) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
	}
	
	if (rekey == 6) {
		key.Rand(nbit);
		if (diz == 0) {
			printf("\r (%d bit) ", key.GetBitLength());
		}
		if (diz == 1) {
			printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
		}
	}
	

	Int km(&key);
	km.Add((uint64_t)CPU_GRP_SIZE / 2);
	startP = secp->ComputePublicKey(&km);
}




void LostCoins::FindKeyCPU(TH_PARAM* ph)
{

	if (rekey == 0) {
		int err = 0;
		int thId = ph->threadId;
		counters[thId] = 0;

		IntGroup* grp = new IntGroup(CPU_GRP_SIZE / 1024 + 1);

		Int  key;
		Point startP;
		getCPUStartingKey(thId, key, startP);

		Int dx[CPU_GRP_SIZE / 1024 + 1];
		Point pts[CPU_GRP_SIZE];

		Int dy;
		Int dyn;
		Int _s;
		Int _p;
		Point pp;
		Point pn;
		grp->Set(dx);

		ph->hasStarted = true;
		ph->rekeyRequest = false;
		ifstream file77(seed);

		if (thId == 0) {
			string s77;
			int bt = 0;
			while (getline(file77, s77)) {
				bt++;
				if (bt < kusok + kusok) {
					if (regex_search(s77, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = s77;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						if (nbit > 0) {
							for (int nk = 0; nk < nbit; nk++) {
								if (nk == 0) {
									nos2 = sha256(input);
									char* cstr = &nos2[0];
									key.SetBase16(cstr);
								}
								else {
									string nos3 = sha256(nos2);
									char* cstr2 = &nos3[0];
									key.SetBase16(cstr2);
									nos2 = nos3;
								}

								if (diz == 0) {
									printf("\r [%s] ", input.c_str());
								}
								if (diz == 1) {
									printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
								}
								Int km(&key);
								km.Add((uint64_t)CPU_GRP_SIZE / 1024);
								startP = secp->ComputePublicKey(&km);

								if (ph->rekeyRequest) {
									getCPUStartingKey(thId, key, startP);
									ph->rekeyRequest = false;
								}

								int i = 0;
								dx[i].ModSub(&Gn[i].x, &startP.x);
								dx[i + 1].ModSub(&_2Gn.x, &startP.x);

								grp->ModInv();

								pts[1] = startP;
								pn = startP;
								dyn.Set(&Gn[i].y);
								dyn.ModNeg();
								dyn.ModSub(&pn.y);

								_s.ModMulK1(&dyn, &dx[i]);
								_p.ModSquareK1(&_s);
								pn.x.ModNeg();
								pn.x.ModAdd(&_p);
								pn.x.ModSub(&Gn[i].x);
								pn.y.ModSub(&Gn[i].x, &pn.x);
								pn.y.ModMulK1(&_s);
								pn.y.ModAdd(&Gn[i].y);

								pts[0] = pn;

								switch (searchMode) {
								case SEARCH_COMPRESSED:
									checkAddresses(true, key, i, pts[i]);
									break;
								case SEARCH_UNCOMPRESSED:
									checkAddresses(false, key, i, pts[i]);
									break;
								case SEARCH_BOTH:
									checkAddresses(true, key, i, pts[i]);
									checkAddresses(false, key, i, pts[i]);
									break;
								}
								counters[thId] += 1;
								if (bt >= stope * nbit) {
									int vsego = stope - err * nbit;
									printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
									printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
									if (err > 100) {
										printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
									}
									exit(1);
								}
							}
						}
						else {
							if (diz == 0) {
								printf("\r [%s] ", input.c_str());
							}
							if (diz == 1) {
								printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
							}
							Int km(&key);
							km.Add((uint64_t)CPU_GRP_SIZE / 1024);
							startP = secp->ComputePublicKey(&km);

							if (ph->rekeyRequest) {
								getCPUStartingKey(thId, key, startP);
								ph->rekeyRequest = false;
							}

							int i = 0;
							dx[i].ModSub(&Gn[i].x, &startP.x);
							dx[i + 1].ModSub(&_2Gn.x, &startP.x);

							grp->ModInv();

							pts[1] = startP;
							pn = startP;
							dyn.Set(&Gn[i].y);
							dyn.ModNeg();
							dyn.ModSub(&pn.y);

							_s.ModMulK1(&dyn, &dx[i]);
							_p.ModSquareK1(&_s);
							pn.x.ModNeg();
							pn.x.ModAdd(&_p);
							pn.x.ModSub(&Gn[i].x);
							pn.y.ModSub(&Gn[i].x, &pn.x);
							pn.y.ModMulK1(&_s);
							pn.y.ModAdd(&Gn[i].y);

							pts[0] = pn;

							switch (searchMode) {
							case SEARCH_COMPRESSED:
								checkAddresses(true, key, i, pts[i]);
								break;
							case SEARCH_UNCOMPRESSED:
								checkAddresses(false, key, i, pts[i]);
								break;
							case SEARCH_BOTH:
								checkAddresses(true, key, i, pts[i]);
								checkAddresses(false, key, i, pts[i]);
								break;
							}
							counters[thId] += 1;
							if (bt >= stope) {
								int vsego = stope - err;
								printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
								printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
								if (err > 100) {
									printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
								}
								exit(1);
							}
						}
					}
				}
			}
		}
		if (thId == 1) {
			string s78;
			int bt1 = 0;
			while (getline(file77, s78)) {
				bt1++;
				if (bt1 > kusok) {
					if (regex_search(s78, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = s78;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}

						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (bt1 >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 2) {
			string s79;
			int bt2 = 0;
			while (getline(file77, s79)) {
				bt2++;
				if (bt2 > kusok + kusok) {
					if (regex_search(s79, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = s79;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (bt2 >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 3) {
			string sk8;
			int bt3 = 0;
			while (getline(file77, sk8)) {
				bt3++;
				if (bt3 > kusok * 3) {
					if (regex_search(sk8, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = sk8;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (bt3 >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 4) {
			string sk9;
			int bt4 = 0;
			while (getline(file77, sk9)) {
				bt4++;
				if (bt4 > kusok * 4) {
					if (regex_search(sk9, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = sk9;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (bt4 >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 5) {
			string sr7;
			int bt5 = 0;
			while (getline(file77, sr7)) {
				bt5++;
				if (bt5 > kusok * 5) {
					if (regex_search(sr7, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = sr7;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (bt5 >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 6) {
			string tr6;
			int bt6 = 0;
			while (getline(file77, tr6)) {
				bt6++;
				if (bt6 > kusok * 6) {
					if (regex_search(tr6, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = tr6;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (bt6 >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 7) {
			string tr7;
			int bt7 = 0;
			while (getline(file77, tr7)) {
				bt7++;
				if (bt7 > kusok * 7) {
					if (regex_search(tr7, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = tr7;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (bt7 >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 8) {
			string tr8;
			int bt8 = 0;
			while (getline(file77, tr8)) {
				bt8++;
				if (bt8 > kusok * 8) {
					if (regex_search(tr8, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = tr8;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (bt8 >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 9) {
			string tr9;
			int bt9 = 0;
			while (getline(file77, tr9)) {
				bt9++;
				if (bt9 > kusok * 9) {
					if (regex_search(tr9, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = tr9;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (bt9 >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 10) {
			string gtr9;
			int btt = 0;
			while (getline(file77, gtr9)) {
				btt++;
				if (btt > kusok * 10) {
					if (regex_search(gtr9, regex("[^А-Яа-яA-Za-z0-9ёЁьЪЬъ `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						err += 1;
					}
					else {
						string input = gtr9;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						else {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}

						if (diz == 0) {
							printf("\r [%s] ", input.c_str());
						}
						if (diz == 1) {
							printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
						}
						Int km(&key);
						km.Add((uint64_t)CPU_GRP_SIZE / 1024);
						startP = secp->ComputePublicKey(&km);

						if (ph->rekeyRequest) {
							getCPUStartingKey(thId, key, startP);
							ph->rekeyRequest = false;
						}

						int i = 0;
						dx[i].ModSub(&Gn[i].x, &startP.x);
						dx[i + 1].ModSub(&_2Gn.x, &startP.x);
						grp->ModInv();

						pts[1] = startP;
						pn = startP;
						dyn.Set(&Gn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&Gn[i].x);
						pn.y.ModSub(&Gn[i].x, &pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
						pts[0] = pn;

						switch (searchMode) {
						case SEARCH_COMPRESSED:
							checkAddresses(true, key, i, pts[i]);
							break;
						case SEARCH_UNCOMPRESSED:
							checkAddresses(false, key, i, pts[i]);
							break;
						case SEARCH_BOTH:
							checkAddresses(true, key, i, pts[i]);
							checkAddresses(false, key, i, pts[i]);
							break;
						}
						counters[thId] += 1;
						if (btt >= stope) {
							int vsego = stope - err;
							printf("\n  Search is Finish! (%d) passphrases checked from total (%d). Found: (%d) \n", vsego, stope, nbFoundKey);
							printf("  Skipped passphrases with incorrect letters, characters (%d) \n", err);
							if (err > 100) {
								printf("  Check the file %s for incorrect characters, remove the garbage from %d passphrases and try again.  \n  Help by link https://github.com/phrutis/LostCoins/issues/16 \n", seed.c_str(), err);
							}
							exit(1);
						}
					}
				}
			}
		}
		//ph->isRunning = false;
	}
	else
	{

		// Global init
		int thId = ph->threadId;
		counters[thId] = 0;

		// CPU Thread
		IntGroup* grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);

		// Group Init
		Int  key;
		Point startP;
		getCPUStartingKey(thId, key, startP);

		Int dx[CPU_GRP_SIZE / 2 + 1];
		Point pts[CPU_GRP_SIZE];

		Int dy;
		Int dyn;
		Int _s;
		Int _p;
		Point pp;
		Point pn;
		grp->Set(dx);

		ph->hasStarted = true;
		ph->rekeyRequest = false;

		while (!endOfSearch) {

			if (ph->rekeyRequest) {
				getCPUStartingKey(thId, key, startP);
				ph->rekeyRequest = false;
			}

			// Fill group
			int i;
			int hLength = (CPU_GRP_SIZE / 2 - 1);

			for (i = 0; i < hLength; i++) {
				dx[i].ModSub(&Gn[i].x, &startP.x);
			}
			dx[i].ModSub(&Gn[i].x, &startP.x);  // For the first point
			dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point

			// Grouped ModInv
			grp->ModInv();

			// We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
			// We compute key in the positive and negative way from the center of the group

			// center point
			pts[CPU_GRP_SIZE / 2] = startP;

			for (i = 0; i < hLength && !endOfSearch; i++) {

				pp = startP;
				pn = startP;

				// P = startP + i*G
				dy.ModSub(&Gn[i].y, &pp.y);

				_s.ModMulK1(&dy, &dx[i]);       // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
				_p.ModSquareK1(&_s);            // _p = pow2(s)

				pp.x.ModNeg();
				pp.x.ModAdd(&_p);
				pp.x.ModSub(&Gn[i].x);           // rx = pow2(s) - p1.x - p2.x;

				pp.y.ModSub(&Gn[i].x, &pp.x);
				pp.y.ModMulK1(&_s);
				pp.y.ModSub(&Gn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);

				// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
				dyn.Set(&Gn[i].y);
				dyn.ModNeg();
				dyn.ModSub(&pn.y);

				_s.ModMulK1(&dyn, &dx[i]);      // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
				_p.ModSquareK1(&_s);            // _p = pow2(s)

				pn.x.ModNeg();
				pn.x.ModAdd(&_p);
				pn.x.ModSub(&Gn[i].x);          // rx = pow2(s) - p1.x - p2.x;

				pn.y.ModSub(&Gn[i].x, &pn.x);
				pn.y.ModMulK1(&_s);
				pn.y.ModAdd(&Gn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);

				pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
				pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;

			}

			// First point (startP - (GRP_SZIE/2)*G)
			pn = startP;
			dyn.Set(&Gn[i].y);
			dyn.ModNeg();
			dyn.ModSub(&pn.y);

			_s.ModMulK1(&dyn, &dx[i]);
			_p.ModSquareK1(&_s);

			pn.x.ModNeg();
			pn.x.ModAdd(&_p);
			pn.x.ModSub(&Gn[i].x);

			pn.y.ModSub(&Gn[i].x, &pn.x);
			pn.y.ModMulK1(&_s);
			pn.y.ModAdd(&Gn[i].y);

			pts[0] = pn;

			// Next start point (startP + GRP_SIZE*G)
			pp = startP;
			dy.ModSub(&_2Gn.y, &pp.y);

			_s.ModMulK1(&dy, &dx[i + 1]);
			_p.ModSquareK1(&_s);

			pp.x.ModNeg();
			pp.x.ModAdd(&_p);
			pp.x.ModSub(&_2Gn.x);

			pp.y.ModSub(&_2Gn.x, &pp.x);
			pp.y.ModMulK1(&_s);
			pp.y.ModSub(&_2Gn.y);
			startP = pp;

			// Check addresses
			if (useSSE) {

				for (int i = 0; i < CPU_GRP_SIZE && !endOfSearch; i += 4) {

					switch (searchMode) {
					case SEARCH_COMPRESSED:
						checkAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
						break;
					case SEARCH_UNCOMPRESSED:
						checkAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
						break;
					case SEARCH_BOTH:
						checkAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
						checkAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
						break;
					}
				}
			}
			else {

				for (int i = 0; i < CPU_GRP_SIZE && !endOfSearch; i++) {

					switch (searchMode) {
					case SEARCH_COMPRESSED:
						checkAddresses(true, key, i, pts[i]);
						break;
					case SEARCH_UNCOMPRESSED:
						checkAddresses(false, key, i, pts[i]);
						break;
					case SEARCH_BOTH:
						checkAddresses(true, key, i, pts[i]);
						checkAddresses(false, key, i, pts[i]);
						break;
					}
				}
			}

			key.Add((uint64_t)CPU_GRP_SIZE);
			counters[thId] += 6 * CPU_GRP_SIZE; // Point + endo #1 + endo #2 + Symetric point + endo #1 + endo #2
		}
		ph->isRunning = false;
	}


}

// ----------------------------------------------------------------------------

void LostCoins::getGPUStartingKeys(int thId, int groupSize, int nbThread, Int *keys, Point *p)
{
   if (rekey == 1) {

	   char* cstra27 = cstra27 + 1;
	   int gaza877 = (int)cstra27;
	   
	   if (gaza877 == 1) {

		   char* gyg = &seed[0];
		   char* fun = &zez[0];
		   this->rangeStart1.SetBase16(gyg);
		   this->rangeEnd1.SetBase16(fun);
		   if (seed == "") {
			   this->rangeStart1.Add(1);
		   }

		   if (zez == "") {
			   this->rangeEnd1.Add(10000000000000000);
		   }
		   Int tRangeDiff;
		   Int tRangeStart2(&rangeStart1);
		   Int tRangeEnd2(&rangeStart1);
		   Int razn;
		   Int tThreads;
		   tThreads.SetInt32(nbThread);
		   tRangeDiff.Set(&rangeEnd1);
		   tRangeDiff.Sub(&rangeStart1);
		   razn.Set(&tRangeDiff);
		   tRangeDiff.Div(&tThreads);
		   this->rangeDiff.Set(&tRangeDiff);
		  
		   if (maxFound == 777) {
			   ifstream file777("LostCoins-Continue.bat");
			   string s777;
			   string kogda;
			   for (int i = 0; i < 5; i++) {
				   getline(file777, s777);
				   if (i == 0) {
					   string kogda = s777;
					   printf("  Rotor       : Continuing search from BAT file. Checkpoint %s \n\n", kogda.c_str());
				   }
				   if (i == 4) {
					   string streek = s777;
					   std::istringstream iss(streek);
					   iss >> value777;
				   }
			   }
			   uint64_t nextt;
			   nextt = value777 / 65535;
			   tRangeStart2.Add(nextt);
			   Int passe;
			   passe.Add(nextt);
			   printf("  Rotor       : Divide the range %s into %d threads, add the passed hex %s to each Thread, for fast parallel search \n", razn.GetBase16().c_str(), nbThread, passe.GetBase16().c_str());

			   for (int i = 0; i < nbThread; i++) {

				   keys[i].Set(&tRangeStart2);
				   if (i == 0) {
					   printf("  Thread 00000: %064s ->", keys[i].GetBase16().c_str());
				   }
				   tRangeStart2.Add(&tRangeDiff);

				   Int k(keys + i);
				   k.Add((uint64_t)(groupSize / 2));
				   p[i] = secp->ComputePublicKey(&k);
				   Int dobb;
				   dobb.Set(&tRangeStart2);
				   dobb.Add(&tRangeDiff);
				   if (i == 0) {
					   printf(" %064s \n", dobb.GetBase16().c_str());
				   }
				   if (i == 1) {
					   printf("  Thread 00001: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
				   if (i == 2) {
					   printf("  Thread 00002: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
				   if (i == 3) {
					   printf("  Thread 00003: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
					   printf("          ... : \n");
				   }
				   if (i == 65533) {
					   printf("  Thread 65533: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
				   if (i == 65534) {
					   printf("  Thread 65534: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
				   if (i == 65535) {
					   printf("  Thread 65535: %064s -> %064s \n\n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
			   } 
		   }
		   else
		   {
			   printf("  Divide the range %s into %d threads  for fast parallel search \n", razn.GetBase16().c_str(), nbThread);
			   for (int i = 0; i < nbThread; i++) {

				   keys[i].Set(&tRangeStart2);
				   if (i == 0) {
					   printf("  Thread 00000: %064s ->", keys[i].GetBase16().c_str());
				   }
				   tRangeStart2.Add(&tRangeDiff);

				   Int k(keys + i);
				   k.Add((uint64_t)(groupSize / 2));
				   p[i] = secp->ComputePublicKey(&k);
				   Int dobb;
				   dobb.Set(&tRangeStart2);
				   dobb.Add(&tRangeDiff);
				   if (i == 0) {
					   printf(" %064s \n", dobb.GetBase16().c_str());
				   }
				   if (i == 1) {
					   printf("  Thread 00001: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
				   if (i == 2) {
					   printf("  Thread 00002: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
				   if (i == 3) {
					   printf("  Thread 00003: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
					   printf("          ... : \n");
				   }
				   if (i == 65533) {
					   printf("  Thread 65533: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
				   if (i == 65534) {
					   printf("  Thread 65534: %064s -> %064s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
				   if (i == 65535) {
					   printf("  Thread 65535: %064s -> %064s \n\n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				   }
			   }
			   
		   }
	   }
   }
   else
   {
   
   
	 for (int i = 0; i < nbThread; i++) {
		
		if (rekey == 2) {
			
			if (nbit == 1) {

				int N = 20 + rand() % 45;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit == 2) {
				int N = 30 + rand() % 35;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			
			}
			if (nbit == 3) {
				int N = 40 + rand() % 25;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit == 4) {
				int N = 50 + rand() % 15;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit == 5) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 6) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 7) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 8) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 9) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 10) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 11) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 12) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 13) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 14) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 15) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 16) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 17) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 18) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 19) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 20) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 21) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 22) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 23) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 24) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 25) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 26) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 27) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 28) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 29) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 30) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 31) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 32) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 33) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 34) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 35) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 36) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 37) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 38) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 39) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 40) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 41) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 42) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 43) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 44) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 45) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 46) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 47) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 48) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 49) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 50) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 51) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 52) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 53) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 54) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 55) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 56) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 57) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 58) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 59) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 60) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 61) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 62) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 63) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 64) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 65) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 66) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 67) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 68) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 69) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 70) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 71) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 72) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 73) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 74) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 75) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 76) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 77) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 78) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 79) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 80) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 81) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 82) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 83) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 84) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}

			if (nbit == 85) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 86) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 87) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 88) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 89) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 90) {
				int N2 = 4;
				char str2[]{ "4567" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 91) {
				int N2 = 4;
				char str2[]{ "89ab" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 92) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 93) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 94) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 95) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 96) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 97) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 98) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 99) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 100) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 101) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 102) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 103) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 104) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 105) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 106) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 107) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 108) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 109) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 110) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 111) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 112) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 113) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 114) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 115) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 116) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 117) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 118) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 119) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 120) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 121) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 122) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 123) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 124) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 125) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 126) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 127) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 128) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 129) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 130) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 131) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 132) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 133) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 134) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 135) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 136) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 137) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 138) {
				int N2 = 4;
				char str2[]{ "4567" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 139) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 140) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 141) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 142) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 143) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 144) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 145) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 146) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 147) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 148) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 149) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 150) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 151) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 152) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 153) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 154) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 155) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 156) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 157) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 158) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 159) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 160) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 161) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 162) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 163) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 164) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 165) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 166) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 167) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 168) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 169) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 170) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 171) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 172) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 173) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 174) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 175) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 176) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 177) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 178) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 179) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 180) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 181) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 182) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 183) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 184) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 185) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 186) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 187) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 188) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 189) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 190) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 191) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 192) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 193) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 194) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 195) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 196) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 197) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 198) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 199) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 200) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 201) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 202) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 203) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 204) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 205) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 206) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 207) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 208) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 209) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 210) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 211) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 212) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 213) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 214) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 215) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 216) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 217) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 218) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 219) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 220) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 221) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 222) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 223) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 224) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 225) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 226) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 227) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 228) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 229) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 230) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 231) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 232) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 233) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 234) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 235) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 236) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 237) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 238) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 239) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 240) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}

			if (nbit == 241) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 242) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 243) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 244) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 245) {
				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 246) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 247) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 248) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 249) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 250) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 251) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 252) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 253) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 254) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 255) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 256) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
		}

		if (rekey == 3) {

			int N = nbit;
			char str[]{ "0123456789abcdef" };
			int strN = 16; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выделяем память для строки пароля
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставляем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			int N2 = maxFound;
			char str2[]{ "0123456789abcdef" };
			int strN2 = 16; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выделяем память для строки пароля
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставляем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки


			std::stringstream ss;
			ss << seed << pass << zez << pass2;
			std::string input = ss.str();
			char* cstr = &input[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}

		if (rekey == 4) {
			int myint1 = std::stoi(seed);
			int myint2 = std::stoi(zez);
			int myint3 = myint2 - myint1;
			int myint4 = rand() % myint3 + 1;
			int nbit2 = myint2 - myint4;
			
			if (nbit2 == 0) {

				int N = 1 + rand() % 64;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}

			if (nbit2 == 1) {

				int N = 20 + rand() % 45;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit2 == 2) {
				int N = 30 + rand() % 35;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit2 == 3) {
				int N = 40 + rand() % 25;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit2 == 4) {
				int N = 50 + rand() % 15;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit2 == 5) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 6) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 7) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 8) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 9) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 10) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 11) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 12) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 13) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 14) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 15) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 16) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 17) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 18) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 19) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 20) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 21) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 22) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 23) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 24) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 25) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 26) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 27) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 28) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 29) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 30) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 31) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 32) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 33) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 34) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 35) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 36) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit2 == 37) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 38) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 39) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 40) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 41) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 42) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 43) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 44) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 45) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 46) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 47) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 48) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 49) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 50) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 51) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 52) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 53) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 54) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 55) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 56) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 57) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 58) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 59) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 60) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 61) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 62) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 63) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 64) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 65) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 66) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 67) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 68) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 69) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 70) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 71) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 72) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 73) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 74) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 75) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 76) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit2 == 77) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 78) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 79) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 80) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit2 == 81) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 82) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 83) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 84) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}

			if (nbit2 == 85) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 86) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 87) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 88) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit2 == 89) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 90) {
				int N2 = 4;
				char str2[]{ "4567" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 91) {
				int N2 = 4;
				char str2[]{ "89ab" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 92) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 93) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 94) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 95) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 96) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 97) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 98) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 99) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 100) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 101) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 102) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 103) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 104) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 105) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 106) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 107) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 108) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 109) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 110) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 111) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 112) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 113) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 114) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 115) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 116) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 117) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 118) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 119) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 120) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 121) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 122) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 123) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 124) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 125) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 126) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 127) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 128) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 129) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 130) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 131) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 132) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 133) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 134) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 135) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 136) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit2 == 137) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 138) {
				int N2 = 4;
				char str2[]{ "4567" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 139) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 140) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 141) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 142) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 143) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 144) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 145) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 146) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 147) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 148) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 149) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 150) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 151) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 152) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 153) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 154) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 155) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 156) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit2 == 157) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 158) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 159) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 160) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 161) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 162) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 163) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 164) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 165) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 166) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 167) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 168) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 169) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 170) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 171) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 172) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 173) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 174) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 175) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 176) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 177) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 178) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 179) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 180) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 181) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 182) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 183) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 184) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 185) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 186) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 187) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 188) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit2 == 189) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 190) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 191) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 192) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit2 == 193) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 194) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 195) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 196) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 197) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 198) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 199) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 200) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit2 == 201) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 202) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 203) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 204) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 205) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 206) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 207) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 208) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 209) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 210) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 211) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 212) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 213) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 214) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 215) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 216) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 217) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 218) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 219) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 220) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 221) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 222) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 223) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 224) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 225) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 226) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 227) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 228) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 229) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 230) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 231) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 232) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 233) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 234) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 235) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 236) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 237) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 238) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 239) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 240) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}

			if (nbit2 == 241) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 242) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 243) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 244) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit2 == 245) {
				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 246) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 247) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 248) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 249) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 250) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 251) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 252) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 253) {

				int N2 = 1;
				char str2[]{ "123" };
				int strN2 = 3;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit2 == 254) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 255) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit2 == 256) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
		}
		if (rekey == 5) {
			printf("\n GPU Not support is mode 5! Only for CPU 1 core! USE -t 1");
		}
		
		if (rekey == 6) {
			keys[i].Rand(nbit);
			if (diz == 0) {
				printf("\r (%d bit) ", keys[i].GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
			}
		}

		if (rekey == 7) {
			
			printf("\n  ERROR!!! \n  Search mode for Passphrases from file on gpu in development\n\n  BYE   \n\n");
			exit(-1);
		}

		Int k(keys + i);
		// Starting key is at the middle of the group
		k.Add((uint64_t)(groupSize / 2));
		p[i] = secp->ComputePublicKey(&k);
		//if (startPubKeySpecified)
		//	p[i] = secp->AddDirect(p[i], startPubKey);
	 }
   }
}

void LostCoins::FindKeyGPU(TH_PARAM* ph)
{

	bool ok = true;

#ifdef WITHGPU

	// Global init
	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart1;
	Int tRangeEnd = ph->rangeEnd1;
	GPUEngine g(ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, (rekey != 0),
		BLOOM_N, bloom->get_bits(), bloom->get_hashes(), bloom->get_bf(), DATA, TOTAL_ADDR);
	int nbThread = g.GetNbThread();
	Point* p = new Point[nbThread];
	Int* keys = new Int[nbThread];
	vector<ITEM> found;
	printf("  GPU         : %s\n\n", g.deviceName.c_str());
	counters[thId] = 0;

	getGPUStartingKeys(thId, g.GetGroupSize(), nbThread, keys, p);
	g.SetSearchMode(searchMode);
	g.SetSearchType(searchType);

	getGPUStartingKeys(thId, g.GetGroupSize(), nbThread, keys, p);
	ok = g.SetKeys(p);
	ph->rekeyRequest = false;

	ph->hasStarted = true;

	// GPU Thread
	while (ok && !endOfSearch) {

		if (ph->rekeyRequest) {
			getGPUStartingKeys(thId, g.GetGroupSize(), nbThread, keys, p);
			ok = g.SetKeys(p);
			ph->rekeyRequest = false;
		}

		// Call kernel
		ok = g.Launch(found, false);

		for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {

			ITEM it = found[i];
			//checkAddr(it.hash, keys[it.thId], it.incr, it.endo, it.mode);
			string addr = secp->GetAddress(searchType, it.mode, it.hash);
			if (checkPrivKey(addr, keys[it.thId], it.incr, it.endo, it.mode)) {
				nbFoundKey++;
			}

		}

		if (ok) {
			for (int i = 0; i < nbThread; i++) {
				keys[i].Add((uint64_t)STEP_SIZE);
			}
			counters[thId] += 6ULL * STEP_SIZE * nbThread; // Point +  endo1 + endo2 + symetrics
		}
		//ok = g.ClearOutBuffer();
	}
	delete[] keys;
	delete[] p;

#else
	ph->hasStarted = true;
	printf("GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif

	ph->isRunning = false;

}

// ----------------------------------------------------------------------------

bool LostCoins::isAlive(TH_PARAM *p)
{

	bool isAlive = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		isAlive = isAlive && p[i].isRunning;

	return isAlive;

}

// ----------------------------------------------------------------------------

bool LostCoins::hasStarted(TH_PARAM *p)
{

	bool hasStarted = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		hasStarted = hasStarted && p[i].hasStarted;

	return hasStarted;

}

// ----------------------------------------------------------------------------

void LostCoins::rekeyRequest(TH_PARAM *p)
{

	bool hasStarted = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		p[i].rekeyRequest = true;

}


// ----------------------------------------------------------------------------

uint64_t LostCoins::getGPUCount()
{
	uint64_t count = 0;
	if (value777 > 1000000) {
		count = value777;
	}

	for (int i = 0; i < nbGPUThread; i++)
		count += counters[0x80L + i];
	return count;

}

uint64_t LostCoins::getCPUCount()
{

	uint64_t count = 0;
	for (int i = 0; i < nbCPUThread; i++)
		count += counters[i];
	return count;

}


void SetupRanges(uint32_t totalThreads)
{
	Int threads;
	Int rangeStart1;
	Int rangeEnd1;
	Int rangeDiff;
	Int rangeDiff2;
	Int rangeDiff3;
	threads.SetInt32(totalThreads);
	rangeDiff2.Set(&rangeEnd1);
	rangeDiff2.Sub(&rangeStart1);
	rangeDiff2.Div(&threads);
}
// ----------------------------------------------------------------------------

void LostCoins::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{
	
	double t0;
	double t1;
	endOfSearch = false;
	nbCPUThread = nbThread;
	nbGPUThread = (useGpu ? (int)gpuId.size() : 0);
	nbFoundKey = 0;
	memset(counters, 0, sizeof(counters));

	//printf("Number of CPU thread: %d\n\n", nbCPUThread);

	TH_PARAM *params = (TH_PARAM *)malloc((nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));
	memset(params, 0, (nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));

	// Launch CPU threads
	for (int i = 0; i < nbCPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = i;
		params[i].isRunning = true;
		params[i].rangeStart1.Set(&rangeStart1);
		rangeStart1.Add(&rangeDiff2);
		params[i].rangeEnd1.Set(&rangeStart1);

#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKey, (void *)(params + i), 0, &thread_id);
		ghMutex = CreateMutex(NULL, FALSE, NULL);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKey, (void *)(params + i));
		ghMutex = PTHREAD_MUTEX_INITIALIZER;
#endif
	}

	// Launch GPU threads
	for (int i = 0; i < nbGPUThread; i++) {
		params[nbCPUThread + i].obj = this;
		params[nbCPUThread + i].threadId = 0x80L + i;
		params[nbCPUThread + i].isRunning = true;
		params[nbCPUThread + i].gpuId = gpuId[i];
		params[nbCPUThread + i].gridSizeX = gridSize[2 * i];
		params[nbCPUThread + i].gridSizeY = gridSize[2 * i + 1];

		params[nbCPUThread + i].rangeStart1.Set(&rangeStart1);
		rangeStart1.Add(&rangeDiff2);
		params[nbCPUThread + i].rangeEnd1.Set(&rangeStart1);
#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyGPU, (void *)(params + (nbCPUThread + i)), 0, &thread_id);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyGPU, (void *)(params + (nbCPUThread + i)));
#endif
	}

#ifndef WIN64
	setvbuf(stdout, NULL, _IONBF, 0);
#endif

	uint64_t lastCount = 0;
	uint64_t gpuCount = 0;
	uint64_t lastGPUCount = 0;

	// Key rate smoothing filter
#define FILTER_SIZE 8
	double lastkeyRate[FILTER_SIZE];
	double lastGpukeyRate[FILTER_SIZE];
	uint32_t filterPos = 0;

	double keyRate = 0.0;
	double gpuKeyRate = 0.0;
	char timeStr[256];

	memset(lastkeyRate, 0, sizeof(lastkeyRate));
	memset(lastGpukeyRate, 0, sizeof(lastkeyRate));

	// Wait that all threads have started
	while (!hasStarted(params)) {
		Timer::SleepMillis(500);
	}

	// Reset timer
	Timer::Init();
	t0 = Timer::get_tick();
	startTime = t0;
	Int p100;
	Int ICount;
	p100.SetInt32(100);
	int completedPerc = 0;
	uint64_t rKeyCount = 0;
	while (isAlive(params)) {

		int delay = 1000;
		while (isAlive(params) && delay > 0) {
			Timer::SleepMillis(500);
			delay -= 500;
		}

		gpuCount = getGPUCount();
		uint64_t count = getCPUCount() + gpuCount;
		ICount.SetInt64(count);
		int completedBits = ICount.GetBitLength();

		char* gyg = &seed[0];
		char* fun = &zez[0];
		this->rangeStart1.SetBase16(gyg);
		this->rangeEnd1.SetBase16(fun);

		rangeDiff3.Set(&rangeStart1);
		rangeDiff3.Add(&ICount);
		minuty++;
		
		if (diz == 4) {
			if (nbit == 0) {
				nbit = nbit + 60;
			}
			if (minuty == nbit * 60) {

				char* ctimeBuff;
				time_t now = time(NULL);
				ctimeBuff = ctime(&now);

				FILE* ptrFile = fopen("LostCoins-Continue.bat", "w+");
				fprintf(ptrFile, "created: %s", ctimeBuff);
				fprintf(ptrFile, ":loop \n");
				fprintf(ptrFile, "LostCoins.exe -t 0 -g -i 0 -x 256,256 -f %s -r 1 -s %s -z %s -d 4 -n %d -m 777 \n", addressFile.c_str(), rangeStart1.GetBase16().c_str(), rangeEnd1.GetBase16().c_str(), nbit);
				fprintf(ptrFile, "goto :loop \n");
				fprintf(ptrFile, "%" PRIu64 "\n", count);
				fclose(ptrFile);
				minuty = minuty - nbit * 60;
			}

			//completedPerc = CalcPercantage(ICount, rangeStart1, rangeDiff2);
			ICount.Mult(&p100);
			ICount.Div(&this->rangeDiff2);
			completedPerc = std::stoi(ICount.GetBase10());
		}

		t1 = Timer::get_tick();
		keyRate = (double)(count - lastCount) / (t1 - t0);
		gpuKeyRate = (double)(gpuCount - lastGPUCount) / (t1 - t0);
		lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
		lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
		filterPos++;

		double avgKeyRate = 0.0;
		double avgGpuKeyRate = 0.0;
		uint32_t nbSample;
		for (nbSample = 0; (nbSample < FILTER_SIZE) && (nbSample < filterPos); nbSample++) {
			avgKeyRate += lastkeyRate[nbSample];
			avgGpuKeyRate += lastGpukeyRate[nbSample];
		}
		avgKeyRate /= (double)(nbSample);
		avgGpuKeyRate /= (double)(nbSample);

		if (nbFoundKey > maxFound) {
			printf(" Exceeded message limit %d Found adreses. \n For more messages use -m 1000 (-m 10000000)  \n\n\n ", maxFound);
			exit(1);
		}
		
		if (diz == 0) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r                                                    [%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					avgKeyRate / 1000000.0,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}
		}
		if (diz == 1) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r                                                                                       [%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					avgKeyRate / 1000000.0,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}
		}
		if (diz == 2) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					avgKeyRate / 1000000.0,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}
		}
		if (diz == 3) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [CPU: %.2f Kk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					avgKeyRate / 1000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}

		}
		if (diz == 4) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%064s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [C: %d%%] [T: %s (%d bit)] [F: %d]              ",
					toTimeStr(t1, timeStr),
					rangeDiff3.GetBase16().c_str(),
					avgKeyRate / 1000000.0,
					avgGpuKeyRate / 1000000.0,
					completedPerc,
					formatThousands(count).c_str(),
					completedBits,
					nbFoundKey);
			}

		}
		if (diz == 5) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r                                    [%s] [CPU: %.2f Kk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					avgKeyRate / 1000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}

		}
		if (diz == 6) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%064s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					rangeDiff3.GetBase16().c_str(),
					avgKeyRate / 1000000.0,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}
		}

		if (diz > 6) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					avgKeyRate / 1000000.0,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}
		}
		
		if (rekey == 0) {

			if (nbit2 > 0) {

				if ((count - lastRekey) > (1 * 1)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
			else {

				if ((count - lastRekey) > (1000000000 * maxFound)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
		}
		
		if (rekey == 2) {

			if (nbit2 > 0) {

				if ((count - lastRekey) > (1 * 1)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
			else {

				if ((count - lastRekey) > (1000000000 * maxFound)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
		}
		if (rekey == 3) {

			if (nbit2 > 0) {

				if ((count - lastRekey) > (1 * 1)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
			else {

				if ((count - lastRekey) > (47200000 * maxFound)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
		}
		if (rekey == 4) {

			if (nbit2 > 0) {

				if ((count - lastRekey) > (1 * 1)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
			else {

				if ((count - lastRekey) > (1000000000 * maxFound)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
		}

		if (rekey == 5) {

			if (nbit2 > 0) {

				if ((count - lastRekey) > (1 * 1)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
			else {

				if ((count - lastRekey) > (1000000000)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
		}
		
		if (rekey == 6) {

			if (nbit2 > 0) {

				if ((count - lastRekey) > (1 * 1)) {
					// Rekey request
					rekeyRequest(params);
					lastRekey = count;
				}
			}
			else {

				if ((count - lastRekey) > (1000000000 * maxFound)) {
					rekeyRequest(params);
					lastRekey = count;
				}
			}
		}

		if (rekey > 6) {
			if ((count - lastRekey) > (1 * 1)) {
				rekeyRequest(params);
				lastRekey = count;
			}
		}

		lastCount = count;
		lastGPUCount = gpuCount;
		t0 = t1;
		//endOfSearch = should_exit;


		if (rekey == 1) {
			lastCount = count;
			lastGPUCount = gpuCount;
			t0 = t1;
			if (should_exit || completedPerc > 101)
				endOfSearch = true;
		}

		
	}
	
	free(params);

}

string LostCoins::GetHex(vector<unsigned char> &buffer)
{
	string ret;

	char tmp[128];
	for (int i = 0; i < (int)buffer.size(); i++) {
		sprintf(tmp, "%02X", buffer[i]);
		ret.append(tmp);
	}
	return ret;
}

int LostCoins::CheckBloomBinary(const uint8_t *hash)
{
	if (bloom->check(hash, 20) > 0) {
		uint8_t* temp_read;
		uint64_t half, min, max, current;
		int64_t rcmp;
		int32_t r = 0;
		min = 0;
		current = 0;
		max = TOTAL_ADDR;
		half = TOTAL_ADDR;
		while (!r && half >= 1) {
			half = (max - min) / 2;
			temp_read = DATA + ((current + half) * 20);
			rcmp = memcmp(hash, temp_read, 20);
			if (rcmp == 0) {
				r = 1;  //Found!!
			}
			else {
				if (rcmp < 0) { //data < temp_read
					max = (max - half);
				}
				else { // data > temp_read
					min = (min + half);
				}
				current = min;
			}
		}
		return r;
	}
	return 0;
}

std::string LostCoins::formatThousands(uint64_t x)
{
	char buf[32] = "";

	sprintf(buf, "%llu", x);

	std::string s(buf);

	int len = (int)s.length();

	int numCommas = (len - 1) / 3;

	if (numCommas == 0) {
		return s;
	}

	std::string result = "";

	int count = ((len % 3) == 0) ? 0 : (3 - (len % 3));

	for (int i = 0; i < len; i++) {
		result += s[i];

		if (count++ == 2 && i < len - 1) {
			result += ",";
			count = 0;
		}
	}
	return result;
}

char* LostCoins::toTimeStr(int sec, char* timeStr)
{
	int h, m, s;
	h = (sec / 3600);
	m = (sec - (3600 * h)) / 60;
	s = (sec - (3600 * h) - (m * 60));
	sprintf(timeStr, "%0*d:%0*d:%0*d", 2, h, 2, m, 2, s);
	return (char*)timeStr;
}


