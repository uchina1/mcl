// To execute this code 
//
//$ make ./bin/bls.exe
//$ ./bin/bls.exe

#include <mcl/bn256.hpp>
#include <iostream>

using namespace mcl::bn256;

void Hash(G1& P, const std::string& m)
{
	Fp t;
	t.setHashOf(m);
	mapToG1(P, t);
}


void KeyGen(Fr& s, G2& pub, const G2& Q)
{
	s.setRand();
	G2::mul(pub, Q, s); // pub = sQ
}

void Sign(G1& sign, const Fr& s, const std::string& m)
{
	G1 Hm;
	Hash(Hm, m);
	G1::mul(sign, Hm, s); // sign = s H(m)
}


bool Verify(const G1& sign, const G2& Q, const G2& pub, const std::string& m)
{
	Fp12 e1, e2;
	G1 Hm;
	Hash(Hm, m);
	pairing(e1, sign, Q); // e1 = e(sign, Q)
	pairing(e2, Hm, pub); // e2 = e(Hm, sQ)
	return e1 == e2;
}


int main(int argc, char *argv[])
{
	std::string m = argc == 1 ? "hello mcl" : argv[1];

	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);

	// generate secret key and public key
	Fr s;
	G2 pub;
	KeyGen(s, pub, Q);
	std::cout << "secret key " << s << std::endl;
	std::cout << "public key " << pub << std::endl;
	Fr s2;
	G2 pub2;
	KeyGen(s2, pub2, Q);
	std::cout << "secret key2 " << s2 << std::endl;
	std::cout << "public key2 " << pub2 << std::endl;

	// sign
	G1 sign;
	Sign(sign, s, m);
	std::cout << "msg " << m << std::endl;
	std::cout << "sign " << sign << std::endl;
	G1 sign2;
	std::string m2 = "goodbye mcl";
	Sign(sign2, s2, m2);
	std::cout << "msg2 " << m2 << std::endl;
	std::cout << "sign2 " << sign2 << std::endl;

	// agg
	G1 agg;
	G1::add(agg,sign,sign2);

	// verify
	bool ok = Verify(sign, Q, pub, m);
	std::cout << "verify sign1 " << (ok ? "ok" : "ng") << std::endl;

	// Aggverify
	Fp12 e1, e2;
	Fp12 eT;
	G1 Hm, Hm2;
	Hash(Hm, m);
	Hash(Hm2, m2);
	pairing(e1, Hm, pub); // 
	pairing(e2, Hm2, pub2); // 
	Fp12 e0;
	Fp12::mul(e0, e1, e2);
	pairing(eT, agg, Q);

	std::cout << "verify agg " << (e0==eT ? "ok" : "ng") << std::endl;


	return e1 == e2;

}
