#include <mcl/bn256.hpp>
#include <iostream>

//my includes
#include <vector>
#include <map>
#include <chrono>
#include <random>
#include <algorithm>

using namespace mcl::bn256;
using namespace std::chrono;

int add_num = 0; double add_time = 0;
int pair_num = 0; double pair_time = 0;
int mul_num = 0; double mul_time = 0;

inline double get_time_msec(void){
    return static_cast<double>(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count()) / 1000000;
}
std::string random_text(int length) {
	std::string text = "";

	std::random_device seed_gen;
	std::mt19937 mt(seed_gen());
	std::uniform_int_distribution<int> dist(0, 25); // 26 letters of a~z
	for (int i = 0; i < length; i++) text += char(dist(mt) + 'a');
 
	return text;
}

class User{
	public:
		std::string m;
		G1 sig;
		G2 pub_key;

		void KeyGen(const G2& Q){
			sec_key.setRand();
			G2::mul(pub_key, Q, sec_key);
		}
		void Sign(const G1& Hm){
			G1::mul(sig, Hm, sec_key);
		}

	private:
		Fr sec_key;
};

class Aggregator{
	public:
		std::vector<User> users;
		G1 agg_signatures;
};


void Hash(G1& P, const std::string& m)
{
	Fp t;
	t.setHashOf(m);
	mapToG1(P, t);
}

/*
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
*/

void Agg(G1& agg_sig, std::vector<G1>& sigs){
	int n = sigs.size();
	agg_sig = sigs[0];
	for(int i=1;i<n;i++){
		auto st = get_time_msec();
		G1::add(agg_sig, agg_sig, sigs[i]);
		auto ed = get_time_msec();
		add_time += ed - st; add_num++;
	}
	
}

bool Verify(G1& sign, const G2& Q, const G2& pub, const std::string& m)
{
	Fp12 e1, e2;
	G1 Hm;
	Hash(Hm, m);
	auto st = get_time_msec();
	pairing(e1, sign, Q); // e1 = e(sign, Q)
	pairing(e2, Hm, pub); // e2 = e(Hm, sQ)
	auto ed = get_time_msec();
	pair_time += ed - st; pair_num += 2;
	return e1 == e2;
}

bool AggVerify(G1& agg_sig, const G2& Q, const std::vector<G2> pubs, const std::vector<std::string> msgs)
{
	int n = msgs.size();
	std::map<std::string, int> distinct;
	for(int i=0;i<n;i++){
		distinct[msgs[i]] = i;
	}
	if((int)distinct.size()!=n){
		return false;
	}

	Fp12 e1, e2;
	G1 Hm;
	Hash(Hm, msgs[0]);
	auto st = get_time_msec();
	pairing(e1, agg_sig, Q); // e1 = e(sign, Q)
	pairing(e2, Hm, pubs[0]); // e2 = e(Hm, sQ)
	auto ed = get_time_msec();
	pair_time += ed - st;
	pair_num += 2;

	for(int i=1;i<n;i++){
		Fp12 e;
		Hash(Hm, msgs[i]);
		auto st = get_time_msec();
		pairing(e, Hm, pubs[i]); // e2 = e(Hm, sQ)
		auto ed = get_time_msec();
		pair_time += ed - st;
		pair_num++;
		
		st = get_time_msec();
		Fp12::mul(e2, e2, e);
		ed = get_time_msec();
		mul_time += ed - st;
		mul_num++;
	}
	
	return e1 == e2;
}


int main(int argc, char *argv[]){
	std::string m = argc == 1 ? "hello mcl" : argv[1];

	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);
	
	printf("Input signer num : ");
	Aggregator agg;
	int num;
	std::cin >> num;

	std::vector<std::string> messages;
	std::vector<G1> signatures;
	std::vector<G2> pubkeys;

	// generate secret key and public key
	for(int i=0;i<num;i++){
		User usr;
		std::string si = std::to_string(i);
		usr.m = m+si;
		usr.KeyGen(Q);

		messages.push_back(usr.m);
		pubkeys.push_back(usr.pub_key);

		agg.users.push_back(usr);
	}	

	// sign
	for(int i=0;i<num;i++){
		G1 Hm;
		Hash(Hm, agg.users[i].m);
		agg.users[i].Sign(Hm);
		signatures.push_back(agg.users[i].sig);
	}

	/*
	for(int i=0;i<num;i++){
		std::cout << "message " << i << " : " << agg.users[i].m << std::endl;
		std::cout << "pub_key " << i << " : " << agg.users[i].pub_key << std::endl;
		std::cout << "Signature " << i << " : " << agg.users[i].sig << std::endl;
	}
	*/
	
	//Aggregator agg
	double st = get_time_msec();
	Agg(agg.agg_signatures, signatures);
	double ed = get_time_msec();
	printf("Agg time : %.6lf msec\n", ed-st);
	
	st = get_time_msec();
	bool aggok2 = AggVerify(agg.agg_signatures, Q, pubkeys, messages);
	ed = get_time_msec();
	printf("AggVerify time : %.6lf msec\n", ed-st);
	std::cout << "verify agg " << (aggok2 ? "ok" : "ng") << std::endl;

	st = get_time_msec();
	for(int i=0;i<num;i++){
		User u = agg.users[i];
		bool ok = Verify(u.sig, Q, u.pub_key, u.m);
		if(!ok){
			std::cout << "ng" << std::endl;
			exit(0);
		}
	}
	ed = get_time_msec();
	
	printf("NormalVerify time : %.6lf msec\n", ed-st);
	std::cout << "all ok" << std::endl;

	printf("EC addition time : %.6lf msec (%d executed)\n", add_time/add_num, add_num);
	printf("pairing time : %.6lf msec (%d executed)\n", pair_time/pair_num, pair_num);
	printf("Fp multiple time : %.6lf msec (%d executed)\n", mul_time/mul_num, mul_num);	
}
