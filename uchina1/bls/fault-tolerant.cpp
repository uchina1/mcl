// To execute this code 
//
//$ make bin/fault-tolerant.exe

#include <mcl/bn256.hpp>
#include <iostream>

//my includes
#include <vector>
#include <map>
#include <time.h>
#include <cmath>
#include <random>

using namespace mcl::bn256;

class User{
	public:
		std::string m;
		G1 sig;
		G2 pk;

		void KeyGen(const G2& Q){
			sk.setRand();
			G2::mul(pk, Q, sk);
		}
		void Sign(const G1& Hm){
			G1::mul(sig, Hm, sk);
		}

	private:
		Fr sk;
};

class Aggregator{
	public:
		std::vector<User> users;
		G1 aggsig;
		void aggregate();
};

void Aggregator::aggregate(){
	this->aggsig = this->users[0].sig;
	for(int i=1;i<(int)this->users.size();i++){
		G1::add(this->aggsig, this->aggsig, this->users[i].sig);
	}
}

class CFF{
	public:
		int q, k, d;
		int Bsize, Ssize;
		std::vector<std::vector<int> > digit;
		std::vector<std::vector<bool> > M;
		std::vector<std::vector<int> > id;
		void setup(int q, int k, int d);
		void view();
};

void CFF::setup(int q, int k, int d){
	this->q = q, this->k = k, this->d = d;
	int Ssize = q*q;
	int Bsize = (int) std::pow(q, k+1);
	this->Ssize = Ssize, this->Bsize = Bsize;
	this->digit.resize(q, std::vector<int>(Bsize));
	this->M.resize(Ssize, std::vector<bool>(Bsize));
	this->id.resize(Ssize);

	for(int i=0; i<q; i++){
		for(int j=0; j<Bsize; j++){
			if(i==0) this->digit[i][j] = j % q;
			else{
				this->digit[i][j] = 0;
				int tmp = j;
				for(int t=0;t<=k;t++){
					this->digit[i][j] += (tmp % q) * (int) std::pow(i, t);
					tmp /= q;
				}
				this->digit[i][j] %= q;
			}
		}
	}
	for(int i=0; i<Ssize; i++){
		int x = i/q;
		int y = i%q;
		for(int j=0; j<Bsize; j++){
			if(this->digit[x][j] == y) this->M[i][j] = true;
			else this->M[i][j] = false;
			if(this->M[i][j]) id[i].push_back(j);
		}
	}
}

void CFF::view(){
	for(int i=0; i<(int)M.size(); i++){
		for(int j=0; j<(int)M[0].size(); j++) std::cout << M[i][j] << " ";
		std::cout << std::endl;
	}
}

class FaultTolerant{
	public:
	CFF cff;
	std::vector<User> users;
	std::vector<Aggregator> aggs;
	std::vector<bool> verify;
	FaultTolerant(CFF& cff);
	void MakeSubsets();
	void ViewValidList();
};

FaultTolerant::FaultTolerant(CFF& cff){
	this->cff = cff;
	this->aggs.resize(cff.M.size());
	this->verify.resize(cff.M[0].size(), false);
}

void FaultTolerant::MakeSubsets(){
	for(int i=0; i<(int)this->cff.M.size(); i++){
		for(int j=0; j<(int)this->cff.M[i].size(); j++){
			if(cff.M[i][j]) this->aggs[i].users.push_back(this->users[j]);
		}
	}
}

void FaultTolerant::ViewValidList(){
	printf("Valid List : ");
	for(int i=0;i<(int)this->users.size();i++){
		if(this->verify[i])	printf("%d, ", i);
	}
	printf("\n");
	printf("Invalid List : ");
	for(int i=0;i<(int)this->users.size();i++){
		if(!this->verify[i])	printf("%d, ", i);
	}
	printf("\n");
}


void Hash(G1& P, const std::string& m){
	Fp t;
	t.setHashOf(m);
	mapToG1(P, t);
}

bool Verify(G1& sign, const G2& Q, const G2& pub, const std::string& m){
	Fp12 e1, e2;
	G1 Hm;
	Hash(Hm, m);
	pairing(e1, sign, Q); // e1 = e(sign, Q)
	pairing(e2, Hm, pub); // e2 = e(Hm, sQ)
	return e1 == e2;
}

bool AggVerify(const Aggregator& agg, const G2& Q){
	int n = agg.users.size();

	std::map<std::string, int> distinct;
	for(int i=0;i<n;i++) distinct[agg.users[i].m] = i;
	if((int)distinct.size()!=n) return false;

	Fp12 e1, e2;
	G1 Hm;
	pairing(e1, agg.aggsig, Q); // e1 = e(sign, Q)
	Hash(Hm, agg.users[0].m);
	pairing(e2, Hm, agg.users[0].pk); // e2 = e(Hm, sQ)
	
	for(int i=1;i<n;i++){
		Fp12 e;
		Hash(Hm, agg.users[i].m);
		pairing(e, Hm, agg.users[i].pk); // e2 = e(Hm, sQ)
		Fp12::mul(e2, e2, e);
	}
	
	return e1 == e2;
}


int main(int argc, char *argv[]){
	std::string m = argc == 1 ? "hello mcl" : argv[1];

	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);

	// Aggregator
	Aggregator agg;
	
	// Fault-Tolerant
	//  q:prime, d:falut sigs, q-k*d >= 1
	CFF cff;
	cff.setup(7,2,3); // setup(q, k, d); 
	//cff.view();
	FaultTolerant ft(cff);
	
	// number of users, q^(k+1)
	int num = cff.Bsize;

	for(int i=0;i<num;i++){
		User usr;
		std::string si = std::to_string(i);
		usr.m = m+si;
		usr.KeyGen(Q);
		agg.users.push_back(usr);
		ft.users.push_back(usr);
	}

	// sign
	for(int i=0;i<num;i++){
		G1 Hm;
		// generate valid aggregate signature
		Hash(Hm, agg.users[i].m);
		agg.users[i].Sign(Hm);
		// randomly generate invalid signatures
		std::random_device rnd;
		if(rnd()%100 == 0) Hash(Hm, agg.users[i].m+"ababa");
		ft.users[i].Sign(Hm);
	}
	
	// Time
	clock_t start,end;
	
	start = clock();
	//Aggregator agg
	agg.aggregate();

	//Aggregator verify
	bool aggok2 = AggVerify(agg, Q);
	end = clock();
	std::cout << "verify agg " << (aggok2 ? "ok" : "ng") << std::endl;
	std::cout << "Agg Verification time : " << (double)(end-start)/CLOCKS_PER_SEC << std::endl;


	start = clock();
	//Fault-tolerant agg
	ft.MakeSubsets();
	for(int i=0;i<(int)ft.aggs.size();i++){
		ft.aggs[i].aggregate();
	}
	
	//Fault-tolerant verify
	for(int i=0;i<(int)ft.aggs.size();i++){
		bool aggok3 = AggVerify(ft.aggs[i], Q);
		//std::cout << "verify agg "<< i <<" " << (aggok3 ? "ok" : "ng") << std::endl;
		if(aggok3){
			for(int j=0;j<(int)ft.aggs[i].users.size();j++){
				ft.verify[ft.cff.id[i][j]] = true;		// adding valid list
			}
		}
	}
	end = clock();
	ft.ViewValidList();
	std::cout << "Fault-Tolerant Verification time : " << (double)(end-start)/CLOCKS_PER_SEC << std::endl;

	// Normal Verificaton
	std::cout << "(Correct answer) Invalid List : ";
	for(int i=0;i<num;i++){
		User u = ft.users[i];
		bool ok = Verify(u.sig, Q, u.pk, u.m);
		if(!ok){
			std::cout << i <<", ";
		}
	}
	std::cout << std::endl;
	
	return 0;
}
