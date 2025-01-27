#include <mcl/bn256.hpp>

#include "ft-2.h"
#include <map>

using namespace mcl::bn256;

typedef pair<state, part> asit;
typedef pair<G2, string> PM;

extern int N;
extern bool show_progress;

void Hash(G1& P, const string& m)
{
	Fp t;
	t.setHashOf(m);
	mapToG1(P, t);
}

void Agg(G1& agg_sig, std::vector<G1>& sigs){
	int n = sigs.size();
	agg_sig = sigs[0];
	for(int i=1;i<n;i++){
		G1::add(agg_sig, agg_sig, sigs[i]);
	}	
}

bool Verify(G1& sign, const G2& Q, const G2& pub, const string& m){
	Fp12 e1, e2;
	G1 Hm;
	Hash(Hm, m);
	pairing(e1, sign, Q); // e1 = e(sign, Q)
	pairing(e2, Hm, pub); // e2 = e(Hm, sQ)
	return e1 == e2;
}


bool AggVerify(G1& agg_sig, const G2& Q, const vector<PM>& pms)
{
	int n = pms.size();
	map<string, int> distinct;
	for(int i=0;i<n;i++){
		distinct[pms[i].second] = i;
	}
	if((int)distinct.size()!=n){
		return false;
	}

	Fp12 e1, e2;
	G1 Hm;
	pairing(e1, agg_sig, Q); // e1 = e(sign, Q)
	Hash(Hm, pms[0].second);
	pairing(e2, Hm, pms[0].first); // e2 = e(Hm, sQ)
	
	for(int i=1;i<n;i++){
		Fp12 e;
		Hash(Hm, pms[i].second);
		pairing(e, Hm, pms[i].first); // e2 = e(Hm, sQ)
		Fp12::mul(e2, e2, e);
	}
	
	return e1 == e2;
}

class User{
	public:
		int id; 
		string m;
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
		vector<G1> agg_sigs;
		
		void Agg(part f, vector<G1>& sigs){
			agg_sigs.clear();

			if(f.size()==0){
				G1 a_sig;
				::Agg(a_sig, sigs);
				agg_sigs.push_back(a_sig);
			}else{
				for(int i=0; i<f.size(); i++){
					G1 a_sig;
					if(f[i].size()==0){
						::Hash(a_sig, "none");
					}else{
						a_sig = sigs[f[i][0]];
						for(int j=1;j<f[i].size();j++){
							G1::add(a_sig, a_sig, sigs[f[i][j]]);
						}
					}
					agg_sigs.push_back(a_sig);
				}
			}
		}
		//vector<G1> Agg(vector<vector<int> > f, G1& agg_sig, vector<G1>& sigs){}
};

class Verifier{
	public:
		part f;
		uset V;
		asit beta;

		bool Verify(G1& sign, const G2& Q, const G2& pub, const string& m){
			return Verify(sign, Q, pub, m);
		}

		bool PartVerify(asit& beta, const G2& Q, const vector<PM>& pms, vector<G1>& agg_sig, int& i){
			state alpha;
			part P;
			if(beta.first.size()==0){
				Init(N, alpha, P);
			}else{
				alpha = beta.first;
				P = beta.second;
			}
			int i2 = -1;
			for(int j=0; j<P.size(); j++){
				for(int k=0; k<P[j].size(); k++){
					if(P[j][k] == i){
						i2 = j;
						break;
					}
				}
			}
			if(i2 == -1) exit(1);
			
			G1 agg_sig2 = agg_sig[i2];
			vector<PM> pms2;
			for(int j=0; j<P[i2].size(); j++){
				pms2.push_back(pms[P[i2][j]]);
			}

			bool v = AggVerify(agg_sig[i2], Q, pms2);
			return v;
		}

		void Trace(const G2& Q, const vector<PM>& pms, vector<G1>& agg_sig){
			state alpha;
			part P;
			V.clear();
		
			if(beta.first.size()==0){
				Init(N, alpha, P);
			}else{
				alpha = beta.first;
				P = beta.second;
			}
			f = P;
			for(int i=0; i<agg_sig.size(); i++){
				if(f[i].size() == 0) continue;

				vector<PM> pms2;
				for(int j=0;j<f[i].size();j++){
					pms2.push_back(pms[f[i][j]]);
				}
				
				if(!AggVerify(agg_sig[i], Q, pms2)){
					if(show_progress) cout << " AVerify ("<< i << ") : " << AggVerify(agg_sig[i], Q, pms2) << endl;
					::Trace(alpha, i, P, V);
					f = P; beta = make_pair(alpha, P);
					break;
				}
			}
			if(show_progress) view(f);
		}

	private:
		
};
