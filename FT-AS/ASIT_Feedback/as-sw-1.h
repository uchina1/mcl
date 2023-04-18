#include <mcl/bn256.hpp>

#include "sw-1.h"
#include <algorithm>
#include <thread>

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
		//cout << pms[i].second << " ";
	}
	//cout << endl;
	if((int)distinct.size()!=n){
		cout << "SAME MSG CONTAINED" << endl;
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
		string m;
		G1 sig;
		G2 pub_key;
		int id;

		void KeyGen(const G2& Q){
			sec_key.setRand();
			G2::mul(pub_key, Q, sec_key);
		}
		/*
		void Sign(const G1& Hm){
			G1::mul(sig, Hm, sec_key);
		}
		*/
		void Sign(const string m){
			this->m = m;
			G1 Hm;
			Hash(Hm, m);
			G1::mul(sig, Hm, sec_key);
		}

	private:
		Fr sec_key;
};

class Aggregator{
	private:
		state alpha;
	public:
		int id;
		vector<int> ids; // ids of sensors
		map<int, G1> sigs; // <id, sigs>
		map<int, PM> pms; // <id, vector<PM> >
		part f2; // Agg's users set partiton in the feedback
		part P; // Set partiton from mark allocation matrix
		vector<G1> agg_sigs; // ASIT agg sigs
		uset V; // traced attacker set

		void Initialize(int N){
			Init(N, alpha, P);
			if(show_progress){
				cout <<"M_rows : " << endl;
				for(int i=1; i<=b; i++){
					for(int x=1; x<=q; x++){
					/* if over n break */if((i-1)*q+x > alpha.n) break;
					cout << (i-1)*q+x <<": " ;
						for(int j=0; j<(p-1)/2; j++){
							cout << " " << alpha.M_rows[j][(i-1)*q+x -1] ;
						}
						cout << endl;
					}
				}
			}
		}
		
		void Agg(part f, map<int, G1>& sigs){
			agg_sigs.clear(); f2.clear();

			if(f.size()==0){
				G1 a_sig;
				vector<G1> all_sigs;
				for(auto itr = sigs.begin(); itr != sigs.end(); ++itr) {
					all_sigs.push_back(itr->second);
				}

				::Agg(a_sig, all_sigs);
				agg_sigs.push_back(a_sig);
				f2.push_back(ids);
			}else{
				// find sensor ids of the agg from the feedback
				for(int i=0; i<(int)f.size(); i++){
					uset u;
					for(int j=0; j<(int)f[i].size(); j++){
						bool traced = false;
						for(int k=0; k<(int)V.size(); k++){
							if(f[i][j]==V[k]){
								traced = true;
								break;
							}
						}
						if(traced) continue;
						for(int k=0; k<(int)ids.size(); k++){
							if(f[i][j]==ids[k]){
								u.push_back(ids[k]);
								break;
							}
						}
					}
					f2.push_back(u);
				}
				
				for(int i=0; i<(int)f2.size(); i++){
					G1 a_sig;
					if(f2[i].size()==0){
						::Hash(a_sig, "NONE");
					}else{
						a_sig = sigs[f2[i][0]];
						for(int j=1;j<f2[i].size();j++){
							int id = f2[i][j];
							G1::add(a_sig, a_sig, sigs[id]);
						}
						// check wheter router correctly agg
						/*
						vector <PM> tmp;
						for(int j=0;j<f2[i].size();j++){
							int id = f2[i][j];
							tmp.push_back(pms[id]);
						}
						G2 Q; mapToG2(Q, 1);
						if(AggVerify(a_sig, Q, tmp)==true){
							cout << "aggregator AGG : OK" << endl;
						}else{
							cout << "aggregator AGG : NG" << endl;
						}
						*/
					}
					/* if(show_progress && i==0){
						cout << "Aggregator : " << endl;
						for(int j=0;j<f2[i].size();j++)cout << f[i][j] << " ";
						cout << endl;
					}*/
					agg_sigs.push_back(a_sig);
				}
			}
			NextPart(alpha, P);
		}
		
};


class Verifier{
	private:
		asit beta;
	public:
		part f;
		uset V;

		bool Verify(G1& sign, const G2& Q, const G2& pub, const string& m){
			return Verify(sign, Q, pub, m);
		}

		bool PartVerify(asit& beta, const G2& Q, const vector<PM>& pms, vector<G1>& agg_sig, int& i){
			state alpha;
			part P;
			if(beta.first.P.size()==0){
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

		void Initialize(int N){
			state alpha;
			part P;
			Init(N, alpha, P);
			f = P;
			beta = make_pair(alpha, P);
			if(show_progress){
				cout <<"M_rows : " << endl;
				for(int i=1; i<=b; i++){
					for(int x=1; x<=q; x++){
					/* if over n break */if((i-1)*q+x > alpha.n) break;
					cout << (i-1)*q+x <<": " ;
						for(int j=0; j<(p-1)/2; j++){
							cout << " " << alpha.M_rows[j][(i-1)*q+x -1] ;
						}
						cout << endl;
					}
				}
			}
		}

		int Trace(const G2& Q, vector<PM>& pms, vector<G1>& agg_sig){
			int valid_num = 0;
			
			state alpha;
			part P;
			//V.clear();
		
			if(beta.first.P.size()==0){
				Init(N, alpha, P);
			}else{
				alpha = beta.first;
				P = beta.second;
			}
			f = P;
			//int revoked_min = alpha.n;
			int id = -1;
			for(int i=0; i<agg_sig.size(); i++){
				if(f[i].size() == 0) continue;

				int revoked_num = 0; // if f contains revoked traitor
				vector<PM> pms2;
				for(int j=0; j<(int)f[i].size(); j++){
					bool revoked = false;
					for(int id=0; id<V.size(); id++){
						if(f[i][j] == V[id]){
							revoked = true;
							break;
						}
					}
					if(!revoked){
						PM pm = pms[f[i][j]];
						pms2.push_back(pm);
					}else{
						revoked_num++;
					}
				}
				if(revoked_num == (int)f[i].size()){
					// Nothing to do
				}else if(!AggVerify(agg_sig[i], Q, pms2)){
					if(show_progress) cout << " agg_sig ["<< i << "] is invalid" << endl;
					id = i;
					::Trace(alpha, id, P, V);
					f = P; beta = make_pair(alpha, P);
					//if(show_progress) view(f);
					break;
				}else{
					// valid agg_sig
					valid_num += pms2.size();
				}
			}
			//if(show_progress) cout << " agg_sig ["<< id << "] is invalid" << endl;

			return valid_num;
		}

		void AVerify(const G2& Q, map<int, PM>& pms, vector<G1>& agg_sig){
			state alpha;
			part P;
			//V.clear();
		
			if(beta.first.P.size()==0){
				Init(N, alpha, P);
			}else{
				alpha = beta.first;
				P = beta.second;
			}
			f = P;
			if(show_progress) cout << " AggVerify : ";
			for(int i=0; i<agg_sig.size(); i++){
				if(f[i].size() == 0) continue;

				vector<PM> pms2;
				for(int j=0;j<f[i].size();j++){
					PM pm = pms[f[i][j]];
					pms2.push_back(pm);
				}

				if(show_progress) cout << (AggVerify(agg_sig[i], Q, pms2) ? "OK, " : "NG, ");
			}
			if(show_progress) cout << endl;

		}
};
