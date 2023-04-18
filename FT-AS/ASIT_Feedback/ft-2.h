using namespace std;
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>

typedef vector<int> uset; // set of users
typedef vector< vector<int> > part;
typedef vector< vector<int> > state;

void Init(int n, state& alpha, part& P);
void Halve(uset& I, uset& A, uset& B);
void Trace(state& alpha, int i, part& P, uset& V);
void view(part& P);


string random_text(int length) {
	string text = "";

	random_device seed_gen;
	mt19937 mt(seed_gen());
	uniform_int_distribution<int> dist(0, 25); // 26 letters of a~z
	for (int i = 0; i < length; i++) text += char(dist(mt) + 'a');
 
	return text;
}

void Init(int n, state& alpha, part& P){
	uset I(n);
	for(int i=0;i<n;i++) I[i] = i;
	//int p = 0;
	P.push_back(I);
	alpha = P;
}

void Halve(uset& I, uset& A, uset& B){
	for(int i=0; i<I.size(); i++){
		if(i<I.size()/2) A.push_back(I[i]);
		else B.push_back(I[i]);
	}
}

void Trace(state& alpha, int i, part& P, uset& V){
	//int p = 0;
	if(i==0){	 		// If Q_i = I
		uset L, R;
		Halve(P[0], L, R); // Halve
		
		P[0].clear();
		P.push_back(L);
		P.push_back(R);
	}else{
		int l,r;
		if(i%2==1){
			l = i; r = i+1;
		}else{
			l = i; r = i-1;
		} 
		for(int t=0; t<P[r].size(); t++) P[0].push_back(P[r][t]);
		if(P[l].size()>1){
			uset L, R;
			Halve(P[l], L, R); // Halve
			P[l].clear(); P[r].clear(); 
			P[l] = L; P[r] = R;
		}else{
			V.push_back(P[l][0]);
			P.erase(P.begin()+min(l,r), P.begin()+max(l,r)+1);
		}
	}	
		
	alpha = P;
	//newpart = P;
}

void view(part& P){
	cout << "partition" << " : " << endl;
	for(int i=0;i<P.size();i++){
		for(int j=0;j<P[i].size();j++){
			cout << " " << P[i][j] ;
		}
		cout << endl;
	}
}