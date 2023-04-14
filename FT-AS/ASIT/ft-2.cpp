/*
 * This file is for checking correctness of FT-2 algorithms.
 */

#include <map>
#include "ft-2.h" 
using namespace std;


int main(){
	int num = 100;

	//cout << "Input num : "; cin >> num;

	part state;
	part P;
	Init(num, state, P);

	uset C;
	std::random_device rnd;
	map<int,int> mp;
	for(int i=0;i<num;i++){
		int t = rnd()%num;
		if(mp[t]==0) C.push_back(t);
		else i--;
		mp[t]++;
		//cout << t << ":" << mp[t]<< endl;
	}

	int R = 1;
	while(C.size()>0){
		cout << "Round : " << R << endl;
		int t = rnd()%(C.size());
		cout << "-- traitor : " << C[t] << endl;
		uset V;
		for(int i=0;i<P.size();i++){
			bool found = false;
			for(int j=0;j<P[i].size();j++){
				if(P[i][j] == C[t]){
					Trace(state, i, P, V);
					found = true;
					break;
				}
			}
			if(found) break;
		}
		view(P);
		if(V.size()>0){
			cout << "--- V : ";
			for(int i=0;i<V.size();i++) cout << V[i] << " ";
			cout << endl;
			for(int i=0;i<C.size();i++){
				if(C[i]==V[0]){
					C[i] = C.back();
					C.pop_back();
					break;
				}
			}
		}
		cout << "--- C : ";
		for(int i=0;i<C.size();i++) cout << C[i] << " ";
		cout << endl;

		R++;
	}

	return 0;
}
