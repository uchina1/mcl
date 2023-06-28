using namespace std;
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <string>

typedef vector<int> uset; // set of users
typedef vector< vector<int> > part;
//typedef vector< vector<int> > state;
struct state{
	int n;
	uset U;
	int h;
	uset F;
	part P;
	vector<int> F_cnt;
	vector< vector<int> > M_rows;
};

extern int p; // prime number
extern int b; // the num of blocks
extern int q; // the num of marks
extern int d; // the num of traitors

void Init(int n, state& alpha, part& P);
//void Halve(uset& I, uset& A, uset& B);
void NextPart(state& alpha, part& P);
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

vector<int> Eratosthenes( const int n ){
	vector<bool> is_prime( n + 1 );
	for(int i=0; i<=n; i++){
		is_prime[i] = true;
	}
	vector<int> P;
	for(int i=2; i<=n; i++){
		if( is_prime[ i ] ){
			for(int j=2*i; j<=n; j+=i){
				is_prime[j] = false;
			}
			P.emplace_back(i);
		}
	}
	return P;
}


int phi(int i, int j, int x){
	int ret;
	if(j == 0) ret = i;
	else ret = ((i+j) * x) % p - 1;
	//if(ret == 0) ret = p;

	return ret;
}

void Init(int n, state& alpha, part& P){
	if(2*n > (p-1)*(p-1) || (2*d*d)+2*d > p-1){
		perror("too many users\n");
		exit(1);
	}

	uset U(n);
	for(int i=0;i<n;i++) U[i] = i;
	uset F;
	vector<int> F_cnt(n);
	for(int i=0;i<n;i++) F_cnt[i] = 0;
	alpha.h = 0;
	alpha.U = U;
	alpha.F = F;
	alpha.n = n;
	alpha.F_cnt = F_cnt;

	NextPart(alpha, P);
	view(P);

	vector< vector<int> > M_rows;
	for(int j=1; j<=(p-1)/2; j++){
		vector<int> v;
		for(int i=1; i<=b; i++){
			for(int x=1; x<=q; x++){
				/* if over n break */if((i-1)*q+x > n) break;
				v.push_back(phi(i, j, x));
			}
		}
		M_rows.push_back(v);
	}

	alpha.M_rows = M_rows;
}

void NextPart(state& alpha, part& P){
	P.clear();
	uset marks[p-1];
	alpha.h++;

	if(alpha.h > (p-1)/2) return; // if last round, return no partition

	for(int r=1; r<=b; r++){
		//cout << "r : " << r <<endl;
		for(int k=1; k<=q; k++){
			//cout << "phi " << phi(r, alpha.h, k) << endl;
			/* if over n break */ if((r-1)*q+k-1 == alpha.n) break;
			// /* if revoked continue */ if(alpha.U[(r-1)*q+k-1] < 0) continue;
			marks[phi(r, alpha.h, k)].push_back( (r-1)*q+k -1 );
		}
	}	

	for(int i=0; i<p-1; i++) P.emplace_back(marks[i]);
	alpha.P = P;
}

void Trace(state& alpha, int i, part& P, uset& V){
	alpha.F.push_back(i);
	for(int row=0; row<q*b; row++){
		/* if over n break */if(row == alpha.n) break;
		if(alpha.M_rows[alpha.h-1][row] == alpha.F[alpha.h-1]){
			alpha.F_cnt[row]++;
			cout << "Row " << row << " cnt++ -> " << alpha.F_cnt[row] << endl;
		}
		//cout << "Row " << row << "'s cnt" << cnt << endl;
		//if(cnt >= q+1){
		if(alpha.F_cnt[row] == d+1){
			alpha.U[row] = -1; // revoke user [row]
			bool exist = false;
			for(int j=0; j<(int)V.size(); j++){
				if(V[j]==row) exist = true;
			}
			if(!exist) V.push_back(row);
		}
	}

	// next partition
	NextPart(alpha, P);
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