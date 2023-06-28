//my includes
#include <map>
#include "as-sw-1.h" // stt-1 -> sw-1

int p; // prime number
int b; // the num of blocks
int q; // the N of marks

int N = 100; // the num of sensors
int d = 3; // the num of traitors

vector<int> prime; // set of prime numbers

int invalid_percent = 100;
bool show_progress = true;
int Loop = 1;


using namespace std::chrono;
inline double get_time_sec(void){
    return static_cast<double>(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count())/1000000000;
}


int main(int argc, char *argv[]){
	string m = argc == 1 ? "hello mcl" : argv[1];

	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);

	prime = Eratosthenes(100000);
	int x1 = (int)(1.0+sqrt(2*N)+0.9999);
	auto iter = lower_bound(prime.begin(),prime.end(), max(x1, (2*d*d)+(2*d)+1));
	p = *iter;

	cout << "p : " << p << endl;
	q = p-1;
	b = N/q; if(N%q != 0 || b==0) b++;
	//b = (p-1)/2;					//cannot trace this setting...
	//q = N/b; if(N%b != 0) q++;
	cout << "q : "<< q << ", b : "<< b << endl;

	double time_sum = 0.0;
	double time2_sum = 0.0;
	double trace_time_sum = 0.0;
	
	long long R_sum = 0;
	long long R2_sum = 0;

	long long valid_sum = 0;
	//long long valid2_sum = 0;
	long long sig_len_sum = 0;

// start Loop timer
auto st = get_time_sec(); //st = std::chrono::system_clock::now(); 
auto ed = get_time_sec();

for(int loop=0;loop<Loop;loop++){
	// Setup AS-SW-1

	long long valid = 0;
	//long long valid2 = 0;
	long long sig_len = 0;

	//ASIT simulation
	vector<User> users;

	Aggregator agg;
	agg.Initialize(N);
	//Aggregator aggs[M]; // aggegators

	Verifier ver; // verifier
	ver.Initialize(N);

	//cin >> N;

	//vector<G1> sigs;
	vector<PM> pms(N);

	// generate secret key and public key
	for(int i=0;i<N;i++){
		User usr;
		usr.KeyGen(Q);
		usr.id = i;
		users.push_back(usr);
	}

	// set a map of (agg's ids_id, ver's ids_id)
	for(int i=0;i<N;i++) agg.ids.push_back(i);
	
	uset C;
	std::random_device rnd;
	map<int,int> mp;
	for(int i=0;i<min(N, d);i++){
		int t = rnd()%N;
		if(mp[t]==0) C.push_back(t);
		else i--;
		mp[t]++;
		//cout << t << ":" << mp[t] <<  " i : " << i << endl;
	}

	int R = 1;
	int R2 = 0;

	if(show_progress){
		cout << "C : ";
		for(int i=0;i<C.size();i++) cout << C[i] << " ";
		cout << endl;
	}
	
	double time = 0.0;
	double time2 = 0.0;
	double trace_time = 0.0;

	// Start AS-SW-1
	for(;C.size()>0;R++){
		if(R > (p-1)/2){
			cout << "Round exceeds allocation matrix!!" << endl;
			cout << "N : " << N << ", d : " << d << ", p : " << p << ", b : " << b << ", q : " << q << endl;
			return -1;
		}

		if(show_progress) cout << "[Round " << R << "]" << endl;


		// Reset agg
		agg.sigs.clear();
		agg.pms.clear();
		pms.clear();

		// choice of Traitors
		uset C2;
		for(int i=0;i<C.size();i++){
			if(rnd()%100 < invalid_percent) C2.push_back(C[i]);
		}
		if(C2.size()==0) R2--;

		//int t = rnd()%(C.size()); C2.push_back(C[t]);
		if(show_progress){
			cout << "  traitor : ";
			for(int i=0;i<C2.size();i++) cout << C2[i] << " ";
			cout << endl;
		}

		// Timer start
		st = get_time_sec();

		// User: sign		
		vector<thread> threads;
		for(int i=0; i<N; i++){
			string str = random_text(127)+to_string(i);
			threads.emplace_back(&User::Sign, &users[i], str);
		}
		for(std::thread &th : threads) th.join();

		//for(int i=0; i<N; i++) agg.sigs.push_back(users[i].sig); // Send to an aggregator
		
		// Send to aggergator
		for(int i=0; i<agg.ids.size(); i++){
			int id = agg.ids[i];
			agg.sigs[id] = users[id].sig;
		}

		// Traitor
		for(int i=0; i<C2.size(); i++){
			users[C2[i]].m = to_string(rnd()); // Tampering messages
		}


		// Send a set of (public key, message)
		for(int i=0; i<agg.ids.size(); i++){
			int id = agg.ids[i];
			PM pm = make_pair(users[id].pub_key, users[id].m);
			agg.pms[id] = pm;
			pms[id] = pm;
		}
		

		// Aggregator
		// agg.Agg(ver.f, agg.sigs);
		vector<thread> threads2;
		threads2.emplace_back(&Aggregator::Agg, &agg, ref(agg.P), ref(agg.sigs));
		for (std::thread &th : threads2) th.join();
		if(show_progress) {
			cout << "Aggregator sent ";
			view(agg.P);
		}

		int len = agg.agg_sigs.size();
		sig_len += len;

		// ASIT Verify and Trace
		//valid += ver.Trace(Q, agg.pms, agg.agg_sigs); // Router, Multi rt.aggs
		valid += ver.Trace(Q, pms, agg.agg_sigs);

		ed = get_time_sec();
		time += ed - st;
		trace_time += ed - st;

		// Traced Attacker
		if(ver.V.size()>0){
			if(show_progress){
				cout << "--- V : ";
				for(int i=0;i<ver.V.size();i++) cout << ver.V[i] << " ";
				cout << endl;
			}
			// Remove from Traitor set
			for(int i=0; i<ver.V.size(); i++){
				for(int j=0;j<C.size();j++){
					if(C[j]==ver.V[i]){
						C[j] = C.back();
						C.pop_back();
						break;
					}
				}
			}
		}
		agg.V = ver.V;

		if(C.size()==0) break; // end if traced all traiitors
	}
	// End AS-SW-1
	ed = get_time_sec();
	
	// Whole time of AS-SW-1
	cout << "ed - st : " << (ed - st)*1000 << " msec" << endl;
	R2 += R;

	time = ed - st; // Total time of a run of AS-SW-1
	time2 = time/R; //  per round
	trace_time /= R;
	if(show_progress){
		cout << "Time (AS-SW-1) : " << time << " sec" << endl;
		cout << "Time per round (AS-SW-1) : " << time2 << " sec" << endl;
		cout << "Trace Time per Round (AS-SW-1) : " << trace_time << " sec" << endl;
		cout << "R = " << R << endl;
		cout << "R2 = " << R2 << endl;
		printf("valid : %lld, rate : %lf\n", valid, (double)valid/(N*R));
		printf("sig length per round : %lf\n", (double)(sig_len)/R);
		//printf("valid2 : %lld, rate : %lf\n", valid2, (double)valid2/(N*R));
	}
	R_sum += R;
	R2_sum += R2;
	time_sum += time;
	time2_sum += time2;
	trace_time_sum += trace_time;
	valid_sum += valid;
	sig_len_sum += sig_len;

} // End loop

	cout << endl;
	cout << "N : " << N << ", d : " << d << ", p : " << p << ", b : " << b << ", q : " << q << endl;
	cout << "Invalid percent : " << invalid_percent << endl;
	cout << "Average Time (AS-SW-1) : " << time_sum / Loop << " sec" << endl;
	cout << "Average Time per round (AS-SW-1) : " << time2_sum / Loop << " sec" << endl;
	cout << "Average Trace Time per round (AS-SW-1) : " << trace_time_sum / Loop << " sec" << endl;
	cout << "Average R : " << (double) R_sum / Loop << endl;
	cout << "Average R2 : " << (double) R2_sum / Loop << endl;
	printf("Average valid rate : %lf\n", (double)valid_sum/(R_sum * N));
	printf("Average sig length per round : %lf\n", (double)sig_len_sum/R_sum);

	return 0;
}
