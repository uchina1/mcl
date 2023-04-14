#include <mcl/bn256.hpp>

//includes
#include <map>
#include <time.h>
#include <chrono>
#include <fstream>
#include <iomanip>
#include "as-ft-2.h"

int N = 100;
int d = 10;
double invalid_rate = 1; // / ((double)1*N); // 0.0 ~ 1.0

bool show_progress = true; 
bool show_lap = true;
bool file_output = false;

int Loop = 1;

string getDatetimeStr() {
    time_t t = time(nullptr);
    const tm* localTime = localtime(&t);
    std::stringstream s;
    s << localTime->tm_year + 1900;
    // setw(),setfill() to fill 0
    s << setw(2) << setfill('0') << localTime->tm_mon + 1;
    s << setw(2) << setfill('0') << localTime->tm_mday;
    s << setw(2) << setfill('0') << localTime->tm_hour;
    s << setw(2) << setfill('0') << localTime->tm_min;
    //s << setw(2) << setfill('0') << localTime->tm_sec;
    return s.str();
}

using namespace std::chrono;
inline double get_time_sec(void){
    return static_cast<double>(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count())/1000000000;
}


int main(int argc, char *argv[])
{
	string m = argc == 1 ? "hello mcl" : argv[1];

	ofstream writing_file;
	string filename = "as-ft-2-"+getDatetimeStr()+".csv";
	writing_file.open(filename, std::ios::out);

	writing_file << N << ", " << d << ", " << invalid_rate << endl;
	writing_file << "Time, Round Time, R, R2, Agg_PK, Agg_MSG, Agg_AS, Agg_ASmax, Tr_fdbk" << endl;

	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);


	double st = 0;
	auto ch_time_sum = 0.0;
	auto ch_time2_sum = 0.0;
	auto ch_trace_sum = 0.0;
	
	
	long long R_sum = 0;
	long long R2_sum = 0;

	long long valid_sum = 0;
	//long long valid2_sum = 0;
	long long sig_len_sum = 0;
	long long part_size_sum = 0;
	
	double Agg_AS_sum = 0;
	double Agg_ASmax_sum = 0;
	double Agg_MSG_sum = 0;
	double Agg_PK_sum = 0;
	double Tr_fdbk_sum = 0;

	for(int loop=0;loop<Loop;loop++){
	long long valid = 0;
	//long long valid2 = 0;
	long long sig_len = 0;
	long long part_size = 0;
	
	double Agg_AS = 0;
	double Agg_ASmax = 0;
	double Agg_MSG = 0;
	double Agg_PK = 0;
	double Tr_fdbk = 0;

	//ASIT simulation
	vector<User> users;
	Aggregator agg;
	Verifier ver;

	int num = N;
	//cin >> num;

	vector<G1> sigs;
	vector<PM> pms;

	// generate secret key and public key
	for(int i=0;i<num;i++){
		User usr;
		usr.KeyGen(Q);
		users.push_back(usr);
	}


	uset C;
	std::random_device rnd;
	map<int,int> mp;
	for(int i=0;i<min(num, d);i++){
		int t = rnd()%num;
		if(mp[t]==0) C.push_back(t);
		else i--;
		mp[t]++;
		//cout << t << ":" << mp[t] <<  " i : " << i << endl;
	}

	int R = 1;
	int R2 = 0;

	//*
	if(show_progress){
		cout << "C : ";
		for(int i=0;i<C.size();i++) cout << C[i] << " ";
		cout << endl;
	}
	//*/

	auto ch_time = 0.0;
	auto ch_time2 = 0.0;
	auto ch_trace = 0.0;

	for(;C.size()>0;R++){
		if(show_progress) cout << "[Round " << R << ", (R2=" << (R2+R) << ")]" << endl;
		// Clear memory
		stringstream ss;
		ss.str("");
		sigs.clear();
		pms.clear();

		// choice of Traitors
		uset C2;
		std::mt19937 mt{ std::random_device{}() };
		std::uniform_real_distribution<double> dist(0.0, 1.0);
		for(int i=0;i<C.size();i++){
			if(dist(mt) < invalid_rate) C2.push_back(C[i]);
		}
		if(C2.size()==0) R2--;

		//int t = rnd()%(C.size()); C2.push_back(C[t]);
		if(show_progress){
			cout << "  traitor : ";
			for(int i=0;i<C2.size();i++) cout << C2[i] << " ";
			cout << endl;
		}

		//st = std::chrono::system_clock::now();
		st = get_time_sec();

		// User: sign
		vector<thread> threads;
			for(int i=0; i<num; i++){
			string random_m = random_text(128-to_string(i+1).length());
			users[i].m = random_m+to_string(i+1);
			G1 Hm;
			Hash(Hm, users[i].m);
			threads.emplace_back(&User::Sign, &users[i], Hm);
		}
		for(std::thread &th : threads) th.join();
		
		for(int i=0; i<num; i++){			
			sigs.push_back(users[i].sig);
			//pms.push_back(make_pair(users[i].pub_key, users[i].m));
		}

		// Traitor
		for(int i=0; i<C2.size(); i++){
			users[C2[i]].m = random_text(128); // Tampering messages
		}

		// Send a set of (public key, message)
		for(int i=0; i<num; i++){
			pms.push_back(make_pair(users[i].pub_key, users[i].m));
		}

		// Aggregator
		agg.Agg(ver.f, sigs);
		//cout << (AggVerify(agg.agg_sigs[0], Q, pms) ? "ok" : "ng") << endl;
		sig_len += agg.agg_sigs.size();

		//auto ed = std::chrono::system_clock::now();
		auto ed = get_time_sec();

		ch_time += ed-st;

		ss.str("");
		for(int i=0; i<num; i++){
			ss << users[i].m;
		}
		Agg_MSG += ss.str().length();
		ss.str("");
		for(int i=0; i<num; i++){
			ss << users[i].pub_key;
		}
		Agg_PK += ss.str().length();
		ss.str("");
		for(int i=0; i<(int)agg.agg_sigs.size(); i++){
			ss << agg.agg_sigs[i];
		}
		Agg_AS += ss.str().length();
		if(Agg_ASmax < ss.str().length()) Agg_ASmax = ss.str().length();
		
		// ASIT Verify and Trace
		st = get_time_sec();

		valid += ver.Trace(Q, pms, agg.agg_sigs);
		
		ed = get_time_sec();
		ch_time += ed - st;
		ch_trace += ed - st;
		part_size += ver.f.size();
		ss.str("");
		for(int i=0; i<ver.f.size(); i++){
			for(int j=0; j<ver.f[i].size(); j++){
				ss << ver.f[i][j] << " ";;
			}
			ss << endl;
		}
		Tr_fdbk += ss.str().length();

		// Individual Verify
		/*
		for(int i=0;i<sigs.size();i++) Verify(users[i].sig, Q, users[i].pub_key, users[i].m);
		*/

		// Traced Attacker
		if(ver.V.size()>0){
			if(show_progress){
				cout << "--- V : ";
				for(int i=0;i<ver.V.size();i++) cout << ver.V[i] << " ";
				cout << endl;
			}
			// Remove from Traitor set
			for(int i=0;i<C.size();i++){
				if(C[i]==ver.V[0]){
					C[i] = C.back();
					C.pop_back();
					break;
				}
			}
		}

		if(C.size()==0) break;
	}
	R2 += R;

	ch_time2 = ch_time /R;  
	ch_trace /= R;
	
	Agg_PK /= R;
	Agg_MSG /= R;
	Agg_AS /= R;
	Tr_fdbk /= R;
	
	if(show_lap){
		cout << "Time (AS-FT-2) : " << ch_time << " sec" << endl;
		cout << "Time per Round (AS-FT-2) : " << ch_time2 << " sec" << endl;
		cout << "R = " << R << endl;
		cout << "R2 = " << R2 << endl;
		printf("Agg_PK %.2lf, Agg_MSG %.2lf, Agg_AS %.2lf, Agg_ASmax %.2lf, Tr_fdbk %.2lf\n", Agg_PK, Agg_MSG, Agg_AS, Agg_ASmax, Tr_fdbk);
		//printf("sig length per round : %lf\n", (double)(sig_len)/R);
		//printf("valid2 : %lld, rate : %lf\n", valid2, (double)valid2/(N*R));
	}
	writing_file << ch_time << ", " << ch_time2 << ", " << R << ", " <<  R2 << ", " << Agg_PK << ", " << Agg_MSG << ", " << Agg_AS << ", " << Agg_ASmax << ", " << Tr_fdbk << endl;

	R_sum += R;
	R2_sum += R2;

	ch_time_sum += ch_time;
	ch_time2_sum += ch_time2;
	ch_trace_sum += ch_trace;
	valid_sum += valid;
	//valid2_sum += valid2;
	sig_len_sum += sig_len;
	part_size_sum += part_size;

	Agg_PK_sum += Agg_PK;
	Agg_MSG_sum += Agg_MSG;
	Agg_AS_sum += Agg_AS;
	Agg_ASmax_sum += Agg_ASmax;
	Tr_fdbk_sum += Tr_fdbk;

	cout << "Loop " << loop << " end"<< endl;
	}

	cout << endl;
	cout << "Invalid rate : " << invalid_rate << endl;
	cout << "Average Time (AS-FT-2) : " << ch_time_sum / Loop << " sec" << endl;
	cout << "Average Time per round (AS-FT-2) : " << ch_time2_sum / Loop << " sec" << endl;
	cout << "Average R : " << (double) R_sum / Loop << endl;
	cout << "Average R2 : " << (double) R2_sum / Loop << endl;
	printf("Agg_PK %.2lf, Agg_MSG %.2lf, Agg_AS %.2lf, Agg_ASmax %.2lf, Tr_fdbk %.2lf\n", Agg_PK_sum/Loop, Agg_MSG_sum/Loop, Agg_AS_sum/Loop, Agg_ASmax_sum/Loop, Tr_fdbk_sum/Loop);

	writing_file.close();
	if(!file_output){
		remove(filename.c_str());
	}

	return 0;
}
