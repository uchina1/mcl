//my includes
#include <map>
#include <chrono>
#include <fstream>
#include <iomanip>
#include "aug-as-ft-2.h"

int N = 100;
int d = 1;
double invalid_rate = 0.1; // /((double)1.0*N); // 0.0 ~ 1.0

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
	const string filename2 = "aug-as-ft-2new-"+getDatetimeStr()+".csv";
	writing_file.open(filename2, std::ios::out);

	writing_file << N << ", " << d << ", " << invalid_rate << endl;
	writing_file << "Time, Round Time, R, R2, Agg0_MSG, Agg0_AS, Tr0_Result, Agg1_AS, Agg1_ASmax, Tr1_Index" << endl;


	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);

	double st = 0.0;
	auto ch_time_sum = 0.0;
	auto ch_time2_sum = 0.0;
	auto ch_trace_sum = 0.0;
	auto ch_trace2_sum = 0.0;
	
	long long R_sum = 0;
	long long R2_sum = 0;

	long long valid_sum = 0;
	long long sig_len_sum = 0;
	long long part_size_sum = 0;
	double Agg0_AS_sum = 0;
	double Agg0_MSG_sum = 0;
	double Tr0_Result_sum = 0;
	double Agg1_AS_sum = 0;
	double Agg1_ASmax_sum = 0;
	double Tr1_Index_sum = 0;
	

for(int loop=0;loop<Loop;loop++){
	long long valid = 0;
	long long sig_len = 0;
	long long part_size = 0;
	double Agg0_AS = 0;
	double Agg0_MSG = 0;
	double Tr0_Result = 0;
	double Agg1_AS = 0;
	double Agg1_ASmax = 0;
	double Tr1_Index = 0;

	//ASIT simulation
	vector<User> users;
	Aggregator agg;
	Verifier ver;

	int num = N;
	//cin >> num;

	vector<G1> sigs;
	vector<string> msgs;

	// generate secret key and public key
	for(int i=0;i<num;i++){
		User usr;
		usr.KeyGen(Q);
		users.push_back(usr);
	}

	// Init agg, ver
	vector<G2> pks;
	for(int i=0;i<num;i++){
		pks.push_back(users[i].pub_key);
	}
	agg.Init(pks);
	ver.Init(pks);

	// Agg recieved init feedback
	agg.f = ver.f;
	agg.alpha = agg.f.alpha;
	agg.P = agg.f.P;
	agg.V = agg.f.V;

	// Select d attackers
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
		for(int i=0;i<(int)C.size();i++) cout << C[i] << " ";
		cout << endl;
	}
	//*/	
	auto ch_time = 0.0;
	auto ch_time2 = 0.0;
	auto ch_trace = 0.0;
	auto ch_trace2 = 0.0;

	// Start tracing
	for(;C.size()>0;R++){
		if(show_progress) cout << "[Round " << R << ", (R2=" << (R2+R) << ")]" << endl;

		// Clear memory
		stringstream ss;
		ss.str("");
		sigs.clear();
		msgs.clear();

		// choice of Traitors
		uset C2;
		std::mt19937 mt{ std::random_device{}() };
		std::uniform_real_distribution<double> dist(0.0, 1.0);
		for(int i=0;i<(int)C.size();i++){
			if(dist(mt) < invalid_rate) C2.push_back(C[i]);
		}
		if(C2.size()==0) R2--;

		//int t = rnd()%(C.size()); C2.push_back(C[t]);
		if(show_progress){
			cout << "  traitor : ";
			for(int i=0;i<(int)C2.size();i++) cout << C2[i] << " ";
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
		}

		// Traitor
		for(int i=0; i<(int)C2.size(); i++){
			//users[C2[i]].m = to_string(rnd()); // Tampering messages
			users[C2[i]].m = random_text(128);
		}

		// Send a set of (public key, message)
		for(int i=0; i<num; i++){
			msgs.push_back(users[i].m);
		}
		// Aggregator
		// Agg0
		agg.Agg0(agg.f, sigs);

		auto ed = get_time_sec();
		ch_time += ed-st;

		ss.str("");
		for(int i=0; i<num; i++){
			ss << users[i].m;
		}
		Agg0_MSG += ss.str().length();
		ss.str("");
		ss << agg.agg_all_sigs;
		Agg0_AS += ss.str().length();

		// ASIT Verify and Trace
		st = get_time_sec();
		
		// Trace0
		valid += ver.Trace0(Q, msgs, agg.agg_all_sigs);
		sig_len += 1;

		ed = get_time_sec();
		ch_time += ed - st;
		ch_trace += ed - st;

		// Trace0 byte size
		ss.str("");
		ss << ver.v;
		Tr0_Result += ss.str().length();

		// Trace1
		st = get_time_sec();
		bool all_valid = agg.Agg1(agg.f, ver.v);		
		ed = get_time_sec();
		ch_time += ed - st;

		if(!all_valid){
			if(show_progress){
				cout << "Move to Trace1" << endl;
			}
			sig_len += agg.agg_sigs.size();
			part_size += ver.beta.second.size();
			
			// Agg1 byte size
			ss.str("");
			for(int i=0;i<(int)agg.agg_sigs.size();i++){
				ss << agg.agg_sigs[i];
			}
			Agg1_AS += ss.str().length();
			if(Agg1_ASmax < ss.str().length()) Agg1_ASmax = ss.str().length();

			// Trace1
			st = get_time_sec();			
			valid += ver.Trace1(Q, msgs, agg.agg_sigs);
			ed = get_time_sec();
			ch_time += ed - st;
			ch_trace2 += ed - st;
			ss.str("");
			ss << ver.invalid_id;
			Tr1_Index += ss.str().length();

			// Divide
			agg.Divide(ver.invalid_id);
		}
		//valid += ver.Trace(Q, pms, agg.agg_sigs);
		ed = get_time_sec();
		ch_time += ed - st;
		ch_trace2 += ed - st;
		


		// Traced Attacker
		if(ver.V.size()>0){
			if(show_progress){
				cout << "--- V : ";
				for(int i=0;i<(int)ver.V.size();i++) cout << ver.V[i] << " ";
				cout << endl;
			}
			// Remove from Traitor set
			for(int i=0;i<(int)C.size();i++){
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

	ch_time2 = ch_time/R;
	ch_trace /= R;
	ch_trace2 /= R;
	
	Agg0_MSG /= R;
	Agg0_AS /= R;
	Tr0_Result /= R;
	Agg1_AS /= R;
	Tr1_Index /= R;
	
	if(show_lap){
		cout << "Time (AUG-AS-FT-2) : " << ch_time << " sec" << endl;
		cout << "Time per Round (AUG-AS-FT-2) : " << ch_time2 << " sec" << endl;
		cout << "R = " << R << endl;
		cout << "R2 = " << R2 << endl;
		printf("Agg0_MSG %.2lf, Agg0_AS %.2lf, Tr0_Result %.2lf, Agg1_AS %.2lf, Agg1_ASmax %.2lf, Tr1_Index %.2lf\n",Agg0_MSG, Agg0_AS, Tr0_Result, Agg1_AS, Agg1_ASmax, Tr1_Index);
		//printf("valid2 : %lld, rate : %.2lf\n", valid2, (double)valid2/(N*R));
	}
	if(file_output){
	writing_file << ch_time << ", " << ch_time2 << ", " << R << ", " <<  R2 << ", " << Agg0_MSG << ", " << Agg0_AS << ", " << Tr0_Result << ", " << Agg1_AS << ", " << Agg1_ASmax << ", "<< Tr1_Index << endl;
	}
	R_sum += R;
	R2_sum += R2;
	ch_time_sum += ch_time;
	ch_time2_sum +=ch_time2;
	ch_trace_sum += ch_trace;
	ch_trace2_sum += ch_trace2;
	valid_sum += valid;
	sig_len_sum += sig_len;
	part_size_sum += part_size;
	Agg0_AS_sum += Agg0_AS;
	Agg0_MSG_sum += Agg0_MSG;
	Tr0_Result_sum += Tr0_Result;
	Agg1_AS_sum += Agg1_AS;
	Agg1_ASmax_sum += Agg1_ASmax;
	Tr1_Index_sum += Tr1_Index_sum;
	
	cout << "* " << loop << endl;
}

	cout << endl;
	cout << "Invalid rate : " << invalid_rate << endl;
	cout << "Average Time (AUG-AS-FT-2) : " << ch_time_sum / Loop << " sec" << endl;
	cout << "Average Time per round (AUG-AS-FT-2) : " << ch_time2_sum / Loop << " sec" << endl;
	cout << "Average R : " << (double) R_sum / Loop << endl;
	cout << "Average R2 : " << (double) R2_sum / Loop << endl;
	printf("Agg0_MSG %.2lf, Agg0_AS %.2lf, Tr0_Result %.2lf, Agg1_AS %.2lf, Agg1_ASmax %.2lf, Tr1_Index %.2lf\n",Agg0_MSG_sum/Loop, Agg0_AS_sum/Loop, Tr0_Result_sum/Loop, Agg1_AS_sum/Loop, Agg1_ASmax_sum/Loop, Tr1_Index_sum/Loop);
	//printf("Total sent bytes : %lld\n", sent_byte_sum);

	writing_file.close();
	if(!file_output){
		remove(filename2.c_str());
	}

	return 0;
}