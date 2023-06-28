#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <map>
#include <iostream>
#include <chrono>
#include <mcl/bn256.hpp>

#include <fstream>
#include <iomanip>
#include "as-sw-1.h"

using namespace mcl::bn256;

int p; // prime number
int b; // the num of blocks
int q; // the N of marks

int N; // the num of sensors
int d; // the num of traitors

vector<int> prime;

bool show_progress = false;
int Loop = 2;

string getDatetimeStr() {
	time_t t = time(nullptr);
	const tm* localTime = localtime(&t);
	std::stringstream s;
	//s << localTime->tm_year + 1900;
	// setw(),setfill() to fill 0
	s << setw(2) << setfill('0') << localTime->tm_mon + 1;
	s << setw(2) << setfill('0') << localTime->tm_mday;
	s << setw(2) << setfill('0') << localTime->tm_hour;
	s << setw(2) << setfill('0') << localTime->tm_min;
	s << setw(2) << setfill('0') << localTime->tm_sec;
	return s.str();
}
 
int main() {
	ofstream writing_file;
	string filename = "sw1ser-"+getDatetimeStr()+".csv";
	writing_file.open(filename, std::ios::out);


	int sockfd;
	int client_sockfd;
	struct sockaddr_in addr;
 
	socklen_t len = sizeof( struct sockaddr_in );
	struct sockaddr_in from_addr;
 
	char buf[1024];
	memset( buf, 0, sizeof( buf ) );
 
	// ソケット生成
	if( ( sockfd = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 ) {
		perror( "socket" );
	}
 
	// 待ち受け用IP・ポート番号設定
	addr.sin_family = AF_INET;
	addr.sin_port = htons( 1235 );
	addr.sin_addr.s_addr = INADDR_ANY;
 
	// バインド
	if( ::bind( sockfd, (struct sockaddr *) &addr, sizeof( addr ) ) < 0 ) {
		perror( "bind" );
	}
 
	// 受信待ち
	if( listen( sockfd, SOMAXCONN ) < 0 ) {
		perror( "listen" );
	}
 
	// クライアントからのコネクト要求待ち
	if( ( client_sockfd = accept( sockfd, (struct sockaddr *)&from_addr, &len ) ) < 0 ) {
		perror( "accept" );
	}else{
		write( client_sockfd, "ACK\n", 4);
		cout << "[server] send ACK " << endl;
		// get N from aggregator
		if ( recv( client_sockfd, buf, sizeof( buf ), 0 ) > 0 ) {
			stringstream ss = stringstream(buf);
			string s; 
			getline(ss, s); N = atoi(s.c_str());
			cout << "[server] recv " << N << endl;
			getline(ss, s); d = atoi(s.c_str());
			cout << "[server] recv " << d << endl;
			write( client_sockfd, "ACK\n", 4);
			if(show_progress) cout << "[server] send ACK " << endl;
			
		}
		writing_file << N << endl;
		writing_file << d << endl;
		writing_file <<"sig_byte, trace_sec" << endl;
	}

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
	b = N/q; if(N%q != 0 || (b==0)) b++;
	//b = (p-1)/2;					//cannot trace this setting...
	//q = N/b; if(N%b != 0) q++;
	cout << "q : "<< q << ", b : "<< b << endl;
	writing_file << q << endl;
	writing_file << b << endl;

	Verifier ver;
	ver.Initialize(N);

	long long sig_len = 0;

	auto st = std::chrono::system_clock::now();
	auto trace_time = st - st;

int R=0;
bool traced = false;
auto system_st = std::chrono::system_clock::now();;
uset lastV; // last traced attacker set
long long total_sig_byte = 0;

for(; R<(p-1)/2; R++){
	// recieve pk, msg, sig
	vector<G2> pks;
	G2 pk;
	vector<string> msgs;
	string msg;
	vector<G1> sigs(N);
	G1 sig;
	G1 NONE; ::Hash(NONE, "NONE"); // set Hash "none"
	G1 agg_sig = NONE;
	vector<G1> asit_sig;
	
	int rsize; // recv size


	while( 1 ) {
		rsize = recv( client_sockfd, buf, sizeof( buf ), 0 );
		if(R == 0) system_st = std::chrono::system_clock::now(); // System Start Time

		if ( rsize == 0 ) {
			break;
		} else if ( rsize == -1 ) {
			perror( "recv" );
		} else {
			stringstream ss = stringstream(buf);
			string header;
			//ss >> header;
			getline(ss, header);
			if(show_progress) cout << "[server] receive : " << header << endl;

			if(header=="PK"){
				ss >> pk;
				pks.push_back(pk);
				//cout << "[server] receive pk: " << pk << endl;
			}else if(header=="MSG"){
				getline(ss, msg);
				msgs.push_back(msg);
				//cout << "[server] receive msg: \n" << msg << endl;
			}else if(header=="SIG"){
				ss >> sig;
				sigs.push_back(sig);
				//cout << "[server] receive sig: " << sig << endl;
			}else if(header=="PM"){
				ss >> pk;
				pks.push_back(pk);
				getline(ss, msg);
				msgs.push_back(msg);
				//cout << "[server] receive PK, MSG: " << pk << msg << endl;
			}else if(header=="AGGSIG"){
				ss >> agg_sig;
				//cout << "[server] receive agg_sig: " << agg_sig << endl;
				sig_len++;
			}else if(header=="ASITSIG"){
				G1 a_sig;
				vector<G1> agg_sigs;
				string s;
				if(show_progress) cout << "ss.length = " << ss.str().length() << endl;
				bool isend = false;
				long long sig_byte = 0;
				while(!isend){
					if(!getline(ss, s)){
						write( client_sockfd, "SEND\n", 5);
						memset( buf, 0, sizeof( buf ) );
						recv( client_sockfd, buf, sizeof( buf ), 0 );
						ss = stringstream(buf);
						continue;
					}
					if(s=="ENDASITSIG"){
						isend = true;
						break;
					}
					stringstream s2;
					s2 << s;
					int tmp = s2.str().length();
					s2 >> a_sig;
					agg_sigs.push_back(a_sig);
					if(a_sig != NONE){
						sig_len++;
						sig_byte += tmp;
					}
					//cout << "[server] receive asit_sig: " << a_sig << endl;
					//cout << "ss.length = " << ss.str().length() << endl;
				}
				asit_sig = agg_sigs;
				writing_file << sig_byte << ", ";
				total_sig_byte += sig_byte;
			}else if(header=="ENDTRACE"){
				traced = true;
			}else{
				cout << "error :header " << header << endl;
				break;
			}
			
			//sleep( 1 );
			// 応答
			//write( client_sockfd, buf, rsize );
			if(write( client_sockfd, "ACK\n", 4)>0){
				if(show_progress) cout << "[server] send ACK " << endl;
				memset( buf, 0, sizeof( buf ) );
				if((int)asit_sig.size() > 0) break;
			}
		}
	}

	if(traced){
		break;
	}
	// Verify
	vector<PM> pms;
	for(int i=0; i<N; i++){
		PM pm = make_pair(pks[i], msgs[i]);
		pms.push_back(pm);
	}
/*
	if(AggVerify(agg_sig, Q, pms)){
		cout << "AggVerify : OK" << endl;
	}else{
		cout << "AggVerify : NG" << endl;
	}

	Fp12 e1, e2;
	G1 Hm;
	pairing(e1, agg_sig, Q); // e1 = e(sign, Q)

	Hash(Hm, msgs[0]);
	pairing(e2, Hm, pks[0]); // e2 = e(Hm, sQ)
	for(int i=1;i<(int)pks.size();i++){
		Fp12 e;
		Hash(Hm, msgs[i]);
		pairing(e, Hm, pks[i]); // e2 = e(Hm, sQ)
		Fp12::mul(e2, e2, e);
	}

	if(e1==e2){
		cout << "AggVerify : OK" << endl;
	}else{
		cout << "AggVerify : NG" << endl;
	}
*/

	st = std::chrono::system_clock::now();
	// ASIT Trace
	ver.Trace(Q, pms, asit_sig);
	auto ed = std::chrono::system_clock::now();
	trace_time += ed-st;
	std::chrono::duration<double> sec = ed - st;
	double trace_sec = sec.count();
	writing_file << trace_sec << ", ";
	

	stringstream ss;
	//ss.str("");
	//ss << "FEEDBACK\n";
	//write( client_sockfd, ss.str().c_str(), ss.str().length());
	//cout << "sent " << ss.str().c_str() << endl;

	
	ss.str("");
	// No partition feedback
	// Send traced attackers if found
	if((int)lastV.size() < (int)ver.V.size()){
		write( client_sockfd, "FDBK\n", 5);
		if(show_progress) cout << "sent FDBK"<< endl;
		recv( client_sockfd, buf, sizeof( buf ), 0 );
		if(show_progress) cout << "[server] receive: " << buf << endl;

		cout << "--- traced : ";
		for(int i=(int)lastV.size(); i<(int)ver.V.size(); i++){
			if(ss.str().length() +to_string(ver.V[i]).length() > 1000){
				write( client_sockfd, ss.str().c_str(), ss.str().length());
				//cout << "sent " << ss.str().c_str() << endl;
				ss.str("");
				memset( buf, 0, sizeof( buf ) );
				recv( client_sockfd, buf, sizeof( buf ), 0 );
			}
			ss << ver.V[i] << " ";
			cout << ver.V[i] << " ";
		}
		ss << "EL\n";
		ss << "END\n";
		cout << endl;
	}else{
		ss << "NOTTRACED\n";
	}
	lastV = ver.V;
	if(ver.V.size()>0){
		if(show_progress){
			cout << "--- V : ";
			for(int i=0;i<ver.V.size();i++) cout << ver.V[i] << " ";
			cout << endl;
		}
	}
	
	write( client_sockfd, ss.str().c_str(), ss.str().length());
	//cout << "sent " << ss.str().c_str() << endl;
	memset( buf, 0, sizeof( buf ) );
	recv( client_sockfd, buf, sizeof( buf ), 0 );
	if(show_progress) cout << "[server] receive: " << buf << endl;

	cout << "[server] Round " << R << " end" << endl;
	//writing_file << "R " << R << " end" << endl;
	writing_file << endl;
}
	auto system_ed = std::chrono::system_clock::now();
	std::chrono::duration<double> sec = system_ed - system_st;
	double system_time = sec.count();

	cout << "N : " << N << ", d : " << d << ", p : " << p << ", b : " << b << ", q : " << q << endl;
	cout << "Total round : " << R << endl;
	cout << "Total sig num : " << sig_len << endl;
	cout << "Total sig byte : " << total_sig_byte << endl;
	trace_time /= R;
	cout << "Trace Time per round (AS-SW-1) : " << std::chrono::duration_cast<std::chrono::microseconds>(trace_time).count() << " microsec" << endl;
	cout << "Total time : " << system_time << " sec" << endl;

	writing_file << "N : " << N << ", d : " << d << ", p : " << p << ", b : " << b << ", q : " << q << endl;
	writing_file << "Total round : " << R << endl;
	writing_file << "Total sig num : " << sig_len << endl;
	writing_file << "Total sig byte : " << total_sig_byte << endl;
	writing_file << "Trace Time per round (AS-SW-1) : " << std::chrono::duration_cast<std::chrono::microseconds>(trace_time).count() << " microsec" << endl;
	writing_file << "Total time : " << system_time << " sec" << endl;

	writing_file.close();

	// ソケットクローズ
	close( client_sockfd );
	close( sockfd );

	return 0;
}