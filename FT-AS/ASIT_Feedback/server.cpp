#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <iostream>
#include <chrono>
#include <mcl/bn256.hpp>

#include <fstream>
#include <iomanip>
#include "as-ft-2.h"

using namespace mcl::bn256;

int N;
bool show_progress = false;

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
	//s << setw(2) << setfill('0') << localTime->tm_sec;
	return s.str();
}
 
int main() {
	ofstream writing_file;
	string filename = "ft2ser-"+getDatetimeStr()+".csv";
	writing_file.open(filename, std::ios::out);



	int sockfd;
	int client_sockfd;
	struct sockaddr_in addr;
 
	socklen_t len = sizeof( struct sockaddr_in );
	struct sockaddr_in from_addr;
 
	char buf[1024];
 
	// 受信バッファ初期化
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
			string s; getline(ss, s);
			N = atoi(s.c_str());
			cout << "[server] recv " << N << endl;
			writing_file << N << endl;
			writing_file << "sig_byte" << endl;
			write( client_sockfd, "ACK\n", 4);
			if(show_progress) cout << "[server] send ACK " << endl;
		}
	}

	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);

	Verifier ver;

	long long sig_len = 0;
	long long total_sig_byte = 0;
	auto st = std::chrono::system_clock::now();
	auto trace_time = st - st;

int R = 0;
bool traced = false;
auto system_st = std::chrono::system_clock::now();

for(; R<N*((int)log2(N)+1); R++){
	// recieve pk, msg, sig
	vector<G2> pks;
	G2 pk;
	vector<string> msgs;
	string msg;
	vector<G1> sigs;
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
					sig_byte += s2.str().length();
					s2 >> a_sig;
					agg_sigs.push_back(a_sig);
					//cout << "[server] receive asit_sig: " << a_sig << endl;
					//cout << "ss.length = " << ss.str().length() << endl;
					sig_len++;
				}
				asit_sig = agg_sigs;
				writing_file << sig_byte << endl;
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

	st = std::chrono::system_clock::now();
	// ASIT Trace
	ver.Trace(Q, pms, asit_sig);
	auto ed = std::chrono::system_clock::now();
	trace_time += ed-st;

	stringstream ss;

	write( client_sockfd, "FDBK\n", 5);
	if(show_progress) cout << "sent FDBK"<< endl;
	ss.str("");
	recv( client_sockfd, buf, sizeof( buf ), 0 );
	if(show_progress) cout << "[server] receive: " << buf << endl;
	for(int i=0; i<(int)ver.f.size(); i++){
		for(int j=0; j<(int) ver.f[i].size(); j++){
			if(ss.str().length() +to_string(ver.f[i][j]).length() > 485){
				write( client_sockfd, ss.str().c_str(), ss.str().length());
				//cout << "sent " << ss.str().c_str() << endl;
				ss.str("");
				memset( buf, 0, sizeof( buf ) );
				recv( client_sockfd, buf, sizeof( buf ), 0 );
			}
			ss << ver.f[i][j] << " ";
		}
		ss << "EL\n"; // End Line
	}
	ss << "END\n";
	write( client_sockfd, ss.str().c_str(), ss.str().length());
	//cout << "sent " << ss.str().c_str() << endl;
	memset( buf, 0, sizeof( buf ) );
	recv( client_sockfd, buf, sizeof( buf ), 0 );
	if(show_progress) cout << "[server] receive: " << buf << endl;

	cout << "[server] Round " << R << " end" << endl;
	//writing_file << "R " << R << " end" << endl;
}
	auto system_ed = std::chrono::system_clock::now();
	std::chrono::duration<double> sec = system_ed - system_st;
	double system_time = sec.count();

	cout << "Total round : " << R << endl;
	cout << "Total sig num : " << sig_len << endl;
	cout << "Total sig byte : " << total_sig_byte << endl;
	trace_time /= R;
	cout << "Trace Time per round (AS-FT-2) : " << std::chrono::duration_cast<std::chrono::microseconds>(trace_time).count() << " microsec" << endl;
	cout << "Total time : " << system_time << " sec" << endl;

	writing_file << "Total round : " << R << endl;
	writing_file << "Total sig num : " << sig_len << endl;
	writing_file << "Total sig byte : " << total_sig_byte << endl;
	writing_file << "Trace Time per round (AS-FT-2) : " << std::chrono::duration_cast<std::chrono::microseconds>(trace_time).count() << " microsec" << endl;
	writing_file << "Total time : " << system_time << " sec" << endl;

	writing_file.close();

	// ソケットクローズ
	close( client_sockfd );
	close( sockfd );

	return 0;
}