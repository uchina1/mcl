#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
#include <map>
#include <chrono>
#include <cmath>

#include <fstream>
#include <iomanip>

#include <mcl/bn256.hpp>

#include "as-sw-1.h"

using namespace mcl::bn256;

int p; // prime number
int b; // the num of blocks
int q; // the N of marks

int N; // the num of sensors
int d; // the num of traitors

vector<int> prime;

bool show_progress = false;

int attacker;

string getDatetimeStr() {
	time_t t = time(nullptr);
	const tm* localTime = localtime(&t);
	std::stringstream s;
	// s << localTime->tm_year + 1900;
	// setw(),setfill() to fill 0
	s << setw(2) << setfill('0') << localTime->tm_mon + 1;
	s << setw(2) << setfill('0') << localTime->tm_mday;
	s << setw(2) << setfill('0') << localTime->tm_hour;
	s << setw(2) << setfill('0') << localTime->tm_min;
	//s << setw(2) << setfill('0') << localTime->tm_sec;
	return s.str();
}
 
int main(int argc, char *argv[]) {
	if(argc != 3 && argc != 4){
		printf("usage : ./bin/aggregator2.exe [signer] [attacker] (ip)\n");
		return -1;
	}else{
		N = atoi(argv[1])+atoi(argv[2]);
		attacker = atoi(argv[2]);
		d = attacker;
	}

	ofstream writing_file;
	string filename = "sw1agg"+getDatetimeStr()+".csv";
	writing_file.open(filename, std::ios::out);

	int sockfd;
	int client_sockfd;
	int fd2[10000];
	int cnt;
	struct sockaddr_in addr;
 
	socklen_t len = sizeof( struct sockaddr_in );
	struct sockaddr_in from_addr;

	int to_sockfd;
	struct sockaddr_in to_addr;
 
	char buf[1024];
	char receive_str[1024];
 
	// 受信バッファ初期化
	memset( buf, 0, sizeof( buf ) );
	memset( receive_str, 0, sizeof( receive_str ) );
 
	// ソケット生成
	if( ( sockfd = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 ) {
		perror( "socket" );
	}

	 for ( int i = 0; i < sizeof(fd2)/sizeof(fd2[0]); i++ ){
		fd2[i] = -1;
	}
 
	// 待ち受け用IP・ポート番号設定
	addr.sin_family = AF_INET;
	addr.sin_port = htons( 1234 );
	addr.sin_addr.s_addr = INADDR_ANY;
 
	// バインド
	if( ::bind( sockfd, (struct sockaddr *) &addr, sizeof( addr ) ) < 0 ) {
		perror( "bind" );
	}
 
	// 受信待ち
	if( listen( sockfd, SOMAXCONN ) < 0 ) {
		perror( "listen" );
	}

	// ソケット生成
	if( (to_sockfd = socket( AF_INET, SOCK_STREAM, 0) ) < 0 ) {
		perror( "socket" );
	}

	// 送信先アドレス・ポート番号設定
	to_addr.sin_family = AF_INET;
	to_addr.sin_port = htons( 1235 );
	to_addr.sin_addr.s_addr = inet_addr( "127.0.0.1" );
	if(argc == 4){
		to_addr.sin_addr.s_addr = inet_addr(argv[3]);
	}

	// サーバ接続
	if(connect( to_sockfd, (struct sockaddr *)&to_addr, sizeof( struct sockaddr_in ) ) < 0){
		perror("connect");
	}else{
		memset( buf, 0, sizeof( buf ) );
		cnt = recv( to_sockfd, buf, sizeof(buf), 0 );
		// cout << "cnt " << cnt << endl;
		if(cnt > 0){
			cout <<  "Server Connected\n" << buf;
			stringstream ss;
			ss.str(""); ss << N << "\n" << d << "\n";
			//usleep(100*1000);
			if( send(to_sockfd, ss.str().c_str(), ss.str().length(), 0 ) > 0 ) {
				if(show_progress) cout << "sent " << ss.str().c_str() << endl;
				memset( buf, 0, sizeof( buf ) );
				recv( to_sockfd, buf, sizeof(buf), 0 );
				if(show_progress) cout << "[agg] receive: " << buf << endl;
			}
			writing_file << N << endl;
			writing_file << d << endl;
		}else{
			cout <<  "Server not sent\n";
		}
	}
	
	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);
	G1 NONE; ::Hash(NONE, "NONE");

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

	Aggregator agg;
	agg.Initialize(N);

	// set a map of (agg's ids_id, ver's ids_id)
	for(int i=0;i<N;i++) agg.ids.push_back(i);

	part f;
	int num = 0;


	long long sig_len = 0;

	auto st = std::chrono::system_clock::now();
	auto feedback_time = st - st;

int R=0;
vector<int> ids(N);
for(int i=0;i<N;i++) ids[i] = i;
std::random_device get_rand_dev;
std::mt19937 get_rand_mt( get_rand_dev() ); 
shuffle( ids.begin(), ids.end(), get_rand_mt ); // shuffle id set

for(; R<(p-1)/2; R++){
	if(attacker==0 && R==10){
		stringstream ss;
		ss.str("");
		ss << "ENDTRACE\n";
		if( send(to_sockfd, ss.str().c_str(), ss.str().length(), 0 ) < 0 ) {
				perror( "send" );
		} else {
			cout << "sent " << ss.str().c_str() << endl;
			memset( receive_str, 0, sizeof( receive_str ) );
			recv( to_sockfd, receive_str, sizeof(receive_str), 0 );
			if(show_progress) cout << "[agg] receive: " << receive_str << endl;
		}
		cout << "NO attacker in 10 rounds!!" << endl;
		break;
	}
	
	vector<G2> pks(N);
	G2 pk;
	vector<string> msgs(N);
	string msg;
	vector<G1> sigs(N);
	G1 sig;
	vector<bool> is_recv(N,false);

	// Reset agg
	agg.sigs.clear();
	agg.pms.clear();

	int maxfd;		  // ディスクリプタの最大値
	fd_set rfds;		   // 接続待ち、受信待ちをするディスクリプタの集合
	struct timeval  tv;	 // タイムアウト時間
	
	// 受信
	int rsize;

	stringstream ss;

	while( 1 ) {
		// 接続待ちのディスクリプタをディスクリプタ集合に設定する
		FD_ZERO( &rfds );
		FD_SET( sockfd, &rfds );
		maxfd = sockfd;

		// 受信待ちのディスクリプタをディスクリプタ集合に設定する
		for ( int i = 0; i < sizeof(fd2)/sizeof(fd2[0]); i++ ){
			if ( fd2[i] != -1 ){
				FD_SET( fd2[i], &rfds );
				if ( fd2[i] > maxfd ) maxfd = fd2[i];
			}
		}
		// タイムアウト時間を10sec+500000μsec に指定する。
		tv.tv_sec = 10;
		tv.tv_usec = 500000;

		// 接続＆受信を待ち受ける
		cnt = select( maxfd+1, &rfds, NULL, NULL, &tv );
		if ( cnt < 0 ){
			// シグナル受信によるselect終了の場合、再度待ち受けに戻る
			if ( errno == EINTR ) continue;
				// パケット送受信用ソケットクローズ
				for (int i=0; i<sizeof(fd2)/sizeof(fd2[0]);i++){
					close(fd2[i]);
				}
				return 0;
		} else if ( cnt == 0 ) {
			// タイムアウトした場合、再度待ち受けに戻る
			continue;
		} else {
			// 接続待ちディスクリプタに接続があったかを調べる
			if ( FD_ISSET( sockfd, &rfds )){
				// 接続されたならクライアントからの接続を確立する
				for ( int i = 0; i < sizeof(fd2)/sizeof(fd2[0]); i++ ){
					if ( fd2[i] == -1 ){
						if (( fd2[i] = accept(sockfd, (struct sockaddr *)&from_addr, &len )) < 0 ) {
							// パケット送受信用ソケットクローズ
							for (int i=0; i<sizeof(fd2)/sizeof(fd2[0]);i++){
								close(fd2[i]);
							}
							return 0;
						}
						fprintf( stdout, "socket:%d  connected. \n", fd2[i] );
						break;
					}
				}
			}
			for ( int i = 0; i < sizeof(fd2)/sizeof(fd2[0]); i++ ){
				if(fd2[i] == -1) continue; // check fd2[i]

				// 受信待ちディスクリプタにデータがあるかを調べる
				if ( FD_ISSET( fd2[i], &rfds )){
					// データがあるならパケット受信する
					cnt = recv( fd2[i], buf, sizeof(buf), 0 );
					if ( cnt > 0 ) { // Success received
						if(show_progress) cout << "receive!! " << cnt << endl;
						stringstream ss = stringstream(buf);
						string header;
						//ss >> header;
						getline(ss, header);
						if(show_progress) cout << header << endl;
						if(header=="HELO"){
							if(show_progress) cout << "[agg] NEW client CONNECT : " << fd2[i] << endl;
							string client_num;
							getline(ss, client_num);
							string s = to_string(num);
							write(fd2[i], s.c_str(), s.length());
							//write(fd2[i], "Agg connected!\n", 15);
							num += stoi(client_num);
							continue;
						}
						string id_str;
						//ss >> header;
						getline(ss, id_str);
						int recv_cli_id = ids[stoi(id_str)];
						if(header=="PK"){
							//recv( client_sockfd, buf2, sizeof( buf2 ), 0 );
							//stringstream ss2 = stringstream(buf2);
							//cout << ss2.str() << endl;
							ss >> pk;
							pks[recv_cli_id] = pk;
							//pks.push_back(pk);
							// cout << "[server] receive pk: " << pk << endl;
							if(show_progress) cout << "[agg] receive pk of user" << recv_cli_id  << " from " << fd2[i] << endl;
						}else if(header=="MSG"){
							getline(ss, msg);
							msgs[recv_cli_id] = msg;
							//msgs.push_back(msg);
							//cout << "[server] receive msg: \n" << msg << endl;
							if(show_progress) cout << "[agg] receive msg of user" << recv_cli_id  << " from " << fd2[i] << endl;
						}else if(header=="SIG"){
							//recv( client_sockfd, buf2, sizeof( buf2 ), 0 );
							//stringstream ss2 = stringstream(buf2);
							//cout << ss2.str() << endl;
							ss >> sig;
							sigs[recv_cli_id] = sig;
							//sigs.push_back(sig);
							//cout << "[server] receive sig: " << sig << endl;
							if(show_progress) cout << "[agg] receive sig of user" << recv_cli_id  << " from " << fd2[i] << endl;
							is_recv[recv_cli_id] = true;
						}else if(header=="PMS"){
							ss >> pk;
							pks[recv_cli_id] = pk;
							getline(ss, msg);
							msgs[recv_cli_id] = msg;
							ss >> sig;
							sigs[recv_cli_id] = sig;
							if(show_progress) cout << "[agg] receive PK MSG SIG of user" << recv_cli_id  << " from " << fd2[i] << endl;
							is_recv[recv_cli_id] = true;
						}else{
							cout << "header error "<< header << " " << fd2[i] << endl;
						}
						//sleep( 1 );
						// 応答
						if(show_progress) cout << "[agg] send ACK to client " << fd2[i] << endl;
						write(fd2[i], "ACK\n", 4);
		   			} else if ( cnt == 0 ) {
			 			// 切断された場合、クローズする
			 			fprintf( stdout, "socket:%d  disconnected. \n", fd2[i] );
						close( fd2[i] );
						fd2[i] = -1;
				 	} else {
						// パケット送受信用ソケットクローズ
						for (int i=0; i<sizeof(fd2)/sizeof(fd2[0]);i++){
							close(fd2[i]);
						}
						return 0;
				 	}
				}
			}
	   	}
		memset( buf, 0, sizeof( buf ) );

		bool isallrecv = true;
		for(int tmp=0; tmp<N; tmp++) if(!is_recv[tmp]) isallrecv = false;
		if(isallrecv) break;
	}

	// Send to aggergator
	for(int i=0; i<agg.ids.size(); i++){
		int id = agg.ids[i];
		agg.sigs[id] = sigs[id];
		PM pm = make_pair(pks[id], msgs[id]);
		agg.pms[id] = pm;
	}

 
	// Normal Aggregate 
	if(show_progress) cout << "[agg] Aggregate " << endl;
/*
	G1 agg_sig = sigs[0];
	for(int i=1;i<(int)sigs.size();i++){
		G1::add(agg_sig, agg_sig, sigs[i]);
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
		cout << "OK" << endl;
	}else{
		cout << "NG" << endl;
	}
*/
	// ASIT Agg
	cout << "Agg "; view(agg.P); //view(f);
	agg.Agg(agg.P, agg.sigs);
	cout << "Agg end" << endl;


	// send PK, MSG, agg_sig to server
	/*
	for(int i=0; i<pks.size(); i++){
		ss.str("");
		ss << "PK\n";
		ss << pks[i];

		if( send( to_sockfd, ss.str().c_str(), ss.str().length(), 0 ) < 0 ) {
			perror( "send" );
   		} else {
			cout << "[agg] sent: " << ss.str().c_str() << endl;
			memset( receive_str, 0, sizeof( receive_str ) );
			recv( to_sockfd, receive_str, sizeof(receive_str), 0 );
			cout << "[agg] receive: " << receive_str << endl;
		}
		//sleep( 1 );
		usleep(10 * 1000);
	}

	for(int i=0; i<msgs.size(); i++){
		ss.str("");
		ss << "MSG\n";
		ss << msgs[i];

		if( send(to_sockfd, ss.str().c_str(), ss.str().length(), 0) < 0 ) {
			perror( "send" );
   		} else {
			cout << "sent " << ss.str().c_str() << endl;
			memset( receive_str, 0, sizeof( receive_str ) );
			recv( to_sockfd, receive_str, sizeof(receive_str), 0 );
			cout << "[agg] receive: " << receive_str << endl;
		}
		//sleep( 1 );
		usleep(5 * 1000);
	}
	*/
	for(int i=0; i<N; i++){
		ss.str("");
		ss << "PM\n";
		ss << pks[i] << endl;
		ss << msgs[i] << endl;

		if( send(to_sockfd, ss.str().c_str(), ss.str().length(), 0) < 0 ) {
			perror( "send" );
   		} else {
			if(show_progress) cout << "sent PM " << i << endl; //cout << ss.str().c_str() << endl;
			memset( receive_str, 0, sizeof( receive_str ) );
			recv( to_sockfd, receive_str, sizeof(receive_str), 0 );
			if(show_progress) cout << "[agg] receive: " << receive_str << endl;
		}
		//sleep( 1 );
		//usleep(1 * 1000);
	}
/*
	for(int i=0; i<1; i++){
		ss.str("");
		ss << "AGGSIG\n";
		ss << agg_sig;
		//usleep(100*1000);
		if( send( to_sockfd, ss.str().c_str(), ss.str().length(), 0 ) < 0 ) {
				perror( "send" );
		} else {
			cout << "[agg] sent " << ss.str().c_str() << endl;
			memset( receive_str, 0, sizeof( receive_str ) );
			recv( to_sockfd, receive_str, sizeof(receive_str), 0 );
			cout << "[agg] receive: " << receive_str << endl;
		}
		usleep(1 * 1000);
	}
*/

	for(int i=0; i<1; i++){
		ss.str("");
		ss << "ASITSIG\n";
		for(int j=0; j<(int)agg.agg_sigs.size(); j++){
			if(ss.str().length()>900){
				send(to_sockfd, ss.str().c_str(), ss.str().length(), 0 );
				memset( receive_str, 0, sizeof( receive_str ) );
				recv( to_sockfd, receive_str, sizeof(receive_str), 0 );
				if(show_progress) cout << "[agg] recieve: " << receive_str << endl;
				ss.str("");
			}
			ss << agg.agg_sigs[j] << "\n";
			if(agg.agg_sigs[j] != NONE) sig_len++;
		} 
		ss << "ENDASITSIG\n";
		//usleep(100*1000);
		if( send(to_sockfd, ss.str().c_str(), ss.str().length(), 0 ) < 0 ) {
				perror( "send" );
		} else {
			if(show_progress) cout << "sent " << ss.str().c_str() << endl;
			memset( receive_str, 0, sizeof( receive_str ) );
			recv( to_sockfd, receive_str, sizeof(receive_str), 0 );
			if(show_progress) cout << "[agg] receive: " << receive_str << endl;
		}

	}

	st = std::chrono::system_clock::now();

	memset( receive_str, 0, sizeof( receive_str ) );
	if ( recv( to_sockfd, receive_str, sizeof(receive_str), 0 ) > 0 ) { // Success received
		stringstream ss = stringstream(receive_str);
		string header;
		getline(ss, header);
		if(header == "FDBK"){
			if(show_progress) cout << "receive!! " << header << endl;
			f.clear();
			string str;
			bool all_recv = false;
			uset P; P.clear();
			string p;
			send( to_sockfd, "ACK\n", 4, 0 );
			while(!all_recv){
				memset( receive_str, 0, sizeof( receive_str ) );
				recv( to_sockfd, receive_str, sizeof(receive_str), 0 );
				cout << receive_str << endl;
				send( to_sockfd, "ACK\n", 4, 0 );
				ss = stringstream(receive_str);
				while(getline(ss, str)){
					istringstream s(str);
					while(s >> p){
						if(p=="EL"){ // End Line
							f.push_back(P);
							P.clear();
							break;
						}
						if(p=="END"){
							all_recv = true;
							break;
						}
						P.push_back(stoi(p));
						agg.V.push_back(stoi(p));
					} 
				}
			}
			auto ed = std::chrono::system_clock::now(); 
			feedback_time += ed - st;
		}else if(header == "NOTTRACED"){
			if(show_progress) cout << "receive!! " << header << endl;
			send( to_sockfd, "ACK\n", 4, 0 );
			auto ed = std::chrono::system_clock::now(); 
			feedback_time += ed - st;
		}else{
			cout << "error : receive " << header << endl;
			return -1;
		}
		if(show_progress) view(f);
		//usleep(5*1000);

		// condition of tracing stop
		//if(attacker !=0 && (int)f.size()==1 && (int)f[0].size()==N-attacker){
		if(attacker !=0 && (int)f.size()==1 && (int)agg.V.size()==attacker){
			stringstream ss;
			ss.str("");
			ss << "ENDTRACE\n";
			if( send(to_sockfd, ss.str().c_str(), ss.str().length(), 0 ) < 0 ) {
				perror( "send" );
			} else {
				if(show_progress) cout << "sent " << ss.str().c_str() << endl;
				memset( receive_str, 0, sizeof( receive_str ) );
				recv( to_sockfd, receive_str, sizeof(receive_str), 0 );
				if(show_progress) cout << "[agg] receive: " << receive_str << endl;
			}
			for(int i=0; i<sizeof(fd2)/sizeof(fd2[0]); i++){
				if(fd2[i] == -1) continue; // check fd2[i]
				write( fd2[i], "SENDEND\n", 8);
			}
			cout << "All Traced!!" << endl;
			R++;
			break;
		}

		for ( int i = 0; i < sizeof(fd2)/sizeof(fd2[0]); i++ ){
			if(fd2[i] == -1) continue; // check fd2[i]
			write( fd2[i], "SENDOK\n", 7);
			usleep(200*1000);
		}

		cout << "[aggregator] Round " << R << " end" << endl;
		writing_file << "R " << R << " end" << endl;
	}


}
	cout << "honest ids("<< N-attacker << ") : ";
	for(int i=0;i<N-attacker;i++){
		cout << ids[i] << " ";
	}
	cout << endl;
	cout << "attacker ids("<< attacker << ") : ";
	for(int i=N-attacker;i<N;i++){
		cout << ids[i] << " ";
	}
	cout << endl;
	cout << "N : " << N << ", d : " << d << ", p : " << p << ", b : " << b << ", q : " << q << endl;
	cout << "Total round : " << R << endl;
	cout << "Total sig num : " << sig_len << endl;
	feedback_time /= R;
	cout << "Feedback Time per round (AS-SW-1) : " << std::chrono::duration_cast<std::chrono::microseconds>(feedback_time).count() << " microsec" << endl;

	writing_file << "N : " << N << ", d : " << d << ", p : " << p << ", b : " << b << ", q : " << q << endl;
	writing_file << "Total round : " << R << endl;
	writing_file << "Total sig num : " << sig_len << endl;
	writing_file << "Feedback Time per round (AS-SW-1) : " << std::chrono::duration_cast<std::chrono::microseconds>(feedback_time).count() << " microsec" << endl;

	writing_file.close();

	// ソケットクローズ
	close( to_sockfd );
	close( sockfd );
	for (int i=0; i<sizeof(fd2)/sizeof(fd2[0]);i++){
		close(fd2[i]);
	}
 
	return 0;
}