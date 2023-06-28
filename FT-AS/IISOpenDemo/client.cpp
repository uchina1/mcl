#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <mcl/bn256.hpp>
#include <iostream>
#include "as-ft-2.h"

using namespace mcl::bn256;

 
 int main(int argc, char *argv[]) {
	int sockfd;
	struct sockaddr_in addr;

	// ソケット生成
	if( (sockfd = socket( AF_INET, SOCK_STREAM, 0) ) < 0 ) {
		perror( "socket" );
	}
 
	// 送信先アドレス・ポート番号設定
	addr.sin_family = AF_INET;
	addr.sin_port = htons( 1234 );
	addr.sin_addr.s_addr = inet_addr( "127.0.0.1" );
	if(argc > 2){
		addr.sin_addr.s_addr = inet_addr(argv[2]);
	}
 
	// サーバ接続
	connect( sockfd, (struct sockaddr *)&addr, sizeof( struct sockaddr_in ) );
 
//*
	int num = 1;
	if(argc > 1){
		num = atoi(argv[1]);
	}else{
		cout << "Input the num of honest signers: ";
		cin >> num;
	}
	vector<User> users(num);
	
	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);
	for(int i=0;i<num;i++){
		users[i].KeyGen(Q);
	}


char receive_str[100];

stringstream ss;
ss.str("");
ss << "HELO\n";
ss << num << endl;

if( send( sockfd, ss.str().c_str(), ss.str().length(), 0 ) < 0 ) {
	perror( "send" );
} else {
	cout << "sent " << ss.str().c_str() << endl;
	memset( receive_str, 0, sizeof( receive_str ) );
	recv( sockfd, receive_str, sizeof(receive_str), 0 );
	cout << "[client] receive: " << receive_str << endl;
}

int start_id;
start_id = atoi(receive_str);
cout << "Our ID is " << endl;
for(int i=0; i<num; i++){
	users[i].id = start_id + i;
	cout << " " << users[i].id;
}
cout << endl;


for(int R=0; R<100000; R++){

	for(int i=0; i<num; i++){
		// sign
		users[i].m = random_text(128-to_string(users[i].id).length())+to_string(users[i].id);
		G1 hm;
		Hash(hm, users[i].m); users[i].Sign(hm);

		// send PK MSG SIG
		ss.str("");
		ss << "PMS\n";
		int tmp = 0;
		//cout << "hd size " << ss.str().length() - tmp << endl;
		tmp = ss.str().length();
		ss << users[i].id << endl;
		//cout << "id size " << ss.str().length() - tmp << endl;
		tmp = ss.str().length();
		ss << users[i].pub_key << endl;
		//cout << "pk size " << ss.str().length() - tmp << endl;
		tmp = ss.str().length();
		ss << users[i].m << endl;
		//cout << "msg size " << ss.str().length() - tmp << endl;
		tmp = ss.str().length();
		ss << users[i].sig << endl;
		//cout << "sig size " << ss.str().length() - tmp << endl;
		tmp = ss.str().length();
		
		if( send( sockfd, ss.str().c_str(), ss.str().length(), 0 ) < 0 ) {
			perror( "send" );
		} else {
			cout << "sent size " << ss.str().length() << endl;
			cout << "sent " << ss.str().c_str() << endl;
			recv( sockfd, receive_str, 100, 0 );
			cout << "[client] receive: " << receive_str << endl;
		}
		usleep( 500 * 1000 );
	}

	memset( receive_str, 0, sizeof( receive_str ) );
	recv( sockfd, receive_str, 100, 0 );
	cout << "[client] receive: " << receive_str << endl;
	stringstream ss = stringstream(receive_str);
	string recvstr;
	getline(ss, recvstr);
	if(recvstr=="SENDEND"){
		break;
	}
	usleep( 1*1000 ); // transmit interval
}

	cout << "End Sending" << endl; 
	// ソケットクローズ
	close( sockfd );


	return 0;
}