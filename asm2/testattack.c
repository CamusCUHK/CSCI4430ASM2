#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define IPADDR "10.0.2.15"
#define PORT 12345
void h_attack(int);
void v_attack(int);
void heavy_bitter(int);
int main(int argc, char **argv) {
  /* if(connect(sd,(struct sockaddr *)&server_addr,sizeof(server_addr))<0){ */
  /*     printf("connection error: %s (Errno:%d)\n",strerror(errno),errno); */
  /*     exit(0); */
  /* } */
  int s_time;
  if (argc != 5) {
		fprintf(stderr, "Usage: %s <heavy_bitter KB> <h_attack time> <v_attack time> <sleep time>\n", argv[0]);
		exit(-1);
	}
	s_time = atoi(argv[4]);
  heavy_bitter(atoi(argv[1]));
  printf("heavy_bitter\n");
  sleep(s_time);
  h_attack(atoi(argv[2]));
  printf("h_attack\n");
  sleep(s_time);
  v_attack(atoi(argv[3]));
  printf("v_attack\n");
  return 0;
}
void heavy_bitter(int size){
	

  for (int i = 0; i < size; i++) {
	  char buf[1025];
	  char temp[2];
	  temp[0] = '\0';
	  buf[0] = '\0';
	  sprintf(temp, "%d", i%10);
	  memset(buf,temp[0],1024);
	  
	  
	 // printf("%s\n", buf);
	  int sd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(IPADDR);      //change
  server_addr.sin_port = htons(PORT);           //fix
  socklen_t addrLen = sizeof(server_addr);

  char recvBuff[100];
  char *buff = "hello";
  struct sockaddr_in client_addr;
    int len;
    if ((len = sendto(sd, buf, strlen(buf), 0,
                      (struct sockaddr *)&server_addr, addrLen)) <= 0) {
      printf("Send Error: %s (Errno:%d)\n", strerror(errno), errno);
      exit(0);
    }
    /** Even directly use the following "if" is okay. Knowing IP addr just
     * decides who sends data first*/
    //    if ((len = recvfrom(sd, recvBuff, sizeof(recvBuff), 0, NULL, NULL)) <=
    //    0) {
    
    close(sd);
  }
  
}

void v_attack(int size){
	

  for (int i = 0; i < size; i++) {
	  int sd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(IPADDR);      //change
  server_addr.sin_port = htons(PORT+i);           //fix
  socklen_t addrLen = sizeof(server_addr);

  char recvBuff[100];
  char *buff = "hello";
  struct sockaddr_in client_addr;
    int len;
    if ((len = sendto(sd, buff, strlen(buff), 0,
                      (struct sockaddr *)&server_addr, addrLen)) <= 0) {
      printf("Send Error: %s (Errno:%d)\n", strerror(errno), errno);
      exit(0);
    }
    /** Even directly use the following "if" is okay. Knowing IP addr just
     * decides who sends data first*/
    //    if ((len = recvfrom(sd, recvBuff, sizeof(recvBuff), 0, NULL, NULL)) <=
    //    0) {
    
    close(sd);
  }
  
}
void h_attack(int size){
	

  for (int i = 0; i < size; i++) {
	  char last_ip[5];
	  char source_ip[20];
	  last_ip[0] = '\0';
	  source_ip[0] = '\0';
	  strcat(source_ip, "10.0.31.");
	  //itoa(i,last_ip,10);
	  
	  sprintf(last_ip, "%d", i);
	  strcat(source_ip, last_ip);
	  //printf("Target dest ip: %s\n", source_ip);
	  int sd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(source_ip);      //change
  server_addr.sin_port = htons(PORT);           //fix
  socklen_t addrLen = sizeof(server_addr);

  char recvBuff[100];
  char *buff = "hello";
  struct sockaddr_in client_addr;
    int len;
    if ((len = sendto(sd, buff, strlen(buff), 0,
                      (struct sockaddr *)&server_addr, addrLen)) <= 0) {
      printf("Send Error: %s (Errno:%d)\n", strerror(errno), errno);
      exit(0);
    }
    /** Even directly use the following "if" is okay. Knowing IP addr just
     * decides who sends data first*/
    //    if ((len = recvfrom(sd, recvBuff, sizeof(recvBuff), 0, NULL, NULL)) <=
    //    0) {
    
    close(sd);
  }
  
}
