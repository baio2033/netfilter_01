#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "sys/types.h"
#include "regex.h"

char *target;

void iptable_set(){
	printf("\n[+] iptable setting\n\n");
	system("iptables -F");
	system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	system("iptables -A INPUT -j NFQUEUE --queue-num 0");
	printf(system("iptables -L"));
	printf("\n\n");
}

void iptable_restore(){
	system("iptables -F");
	printf(system("iptables -L"));
	printf("\n[+] TERMINATE THE PROGRAM\n");
}

void reg_check(u_char *data){
	regex_t state;
	const char *pattern = "(Host:) ([^/n]*)";
	int index;
	regcomp(&state, pattern, REG_EXTENDED);
	int status = regexec(&state, data, 0, NULL, 0);
	if(status == 0)
		printf("\nmatch\n%s\n",data);
	else
		printf("\nno match\n");
}

void dump(u_char *data, int len){
	for(int i=0;i<len;i++){
		if(i%16==0 && i!=0)
			printf("\n");
		printf("%02x ", data[i]);
	}
}

void compare(u_char *data, int len){
	int target_len = strlen(target);
	data += 40;
	for(int i=0;i<len-40;i++){
		if(!strncmp(data,"Host: ",6)){
			if(!strncmp(data+6, target, target_len)){
				printf("%s\n",data);
				break;
			}
		}
		else
			data++;
	}
}

static u_int32_t print_pkt(struct nfq_data *tb){
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	u_char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if(ph){
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if(hwph){
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for(i=0;i<hlen-1;i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ",hwph->hw_addr[hlen-1]);
	}

	ret = nfq_get_payload(tb, &data);
	if(ret >= 0){
		printf("payload length = %d\n", ret);
		//dump2(data, ret);
		//convert(data, ret);
		//dump3(data);
		//reg_check(data);
		compare(data,ret);
	}

	printf("\n");

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv){
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	iptable_set();
	target = argv[1];

	printf("\n[+] target to block : %s\n\n", target);
	printf("[+] opening library handle\n");
	h = nfq_open();
	if(!h){
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("[+] unbinding existing nf_queue handler for AF_INET (if any)\n");
	if(nfq_unbind_pf(h, AF_INET) < 0){
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("[+] binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if(nfq_bind_pf(h, AF_INET) < 0){
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("[+] binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if(!qh){
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	printf("[+] setting copy_packet mode\n");
	if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0){
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while(1){
		if((rv = recv(fd, buf, sizeof(buf), 0)) >= 0){
			printf("packet received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if(rv < 0 && errno == ENOBUFS){
			printf("losing packet!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("[+] unbinding from queue 0 \n");
	nfq_destroy_queue(qh);

	printf("[+] unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);

	printf("[+] closing library handle\n");
	nfq_close(h);

	return 0;
}