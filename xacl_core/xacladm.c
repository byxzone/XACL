#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#include <bpf/bpf.h>

#include "map_common.h"
#include "common_kern_user.h"

char *ifname;

int rules_ipv4_map;

int print_usage(int id){
    switch(id){
        case 0:
            fprintf(stderr, "Usage: <command> <arg1> <arg2>\n");
            break;
        default:
            break;
    };

    return 0;
}

int load_bpf_map(){
    rules_ipv4_map = open_map(ifname, "rules_ipv4_map");
    if(rules_ipv4_map < 0){
        fprintf(stderr, "load bpf map error,check device name\n");
        return -1;
    }

    return 0;
}

static __u32 ip_to_u32(__u8 *ip_u8) {
    __u32 ip_u32 = 0;
    ip_u32 = (ip_u8[0]<<24) | (ip_u8[1]<<16) | (ip_u8[2]<<8) | (ip_u8[3]);
    //printf("%hhu.%hhu.%hhu.%hhu,%u\n",ip_u8[0],ip_u8[1],ip_u8[2],ip_u8[3],ip_u32);
    return ip_u32;
}

int clear_map(){
    __u16 keys[MAX_RULES];
    for(int i=0; i<MAX_RULES; i++){
        keys[i] = i;
    }

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

    __u32 count = MAX_RULES - 1;

    bpf_map_delete_batch(rules_ipv4_map, &keys, &count, &opts);

    return count;
}

int load_handler(int argc, char *argv[]){
    if(argc < 1){
        print_usage(1);
        return EXIT_FAILURE;
    }

    char *path = argv[0];
    printf("loading config file:%s\n",path);
    
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    __u16 keys[MAX_RULES];
    struct rules_ipv4 rules[MAX_RULES];

    __u32 i = 1;
    keys[0] = 0;
    char line[256];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';

        __u8 saddr[4];
        __u8 daddr[4];
        char proto[10];
        char action[10];
        sscanf(line, "%hhu.%hhu.%hhu.%hhu/%hhu %hhu.%hhu.%hhu.%hhu/%hhu %hu %hu %s %s",
           &saddr[0] ,&saddr[1] ,&saddr[2] ,&saddr[3] ,&rules[i].saddr_mask, 
           &daddr[0] ,&daddr[1] ,&daddr[2] ,&daddr[3] ,&rules[i].daddr_mask, 
           &rules[i].sport, &rules[i].dport, proto, action);

        rules[i].saddr = ip_to_u32(saddr);
        rules[i].daddr = ip_to_u32(daddr);

        if(strcmp("TCP", proto) == 0){
            rules[i].ip_proto = IPPROTO_TCP;
        }else if(strcmp("UDP", proto) == 0){
            rules[i].ip_proto = IPPROTO_UDP;
        }else if(strcmp("ICMP", proto) == 0){
            rules[i].ip_proto = IPPROTO_ICMP;
        }else{
            rules[i].ip_proto = 0;
        }

        if(strcmp("ALLOW", action) == 0){
            rules[i].action = XDP_PASS;
        }else if(strcmp("DENY", action) == 0){
            rules[i].action = XDP_DROP;
        }else{
            rules[i].action = XDP_ABORTED;
        }

        rules[i-1].next_rule = i;
        rules[i].prev_rule = i - 1;
        rules[i].next_rule = 0;
        keys[i] = i;

        i += 1;
    }
    printf("%d rules loaded\n",i-1);
    rules[0].prev_rule = i - 1;

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);
    clear_map();
    bpf_map_update_batch(rules_ipv4_map, keys, rules, &i, &opts);

    return 0;   
}

int clear_handler(int argc, char *argv[]){
    int ret = clear_map();
    printf("%d rules are cleared\n", ret-1);
    return 0;
}


int main(int argc, char *argv[]){ //xacladm load enp1s0 ./conf.d/ipv4.conf
    int ret = 0;

    if(argc < 3){
        print_usage(0);
        return EXIT_FAILURE;
    }

    char *command = argv[1];
    ifname = argv[2];

    load_bpf_map();
    if (strcmp(command, "load") == 0) {
        ret = load_handler(argc - 2, argv + 3);
    } else if (strcmp(command, "clear") == 0) {
        ret = clear_handler(argc - 2, argv + 3);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(0);
        return EXIT_FAILURE;
    }

    return ret;
}