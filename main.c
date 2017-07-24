nclude <netinet/in.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])

{
    
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    
    
    
    int i,j;
    struct ip *iph;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int show;
    const char *sbuf[32];
    const char *dbuf[32];
    
    
    /* Define the device */
    
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
        
    }
    printf("lookupdev complete\n");
    /* Find the properties for the device */
    
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    printf("lookupnet complete\n");
    /* Open the session in promiscuous mode */
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    printf("pcap open live complete\n");
    /* Compile and apply the filter */
    
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    printf("right before grabbing packet\n");
    /* Grab a packet */
    show = pcap_next_ex(handle, &header,&packet);
    
    while(pcap_next_ex(handle,&header,&packet)==1)
    {
        
        ethh =(struct ether_header *)packet;
        
        packet +=sizeof(struct ether_header);
        
        iph =(struct ip *)packet;
        
        packet += sizeof(struct ip);
        
        tcph =(struct tcphdr *)packet;
        
        packet += sizeof(struct tcphdr);
        printf("%02x:",ethh->ether_shost[0]);
        
        printf("-------------------------\n");
        
        
        printf("eth.smac = ");
        
        printf("%02x:%02x:%02x:%02x:%02x:%02x:",ethh->ether_shost[0],ethh->ether_shost[1],ethh->ether_shost[2],ethh->ether_shost[3],ethh->ether_shost[4],ethh->ether_shost[5]);
        printf("\n");
        
        printf("eth.dmac = ");
        
        printf("%02x:%02x:%02x:%02x:%02x:%02x:",ethh->ether_dhost[0],ethh->ether_dhost[1],ethh->ether_dhost[2],ethh->ether_dhost[3],ethh->ether_dhost[4],ethh->ether_dhost[5]);
        
        
        
        printf("\n");
        
        printf("SIP = %s\n",inet_ntop(AF_INET,&iph->ip_src,&sbuf,16));
        printf("DIP = %s\n",inet_ntop(AF_INET,&iph->ip_src,&dbuf,16));
        
        printf("SPORT = %d\n",ntohs(tcph->th_sport));
        printf("DPORT = %d\n",ntohs(tcph->th_dport));
        
        
        
        printf("DATA:\n");
        
        for(j=0;j<(header->len)-sizeof(struct ether_header)-sizeof(struct ip)-sizeof(struct tcphdr);j++)
        {
            
            printf("%02x ",*packet);
            packet++;
            
            if(j % 16 == 0 )
                printf("\n");
            
        }
        
        printf("\n-------------------------------\n");
     
        
    }
    
    pcap_close(handle);
    
    return(0);
    
}


