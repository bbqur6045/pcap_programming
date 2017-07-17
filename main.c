#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>


int main(int argc, char **argv)
{
#define NONPROMISCUOUS 0
	char *dev;
	char dicebuf[PCAP_ERRBUF_SIZE];
	
	pcap_t *pc;

	dev = pcap_lookupdev(dicebuf);
	if (dev != NULL)
	{	
		printf("%s\n", dev);
	}
	printf("%s\n", dev);
	
	pc= pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, dicebuf);
	if (pc == NULL)
	{
	printf("%s\n", dicebuf);
	exit(1);
	}
}

