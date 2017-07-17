#include <stdio.h>
#include <pcap.h>

int main(int argc, char **argv)
{
    char *dev;
    char dicebuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(dicebuf);
    if (dev != NULL)
    {
        printf("%s\n", dev);
    }
}
