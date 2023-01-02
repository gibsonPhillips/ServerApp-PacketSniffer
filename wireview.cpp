#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#include <time.h>
#include <string.h>
#include <iostream>
#include <map>

using namespace std;

int minimum = 2147483647;
int maximum = 0;
int average = 0;
int count = 0;

long int timeElapsed = 0;
long int timeElapsedMicro = 0;
long int timeElapsedStart = 0;
long int timeElapsedStartMicro = 0;

map<string, int> macAddressSourceMap;
map<string, int> macAddressDestMap;
map<string, int> IPSourceMap;
map<string, int> IPDestMap;
map<string, int> ARPMap;

struct my_ip
{
    u_int8_t ip_vhl; /* header length, version */
    // u_int8_t	ip_tos;		/* type of service */
    u_int16_t ip_len;     /* total length */
    u_int16_t ip_id;      /* identification */
    u_int16_t ip_off;     /* fragment offset field */
#define IP_DF 0x4000      /* dont fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    // u_int8_t	ip_ttl;		/* time to live */
    u_int8_t ip_p;                 /* protocol */
    u_int16_t ip_sum;              /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

void my_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    count++;

    // assign the time values from the pkthdr struct
    time_t unixTime = pkthdr->ts.tv_sec;
    time_t unixTimeMicro = pkthdr->ts.tv_usec;
    char microSec[sizeof(long int)];
    sprintf(microSec, "%ld", pkthdr->ts.tv_usec);

    //fixes problems with leading 0's
    while (strlen(microSec) < 6)
    {
        char tempBuffer[sizeof(long int)];
        strcpy(tempBuffer, "0");
        strcat(tempBuffer, microSec);
        strcpy(microSec, tempBuffer);
    }

    //changes unix time
    struct tm *tmp = gmtime(&unixTime);

    // initiate the lengtt of the current packet
    int pktlen = pkthdr->len;

    //calculates the elapsed time of the packet
    char timeElapsedMicroSec[sizeof(long int)];
    if (count == 1)
    {
        timeElapsedStart = unixTime;
        timeElapsedStartMicro = unixTimeMicro;
        strcpy(timeElapsedMicroSec, "000000");
    }
    else
    {
        timeElapsedMicro = unixTimeMicro - timeElapsedStartMicro;
        if (timeElapsedMicro < 0)
        {
            timeElapsed = unixTime - timeElapsedStart - 1;
            timeElapsedMicro = 1000000 + timeElapsedMicro;
        }
        else
        {
            timeElapsed = unixTime - timeElapsedStart;
        }

        sprintf(timeElapsedMicroSec, "%ld", timeElapsedMicro);

        //deals with leading 0's
        while(strlen(timeElapsedMicroSec) < 6) {
            char tempBuffer[sizeof(long int)];
            strcpy(tempBuffer, "0");
            strcat(tempBuffer, timeElapsedMicroSec);
            strcpy(timeElapsedMicroSec, tempBuffer);
        }
    }

    // big info dump
    printf("%d\t%02d/%02d/%02d - %02d:%02d:%02d.%s EST\t%ld.%s\t%d\n", count, tmp->tm_year + 1900, tmp->tm_mon + 1,
           tmp->tm_mday, tmp->tm_hour - 4, tmp->tm_min, tmp->tm_sec, microSec, timeElapsed, timeElapsedMicroSec, pktlen);

    // check if min
    if (pktlen <= minimum)
    {
        minimum = pktlen;
    }

    // check if max
    if (pktlen >= maximum)
    {
        maximum = pktlen;
    }

    // add to average
    average += pktlen;


    int i;
    struct ether_header *eptr; /* net/ethernet.h */
    u_char *ptr;               /* printing out hardware header info */

    /* lets start with the ether header... */
    eptr = (struct ether_header *)packet;


    // adapting code from Stanford website given in class to find MAC addresses
    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    string sourceMacAddress = "";
    char tempValue[4];

    // assigns source mac address to variable sourceMacAddress
    do
    {
        sprintf(tempValue, "%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
        sourceMacAddress += tempValue;
    } while (--i > 0);

    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    string destMacAddress = "";


    // assigns destination mac address to variable destMacAddress
    do
    {
        sprintf(tempValue, "%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
        destMacAddress += tempValue;
    } while (--i > 0);

    //adds addresses to maps or increments the value if already in the map
    if (macAddressSourceMap.find(sourceMacAddress) != macAddressSourceMap.end())
    {
        macAddressSourceMap[sourceMacAddress] = macAddressSourceMap[sourceMacAddress] + 1;
    }
    else
    {
        macAddressSourceMap.insert(pair<string, int>(sourceMacAddress, 1));
    }

    if (macAddressDestMap.find(destMacAddress) != macAddressDestMap.end())
    {
        macAddressDestMap[destMacAddress] = macAddressDestMap[destMacAddress] + 1;
    }
    else
    {
        macAddressDestMap.insert(pair<string, int>(destMacAddress, 1));
    }

    // checking if ARP as ARP has no IP addresses
    if (ntohs(eptr->ether_type) != ETHERTYPE_ARP)
    {
        // adapting code from Stanford website given in class to find IP addresses
        const struct my_ip *ip;
        u_int length = pkthdr->len;
        u_int hlen, off, version;

        int len;

        /* jump pass the ethernet header */
        ip = (struct my_ip *)(packet + sizeof(struct ether_header));
        length -= sizeof(struct ether_header);

        /* check to see we have a packet of valid length */
        if (length < sizeof(struct my_ip))
        {
            printf("truncated ip %d", length);
        }

        len = ntohs(ip->ip_len);

        /* see if we have as much packet as we should */
        if (length < len)
            printf("\ntruncated IP - %d bytes missing\n", len - length);

        /* Check to see if we have the first fragment */
        off = ntohs(ip->ip_off);
        if ((off & 0x1fff) == 0) // aka no 1's in first 13 bits
        {
            string sourceIP = inet_ntoa(ip->ip_src);
            string destIP = inet_ntoa(ip->ip_dst);

            //adds addresses to maps or increments the value if already in the map
            if (IPSourceMap.find(sourceIP) != IPSourceMap.end())
            {
                IPSourceMap[sourceIP] = IPSourceMap[sourceIP] + 1;
            }
            else
            {
                IPSourceMap.insert(pair<string, int>(sourceIP, 1));
            }

            if (IPDestMap.find(destIP) != IPDestMap.end())
            {
                IPDestMap[destIP] = IPDestMap[destIP] + 1;
            }
            else
            {
                IPDestMap.insert(pair<string, int>(destIP, 1));
            }
        }
    }
    else
    {
        // if the packet is arp, add the mac addresses to the arp map
        if (ARPMap.find(sourceMacAddress) != ARPMap.end())
        {
            ARPMap[sourceMacAddress] = ARPMap[sourceMacAddress] + 1;
        }
        else
        {
            ARPMap.insert(pair<string, int>(sourceMacAddress, 1));
        }

        if (ARPMap.find(destMacAddress) != ARPMap.end())
        {
            ARPMap[destMacAddress] = ARPMap[destMacAddress] + 1;
        }
        else
        {
            ARPMap.insert(pair<string, int>(destMacAddress, 1));
        }
    }
}

int main(int argc, char **argv)
{

    // adapting code from Stanford website given in class
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    struct bpf_program fp; /* hold compiled program     */
    bpf_u_int32 maskp;     /* subnet mask               */
    bpf_u_int32 netp;      /* ip                        */
    u_char *args = NULL;

    int i;
    const u_char *packet;
    struct pcap_pkthdr hdr;    /* pcap.h */
    struct ether_header *eptr; /* net/ethernet.h */
    u_char *ptr;               /* printing out hardware header info */

    if (argc < 2)
    {
        fprintf(stdout, "usage: %s numpackets \"options\"\n", argv[0]);
        return 0;
    }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    descr = pcap_open_offline(argv[1], errbuf);
    if (descr == NULL)
    {
        printf("pcap_open_offline(): %s\n", errbuf);
        exit(1);
    }

    if (argc > 2)
    {
        if (pcap_compile(descr, &fp, argv[2], 0, netp) == -1)
        {
            fprintf(stderr, "Error calling pcap_compile\n");
            exit(1);
        }

        /* set the compiled program as the filter */
        if (pcap_setfilter(descr, &fp) == -1)
        {
            fprintf(stderr, "Error setting filter\n");
            exit(1);
        }
    }

    /* ... and loop */
    pcap_loop(descr, -1, my_callback, args);


    // print end stats
    printf("Number of Packets: %d\tMinlen: %d\tMaxlen: %d\tAverage: %lf\n", count, minimum, maximum, ((double)average / count));

    // print source mac addresses
    cout << "MAC Address Source Map\n";
    for (map<string, int>::const_iterator it = macAddressSourceMap.begin(); it != macAddressSourceMap.end(); ++it)
    {
        cout << "\t" << it->first << " = " << it->second << "\n";
    }

    // print destination mac addresses
    cout << "MAC Address Dest Map\n";
    for (map<string, int>::const_iterator it = macAddressDestMap.begin(); it != macAddressDestMap.end(); ++it)
    {
        cout << "\t" << it->first << " = " << it->second << "\n";
    }

    // print source IP addresses
    cout << "IP Address Source Map\n";
    for (map<string, int>::const_iterator it = IPSourceMap.begin(); it != IPSourceMap.end(); ++it)
    {
        cout << "\t" << it->first << " = " << it->second << "\n";
    }

    // print destination IP addresses
    cout << "IP Address Dest Map\n";
    for (map<string, int>::const_iterator it = IPDestMap.begin(); it != IPDestMap.end(); ++it)
    {
        cout << "\t" << it->first << " = " << it->second << "\n";
    }

    // print arp map
    cout << "ARP Map\n";
    for (map<string, int>::const_iterator it = ARPMap.begin(); it != ARPMap.end(); ++it)
    {
        cout << "\t" << it->first << " = " << it->second << "\n";
    }

    fprintf(stdout, "\nfinished\n");
    return 0;
}
