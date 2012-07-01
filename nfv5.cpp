/*
* Projekt ISA 2009
* Varianta - Sledovani site s vyuzitim NetFlow v5
* nfv5.cpp - zpracovani paketu, export toku
* autor: Petr Mrazek (xmraze03)
*/

// nadmerny vyskyt #define __USE_BSD je kvuli linuxu

#define __USE_BSD
#include <sys/types.h>
#include <sys/socket.h>
#define __USE_BSD
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#define __USE_BSD
#include <sys/types.h>
#include <time.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>

#include <list>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <stdexcept>
using namespace std;

#include "nfv5.h"
#include "nfv5util.h"

/*******************************************************************************
                                privatni cast                                   
*******************************************************************************/

// dump toku do terminalu
ostream& operator<<(ostream& os, const flow& ia)
{
    const nf5_flow_desc* data = ia.getCData();
    // duration
    os << (data->h_flow_finish - data->h_flow_start) / 1000 << ".";
    os << (data->h_flow_finish - data->h_flow_start) % 1000 << " ";
    // proto
    os << (int) data->n_protocol << " ";
    // src IP
    os << inet_ntoa(data->n_src_ip) << " ";
    os << inet_ntoa(data->n_dest_ip) << " ";
    os << ntohs(data->n_src_port) << " ";
    os << ntohs(data->n_dest_port) << " ";
    os << data->h_flow_packets << " ";
    os << data->h_flow_bytes;
    return os;
}

// privatni cast nfv5
class nfv5::Private
{
    public:
        // ctor
        Private (params & _p)
        {
            // osetreni logovaciho souboru
            logfile = 0;
            if(_p.output_file != 0)
            {
                logfile = fopen(_p.output_file,"w");
                if(!logfile)
                    throw std::runtime_error("can't open logfile for writing");
            }
            
            // nulovani pameti
            numflows_seen = 0;
            traffic = 0;
            // zaznamename si pocatek hodin
            clock_gettime(CLOCK_MONOTONIC, &started);
            // a timeouty z parametru
            active_timeout = _p.active_timeout;
            inactive_timeout = _p.inactive_timeout;
            
            // vytvoreni UDP socketu
            if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
            {
                throw std::runtime_error("Failed to create socket");
            }
            // sestaveni adresove struktury
            memset(&server, 0, sizeof(server));
            server.sin_family = AF_INET;      // IP
            server.sin_addr = _p.destination; // adresa
            server.sin_port = htons(_p.port); // port
            output_to_stdout = _p.output_to_stdout;
            cerr << "inited" << endl;
        }
        
        // dtor
        ~Private()
        {
            if(logfile)
            {
                fclose(logfile);
            }
            if(sock)
            {
                close(sock);
            }
        }
        
        // pridani noveho toku
        void addFlow (flow& temp)
        {
            flows_by_activity.push_front(temp);
            numflows_seen ++;
        }
        
        // odeslani netflow v.5 paketu, volano z expiracnich metod
        void sendPacket (nf5_packet & p, timespec & ts)
        {
            // pocet videnych toku
            p.h.flows_seen = htonl (numflows_seen);
            // uptime v milisekundach
            p.h.uptime_ms = htonl (getSysUptimeMillis());
            // unixovy cas
            p.h.time_sec = htonl(ts.tv_sec);
            p.h.time_nanosec = htonl(ts.tv_nsec);
            
            p.h.version = htons(5);
            int count = p.h.count;
            p.h.count = htons(p.h.count);
            // odesleme
            sendto(sock,
                   &p,
                   sizeof(nf5_hlavicka) + count * sizeof(nf5_flow_desc),
                   0,
                   (const sockaddr *)&server,
                   sizeof(server));
                   
            // nulujeme, aby se nestalo neco velmi spatneho
            p.h.count = 0;
        }
        
        // vraci v output zaznam do logu
        void getExpiredFlowText(timespec& ts, flow& f, string& output)
        {
            stringstream stamp;
            // ziskame cas
            clock_gettime(CLOCK_REALTIME, &ts);
            // cas rozlozime na obvykle casti
            tm * broken_time = localtime(&ts.tv_sec);
            // <YYYY-MM-DD> <HH:MM:SS.MS>
            stamp << setfill ('0')
                  << 1900 + broken_time->tm_year << "-"
                  << setw(2)
                  << broken_time->tm_mon + 1 << "-"
                  << setw(2)
                  << broken_time->tm_mday
                  << " "
                  << setw(2)
                  << broken_time->tm_hour << ":"
                  << setw(2)
                  << broken_time->tm_min << ":"
                  << setw(2)
                  << broken_time->tm_sec << "."
                  << setw(3) // milisekundy maji 3 mista
                  << ts.tv_nsec / 1000000 << " "
                  << f; // text z toku
            output = stamp.str();
        }
        
        void prepareExpiredFlow( nf5_flow_desc * data )
        {
            // veci prevedene pro zpracovani prevedeme zpatky
            data->h_flow_start = htonl (data->h_flow_start);
            data->h_flow_finish = htonl (data->h_flow_finish);
            data->h_flow_bytes = htonl (data->h_flow_bytes);
            data->h_flow_packets = htonl (data->h_flow_packets);
        }
        
        // uplynule milisekundy od pocatku hodin programu
        uint64_t getSysUptimeMillis()
        {
            timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t millis = 1000 * uint64_t(ts.tv_sec - started.tv_sec);
            millis += (ts.tv_nsec  - started.tv_nsec) / 1000000;
            return millis;
        }
        
        // data
        bool output_to_stdout;
        FILE * logfile;
        struct sockaddr_in server;
        int sock;
        // nejspis by bylo lepsi pouzit pointer,
        // ale pro prehlednost to necham takto
        list <flow> flows_by_activity;
        vector <flow> expired;
        int numflows_seen;
        timespec started;
        uint64_t traffic;
        uint32_t active_timeout;
        uint32_t inactive_timeout;
};

/*******************************************************************************
                                 verejna cast                                   
*******************************************************************************/

// ctor
nfv5::nfv5(params & p)
{
    d = new Private(p);
}

// dtor
nfv5::~nfv5()
{
    uint64_t traf = d->traffic / (1024 * 1024);
    cerr << "traffic: " << traf << "MB" <<  endl;
    delete d;
}

// expirace toku kterym vyprsel cas
void nfv5::expire ( void )
{
    // vynulovany paket
    nf5_packet pack;
    
    // cas, musi byt zdem aby se shodovaly logy s odeslanymi pakety
    timespec ts;
    
    // premazeme celou maximalni delku paketu
    memset(&pack,0, sizeof(pack));
    
    // uptime pro kontrolu expirace
    uint64_t uptime = d->getSysUptimeMillis();
    
    // iteratory :)
    list<flow>::reverse_iterator finger = d->flows_by_activity.rbegin();
    while (finger != d->flows_by_activity.rend())
    {
        // vytahneme data
        nf5_flow_desc *data = (*finger).getData();
        // pokud tok expiroval, sazi se primo do struktury paketu
        if(uptime - data->h_flow_finish >= d->inactive_timeout
           || uptime - data->h_flow_start >= d->active_timeout
           || (*finger).getForceExpired())
        {
            // ziskame textovou reprezentaci toku
            if(d->output_to_stdout || d->logfile)
            {
                string log;
                d->getExpiredFlowText(ts, *finger, log );
                if(d->output_to_stdout)
                {
                    cout << log << endl;
                }
                if(d->logfile)
                {
                    fprintf(d->logfile,"%s\n",log.c_str());
                }
            }
                
            //pripravime tok k exportu
            d->prepareExpiredFlow( data );
            
            // preklopime tok do paketu
            memcpy(&pack.f[pack.h.count],data,sizeof(nf5_flow_desc));
            pack.h.count ++;
            // smazeme ze seznamu
            d->flows_by_activity.erase( --finger.base());
        }
        else
        {
            ++finger;
        }
        // plny paket -> odeslat, zresetovat
        if(pack.h.count == 30)
        {
            d->sendPacket(pack,ts);
        }
    }
    // zbytek
    if(pack.h.count)
    {
        d->sendPacket(pack,ts);
    }
}

// expirace vsech zbylych toku (pouzito pri normalnim ukonceni programu)
void nfv5::expireAll ( void )
{
    // vynulovany paket
    nf5_packet pack;
    
    // cas, musi byt zdem aby se shodovaly logy s odeslanymi pakety
    timespec ts;
    
    // premazeme celou maximalni delku paketu
    memset(&pack,0, sizeof(pack));
    
    list<flow>::iterator finger = d->flows_by_activity.begin();
    while (finger != d->flows_by_activity.end())
    {
        nf5_flow_desc *data = (*finger).getData();
        // ziskame textovou reprezentaci toku
        if(d->output_to_stdout || d->logfile)
        {
            string log;
            d->getExpiredFlowText(ts, *finger, log );
            if(d->output_to_stdout)
            {
                cout << log << endl;
            }
            if(d->logfile)
            {
                fprintf(d->logfile,"%s\n",log.c_str());
            }
        }
            
        //pripravime tok k exportu
        d->prepareExpiredFlow( data );
        
        // preklopime tok do paketu
        memcpy(&pack.f[pack.h.count],data,sizeof(nf5_flow_desc));
        pack.h.count ++;
        
        // plny paket -> odeslat, zresetovat
        if(pack.h.count == 30)
        {
            d->sendPacket(pack,ts);
        }
        // dalsi
        finger++;
    }
    // zbytek
    if(pack.h.count)
    {
        d->sendPacket(pack,ts);
    }
}

// zpracovani packetu z pcap na tok
void nfv5::process (const pcap_pkthdr* header, const u_char* packet)
{
    const ether_header * ethernet; // ethernetova hlavicka
    const ip *iphlavicka; // IP hlavicka (BSD styl)
    const tcphdr *tcp; // tcp hlavicka
    const udphdr *udp; // udp hlavicka
    ethernet = (ether_header*) packet;
    
    // je to IP? NetFlow v.5 zna jenom IPv4
    if (ntohs (ethernet->ether_type) != ETHERTYPE_IP)
    {
        return;
    }
    iphlavicka = (ip*) (packet + ETHER_HDR_LEN);

    u_int ip_hdr_size;
    ip_hdr_size = iphlavicka->ip_hl << 2;
    
    // prisel nam nejaky odpad
    if (ip_hdr_size < 20)
    {
        return;
    }

    flow temp;
    nf5_flow_desc* flowdata = temp.getData();
    flowdata->n_dest_ip = iphlavicka->ip_dst;
    flowdata->n_src_ip = iphlavicka->ip_src;
    flowdata->n_protocol = iphlavicka->ip_p;
    flowdata->n_tos = iphlavicka->ip_tos;
    
    // kontrola delky toku - expirujeme drive nez pretece
    // 
    uint64_t guard = flowdata->h_flow_bytes;
    guard += ntohs(iphlavicka->ip_len);
    if(guard > 3*1024*1024*1024) // 3GB limit
    {
        temp.forceExpire();
    }
    flowdata->h_flow_bytes = guard;
    
    d->traffic += flowdata->h_flow_bytes;
    flowdata->h_flow_packets = 1;
    switch (iphlavicka->ip_p)
    {
        case PROT_TCP:
            tcp = (tcphdr*) (packet + ETHER_HDR_LEN + ip_hdr_size);
            if (tcp->th_off * 4 < 20)
            {
                // spatny TCP paket?
                break;
            }
            flowdata->n_dest_port = tcp->th_dport;
            flowdata->n_src_port = tcp->th_sport;
            flowdata->n_tcp_flags = tcp->th_flags;
        break;
        case PROT_UDP:
            udp = (udphdr*) (packet + ETHER_HDR_LEN + ip_hdr_size);
            flowdata->n_src_port = udp->uh_sport;
            flowdata->n_dest_port = udp->uh_dport;
        break;
        default:
        break;
    }
    
    // potrebujeme uptime v milisekundach, trochu carovani s casem
    flowdata->h_flow_start = flowdata->h_flow_finish = d->getSysUptimeMillis();
    
    list<flow>::iterator it_begin = d->flows_by_activity.begin();
    list<flow>::iterator it_end = d->flows_by_activity.end();
    // prazdny seznam, pridame novy tok
    if(it_begin == it_end)
    {
        d->addFlow(temp);
    }
    // neprazdny seznam
    else
    {
        // najdi tok
        list<flow>::iterator finger = it_begin;
        for(finger = it_begin; finger != it_end; finger++)
        {
            if(*finger == temp)
            {
                flow temp2 = *finger;
                temp2 += temp;
                d->flows_by_activity.erase(finger);
                d->flows_by_activity.push_front(temp2);
                return;
            }
        }
        // pokud nebyl nalezen 'stejny' tok, pridame novy
        d->addFlow(temp);
    }
}
