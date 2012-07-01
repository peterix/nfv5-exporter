/*
* Projekt ISA 2009
* Varianta - Sledovani site s vyuzitim NetFlow v5
* main.cpp - vstupni bod, zachyceni paketu, prace s casovanim a signaly
* autor: Petr Mrazek (xmraze03)
*/

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>

#include <string>
#include <iostream>
#include <stdexcept>
using namespace std;
#include <arpa/inet.h>

#include "nfv5.h"

// neco globalnich zalezitosti
struct itimerval tick;
pcap_t *handle; // pcap 'session handle'
int killswitch = 0; // ukoncovaci priznak
nfv5 *engine; // zpracovac paketu

// defaultni hodnoty nekterych parametru
const int defaultPort = 2055;
const int defaultActiveTimeout =
    30 /*minut*/ * 60 /* vteriny v minute*/ * 1000 /*milisekundy ve vterine*/;
const int defaultInactiveTimeout =
    15 /*vterin*/ * 1000 /*milisekundy ve vterine*/;

// callback pro SIGALRT
void timer_handler (int signum)
{
    // maskovani signalu - pro jistotu
    sigset_t maska;
    sigset_t zaloha;
    sigfillset(&maska);
    sigprocmask(SIG_SETMASK, &maska, &zaloha);
    
    // odesleme expirovane
    engine->expire();
    
    sigprocmask(SIG_SETMASK, &zaloha, NULL);
}

// callback pro signaly ukonceni
void termination_handler (int signum)
{
    // maskovani signalu - pro jistotu
    sigset_t maska;
    sigset_t zaloha;
    sigfillset(&maska);
    sigprocmask(SIG_SETMASK, &maska, &zaloha);
    
    // ukonceni, zastavime timer
    tick.it_value.tv_sec = 0;
    tick.it_value.tv_usec = 0;
    tick.it_interval.tv_sec = 0;
    tick.it_interval.tv_usec = 0;
    setitimer (ITIMER_REAL, &tick, 0);
    // nastaveni ukoncovaciho priznaku
    killswitch = 1;
    // ukoncit zaznamovou smycku pcap, bude cekat na posledni paket,
    // ktery se zahodi
    pcap_breakloop(handle);
    // odesleme vsechny zbyle toky
    engine->expireAll();
    
    sigprocmask(SIG_SETMASK, &zaloha, NULL);
}

// callback pro odchytavani
void catch_packet (u_char *args, const pcap_pkthdr *header, const u_char *packet)
{
    // maskovani signalu - pro jistotu
    sigset_t maska;
    sigset_t zaloha;
    sigfillset(&maska);
    sigprocmask(SIG_SETMASK, &maska, &zaloha);
    
    // zpracujeme packet
    nfv5 * nf = (nfv5 * ) args;
    nf->process(header, packet);
    
    sigprocmask(SIG_SETMASK, &zaloha, NULL);
}

// popis pouziti programu
void usage (void)
{
    cout
    << "Pouziti: " << endl
    << "nf5exporter -h" << endl
    << "nf5exporter -n <interface> -d <ip-address> -p <port> -i \
<inactive-timeout-ms> -a <active-timeout-ms> -o <output-file> -O" << endl
    << "kde:" << endl
    << "-h                    vypise napovedu" << endl
    << "<interface>           nazev rozhrani, napr. lo0" << endl
    << "default : autodetekce" << endl
    << "<ip-address>          IP adresa kolektoru" << endl
    << "<port>                číslo portu, na kterém kolektor naslouchá" << endl
    << "default : " << defaultPort << endl
    << "<inactive-timeout-ms> neaktivni timeout v milisekundach" << endl
    << "default : " << defaultInactiveTimeout << endl
    << "<active-timeout-ms>   aktivni timeout v milisekundach" << endl
    << "default : " << defaultActiveTimeout << endl
    << "<output-file>         odchozi zaznamy se loguji do souboru" << endl
    << "-O                    odchozi zaznamy se loguji do stdout" << endl;
}

// vstupni bod, prace s parametry, zachytavani paketu
int main (int argc, char *argv[])
{
    params p;
    char *device = 0;
    
    // zachyceni SIGHUP, SIGINT a SIGTERM
    signal (SIGINT, termination_handler);
    signal (SIGHUP, termination_handler);
    signal (SIGTERM, termination_handler);
    
    // default
    p.port = defaultPort;
    p.inactive_timeout = defaultInactiveTimeout;
    p.active_timeout = defaultActiveTimeout;
    p.output_file = 0;
    p.output_to_stdout = 0;
    
    // prace s parametry
    bool has_addr = false;
    char argument;
    while ( (argument = getopt (argc, argv, "hOn:d:p:i:a:o:")) != -1)
    {
        switch (argument)
        {
                // napoveda
            case 'h':
                usage();
                return EXIT_SUCCESS;
                // zarizeni pro odposlech
            case 'n':
                device = optarg;
                break;
                // IP adresa kolektoru
            case 'd':
                if (inet_aton (optarg, &p.destination) == 0)
                {
                    cerr << "adresa "
                         << optarg << " ma nespravny format" << endl;
                    usage();
                    return EXIT_FAILURE;
                }
                has_addr = true;
                break;
                // port
            case 'p':
                p.port = atoi (optarg);
                break;
                // neaktivni timeout v ms
            case 'i':
                p.inactive_timeout = atoi ("optarg");
                break;
                // aktivni timeout v ms
            case 'a':
                p.active_timeout = atoi ("optarg");
                break;
                // soubor pro logovani
            case 'o':
                p.output_file = optarg;
                break;
            case 'O':
                p.output_to_stdout = 1;
                break;
                // pro pripad chyby ve zpracovani parametru
            default:
                usage();
                return EXIT_FAILURE;
        }
    }
    
    if(!has_addr)
    {
        cerr << "nebyla zadana cilova IP adresa!" << endl;
        return EXIT_FAILURE;
    }
    
    // inicializace pcap
    char chyby[PCAP_ERRBUF_SIZE]; // Retezec pro chyby z libpcap
    cerr << pcap_lib_version() << endl;

    // pokud neni specifikovano uzivatelem, najdi vhodne zarizeni
    if (!device)
        device = pcap_lookupdev (chyby);
    if (!device)
    {
        cerr << "Nelze najit zarizeni ke cteni: " << chyby << endl;
        return EXIT_FAILURE;
    }

    // otevreni zarizeni
    handle = pcap_open_live (device, 64, 0, 1, chyby);
    if (handle == NULL)
    {
        cerr << "Nelze otevrit zarizeni " << device << ": " << chyby << endl;
        return EXIT_FAILURE;
    }

    // overeni ze jde o ethernet (jinde by hlavicky mohly vypadat jinak)
    if(pcap_datalink(handle) != DLT_EN10MB
        && pcap_set_datalink(handle, DLT_EN10MB) < 0)
    {
        cerr << "podporovan jen normalni ethernet" << endl;
        return EXIT_FAILURE;
    }
    
    // zpetna vazba pro uzivatele
    cerr << "Zarizeni: " << device << endl;
    cerr << "aktivni timeout: " << p.active_timeout << "ms" << endl;
    cerr << "neaktivni timeout: " << p.inactive_timeout << "ms" << endl;
    if(p.output_to_stdout)
    {
        cerr << "log vystup na stdout." << endl;
    }
    if(p.output_file)
    {
        cerr << "log vystup do " << p.output_file << endl;
    }
    cerr << "netflow vystup na " << inet_ntoa(p.destination)
    << ":" << p.port << endl;
    
    
    // prvni cast inicializace hotova
    cerr << "ready" << endl;
    
    // cast validace vstupu je posunuta do konstuktoru nfv5
    // a konstruktoru jeho privatni casti
    try
    {
        engine = new nfv5 (p);
    }
    catch (runtime_error & e)
    {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }
    
    // odesilame pakety jednou za vterinu - toto je inicializace casovace
    tick.it_value.tv_sec = 0;
    tick.it_value.tv_usec = 999000;
    tick.it_interval.tv_sec = 0;
    tick.it_interval.tv_usec = 999000;
    signal (SIGALRM, timer_handler);
    setitimer (ITIMER_REAL, &tick, 0);
    
    // hlavni smycka
    while (1)
    {
        // cteme packety, ukonceni prerusenim
        pcap_loop (handle, 0, catch_packet, (u_char *) engine);
        if(killswitch) break;
    }
    
    // uklid
    pcap_close (handle);
    delete engine;
    return EXIT_SUCCESS;
}
