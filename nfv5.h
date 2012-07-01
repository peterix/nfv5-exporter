#ifndef NFV5_INCLUDED
#define NFV5_INCLUDED

#define PROT_ICMP 1
#define PROT_TCP 6
#define PROT_UDP 17

struct params
{
    // odesilani na kolektor
    in_addr destination;
    int port;
    
    // sledovani
    unsigned int inactive_timeout;
    unsigned int active_timeout;
    
    // logovani
    char *output_file;
    bool output_to_stdout;
};

class nfv5
{
    // privatni cast (schovana za d-pointer)
    class Private;
    private:
        Private * d;
    public:
        // ctor
        nfv5(params & p);
        // dtor
        ~nfv5();
        // zpracovani packetu ziskaneho pomoci pcap knihovny
        void process (const pcap_pkthdr *header, const u_char *packet);
        // expirace toku kterym vyprsel cas
        void expire ( void );
        // expirace vsech toku (pouzito pri normalnim ukonceni programu)
        void expireAll ( void );
};

#endif // NFV5_INCLUDED