/*
* Projekt ISA 2009
* Varianta - Sledovani site s vyuzitim NetFlow v5
* nfv5util.h - pouzite struktury a zakladni operace nad nimi,
*              oddelene pro prehlednost
* autor: Petr Mrazek (xmraze03)
*/

#ifndef NFV5UTIL
#define NFV5UTIL

struct nf5_hlavicka
{
    u_int16_t version; // = 5
    u_int16_t count; // pocet zaznamu v paketu
    u_int32_t uptime_ms; // uptime v dobe odesilani paketu
    // unixovy cas - vteriny a rezidualni nanosekundy
    u_int32_t time_sec;
    u_int32_t time_nanosec;
    u_int32_t flows_seen;// pocet zaznamenanych toku od startu zarizeni
    u_int8_t engine_type; // = 0
    u_int8_t engine_id; // = 0
    // filler
    u_int16_t sampling; // = 0
}__attribute__((packed));

struct nf5_flow_desc
{
    in_addr n_src_ip;
    in_addr n_dest_ip;
    in_addr z_nexthop_ip; // = 0, nepouzivame
    
    u_int16_t z_if_index_in;// = 0
    u_int16_t z_if_index_out;// = 0
    
    u_int32_t h_flow_packets;// no. of packets in flow, !!!!host order in app!!!
    u_int32_t h_flow_bytes;// total bytes, !!!!host order in app!!!!
    
    u_int32_t h_flow_start;// cas prichodu prvniho paketu v ms
    u_int32_t h_flow_finish;// cas prichodu posledniho paketu v ms
    
    u_int16_t n_src_port;
    u_int16_t n_dest_port;
    
    u_int8_t z_pad1; // = 0
    
    u_int8_t n_tcp_flags; // kumulativi OR TCP priznaku
    u_int8_t n_protocol; // TCP/UDP/ICMP/...
    u_int8_t n_tos; // type of service... 
    
    // fluff
    u_int16_t z_src_as;// = 0
    u_int16_t z_dest_as;// = 0
    
    u_int8_t z_src_mask;// = 0
    u_int8_t z_dst_mask;// = 0
    
    // filler
    u_int16_t z_pad2; // = 0
}__attribute__((packed));

// struktura pro netflow paket, pouzivana pri odesilani
struct nf5_packet
{
    nf5_hlavicka h;
    nf5_flow_desc f[30];
    int getSize()
    {
        return sizeof(nf5_hlavicka) + h.count * sizeof(nf5_flow_desc);
    }
}__attribute__((packed));

// netflow v5 tok
class flow
{
    private:
        nf5_flow_desc data;
        bool forceExpired;
        
    public:
        // ctor
        flow(const nf5_flow_desc &_data)
        {
            memcpy(&data, &_data, sizeof(nf5_flow_desc));
            forceExpired = 0;
        }
        
        // ctor
        flow()
        {
            memset(&data,0,sizeof(nf5_flow_desc));
            forceExpired = 0;
        }
        
        // srovnani toku podle klice
        bool operator ==(const flow &f) const
        {
            if(data.n_src_port == f.data.n_src_port)
                if(data.n_src_ip.s_addr == f.data.n_src_ip.s_addr)
                    if(data.n_dest_port == f.data.n_dest_port)
                        if(data.n_dest_ip.s_addr == f.data.n_dest_ip.s_addr)
                            if(data.n_protocol == f.data.n_protocol)
                                if(data.n_tos == f.data.n_tos)
                                    return true;
            return false;
        };
        // prepsani jednoho toku druhym
        flow& operator=(const flow& f)
        {
            memcpy(&data, &(f.data),sizeof( nf5_flow_desc ));
            forceExpired = f.forceExpired;
            return *this;
        }
        // srovnani toku podle klice
        bool operator<(const flow& f) const
        {
            if(data.n_src_port < f.data.n_src_port)
                return true;
            if(data.n_src_ip.s_addr < f.data.n_src_ip.s_addr)
                return true;
            if(data.n_dest_port < f.data.n_dest_port)
                return true;
            if(data.n_dest_ip.s_addr < f.data.n_dest_ip.s_addr)
                return true;
            if(data.n_protocol < f.data.n_protocol)
                return true;
            if(data.n_tos < f.data.n_tos)
                return true;
            return false;
        }
        
        // ziskani dat pro prime operace
        nf5_flow_desc* getData()
        {
            return &data;
        }
        
        // ziskani dat pro cteni
        const nf5_flow_desc* getCData() const
        {
            return &data;
        }
        
        // soucet toku, pouzito pro pridavani novych toku k jiz znamym
        flow& operator+=(const flow& f)
        {
            data.h_flow_bytes += f.data.h_flow_bytes;
            data.h_flow_packets += f.data.h_flow_packets;
            data.h_flow_finish = f.data.h_flow_finish;
            data.n_tcp_flags |= f.data.n_tcp_flags;
            return *this;
        }
        
        // vynutit expiraci toku
        void forceExpire()
        {
            forceExpired = true;
        }
        
        // ma se ihned exportovat?
        bool getForceExpired()
        {
            return forceExpired;
        }
        
        // vystup nekterych udaju jako text (pro logovani)
        friend ostream& operator<<(ostream& os, const flow& ia);
};
#endif