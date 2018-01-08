/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  /* Handle ARP packet */
  if(ethertype(packet) == ethertype_arp) {

    /* Check for valid len */
    if(len < (sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t))) {
      fprintf(stderr, "Dropping bad ARP packet.\n");
      return;
    }
    
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t* ar_hdr = 
      (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* iface = sr_get_interface(sr, interface);

    struct sr_if* if_ptr, *if_i;
    for(if_i = sr_get_interface(sr, interface); if_i; if_i = if_i->next) {
      if(if_i->ip == ar_hdr->ar_tip) {
        if_ptr = if_i;
        break;
      }
    }

    if(!if_ptr) {
      fprintf(stderr, "ARP packet not for me.\n");
      return;
    }

    /* Handle ARP Request */
    if(ntohs(ar_hdr->ar_op) == arp_op_request) {
      memset(eth_hdr->ether_dhost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
      memset(eth_hdr->ether_shost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_shost, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
      
      ar_hdr->ar_tip = ar_hdr->ar_sip;
      ar_hdr->ar_sip = if_ptr->ip;

      memset(ar_hdr->ar_tha, 0, sizeof(unsigned char)*ETHER_ADDR_LEN);
      memcpy(ar_hdr->ar_tha, ar_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
      memset(ar_hdr->ar_sha, 0, sizeof(unsigned char)*ETHER_ADDR_LEN);
      memcpy(ar_hdr->ar_sha, iface->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);

      ar_hdr->ar_op = htons(arp_op_reply);
      sr_send_packet(sr, packet, len, iface->name);
    }

    /* Handle ARP Reply */
    else if(ntohs(ar_hdr->ar_op) == arp_op_reply) {
      struct sr_arpreq* ar_req = 
        sr_arpcache_insert(&(sr->cache), ar_hdr->ar_sha, ar_hdr->ar_sip);
      
      /* Send outstanding packets */
      struct sr_packet* tmp_pkt = ar_req->packets;
      while(tmp_pkt) {
        sr_ethernet_hdr_t* eth_ptr = (sr_ethernet_hdr_t*) tmp_pkt->buf;
        memset(eth_ptr->ether_dhost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(eth_ptr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memset(eth_ptr->ether_shost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(eth_ptr->ether_shost, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

        sr_send_packet(sr, tmp_pkt->buf, tmp_pkt->len, iface->name);
        tmp_pkt = tmp_pkt->next;
      }

      sr_arpreq_destroy(&(sr->cache), ar_req);
    }
  }

  /* Handle IP packet */
  else if(ethertype(packet) == ethertype_ip) {
 
    /* Check for valid len */
    if(len < sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, "Dropping bad IP packet: too small.\n");
      return;
    }

    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_hdr = 
      (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    
    uint16_t chksm = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Check for valid IP header */
    if(ip_hdr->ip_v != 4 || ip_hdr->ip_hl < 5 ||
       ip_hdr->ip_len > IP_MAXPACKET || chksm != IP_MAXPACKET) {
      fprintf(stderr, "Dropping bad IP packet: invalid header.\n");
      return;
    }
    
    /* Check if package mailed to correct address */
    struct sr_if* if_ptr = NULL, *if_i; 
    for(if_i = sr_get_interface(sr, interface); if_i; if_i = if_i->next) {
      if(if_i->ip == ip_hdr->ip_dst) {
        if_ptr = if_i;
        break;
      }
    }

    /* It is for me */
    if(if_ptr) {
      
      struct sr_if* iface = sr_get_interface(sr, interface);
      
      if(ip_hdr->ip_p != ip_protocol_icmp) {
        fprintf(stderr, "Dropping bad IP packet: non-ICMP.\n");
        size_t out_len = sizeof(sr_ethernet_hdr_t) +
          sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
        uint8_t* out_pkt = malloc(out_len);
        
        sr_ethernet_hdr_t* out_eth = (sr_ethernet_hdr_t*) out_pkt;
        sr_ip_hdr_t* out_ip =
          (sr_ip_hdr_t*) (out_pkt+sizeof(sr_ethernet_hdr_t));
        sr_icmp_t11_hdr_t* out_icmp =
          (sr_icmp_t11_hdr_t*) (out_pkt+sizeof(sr_ethernet_hdr_t)
          +sizeof(sr_ip_hdr_t));

        memset(out_eth->ether_dhost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(out_eth->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memset(out_eth->ether_shost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(out_eth->ether_shost, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
        
        out_eth->ether_type = htons(ethertype_ip);

        out_ip->ip_v = 4;
        out_ip->ip_hl = 5;
        out_ip->ip_tos = 3;
        out_ip->ip_len = htons(20 + sizeof(sr_icmp_t11_hdr_t));
        out_ip->ip_id = htons(1);
        out_ip->ip_off = htons(0);
        out_ip->ip_ttl = 64;
        out_ip->ip_p = ip_protocol_icmp;
        out_ip->ip_sum = htons(0);
        out_ip->ip_src = if_ptr->ip;
        out_ip->ip_dst = ip_hdr->ip_src;

        out_ip->ip_sum = 0x0;
        out_ip->ip_sum = cksum(out_ip, sizeof(sr_ip_hdr_t));

        out_icmp->icmp_type = 3;
        out_icmp->icmp_code = 3;
        out_icmp->icmp_sum = htons(0);
        out_icmp->unused = htonl(0);

        memset(out_icmp->data, 0, sizeof(uint8_t)*ICMP_DATA_SIZE);
        memcpy(out_icmp->data, ip_hdr, sizeof(uint8_t)*ICMP_DATA_SIZE);
        
        out_icmp->icmp_sum = cksum(out_icmp, sizeof(sr_icmp_t11_hdr_t));

        sr_send_packet(sr, out_pkt, out_len, iface->name);
        return;
      }

      /* Handle echo request (type 8) */
      else {
        sr_icmp_t11_hdr_t* icmp_hdr =
          (sr_icmp_t11_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t)
          +sizeof(sr_ip_hdr_t));

        memset(eth_hdr->ether_dhost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);

        memset(eth_hdr->ether_shost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

        ip_hdr->ip_tos = 0x00;
        ip_hdr->ip_ttl = 64;

        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = if_ptr->ip;

        ip_hdr->ip_sum = 0x00;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        icmp_hdr->icmp_code = 0x00;
        icmp_hdr->icmp_type = 0x00;
        icmp_hdr->icmp_sum = 0x00;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, 
          ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
        
        sr_send_packet(sr, packet, len, iface->name);
      }
    }

    /* Not for me - attempt to forward */
    else {
      /* Check for expiring IP packet */
      if(ip_hdr->ip_ttl > 1) {
        struct sr_rt* rt_mask = NULL;
        uint32_t n_mask = 0x0;

        struct sr_rt* rt_i;
        for(rt_i = sr->routing_table; rt_i; rt_i = rt_i->next) {
          if((rt_i->dest.s_addr & rt_i->mask.s_addr) ==
             (ip_hdr->ip_dst & rt_i->mask.s_addr)) {
            if(rt_i->mask.s_addr > n_mask) {
              rt_mask = rt_i;
              n_mask = (ip_hdr->ip_dst & rt_i->mask.s_addr);
            }
          }
        }
        
        /* LPM found */
        if(rt_mask) {
          ip_hdr->ip_ttl--;
          ip_hdr->ip_sum = 0x00;
          ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
          
          struct sr_arpentry* entry =
            sr_arpcache_lookup(&(sr->cache), rt_mask->gw.s_addr);

          struct sr_if* iface = sr_get_interface(sr, rt_mask->interface);
          
          /* ARP entry found */
          if(entry) {
            memset(eth_hdr->ether_dhost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
            
            memset(eth_hdr->ether_shost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

            /*ip_hdr->ip_src = iface->ip;
            ip_hdr->ip_dst = entry->ip;*/

            sr_send_packet(sr, packet, len, rt_mask->interface);
          }

          /* ARP entry not found */
          else {
            sr_arpcache_queuereq(&(sr->cache), rt_mask->gw.s_addr, packet,
              len, rt_mask->interface);
          }
        }

        /* Network unreachable - type 3 */
        else {
          size_t out_len = sizeof(sr_ethernet_hdr_t) +
            sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
          uint8_t* out_pkt = malloc(out_len);
        
          sr_ethernet_hdr_t* out_eth = (sr_ethernet_hdr_t*) out_pkt;
          sr_ip_hdr_t* out_ip =
            (sr_ip_hdr_t*) (out_pkt+sizeof(sr_ethernet_hdr_t));
          sr_icmp_t11_hdr_t* out_icmp =
            (sr_icmp_t11_hdr_t*) (out_pkt+sizeof(sr_ethernet_hdr_t)
            +sizeof(sr_ip_hdr_t));

          struct sr_if* iface = sr_get_interface(sr, interface);

          memset(out_eth->ether_dhost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
          memcpy(out_eth->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
          memset(out_eth->ether_shost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
          memcpy(out_eth->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN);
        
          out_eth->ether_type = htons(ethertype_ip);

          out_ip->ip_v = 4;
          out_ip->ip_hl = 5;
          out_ip->ip_tos = 3;
          out_ip->ip_len = htons(20 + sizeof(sr_icmp_t11_hdr_t));
          out_ip->ip_id = htons(3);
          out_ip->ip_off = htons(0);
          out_ip->ip_ttl = 64;
          out_ip->ip_p = ip_protocol_icmp;
          out_ip->ip_sum = htons(0);
          out_ip->ip_src = iface->ip;
          out_ip->ip_dst = ip_hdr->ip_src;

          out_ip->ip_sum = 0x0;
          out_ip->ip_sum = cksum(out_ip, sizeof(sr_ip_hdr_t));

          out_icmp->icmp_type = 3;
          out_icmp->icmp_code = 0;
          out_icmp->icmp_sum = htons(0);
          out_icmp->unused = htonl(0);

          memset(out_icmp->data, 0, sizeof(uint8_t)*ICMP_DATA_SIZE);
          memcpy(out_icmp->data, ip_hdr, sizeof(uint8_t)*ICMP_DATA_SIZE);
          
          out_icmp->icmp_sum = cksum(out_icmp, sizeof(sr_icmp_t11_hdr_t));

          sr_send_packet(sr, out_pkt, out_len, iface->name);
        }
      }

      /* Handle expired packet - type 11 */
      else {
        size_t out_len = sizeof(sr_ethernet_hdr_t) +
          sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
        uint8_t* out_pkt = malloc(out_len);
        
        sr_ethernet_hdr_t* out_eth = (sr_ethernet_hdr_t*) out_pkt;
        sr_ip_hdr_t* out_ip =
          (sr_ip_hdr_t*) (out_pkt+sizeof(sr_ethernet_hdr_t));
        sr_icmp_t11_hdr_t* out_icmp =
          (sr_icmp_t11_hdr_t*) (out_pkt+sizeof(sr_ethernet_hdr_t)
          +sizeof(sr_ip_hdr_t));

        struct sr_if* iface = sr_get_interface(sr, interface);

        memset(out_eth->ether_dhost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(out_eth->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memset(out_eth->ether_shost, 0, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(out_eth->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN);
        
        out_eth->ether_type = htons(ethertype_ip);

        out_ip->ip_v = 4;
        out_ip->ip_hl = 5;
        out_ip->ip_tos = 11;
        out_ip->ip_len = htons(20 + sizeof(sr_icmp_t11_hdr_t));
        out_ip->ip_id = htons(2);
        out_ip->ip_off = htons(0);
        out_ip->ip_ttl = 64;
        out_ip->ip_p = ip_protocol_icmp;
        out_ip->ip_sum = htons(0);
        out_ip->ip_src = iface->ip;
        out_ip->ip_dst = ip_hdr->ip_src;

        out_ip->ip_sum = cksum(out_ip, sizeof(sr_ip_hdr_t));

        out_icmp->icmp_type = 0x0b;
        out_icmp->icmp_code = 0;
        out_icmp->icmp_sum = htons(0);
        out_icmp->unused = htonl(0);
        memset(out_icmp->data, 0, sizeof(uint8_t)*ICMP_DATA_SIZE);
        memcpy(out_icmp->data, ip_hdr, sizeof(uint8_t)*ICMP_DATA_SIZE);

        out_icmp->icmp_sum = cksum(out_icmp, sizeof(sr_icmp_t11_hdr_t));

        sr_send_packet(sr, out_pkt, out_len, iface->name);
      }
    }
  }

}/* end sr_ForwardPacket */
