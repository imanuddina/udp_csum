#include <stdio.h>
#include <stdint.h>

static inline uint16_t csum_update2(uint16_t old_csum,
            uint16_t old_field, uint16_t new_field)
{
    
    //printf("func %02x %02x %02x\n", old_csum, old_field, new_field);

    uint32_t csum = old_csum + old_field + (~new_field & 0xFFFF);

    csum = (csum >> 16) + (csum & 0xFFFF);

    csum +=(csum >> 16);

    return (uint16_t)csum;

}

/* it is used for IP address udpate */
static inline uint16_t csum_update4(uint16_t old_csum, 
    uint32_t old_field, uint32_t new_field)
{
    
   uint16_t old1 = (old_field >> 16);
   uint16_t old2 = (old_field & 0xFFFF);
   
   uint16_t new1 = (new_field >> 16);
   uint16_t new2 = (new_field & 0xFFFF);

   uint16_t new_sum = csum_update2(old_csum, old1, new1);
   new_sum = csum_update2(new_sum, old2, new2);

   return new_sum;
}

/* Not necessary, see example below 
 * csum_update1(0xf95b,ttl, ttl-1)
 * is similar with
 * csum_update2(0xf95b,ttl<<8, (ttl-1)<<8))
 */
static inline uint16_t csum_update1(uint16_t old_csum,
            uint8_t old_byte, uint8_t new_byte)
{

    uint16_t old, new, csum;
    old = 0; new = 0;
    old |= (old_byte << 8);
    new |= (new_byte << 8);
    printf("%02x %02x \t", old, new);
    csum = csum_update2(old_csum, old, new);

    return (uint16_t)csum;

}

    union tos {
		uint8_t v:8;
		struct {
    		uint8_t ecn: 2;      /*!< IPv4 ECN */            
			uint8_t dscp:6;      /*!< IPv4 DSCP */
		
		} s;
	};
    
    struct ip6 {
        uint32_t ad[4];
    };
	
	struct ip4_dw0{
#if 0
       uint32_t	ip_len		:16;   /*!< IPV4 packet length */
  	   uint32_t tos:8;	  
       uint32_t	ip_hl		:4;   /*!< IPV4 header length */	   
       uint32_t	ip_ver		:4;   /*!< IPV4 version  */
#else
       uint32_t	ip_ver		:4;   /*!< IPV4 version  */
       uint32_t	ip_hl		:4;   /*!< IPV4 header length */
  	   uint32_t tos:8;
       uint32_t	ip_len		:16;   /*!< IPV4 packet length */	
#endif	   
	};
    
static inline dump_byte(uint8_t b[], uint16_t len)
{
	uint16_t i;
	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			printf("\n");
			printf("%02x: ", (b + i));
		}

		printf("%02x ", *(b + i));
	}	
	printf("\n");
}

uint16_t udp_csum()
{
	uint8_t pad=0;
	uint16_t i, s, csum, udp_len;
	uint32_t sum=0;
#if 0	
	uint8_t arr[] = {
		0x80, 0xb0, 0x01, 0x02, 0x03, 0x04, 0x80, 0xb0, 0x11, 0x12, 0x13, 0x14, 0x81, 0x00, 0x81, 0x67,
		0x08, 0x00, 0x45, 0x00, 0x00, 0x96, 0x12, 0x34, 0x40, 0x00, 0x20, 0x11, 0xa3, 0x65, 0xc0, 0x10,
		                                                               // two octets must set 00
		0x20, 0x03, 0xc0, 0x98, 0x04, 0x12, 0x06, 0xa5, 0x06, 0xa5, 0x00, 0x82, 0x00, 0x00, 0x02, 0x02,
		0x51, 0xbe, 0x25, 0x66, 0x00, 0x00, 0xff, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x6e, 0x00, 0x00,
		0x00, 0x00, 0xfe, 0x06, 0x97, 0x10, 0xb1, 0xb2, 0xb3, 0xb4, 0xa0, 0x10, 0x20, 0x02, 0x20, 0x18,
		0x04, 0x04, 0x00, 0x01, 0xe2, 0x40, 0x00, 0x03, 0x94, 0x47, 0x50, 0x10, 0x10, 0x00, 0xca, 0xc3,
		0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
		0x2e, 0x2f, 0x30, 0x31, 0xf1, 0x66, 0xc4, 0xce, 0x07, 0x01, 0xa1, 0x94, 0x37, 0x6f, 0xa0, 0xdc,
		0x07, 0xc0, 0x5b, 0x8c, 0x55, 0x55, 0xca, 0x7c		
	};
#else
	uint8_t arr[] = {
		0x80, 0xb0, 0x01, 0x02, 0x03, 0x04, 0x80, 0xb0, 0x11, 0x12, 0x13, 0x14, 0x81, 0x00, 0x81, 0x67,
		0x08, 0x00, 0x45, 0x00, 0x00, 0x97, 0x12, 0x34, 0x40, 0x00, 0x20, 0x11, 0xa3, 0x64, 0xc0, 0x10,
		                                                               // two octets must set 00
		0x20, 0x03, 0xc0, 0x98, 0x04, 0x12, 0x06, 0xa5, 0x06, 0xa5, 0x00, 0x83, 0xaa, 0xcc, 0x02, 0x02,
		0x51, 0xbe, 0x25, 0x66, 0x00, 0x00, 0xff, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x6e, 0x00, 0x00,
		0x00, 0x00, 0xfe, 0x06, 0x97, 0x10, 0xb1, 0xb2, 0xb3, 0xb4, 0xa0, 0x10, 0x20, 0x02, 0x20, 0x18,
		0x04, 0x04, 0x00, 0x01, 0xe2, 0x40, 0x00, 0x03, 0x94, 0x47, 0x50, 0x10, 0x10, 0x00, 0xca, 0xc3,
		0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
		0x2e, 0x2f, 0x30, 0x31, 0xf1, 0x66, 0xc4, 0xce, 0x07, 0x01, 0xa1, 0x94, 0x37, 0x6f, 0xa0, 0xdc,
		0x07, 0xc0, 0x5b, 0x8c, 0x55, 0x55, 0xca, 0x7c, 0x11		
	};
#endif	
	printf("arr len = %u\n", sizeof(arr)/sizeof(uint8_t));
	
	// Convert pointer
	uint16_t *p = (uint16_t *)arr;
	// Find the IP header
	uint16_t *ip = p + 15;
	// Protocol type
	uint16_t pt = 0x0011;
	// Find UDP length 
	uint16_t *l = p + 21;
	udp_len = (((*l<<8)&0xFF00) + ((*l>>8)&0xFF));
	if (udp_len&1) {
		printf("padding needed\n");
		pad=1;
	}
	// Sum of pseudo header
	sum += (pt + udp_len);
	printf("len=%u, sum0= %04x\n", udp_len, sum);
	for(i=0; i<4; i++){
		s = (((ip[i]<<8)&0xFF00) + ((ip[i]>>8)&0xFF));
		printf("ip[%u]=%04x ", i, s);
		sum += s;
	}
	printf("sum1= %08x\n", sum);

	// Find start of UDP header
	uint16_t *u = p + 19;
	for(i=0; i<(udp_len+pad)/2; i++){
		if(3==i) continue;
		s = (((u[i]<<8)&0xFF00) + ((u[i]>>8)&0xFF));
		//printf("%2u:%04x\n", i,s);
		sum += s;		
	}	
	
	printf("sum2= %08x\n", sum);
	
    while (sum>>16)
		sum = (sum & 0xFFFF)+(sum >> 16);
		
	// Take the one's complement of sum
	printf("sum3= %08x\n", sum);
	sum = ~sum;	
	
#if 1	
	// Write back to array
	printf("u3=%02x %02x\n", ((sum & 0xFF00) >> 8), sum & 0x00FF);
	// It is the computed checksum
	u[3] = ((sum & 0xFF00) >> 8) +(( sum & 0x00FF) << 8);
	printf("u3=%04x\n", u[3]);
	dump_byte((uint8_t *)u, udp_len);
#endif	
	return sum;
}	

main()
{
   uint8_t ttl = 0x80;
   union tos old_tos, new_tos;
   
   old_tos.s.dscp = 0x0;
   old_tos.s.ecn=0;
   new_tos.s.dscp = 0x3;
   new_tos.s.ecn=0;   
   printf("old tos=%02x, new tos= %02x\n", old_tos.v, new_tos.v);
   
   printf("cs2 %04x\n", csum_update2(0xf95b, old_tos.v, new_tos.v));
   //printf("cs1 %04x\n", csum_update1(0xf95b,ttl, ttl-1));
   
   /* If tos is not an union as described in struct ip4_dw0 
      // Assign new DSCP value and print buf
      // http://stackoverflow.com/questions/3415298/best-way-to-overwrite-some-bits-in-a-particular-range 
    */
#define n_lsb(x)  (1 << x) - 1
#define n_to_m(n, m) n_lsb(n) & ~ n_lsb(m)   
   //printf("n_lsb=%04x\n", n_to_m(8,1));
   
   uint8_t buf[4] = {0x45, 0x0C, 0x01, 0x23};
   struct ip4_dw0 *ip40;
   ip40 = (struct ip4_dw0 *)&buf[0];
   printf("tos=%02x, dscp= %02x, ecn=%x ", ip40->tos, ((ip40->tos)>>2)&0x3F, ((ip40->tos)&0x3)); 
   // tos = 00101000, dscn mask = 11111100
   ip40->tos = (ip40->tos & ~0xFC) | (0xA << 2);
   printf(":%02x %02x %02x %02x: ", buf[0], buf[1], buf[2], buf[3]);
   printf("new tos=%02x, dscp= %02x, ecn=%x\n", ip40->tos, ((ip40->tos)>>2)&0x3F, ((ip40->tos)&0x3));
   
   ////////////////////////////////////////////////
   
   int choose, sel = 15;
   choose  = ((7 < sel && sel < 15) ? 0xF: 0x0);
   printf("choose = %0x\n", choose);
   
   ////////////////////////////////////////////////
   
   struct ip6 ip0 = {0xAAAA0001, 0x00010001, 0x00010001, 0x00010001};
   struct ip6 ip1 = {0xBAAA0001, 0x00010002, 0x00010003, 0x00010004};
   uint16_t d;
   
   d = csum_update4(0xe2f6,     ip0.ad[0], ip1.ad[0]);
   
   d = csum_update4(d, ip0.ad[1], ip1.ad[1]);
   
   d = csum_update4(d, ip0.ad[2], ip1.ad[2]);
   
   d = csum_update4(d, ip0.ad[3], ip1.ad[3]);
   printf("\ncs4 ip6= %04x\n", d);

   printf("UDP csum=%04x\n", udp_csum());
}


