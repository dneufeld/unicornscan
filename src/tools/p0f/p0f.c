/*

  p0f - passive OS fingerprinting 
  -------------------------------

  "If you sit down at a poker game and don't see a sucker, 
  get up. You're the sucker."

  (C) Copyright 2000-2003 by Michal Zalewski <lcamtuf@coredump.cx>

  WIN32 port (C) Copyright 2003 by Michael A. Davis <mike@datanerds.net>
             (C) Copyright 2003 by Kirby Kuehl <kkuehl@cisco.com>

*/

#include <config.h>
#include <settings.h>

#include <unilib/output.h>

#include <ctype.h>
#include <stdarg.h>

/* #define DEBUG_HASH - display signature hash table stats */

#include "p0f-config.h"
#include "tcp.h"
#include "mtu.h"
#include "tos.h"
#include "fpentry.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif /* ! MSG_NOSIGNAL */

static struct fp_entry sig[MAXSIGS];
static uint32_t sigcnt,gencnt;

/* By hash */
static struct fp_entry* bh[16];

#define SIGHASH(tsize,optcnt,q,df) \
	(( (uint8_t) (((tsize) << 1) ^ ((optcnt) << 1) ^ (df) ^ (q) )) & 0x0f)

#define FATAL(fmt, args...) \
	do { \
		ERR(fmt, ## args); \
		return; \
	} while (0)

static uint32_t pkcnt;
static uint8_t problems;

static void outbuf_add(const char *, ...) __attribute__((format(printf, 1, 2)));
static void outbuf_reset(void);
static char *outbuf_return(void);

static uint8_t no_extra,
           no_osdesc,
           no_known,
           no_unknown,
           ack_mode,
           rst_mode,
           always_sig,
           check_collide,
           use_fuzzy;


void set_ackmode(void) {
	ack_mode=1; rst_mode=0;
}

void set_rstmode(void) {
	rst_mode=1; ack_mode=0;
}
void set_fuzzy(void) {
	use_fuzzy=1;
}

static void collide(uint32_t id) {
  uint32_t i,j;
  uint32_t cur;

  if (sig[id].ttl % 32 && sig[id].ttl != 255 && sig[id].ttl % 30) {
    problems=1;
    ERR("[!] Unusual TTL (%d) for signature '%s %s' (line %d).",
          sig[id].ttl, sig[id].os, sig[id].desc, sig[id].line
    );
  }

  for (i=0;i<id;i++) {

    if (!strcmp(sig[i].os,sig[id].os) && 
        !strcmp(sig[i].desc,sig[id].desc)) {
      problems=1;
      ERR("[!] Duplicate signature name: '%s %s' (line %d and %d).\n",
            sig[i].os,sig[i].desc,sig[i].line,sig[id].line);
    }

    /* If TTLs are sufficiently away from each other, the risk of
       a collision is lower. */
    if (abs((int32_t)sig[id].ttl - (int32_t)sig[i].ttl) > 25) continue;

    if (sig[id].df ^ sig[i].df) continue;
    if (sig[id].zero_stamp ^ sig[i].zero_stamp) continue;

    /* Zero means >= PACKET_BIG */
    if (sig[id].size) { if (sig[id].size ^ sig[i].size) continue; }
      else if (sig[i].size < PACKET_BIG) continue;

    if (sig[id].optcnt ^ sig[i].optcnt) continue;
    if (sig[id].quirks ^ sig[i].quirks) continue;

    switch (sig[id].wsize_mod) {

      case 0: /* Current: const */

        cur=sig[id].wsize;

do_const:

        switch (sig[i].wsize_mod) {
       
          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].wsize) continue; 
            break;

          case MOD_CONST: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].wsize) continue;
            break;

          case MOD_MSS: /* Current: const, prev: mod MSS */

            if (sig[i].mss_mod || sig[i].wsize *
	       (sig[i].mss ? sig[i].mss : 1460 ) != cur)
              continue;

            break;

          case MOD_MTU: /* Current: const, prev: mod MTU */

            if (sig[i].mss_mod || sig[i].wsize * (
	        (sig[i].mss ? sig[i].mss : 1460 )+40) != cur)
              continue;

            break;

        }
        
        break;

      case 1: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the 
           previous modulo */

        if (sig[i].wsize_mod != MOD_CONST) continue;
        if (sig[id].wsize % sig[i].wsize) continue;

        break;

      case MOD_MSS: /* Current is modulo MSS */
  
        /* There's likely a problem only if the previous one is close
           to '*'; we do not check known MTUs, because this particular
           signature can be made with some uncommon MTUs in mind. The
           problem would also appear if current signature has a fixed
           MSS. */

        if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize >= 8) {
          if (!sig[id].mss_mod) {
            cur = (sig[id].mss ? sig[id].mss : 1460 ) * sig[id].wsize;
            goto do_const;
          }
          continue;
        }

        break;

      case MOD_MTU: /* Current is modulo MTU */

        if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize <= 8) {
          if (!sig[id].mss_mod) {
            cur = ( (sig[id].mss ? sig[id].mss : 1460 ) +40) * sig[id].wsize;
            goto do_const;
          }
          continue;
        }
  
        break;

    }

    /* Same for wsc */
    switch (sig[id].wsc_mod) {

      case 0: /* Current: const */

        cur=sig[id].wsc;

        switch (sig[i].wsc_mod) {
       
          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].wsc) continue; 
            break;

          case 1: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].wsc) continue;
            break;

        }
        
        break;

      case MOD_CONST: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the 
           previous modulo */

        if (!sig[i].wsc_mod) continue;
        if (sig[id].wsc % sig[i].wsc) continue;

        break;

     }

    /* Same for mss */
    switch (sig[id].mss_mod) {

      case 0: /* Current: const */

        cur=sig[id].mss;

        switch (sig[i].mss_mod) {
       
          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].mss) continue; 
            break;

          case 1: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].mss) continue;
            break;

        }
        
        break;

      case MOD_CONST: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the 
           previous modulo */

        if (!sig[i].mss_mod) continue;
        if ((sig[id].mss ? sig[id].mss : 1460 ) % 
	    (sig[i].mss ? sig[i].mss : 1460 )) continue;

        break;

     }

     /* Now check option sequence */

    for (j=0;j<sig[id].optcnt;j++)
      if (sig[id].opt[j] ^ sig[i].opt[j]) goto reloop;

    problems=1;
    ERR("[!] Signature '%s %s' (line %d)\n"
          "    is already covered by '%s %s' (line %d).\n",
          sig[id].os,sig[id].desc,sig[id].line,sig[i].os,sig[i].desc,
          sig[i].line);

reloop:

    ;

  }

}


void load_config(void) {
  uint32_t ln=0;
  uint8_t buf[MAXLINE];
  uint8_t* p;
  const char *cf=NULL;
  FILE *c=NULL;

  if (ack_mode) {
    cf=SYSCONFDIR "/" SYNACK_DB;
  }
  else {
    cf=SYSCONFDIR "/" RST_DB;
  }
  c = fopen(cf ,"r");

  if (c == NULL) {
    FATAL("cant open config file `%s'", cf);
    return;
  }

  while ((p=fgets(buf,sizeof(buf),c))) {
    uint32_t l;

    uint8_t obuf[MAXLINE],genre[MAXLINE],desc[MAXLINE],quirks[MAXLINE];
    uint8_t w[MAXLINE],sb[MAXLINE];
    uint8_t* gptr = genre;
    uint32_t t,d,_s;
    struct fp_entry* e;
      
    ln++;

    /* Remove leading and trailing blanks */
    while (isspace(*p)) p++;
    l=strlen(p);
    while (l && isspace(*(p+l-1))) *(p+(l--)-1)=0;
	
    /* Skip empty lines and comments */
    if (!l) continue;
    if (*p == '#') continue;

    if (sscanf(p,"%[0-9%*()ST]:%d:%d:%[0-9()*]:%[^:]:%[^ :]:%[^:]:%[^:]",
                  w,         &t,&d,sb,     obuf, quirks,genre,desc) != 8)
      FATAL("Syntax error in config line %d.\n",ln);

    gptr = genre;

    if (*sb != '*') _s = atoi(sb); else _s = 0;

reparse_ptr:

    switch (*gptr) {
      case '-': sig[sigcnt].userland = 1; gptr++; goto reparse_ptr;
      case '*': sig[sigcnt].no_detail = 1; gptr++; goto reparse_ptr;
      case '@': sig[sigcnt].generic = 1; gptr++; gencnt++; goto reparse_ptr;
      case 0: FATAL("Empty OS genre in line %d.\n",ln);
    }

    sig[sigcnt].os     = strdup(gptr);
    sig[sigcnt].desc   = strdup(desc);
    sig[sigcnt].ttl    = t;
    sig[sigcnt].size   = _s;
    sig[sigcnt].df     = d;
 
    if (w[0] == '*') {
      sig[sigcnt].wsize = 1;
      sig[sigcnt].wsize_mod = MOD_CONST;
    } else if (tolower(w[0]) == 's') {
      sig[sigcnt].wsize_mod = MOD_MSS;
      if (!isdigit(*(w+1))) FATAL("Bad Snn value in WSS in line %d.\n",ln);
      sig[sigcnt].wsize = atoi(w+1);
    } else if (tolower(w[0]) == 't') {
      sig[sigcnt].wsize_mod = MOD_MTU;
      if (!isdigit(*(w+1))) FATAL("Bad Tnn value in WSS in line %d.\n",ln);
      sig[sigcnt].wsize = atoi(w+1);
    } else if (w[0] == '%') {
      if (!(sig[sigcnt].wsize = atoi(w+1)))
        FATAL("Null modulo for window size in config line %d.\n",ln);
      sig[sigcnt].wsize_mod = MOD_CONST;
    } else sig[sigcnt].wsize = atoi(w);

    /* Now let's parse options */

    p=obuf;

    sig[sigcnt].zero_stamp = 1;

    if (*p=='.') p++;

    while (*p) {
      uint8_t optcnt = sig[sigcnt].optcnt;
      switch (tolower(*p)) {

        case 'n': sig[sigcnt].opt[optcnt] = TCPOPT_NOP;
                  break;

        case 'e': sig[sigcnt].opt[optcnt] = TCPOPT_EOL;
                  if (*(p+1)) 
                    FATAL("EOL not the last option (line %d).\n",ln);
                  break;

        case 's': sig[sigcnt].opt[optcnt] = TCPOPT_SACKOK;
                  break;

        case 't': sig[sigcnt].opt[optcnt] = TCPOPT_TIMESTAMP;
                  if (*(p+1)!='0') {
                    sig[sigcnt].zero_stamp=0;
                    if (isdigit(*(p+1))) 
                      FATAL("Bogus Tstamp specification in line %d.\n",ln);
                  }
                  break;

        case 'w': sig[sigcnt].opt[optcnt] = TCPOPT_WSCALE;
                  if (p[1] == '*') {
                    sig[sigcnt].wsc = 1;
                    sig[sigcnt].wsc_mod = MOD_CONST;
                  } else if (p[1] == '%') {
                    if (!(sig[sigcnt].wsc = atoi(p+2)))
                      FATAL("Null modulo for wscale in config line %d.\n",ln);
                    sig[sigcnt].wsc_mod = MOD_CONST;
                  } else if (!isdigit(*(p+1)))
                    FATAL("Incorrect W value in line %d.\n",ln);
                  else sig[sigcnt].wsc = atoi(p+1);
                  break;

        case 'm': sig[sigcnt].opt[optcnt] = TCPOPT_MAXSEG;
                  if (p[1] == '*') {
                    sig[sigcnt].mss = 1;
                    sig[sigcnt].mss_mod = MOD_CONST;
                  } else if (p[1] == '%') {
                    if (!(sig[sigcnt].mss = atoi(p+2)))
                      FATAL("Null modulo for MSS in config line %d.\n",ln);
                    sig[sigcnt].mss_mod = MOD_CONST;
                  } else if (!isdigit(*(p+1)))
                    FATAL("Incorrect M value in line %d.\n",ln);
                  else sig[sigcnt].mss = atoi(p+1);
                  break;

        /* Yuck! */
        case '?': if (!isdigit(*(p+1)))
                    FATAL("Bogus ?nn value in line %d.\n",ln);
                  else sig[sigcnt].opt[optcnt] = atoi(p+1);
                  break;

        default: FATAL("Unknown TCP option '%c' in config line %d.\n",*p,ln);
      }

      if (++sig[sigcnt].optcnt >= MAXOPT) 
        FATAL("Too many TCP options specified in config line %d.\n",ln);

      /* Skip separators */
      do { p++; } while (*p && !isalpha(*p) && *p != '?');

    }
 
    sig[sigcnt].line = ln;

    p = quirks;

    while (*p) 
      switch (toupper(*(p++))) {
        case 'E': 
          FATAL("Quirk 'E' (line %d) is obsolete. Remove it, append E to the "
          "options.\n",ln);

        case 'K': 
	  if (!rst_mode) FATAL("Quirk 'K' (line %d) is valid only in RST+ (-R)"
	      " mode (wrong config file?).\n",ln);
  	  sig[sigcnt].quirks |= QUIRK_RSTACK; 
	  break;
	  
        case 'Q': sig[sigcnt].quirks |= QUIRK_SEQEQ; break;
        case '0': sig[sigcnt].quirks |= QUIRK_SEQ0; break;
        case 'P': sig[sigcnt].quirks |= QUIRK_PAST; break;
        case 'Z': sig[sigcnt].quirks |= QUIRK_ZEROID; break;
        case 'I': sig[sigcnt].quirks |= QUIRK_IPOPT; break;
        case 'U': sig[sigcnt].quirks |= QUIRK_URG; break;
        case 'X': sig[sigcnt].quirks |= QUIRK_X2; break;
        case 'A': sig[sigcnt].quirks |= QUIRK_ACK; break;
        case 'T': sig[sigcnt].quirks |= QUIRK_T2; break;
        case 'F': sig[sigcnt].quirks |= QUIRK_FLAGS; break;
        case 'D': sig[sigcnt].quirks |= QUIRK_DATA; break;
        case '!': sig[sigcnt].quirks |= QUIRK_BROKEN; break;
        case '.': break;
        default: FATAL("Bad quirk '%c' in line %d.\n",*(p-1),ln);
      }

    e = bh[SIGHASH(_s,sig[sigcnt].optcnt,sig[sigcnt].quirks,d)];

    if (!e) {
      bh[SIGHASH(_s,sig[sigcnt].optcnt,sig[sigcnt].quirks,d)] = sig + sigcnt;
    } else {
      while (e->next) e = e->next;
      e->next = sig + sigcnt;
    } 

    if (check_collide) collide(sigcnt);

    if (++sigcnt >= MAXSIGS)
      FATAL("Maximum signature count exceeded.\n");

  }

  fclose(c);

  if (!sigcnt)
    ERR("[!] WARNING: no signatures loaded from config file.\n");

}




static uint8_t* lookup_link(uint16_t mss,uint8_t txt) {
  uint32_t i;
  static uint8_t tmp[32];

  if (!mss) return txt ? "unspecified" : 0;
  mss += 40;
  
  for (i=0;i<MTU_CNT;i++) {
   if (mss == mtu[i].mtu) return mtu[i].dev;
   if (mss < mtu[i].mtu)  goto unknown;
  }

unknown:

  if (!txt) return 0;
  sprintf(tmp,"unknown-%d",mss);
  return tmp;

}


static uint8_t* lookup_tos(uint8_t t) {
  uint32_t i;

  if (!t) return 0;

  for (i=0;i<TOS_CNT;i++) {
   if (t == tos[i].tos) return tos[i].desc;
   if (t < tos[i].tos) break;
  }

  return 0;

}

static inline void display_signature(uint8_t ttl,uint16_t tot,uint8_t df,uint8_t* op,uint8_t ocnt,
                                     uint16_t mss,uint16_t wss,uint8_t wsc,uint32_t tstamp,
                                     uint32_t quirks) {

  uint32_t j;
  uint8_t d=0;

  if (mss && wss && !(wss % mss)) outbuf_add("S%d",wss/mss); else
  if (wss && !(wss % 1460)) outbuf_add("S%d",wss/1460); else
  if (mss && wss && !(wss % (mss+40))) outbuf_add("T%d",wss/(mss+40)); else
  if (wss && !(wss % 1500)) outbuf_add("T%d",wss/1500); else
  if (wss == 12345) outbuf_add("*(12345)"); else outbuf_add("%d",wss);

  if (tot < PACKET_BIG) outbuf_add(":%d:%d:%d:",ttl,df,tot);
  else outbuf_add(":%d:%d:*(%d):",ttl,df,tot);

  for (j=0;j<ocnt;j++) {
    switch (op[j]) {
      case TCPOPT_NOP: outbuf_add("%c", 'N'); d=1; break;
      case TCPOPT_WSCALE: outbuf_add("W%d",wsc); d=1; break;
      case TCPOPT_MAXSEG: outbuf_add("M%d",mss); d=1; break;
      case TCPOPT_TIMESTAMP: outbuf_add("%c",'T'); 
        if (!tstamp) outbuf_add("%c",'0'); d=1; break;
      case TCPOPT_SACKOK: outbuf_add("%c",'S'); d=1; break;
      case TCPOPT_EOL: outbuf_add("%c",'E'); d=1; break;
      default: outbuf_add("?%d",op[j]); d=1; break;
    }
    if (j != ocnt-1) outbuf_add("%c",',');
  }

  if (!d) outbuf_add("%c",'.');

  outbuf_add("%c",':');

  if (!quirks) outbuf_add("%c",'.'); else {
    if (quirks & QUIRK_RSTACK) outbuf_add("%c",'K');
    if (quirks & QUIRK_SEQEQ) outbuf_add("%c",'Q');
    if (quirks & QUIRK_SEQ0) outbuf_add("%c",'0');
    if (quirks & QUIRK_PAST) outbuf_add("%c",'P');
    if (quirks & QUIRK_ZEROID) outbuf_add("%c",'Z');
    if (quirks & QUIRK_IPOPT) outbuf_add("%c",'I');
    if (quirks & QUIRK_URG) outbuf_add("%c",'U');
    if (quirks & QUIRK_X2) outbuf_add("%c",'X');
    if (quirks & QUIRK_ACK) outbuf_add("%c",'A');
    if (quirks & QUIRK_T2) outbuf_add("%c",'T');
    if (quirks & QUIRK_FLAGS) outbuf_add("%c",'F');
    if (quirks & QUIRK_DATA) outbuf_add("%c",'D');
    if (quirks & QUIRK_BROKEN) outbuf_add("%c",'!');
  }

}


static inline void find_match(uint16_t tot,uint8_t df,uint8_t ttl,uint16_t wss,uint32_t src,
                       uint32_t dst,uint16_t sp,uint16_t dp,uint8_t ocnt,uint8_t* op,uint16_t mss,
                       uint8_t wsc,uint32_t tstamp,uint8_t _tos,uint32_t quirks,uint8_t ecn,
                       uint8_t* pkt,uint8_t plen,uint8_t* pay) {

  uint32_t j;
  uint8_t* a;
  uint8_t  nat=0;
  struct fp_entry* p;
  uint8_t  orig_df  = df;
  uint8_t* tos_desc = 0;

  struct fp_entry* fuzzy = 0;
  uint8_t fuzzy_now = 0;

re_lookup:

  p = bh[SIGHASH(tot,ocnt,quirks,df)];

  if (_tos) tos_desc = lookup_tos(_tos);

  while (p) {
  
    /* Cheap and specific checks first... */

    /* psize set to zero means >= PACKET_BIG */
    if (p->size) { if (tot ^ p->size) { p = p->next; continue; } }
      else if (tot < PACKET_BIG) { p = p->next; continue; }

    if (ocnt ^ p->optcnt) { p = p->next; continue; }

    if (p->zero_stamp ^ (!tstamp)) { p = p->next; continue; }
    if (p->df ^ df) { p = p->next; continue; }
    if (p->quirks ^ quirks) { p = p->next; continue; }

    /* Check MSS and WSCALE... */
    if (!p->mss_mod) {
      if (mss ^ p->mss) { p = p->next; continue; }
    } else if (mss % p->mss) { p = p->next; continue; }

    if (!p->wsc_mod) {
      if (wsc ^ p->wsc) { p = p->next; continue; }
    } else if (wsc % p->wsc) { p = p->next; continue; }

    /* Then proceed with the most complex WSS check... */
    switch (p->wsize_mod) {
      case 0:
        if (wss ^ p->wsize) { p = p->next; continue; }
        break;
      case MOD_CONST:
        if (wss % p->wsize) { p = p->next; continue; }
        break;
      case MOD_MSS:
        if (mss && !(wss % mss)) {
          if ((wss / mss) ^ p->wsize) { p = p->next; continue; }
        } else if (!(wss % 1460)) {
          if ((wss / 1460) ^ p->wsize) { p = p->next; continue; }
        } else { p = p->next; continue; }
        break;
      case MOD_MTU:
        if (mss && !(wss % (mss+40))) {
          if ((wss / (mss+40)) ^ p->wsize) { p = p->next; continue; }
        } else if (!(wss % 1500)) {
          if ((wss / 1500) ^ p->wsize) { p = p->next; continue; }
        } else { p = p->next; continue; }
        break;
     }

    /* Numbers agree. Let's check options */

    for (j=0;j<ocnt;j++)
      if (p->opt[j] ^ op[j]) goto continue_search;

    /* Check TTLs last because we might want to go fuzzy. */
    if (p->ttl < ttl) {
      if (use_fuzzy) fuzzy = p;
      p = p->next;
      continue;
    }

    /* Naah... can't happen ;-) */
    if (!p->no_detail)
      if (p->ttl - ttl > MAXDIST) { 
        if (use_fuzzy) fuzzy = p;
        p = p->next; 
        continue; 
      }

continue_fuzzy:    
    
    /* Match! */

    if (mss & wss) {
      if (p->wsize_mod == MOD_MSS) {
        if ((wss % mss) && !(wss % 1460)) nat=1;
      } else if (p->wsize_mod == MOD_MTU) {
        if ((wss % (mss+40)) && !(wss % 1500)) nat=2;
      }
    }

    if (!no_known) {

      a=(uint8_t*)&src;

      outbuf_add("%s ",p->os);

      if (!no_osdesc) outbuf_add("%s ",p->desc);

      if (nat == 1) outbuf_add("(NAT!) "); else
        if (nat == 2) outbuf_add("(NAT2!) ");

      if (ecn) outbuf_add("(ECN) ");
      if (orig_df ^ df) outbuf_add("(firewall!) ");

      if (_tos) {
        if (tos_desc) outbuf_add("[%s] ",tos_desc); else outbuf_add("[tos %d] ",_tos);
      }

      if (p->generic) outbuf_add("[GENERIC] ");
      if (fuzzy_now) outbuf_add("[FUZZY] ");

      if (p->no_detail) outbuf_add("* "); else
        if (tstamp) outbuf_add("up: %d hrs ",tstamp/360000);

      if (always_sig || (p->generic && !no_unknown)) {

        outbuf_add("Signature: [");

        display_signature(ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks);

        if (p->generic)
          outbuf_add(":%s:?] ",p->os);
        else
          outbuf_add("] ");

      }

      if (!no_extra && !p->no_detail) {
	a=(uint8_t*)&dst;

        if (fuzzy_now) 
          outbuf_add(" link: %s",
               lookup_link(mss,1));
        else
          outbuf_add(" distance %d, link: %s",
                 p->ttl - ttl,
                 lookup_link(mss,1));
      }

    }

    return;

continue_search:

    p = p->next;

  }

  if (!df) { df = 1; goto re_lookup; }

  if (use_fuzzy && fuzzy) {
    df = orig_df;
    fuzzy_now = 1;
    p = fuzzy;
    fuzzy = 0;
    goto continue_fuzzy;
  }

  if (mss & wss) {
    if ((wss % mss) && !(wss % 1460)) nat=1;
    else if ((wss % (mss+40)) && !(wss % 1500)) nat=2;
  }

  if (!no_unknown) { 
    a=(uint8_t*)&src;
    outbuf_add("UNKNOWN [");

    display_signature(ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks);

    outbuf_add(":?:?] ");

    if (rst_mode) {

      /* Display a reasonable diagnosis of the RST+ACK madness! */
 
      switch (quirks & (QUIRK_RSTACK | QUIRK_SEQ0 | QUIRK_ACK)) {

        /* RST+ACK, SEQ=0, ACK=0 */
        case QUIRK_RSTACK | QUIRK_SEQ0:
          outbuf_add("(invalid-K0) "); break;

        /* RST+ACK, SEQ=0, ACK=n */
        case QUIRK_RSTACK | QUIRK_ACK | QUIRK_SEQ0: 
          outbuf_add("(refused) "); break;
 
        /* RST+ACK, SEQ=n, ACK=0 */
        case QUIRK_RSTACK: 
          outbuf_add("(invalid-K) "); break;

        /* RST+ACK, SEQ=n, ACK=n */
        case QUIRK_RSTACK | QUIRK_ACK: 
          outbuf_add("(invalid-KA) "); break; 

        /* RST, SEQ=n, ACK=0 */
        case 0:
          outbuf_add("(dropped) "); break;

        /* RST, SEQ=m, ACK=n */
        case QUIRK_ACK: 
          outbuf_add("(dropped 2) "); break;
 
        /* RST, SEQ=0, ACK=0 */
        case QUIRK_SEQ0: 
          outbuf_add("(invalid-0) "); break;

        /* RST, SEQ=0, ACK=n */
        case QUIRK_ACK | QUIRK_SEQ0: 
          outbuf_add("(invalid-0A) "); break; 

      }

    }

    if (nat == 1) outbuf_add("(NAT!) ");
      else if (nat == 2) outbuf_add("(NAT2!) ");

    if (ecn) outbuf_add("(ECN) ");

    if (_tos) {
      if (tos_desc) outbuf_add("[%s] ",tos_desc); else outbuf_add("[tos %d] ",_tos);
    }

    if (tstamp) outbuf_add("up: %d hrs ",tstamp/360000);

    if (!no_extra) {
      a=(uint8_t*)&dst;
      outbuf_add(" link: %s", lookup_link(mss,1));
    }

    fflush(0);

  }

}


#define GET16(p) \
        ((uint16_t) *((uint8_t*)(p)+0) << 8 | \
         (uint16_t) *((uint8_t*)(p)+1) )


char *p0f_parse(const uint8_t* packet, uint16_t pklen) {
  const struct ip_header *iph;
  const struct tcp_header *tcph;
  const uint8_t*   end_ptr;
  const uint8_t*   opt_ptr;
  const uint8_t*   pay = 0;
  int32_t   ilen,olen;

  uint8_t    op[MAXOPT];
  uint8_t    ocnt = 0;
  uint16_t   mss_val = 0, wsc_val = 0;
  uint32_t   tstamp = 0;
  uint32_t   quirks = 0;

  pkcnt++;

  outbuf_reset();

  /* Paranoia! */
  end_ptr = packet + pklen;

  iph = (const struct ip_header*)(packet);

  /* Whoops, IP header ends past end_ptr */
  if ((const uint8_t*)(iph + 1) > end_ptr) return NULL;

  if ( ((iph->ihl & 0x40) != 0x40) || iph->proto != IPPROTO_TCP) {
    return NULL;
  }

  /* If the declared length is shorter than the snapshot (etherleak
     or such), truncate this bad boy. */

  opt_ptr = (const uint8_t*)iph + htons(iph->tot_len);
  if (end_ptr > opt_ptr) end_ptr = opt_ptr;

  ilen = iph->ihl & 15;

  /* Borken packet */
  if (ilen < 5) return NULL;

  if (ilen > 5) {

    quirks |= QUIRK_IPOPT;
  }

  tcph = (const struct tcp_header*)(packet + (ilen << 2));
  opt_ptr = (const uint8_t*)(tcph + 1);

  if (ack_mode && (tcph->flags & (TH_ACK|TH_SYN)) != (TH_ACK|TH_SYN)) return NULL;
  if (rst_mode && (tcph->flags & TH_RST) != TH_RST) return NULL;
    
  /* Whoops, TCP header would end past end_ptr */
  if (opt_ptr > end_ptr) return NULL;

  if (rst_mode && (tcph->flags & TH_ACK)) quirks |= QUIRK_RSTACK;
 
  if (tcph->seq == tcph->ack) quirks |= QUIRK_SEQEQ;
  if (!tcph->seq) quirks |= QUIRK_SEQ0;
 
  if (tcph->flags & ~(TH_SYN|TH_ACK|TH_RST|TH_ECE|TH_CWR)) 
    quirks |= QUIRK_FLAGS;

  ilen=((tcph->doff) << 2) - sizeof(struct tcp_header);
  
  if ( (const uint8_t*)opt_ptr + ilen < end_ptr) { 
  
#ifdef DEBUG_EXTRAS
    uint32_t i;
    
    outbuf_add("  -- EXTRA PAYLOAD (packet below): ");
    
    for (i=0;i< (uint32_t)end_ptr - ilen - (uint32_t)opt_ptr;i++)
      outbuf_add("%02x ",*(opt_ptr + ilen + i));

    outbuf_add("%c",'\n');
    fflush(0);
#endif /* DEBUG_EXTRAS */
  
    quirks |= QUIRK_DATA;
    pay = opt_ptr + ilen;
   
  }

  while (ilen > 0) {

    ilen--;

    switch (*(opt_ptr++)) {
      case TCPOPT_EOL:  
        /* EOL */
        op[ocnt] = TCPOPT_EOL;
        ocnt++;

        if (ilen) {

          quirks |= QUIRK_PAST;

        }

        /* This goto will be probably removed at some point. */
        goto end_parsing;

      case TCPOPT_NOP:
        /* NOP */
        op[ocnt] = TCPOPT_NOP;
        ocnt++;
        break;

      case TCPOPT_SACKOK:
        /* SACKOK LEN */
        op[ocnt] = TCPOPT_SACKOK;
        ocnt++; ilen--; opt_ptr++;
        break;
	
      case TCPOPT_MAXSEG:
        /* MSS LEN D0 D1 */
        if (opt_ptr + 3 > end_ptr) {
borken:
          quirks |= QUIRK_BROKEN;
          goto end_parsing;
        }
        op[ocnt] = TCPOPT_MAXSEG;
        mss_val = GET16(opt_ptr+1);
        ocnt++; ilen -= 3; opt_ptr += 3;
        break;

      case TCPOPT_WSCALE:
        /* WSCALE LEN D0 */
        if (opt_ptr + 2 > end_ptr) goto borken;
        op[ocnt] = TCPOPT_WSCALE;
        wsc_val = *(uint8_t *)(opt_ptr + 1);
        ocnt++; ilen -= 2; opt_ptr += 2;
        break;

      case TCPOPT_TIMESTAMP:
        /* TSTAMP LEN T0 T1 T2 T3 A0 A1 A2 A3 */
        if (opt_ptr + 9 > end_ptr) goto borken;
        op[ocnt] = TCPOPT_TIMESTAMP;

	memcpy(&tstamp, opt_ptr+5, 4);
        if (tstamp) quirks |= QUIRK_T2;

	memcpy(&tstamp, opt_ptr+1, 4);
        tstamp = ntohl(tstamp);

        ocnt++; ilen -= 9; opt_ptr += 9;
        break;

      default:

        /* Hrmpf... */
        if (opt_ptr + 1 > end_ptr) goto borken;

        op[ocnt] = *(opt_ptr-1);
        olen = *(uint8_t*)(opt_ptr)-1;
        if (olen > 32 || (olen < 0)) goto borken;

        ocnt++; ilen -= olen; opt_ptr += olen;
        break;

     }

     if (ocnt >= MAXOPT-1) goto borken;

     /* Whoops, we're past end_ptr */
     if (ilen > 0)
       if (opt_ptr >= end_ptr) goto borken;

   }

end_parsing:

   if (tcph->ack) quirks |= QUIRK_ACK;
   if (tcph->urg) quirks |= QUIRK_URG;
   if (tcph->_x2) quirks |= QUIRK_X2;
   if (!iph->id)  quirks |= QUIRK_ZEROID;

   find_match(
     /* total */ ntohs(iph->tot_len),
     /* DF */    (ntohs(iph->off) & IP_DF) != 0,
     /* TTL */   iph->ttl,
     /* WSS */   ntohs(tcph->win),
     /* src */   iph->saddr,
     /* dst */   iph->daddr,
     /* sp */    ntohs(tcph->sport),
     /* dp */    ntohs(tcph->dport),
     /* ocnt */  ocnt,
     /* op */    op,
     /* mss */   mss_val,
     /* wsc */   wsc_val,
     /* tst */   tstamp,
     /* TOS */   iph->tos,
     /* Q? */    quirks,
     /* ECN */   tcph->flags & (TH_ECE|TH_CWR),
     /* pkt */   (uint8_t*)iph,
     /* len */   end_ptr - (uint8_t*)iph,
     /* pay */   pay
  );

  return outbuf_return();
}

static char outbuf[256];
static size_t outbuf_off=0;
static void outbuf_add(const char *fmt, ...) {
	va_list ap;
	int s_ret=0;

	va_start(ap, fmt);
	s_ret=vsnprintf(&outbuf[outbuf_off], sizeof(outbuf) - (1 + outbuf_off), fmt, ap);
	assert(s_ret > 0);

	outbuf_off += s_ret;
	assert(outbuf_off < sizeof(outbuf));
}

static void outbuf_reset() {
	memset(outbuf, 0, sizeof(outbuf));
	outbuf_off=0;
	return;
}

static char *outbuf_return(void) {
	return &outbuf[0];
}
