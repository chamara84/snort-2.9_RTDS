/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         sfbpf_parse
#define yylex           sfbpf_lex
#define yyerror         sfbpf_error
#define yydebug         sfbpf_debug
#define yynerrs         sfbpf_nerrs
#define yylval          sfbpf_lval
#define yychar          sfbpf_char

/* First part of user prologue.  */
#line 1 "./grammar.y"

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */
#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /usr/cvsroot/sfeng/ims/src/libraries/daq/daq/sfbpf/grammar.y,v 1.1 2010/04/15 19:18:35 maltizer Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>

#include "sfbpf-int.h"

#include "gencode.h"
#ifdef HAVE_NET_PFVAR_H
#include <net/if.h>
#include <net/pfvar.h>
#include <net/if_pflog.h>
#endif
#include "ieee80211.h"
#include "namedb.h"

#define QSET(q, p, d, a) (q).proto = (p),\
			 (q).dir = (d),\
			 (q).addr = (a)

struct tok {
	int v;			/* value */
	const char *s;		/* string */
};

static const struct tok ieee80211_types[] = {
	{ IEEE80211_FC0_TYPE_DATA, "data" },
	{ IEEE80211_FC0_TYPE_MGT, "mgt" },
	{ IEEE80211_FC0_TYPE_MGT, "management" },
	{ IEEE80211_FC0_TYPE_CTL, "ctl" },
	{ IEEE80211_FC0_TYPE_CTL, "control" },
	{ 0, NULL }
};
static const struct tok ieee80211_mgt_subtypes[] = {
	{ IEEE80211_FC0_SUBTYPE_ASSOC_REQ, "assocreq" },
	{ IEEE80211_FC0_SUBTYPE_ASSOC_REQ, "assoc-req" },
	{ IEEE80211_FC0_SUBTYPE_ASSOC_RESP, "assocresp" },
	{ IEEE80211_FC0_SUBTYPE_ASSOC_RESP, "assoc-resp" },
	{ IEEE80211_FC0_SUBTYPE_REASSOC_REQ, "reassocreq" },
	{ IEEE80211_FC0_SUBTYPE_REASSOC_REQ, "reassoc-req" },
	{ IEEE80211_FC0_SUBTYPE_REASSOC_RESP, "reassocresp" },
	{ IEEE80211_FC0_SUBTYPE_REASSOC_RESP, "reassoc-resp" },
	{ IEEE80211_FC0_SUBTYPE_PROBE_REQ, "probereq" },
	{ IEEE80211_FC0_SUBTYPE_PROBE_REQ, "probe-req" },
	{ IEEE80211_FC0_SUBTYPE_PROBE_RESP, "proberesp" },
	{ IEEE80211_FC0_SUBTYPE_PROBE_RESP, "probe-resp" },
	{ IEEE80211_FC0_SUBTYPE_BEACON, "beacon" },
	{ IEEE80211_FC0_SUBTYPE_ATIM, "atim" },
	{ IEEE80211_FC0_SUBTYPE_DISASSOC, "disassoc" },
	{ IEEE80211_FC0_SUBTYPE_DISASSOC, "disassociation" },
	{ IEEE80211_FC0_SUBTYPE_AUTH, "auth" },
	{ IEEE80211_FC0_SUBTYPE_AUTH, "authentication" },
	{ IEEE80211_FC0_SUBTYPE_DEAUTH, "deauth" },
	{ IEEE80211_FC0_SUBTYPE_DEAUTH, "deauthentication" },
	{ 0, NULL }
};
static const struct tok ieee80211_ctl_subtypes[] = {
	{ IEEE80211_FC0_SUBTYPE_PS_POLL, "ps-poll" },
	{ IEEE80211_FC0_SUBTYPE_RTS, "rts" },
	{ IEEE80211_FC0_SUBTYPE_CTS, "cts" },
	{ IEEE80211_FC0_SUBTYPE_ACK, "ack" },
	{ IEEE80211_FC0_SUBTYPE_CF_END, "cf-end" },
	{ IEEE80211_FC0_SUBTYPE_CF_END_ACK, "cf-end-ack" },
	{ 0, NULL }
};
static const struct tok ieee80211_data_subtypes[] = {
	{ IEEE80211_FC0_SUBTYPE_DATA, "data" },
	{ IEEE80211_FC0_SUBTYPE_CF_ACK, "data-cf-ack" },
	{ IEEE80211_FC0_SUBTYPE_CF_POLL, "data-cf-poll" },
	{ IEEE80211_FC0_SUBTYPE_CF_ACPL, "data-cf-ack-poll" },
	{ IEEE80211_FC0_SUBTYPE_NODATA, "null" },
	{ IEEE80211_FC0_SUBTYPE_NODATA_CF_ACK, "cf-ack" },
	{ IEEE80211_FC0_SUBTYPE_NODATA_CF_POLL, "cf-poll"  },
	{ IEEE80211_FC0_SUBTYPE_NODATA_CF_ACPL, "cf-ack-poll" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_DATA, "qos-data" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_CF_ACK, "qos-data-cf-ack" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_CF_POLL, "qos-data-cf-poll" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_CF_ACPL, "qos-data-cf-ack-poll" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_NODATA, "qos" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_NODATA_CF_POLL, "qos-cf-poll" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_NODATA_CF_ACPL, "qos-cf-ack-poll" },
	{ 0, NULL }
};
struct type2tok {
	int type;
	const struct tok *tok;
};
static const struct type2tok ieee80211_type_subtypes[] = {
	{ IEEE80211_FC0_TYPE_MGT, ieee80211_mgt_subtypes },
	{ IEEE80211_FC0_TYPE_CTL, ieee80211_ctl_subtypes },
	{ IEEE80211_FC0_TYPE_DATA, ieee80211_data_subtypes },
	{ 0, NULL }
};

static int
str2tok(const char *str, const struct tok *toks)
{
	int i;

	for (i = 0; toks[i].s != NULL; i++) {
		if (sfbpf_strcasecmp(toks[i].s, str) == 0)
			return (toks[i].v);
	}
	return (-1);
}

int n_errors = 0;

static struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF, Q_UNDEF };

static void
yyerror(const char *msg)
{
	++n_errors;
	bpf_error("%s", msg);
	/* NOTREACHED */
}

#ifndef YYBISON
int yyparse(void);

int
sfbpf_parse()
{
	return (yyparse());
}
#endif

#ifdef HAVE_NET_PFVAR_H
static int
pfreason_to_num(const char *reason)
{
	const char *reasons[] = PFRES_NAMES;
	int i;

	for (i = 0; reasons[i]; i++) {
		if (sfbpf_strcasecmp(reason, reasons[i]) == 0)
			return (i);
	}
	bpf_error("unknown PF reason");
	/*NOTREACHED*/
}

static int
pfaction_to_num(const char *action)
{
	if (sfbpf_strcasecmp(action, "pass") == 0 ||
	    sfbpf_strcasecmp(action, "accept") == 0)
		return (PF_PASS);
	else if (sfbpf_strcasecmp(action, "drop") == 0 ||
		sfbpf_strcasecmp(action, "block") == 0)
		return (PF_DROP);
#if HAVE_PF_NAT_THROUGH_PF_NORDR
	else if (sfbpf_strcasecmp(action, "rdr") == 0)
		return (PF_RDR);
	else if (sfbpf_strcasecmp(action, "nat") == 0)
		return (PF_NAT);
	else if (sfbpf_strcasecmp(action, "binat") == 0)
		return (PF_BINAT);
	else if (sfbpf_strcasecmp(action, "nordr") == 0)
		return (PF_NORDR);
#endif
	else {
		bpf_error("unknown PF action");
		/*NOTREACHED*/
	}
}
#else /* !HAVE_NET_PFVAR_H */
static int
pfreason_to_num(const char *reason)
{
	bpf_error("libpcap was compiled on a machine without pf support");
	/*NOTREACHED*/

	/* this is to make the VC compiler happy */
	return -1;
}

static int
pfaction_to_num(const char *action)
{
	bpf_error("libpcap was compiled on a machine without pf support");
	/*NOTREACHED*/

	/* this is to make the VC compiler happy */
	return -1;
}
#endif /* HAVE_NET_PFVAR_H */

#line 308 "y.tab.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_SFBPF_Y_TAB_H_INCLUDED
# define YY_SFBPF_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int sfbpf_debug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    DST = 258,                     /* DST  */
    SRC = 259,                     /* SRC  */
    HOST = 260,                    /* HOST  */
    GATEWAY = 261,                 /* GATEWAY  */
    NET = 262,                     /* NET  */
    NETMASK = 263,                 /* NETMASK  */
    PORT = 264,                    /* PORT  */
    PORTRANGE = 265,               /* PORTRANGE  */
    LESS = 266,                    /* LESS  */
    GREATER = 267,                 /* GREATER  */
    PROTO = 268,                   /* PROTO  */
    PROTOCHAIN = 269,              /* PROTOCHAIN  */
    CBYTE = 270,                   /* CBYTE  */
    ARP = 271,                     /* ARP  */
    RARP = 272,                    /* RARP  */
    IP = 273,                      /* IP  */
    SCTP = 274,                    /* SCTP  */
    TCP = 275,                     /* TCP  */
    UDP = 276,                     /* UDP  */
    ICMP = 277,                    /* ICMP  */
    IGMP = 278,                    /* IGMP  */
    IGRP = 279,                    /* IGRP  */
    PIM = 280,                     /* PIM  */
    VRRP = 281,                    /* VRRP  */
    ATALK = 282,                   /* ATALK  */
    AARP = 283,                    /* AARP  */
    DECNET = 284,                  /* DECNET  */
    LAT = 285,                     /* LAT  */
    SCA = 286,                     /* SCA  */
    MOPRC = 287,                   /* MOPRC  */
    MOPDL = 288,                   /* MOPDL  */
    TK_BROADCAST = 289,            /* TK_BROADCAST  */
    TK_MULTICAST = 290,            /* TK_MULTICAST  */
    NUM = 291,                     /* NUM  */
    INBOUND = 292,                 /* INBOUND  */
    OUTBOUND = 293,                /* OUTBOUND  */
    PF_IFNAME = 294,               /* PF_IFNAME  */
    PF_RSET = 295,                 /* PF_RSET  */
    PF_RNR = 296,                  /* PF_RNR  */
    PF_SRNR = 297,                 /* PF_SRNR  */
    PF_REASON = 298,               /* PF_REASON  */
    PF_ACTION = 299,               /* PF_ACTION  */
    TYPE = 300,                    /* TYPE  */
    SUBTYPE = 301,                 /* SUBTYPE  */
    DIR = 302,                     /* DIR  */
    ADDR1 = 303,                   /* ADDR1  */
    ADDR2 = 304,                   /* ADDR2  */
    ADDR3 = 305,                   /* ADDR3  */
    ADDR4 = 306,                   /* ADDR4  */
    LINK = 307,                    /* LINK  */
    GEQ = 308,                     /* GEQ  */
    LEQ = 309,                     /* LEQ  */
    NEQ = 310,                     /* NEQ  */
    ID = 311,                      /* ID  */
    EID = 312,                     /* EID  */
    HID = 313,                     /* HID  */
    HID6 = 314,                    /* HID6  */
    AID = 315,                     /* AID  */
    LSH = 316,                     /* LSH  */
    RSH = 317,                     /* RSH  */
    LEN = 318,                     /* LEN  */
    IPV6 = 319,                    /* IPV6  */
    ICMPV6 = 320,                  /* ICMPV6  */
    AH = 321,                      /* AH  */
    ESP = 322,                     /* ESP  */
    VLAN = 323,                    /* VLAN  */
    MPLS = 324,                    /* MPLS  */
    PPPOED = 325,                  /* PPPOED  */
    PPPOES = 326,                  /* PPPOES  */
    ISO = 327,                     /* ISO  */
    ESIS = 328,                    /* ESIS  */
    CLNP = 329,                    /* CLNP  */
    ISIS = 330,                    /* ISIS  */
    L1 = 331,                      /* L1  */
    L2 = 332,                      /* L2  */
    IIH = 333,                     /* IIH  */
    LSP = 334,                     /* LSP  */
    SNP = 335,                     /* SNP  */
    CSNP = 336,                    /* CSNP  */
    PSNP = 337,                    /* PSNP  */
    STP = 338,                     /* STP  */
    IPX = 339,                     /* IPX  */
    NETBEUI = 340,                 /* NETBEUI  */
    LANE = 341,                    /* LANE  */
    LLC = 342,                     /* LLC  */
    METAC = 343,                   /* METAC  */
    BCC = 344,                     /* BCC  */
    SC = 345,                      /* SC  */
    ILMIC = 346,                   /* ILMIC  */
    OAMF4EC = 347,                 /* OAMF4EC  */
    OAMF4SC = 348,                 /* OAMF4SC  */
    OAM = 349,                     /* OAM  */
    OAMF4 = 350,                   /* OAMF4  */
    CONNECTMSG = 351,              /* CONNECTMSG  */
    METACONNECT = 352,             /* METACONNECT  */
    VPI = 353,                     /* VPI  */
    VCI = 354,                     /* VCI  */
    RADIO = 355,                   /* RADIO  */
    FISU = 356,                    /* FISU  */
    LSSU = 357,                    /* LSSU  */
    MSU = 358,                     /* MSU  */
    SIO = 359,                     /* SIO  */
    OPC = 360,                     /* OPC  */
    DPC = 361,                     /* DPC  */
    SLS = 362,                     /* SLS  */
    OR = 363,                      /* OR  */
    AND = 364,                     /* AND  */
    UMINUS = 365                   /* UMINUS  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
#define DST 258
#define SRC 259
#define HOST 260
#define GATEWAY 261
#define NET 262
#define NETMASK 263
#define PORT 264
#define PORTRANGE 265
#define LESS 266
#define GREATER 267
#define PROTO 268
#define PROTOCHAIN 269
#define CBYTE 270
#define ARP 271
#define RARP 272
#define IP 273
#define SCTP 274
#define TCP 275
#define UDP 276
#define ICMP 277
#define IGMP 278
#define IGRP 279
#define PIM 280
#define VRRP 281
#define ATALK 282
#define AARP 283
#define DECNET 284
#define LAT 285
#define SCA 286
#define MOPRC 287
#define MOPDL 288
#define TK_BROADCAST 289
#define TK_MULTICAST 290
#define NUM 291
#define INBOUND 292
#define OUTBOUND 293
#define PF_IFNAME 294
#define PF_RSET 295
#define PF_RNR 296
#define PF_SRNR 297
#define PF_REASON 298
#define PF_ACTION 299
#define TYPE 300
#define SUBTYPE 301
#define DIR 302
#define ADDR1 303
#define ADDR2 304
#define ADDR3 305
#define ADDR4 306
#define LINK 307
#define GEQ 308
#define LEQ 309
#define NEQ 310
#define ID 311
#define EID 312
#define HID 313
#define HID6 314
#define AID 315
#define LSH 316
#define RSH 317
#define LEN 318
#define IPV6 319
#define ICMPV6 320
#define AH 321
#define ESP 322
#define VLAN 323
#define MPLS 324
#define PPPOED 325
#define PPPOES 326
#define ISO 327
#define ESIS 328
#define CLNP 329
#define ISIS 330
#define L1 331
#define L2 332
#define IIH 333
#define LSP 334
#define SNP 335
#define CSNP 336
#define PSNP 337
#define STP 338
#define IPX 339
#define NETBEUI 340
#define LANE 341
#define LLC 342
#define METAC 343
#define BCC 344
#define SC 345
#define ILMIC 346
#define OAMF4EC 347
#define OAMF4SC 348
#define OAM 349
#define OAMF4 350
#define CONNECTMSG 351
#define METACONNECT 352
#define VPI 353
#define VCI 354
#define RADIO 355
#define FISU 356
#define LSSU 357
#define MSU 358
#define SIO 359
#define OPC 360
#define DPC 361
#define SLS 362
#define OR 363
#define AND 364
#define UMINUS 365

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 231 "./grammar.y"

	int i;
	sfbpf_u_int32 h;
	u_char *e;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		int atmfieldtype;
		int mtp3fieldtype;
		struct block *b;
	} blk;
	struct block *rblk;

#line 597 "y.tab.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE sfbpf_lval;


int sfbpf_parse (void);


#endif /* !YY_SFBPF_Y_TAB_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_DST = 3,                        /* DST  */
  YYSYMBOL_SRC = 4,                        /* SRC  */
  YYSYMBOL_HOST = 5,                       /* HOST  */
  YYSYMBOL_GATEWAY = 6,                    /* GATEWAY  */
  YYSYMBOL_NET = 7,                        /* NET  */
  YYSYMBOL_NETMASK = 8,                    /* NETMASK  */
  YYSYMBOL_PORT = 9,                       /* PORT  */
  YYSYMBOL_PORTRANGE = 10,                 /* PORTRANGE  */
  YYSYMBOL_LESS = 11,                      /* LESS  */
  YYSYMBOL_GREATER = 12,                   /* GREATER  */
  YYSYMBOL_PROTO = 13,                     /* PROTO  */
  YYSYMBOL_PROTOCHAIN = 14,                /* PROTOCHAIN  */
  YYSYMBOL_CBYTE = 15,                     /* CBYTE  */
  YYSYMBOL_ARP = 16,                       /* ARP  */
  YYSYMBOL_RARP = 17,                      /* RARP  */
  YYSYMBOL_IP = 18,                        /* IP  */
  YYSYMBOL_SCTP = 19,                      /* SCTP  */
  YYSYMBOL_TCP = 20,                       /* TCP  */
  YYSYMBOL_UDP = 21,                       /* UDP  */
  YYSYMBOL_ICMP = 22,                      /* ICMP  */
  YYSYMBOL_IGMP = 23,                      /* IGMP  */
  YYSYMBOL_IGRP = 24,                      /* IGRP  */
  YYSYMBOL_PIM = 25,                       /* PIM  */
  YYSYMBOL_VRRP = 26,                      /* VRRP  */
  YYSYMBOL_ATALK = 27,                     /* ATALK  */
  YYSYMBOL_AARP = 28,                      /* AARP  */
  YYSYMBOL_DECNET = 29,                    /* DECNET  */
  YYSYMBOL_LAT = 30,                       /* LAT  */
  YYSYMBOL_SCA = 31,                       /* SCA  */
  YYSYMBOL_MOPRC = 32,                     /* MOPRC  */
  YYSYMBOL_MOPDL = 33,                     /* MOPDL  */
  YYSYMBOL_TK_BROADCAST = 34,              /* TK_BROADCAST  */
  YYSYMBOL_TK_MULTICAST = 35,              /* TK_MULTICAST  */
  YYSYMBOL_NUM = 36,                       /* NUM  */
  YYSYMBOL_INBOUND = 37,                   /* INBOUND  */
  YYSYMBOL_OUTBOUND = 38,                  /* OUTBOUND  */
  YYSYMBOL_PF_IFNAME = 39,                 /* PF_IFNAME  */
  YYSYMBOL_PF_RSET = 40,                   /* PF_RSET  */
  YYSYMBOL_PF_RNR = 41,                    /* PF_RNR  */
  YYSYMBOL_PF_SRNR = 42,                   /* PF_SRNR  */
  YYSYMBOL_PF_REASON = 43,                 /* PF_REASON  */
  YYSYMBOL_PF_ACTION = 44,                 /* PF_ACTION  */
  YYSYMBOL_TYPE = 45,                      /* TYPE  */
  YYSYMBOL_SUBTYPE = 46,                   /* SUBTYPE  */
  YYSYMBOL_DIR = 47,                       /* DIR  */
  YYSYMBOL_ADDR1 = 48,                     /* ADDR1  */
  YYSYMBOL_ADDR2 = 49,                     /* ADDR2  */
  YYSYMBOL_ADDR3 = 50,                     /* ADDR3  */
  YYSYMBOL_ADDR4 = 51,                     /* ADDR4  */
  YYSYMBOL_LINK = 52,                      /* LINK  */
  YYSYMBOL_GEQ = 53,                       /* GEQ  */
  YYSYMBOL_LEQ = 54,                       /* LEQ  */
  YYSYMBOL_NEQ = 55,                       /* NEQ  */
  YYSYMBOL_ID = 56,                        /* ID  */
  YYSYMBOL_EID = 57,                       /* EID  */
  YYSYMBOL_HID = 58,                       /* HID  */
  YYSYMBOL_HID6 = 59,                      /* HID6  */
  YYSYMBOL_AID = 60,                       /* AID  */
  YYSYMBOL_LSH = 61,                       /* LSH  */
  YYSYMBOL_RSH = 62,                       /* RSH  */
  YYSYMBOL_LEN = 63,                       /* LEN  */
  YYSYMBOL_IPV6 = 64,                      /* IPV6  */
  YYSYMBOL_ICMPV6 = 65,                    /* ICMPV6  */
  YYSYMBOL_AH = 66,                        /* AH  */
  YYSYMBOL_ESP = 67,                       /* ESP  */
  YYSYMBOL_VLAN = 68,                      /* VLAN  */
  YYSYMBOL_MPLS = 69,                      /* MPLS  */
  YYSYMBOL_PPPOED = 70,                    /* PPPOED  */
  YYSYMBOL_PPPOES = 71,                    /* PPPOES  */
  YYSYMBOL_ISO = 72,                       /* ISO  */
  YYSYMBOL_ESIS = 73,                      /* ESIS  */
  YYSYMBOL_CLNP = 74,                      /* CLNP  */
  YYSYMBOL_ISIS = 75,                      /* ISIS  */
  YYSYMBOL_L1 = 76,                        /* L1  */
  YYSYMBOL_L2 = 77,                        /* L2  */
  YYSYMBOL_IIH = 78,                       /* IIH  */
  YYSYMBOL_LSP = 79,                       /* LSP  */
  YYSYMBOL_SNP = 80,                       /* SNP  */
  YYSYMBOL_CSNP = 81,                      /* CSNP  */
  YYSYMBOL_PSNP = 82,                      /* PSNP  */
  YYSYMBOL_STP = 83,                       /* STP  */
  YYSYMBOL_IPX = 84,                       /* IPX  */
  YYSYMBOL_NETBEUI = 85,                   /* NETBEUI  */
  YYSYMBOL_LANE = 86,                      /* LANE  */
  YYSYMBOL_LLC = 87,                       /* LLC  */
  YYSYMBOL_METAC = 88,                     /* METAC  */
  YYSYMBOL_BCC = 89,                       /* BCC  */
  YYSYMBOL_SC = 90,                        /* SC  */
  YYSYMBOL_ILMIC = 91,                     /* ILMIC  */
  YYSYMBOL_OAMF4EC = 92,                   /* OAMF4EC  */
  YYSYMBOL_OAMF4SC = 93,                   /* OAMF4SC  */
  YYSYMBOL_OAM = 94,                       /* OAM  */
  YYSYMBOL_OAMF4 = 95,                     /* OAMF4  */
  YYSYMBOL_CONNECTMSG = 96,                /* CONNECTMSG  */
  YYSYMBOL_METACONNECT = 97,               /* METACONNECT  */
  YYSYMBOL_VPI = 98,                       /* VPI  */
  YYSYMBOL_VCI = 99,                       /* VCI  */
  YYSYMBOL_RADIO = 100,                    /* RADIO  */
  YYSYMBOL_FISU = 101,                     /* FISU  */
  YYSYMBOL_LSSU = 102,                     /* LSSU  */
  YYSYMBOL_MSU = 103,                      /* MSU  */
  YYSYMBOL_SIO = 104,                      /* SIO  */
  YYSYMBOL_OPC = 105,                      /* OPC  */
  YYSYMBOL_DPC = 106,                      /* DPC  */
  YYSYMBOL_SLS = 107,                      /* SLS  */
  YYSYMBOL_OR = 108,                       /* OR  */
  YYSYMBOL_AND = 109,                      /* AND  */
  YYSYMBOL_110_ = 110,                     /* '!'  */
  YYSYMBOL_111_ = 111,                     /* '|'  */
  YYSYMBOL_112_ = 112,                     /* '&'  */
  YYSYMBOL_113_ = 113,                     /* '+'  */
  YYSYMBOL_114_ = 114,                     /* '-'  */
  YYSYMBOL_115_ = 115,                     /* '*'  */
  YYSYMBOL_116_ = 116,                     /* '/'  */
  YYSYMBOL_UMINUS = 117,                   /* UMINUS  */
  YYSYMBOL_118_ = 118,                     /* ')'  */
  YYSYMBOL_119_ = 119,                     /* '('  */
  YYSYMBOL_120_ = 120,                     /* '>'  */
  YYSYMBOL_121_ = 121,                     /* '='  */
  YYSYMBOL_122_ = 122,                     /* '<'  */
  YYSYMBOL_123_ = 123,                     /* '['  */
  YYSYMBOL_124_ = 124,                     /* ']'  */
  YYSYMBOL_125_ = 125,                     /* ':'  */
  YYSYMBOL_YYACCEPT = 126,                 /* $accept  */
  YYSYMBOL_prog = 127,                     /* prog  */
  YYSYMBOL_null = 128,                     /* null  */
  YYSYMBOL_expr = 129,                     /* expr  */
  YYSYMBOL_and = 130,                      /* and  */
  YYSYMBOL_or = 131,                       /* or  */
  YYSYMBOL_id = 132,                       /* id  */
  YYSYMBOL_nid = 133,                      /* nid  */
  YYSYMBOL_not = 134,                      /* not  */
  YYSYMBOL_paren = 135,                    /* paren  */
  YYSYMBOL_pid = 136,                      /* pid  */
  YYSYMBOL_qid = 137,                      /* qid  */
  YYSYMBOL_term = 138,                     /* term  */
  YYSYMBOL_head = 139,                     /* head  */
  YYSYMBOL_rterm = 140,                    /* rterm  */
  YYSYMBOL_pqual = 141,                    /* pqual  */
  YYSYMBOL_dqual = 142,                    /* dqual  */
  YYSYMBOL_aqual = 143,                    /* aqual  */
  YYSYMBOL_ndaqual = 144,                  /* ndaqual  */
  YYSYMBOL_pname = 145,                    /* pname  */
  YYSYMBOL_other = 146,                    /* other  */
  YYSYMBOL_pfvar = 147,                    /* pfvar  */
  YYSYMBOL_p80211 = 148,                   /* p80211  */
  YYSYMBOL_type = 149,                     /* type  */
  YYSYMBOL_subtype = 150,                  /* subtype  */
  YYSYMBOL_type_subtype = 151,             /* type_subtype  */
  YYSYMBOL_dir = 152,                      /* dir  */
  YYSYMBOL_reason = 153,                   /* reason  */
  YYSYMBOL_action = 154,                   /* action  */
  YYSYMBOL_relop = 155,                    /* relop  */
  YYSYMBOL_irelop = 156,                   /* irelop  */
  YYSYMBOL_arth = 157,                     /* arth  */
  YYSYMBOL_narth = 158,                    /* narth  */
  YYSYMBOL_byteop = 159,                   /* byteop  */
  YYSYMBOL_pnum = 160,                     /* pnum  */
  YYSYMBOL_atmtype = 161,                  /* atmtype  */
  YYSYMBOL_atmmultitype = 162,             /* atmmultitype  */
  YYSYMBOL_atmfield = 163,                 /* atmfield  */
  YYSYMBOL_atmvalue = 164,                 /* atmvalue  */
  YYSYMBOL_atmfieldvalue = 165,            /* atmfieldvalue  */
  YYSYMBOL_atmlistvalue = 166,             /* atmlistvalue  */
  YYSYMBOL_mtp2type = 167,                 /* mtp2type  */
  YYSYMBOL_mtp3field = 168,                /* mtp3field  */
  YYSYMBOL_mtp3value = 169,                /* mtp3value  */
  YYSYMBOL_mtp3fieldvalue = 170,           /* mtp3fieldvalue  */
  YYSYMBOL_mtp3listvalue = 171             /* mtp3listvalue  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   669

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  126
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  46
/* YYNRULES -- Number of rules.  */
#define YYNRULES  202
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  274

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   365


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   110,     2,     2,     2,     2,   112,     2,
     119,   118,   115,   113,     2,   114,     2,   116,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   125,     2,
     122,   121,   120,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   123,     2,   124,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,   111,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   117
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   304,   304,   308,   310,   312,   313,   314,   315,   316,
     318,   320,   322,   323,   325,   327,   328,   330,   332,   345,
     354,   363,   372,   381,   383,   385,   387,   388,   389,   391,
     393,   395,   396,   398,   399,   400,   401,   402,   403,   405,
     406,   407,   408,   410,   412,   413,   414,   415,   416,   417,
     420,   421,   424,   425,   426,   427,   428,   429,   430,   431,
     432,   433,   436,   437,   438,   439,   442,   444,   445,   446,
     447,   448,   449,   450,   451,   452,   453,   454,   455,   456,
     457,   458,   459,   460,   461,   462,   463,   464,   465,   466,
     467,   468,   469,   470,   471,   472,   473,   474,   475,   476,
     477,   478,   479,   480,   481,   483,   484,   485,   486,   487,
     488,   489,   490,   491,   492,   493,   494,   495,   496,   497,
     500,   501,   502,   503,   504,   505,   508,   513,   516,   520,
     523,   524,   530,   531,   551,   567,   568,   581,   582,   585,
     588,   589,   590,   592,   593,   594,   596,   597,   599,   600,
     601,   602,   603,   604,   605,   606,   607,   608,   609,   610,
     611,   613,   614,   615,   616,   617,   619,   620,   622,   623,
     624,   625,   626,   627,   628,   629,   631,   632,   633,   634,
     637,   638,   640,   641,   642,   643,   645,   652,   653,   656,
     657,   658,   661,   662,   663,   664,   666,   667,   668,   669,
     671,   680,   681
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "DST", "SRC", "HOST",
  "GATEWAY", "NET", "NETMASK", "PORT", "PORTRANGE", "LESS", "GREATER",
  "PROTO", "PROTOCHAIN", "CBYTE", "ARP", "RARP", "IP", "SCTP", "TCP",
  "UDP", "ICMP", "IGMP", "IGRP", "PIM", "VRRP", "ATALK", "AARP", "DECNET",
  "LAT", "SCA", "MOPRC", "MOPDL", "TK_BROADCAST", "TK_MULTICAST", "NUM",
  "INBOUND", "OUTBOUND", "PF_IFNAME", "PF_RSET", "PF_RNR", "PF_SRNR",
  "PF_REASON", "PF_ACTION", "TYPE", "SUBTYPE", "DIR", "ADDR1", "ADDR2",
  "ADDR3", "ADDR4", "LINK", "GEQ", "LEQ", "NEQ", "ID", "EID", "HID",
  "HID6", "AID", "LSH", "RSH", "LEN", "IPV6", "ICMPV6", "AH", "ESP",
  "VLAN", "MPLS", "PPPOED", "PPPOES", "ISO", "ESIS", "CLNP", "ISIS", "L1",
  "L2", "IIH", "LSP", "SNP", "CSNP", "PSNP", "STP", "IPX", "NETBEUI",
  "LANE", "LLC", "METAC", "BCC", "SC", "ILMIC", "OAMF4EC", "OAMF4SC",
  "OAM", "OAMF4", "CONNECTMSG", "METACONNECT", "VPI", "VCI", "RADIO",
  "FISU", "LSSU", "MSU", "SIO", "OPC", "DPC", "SLS", "OR", "AND", "'!'",
  "'|'", "'&'", "'+'", "'-'", "'*'", "'/'", "UMINUS", "')'", "'('", "'>'",
  "'='", "'<'", "'['", "']'", "':'", "$accept", "prog", "null", "expr",
  "and", "or", "id", "nid", "not", "paren", "pid", "qid", "term", "head",
  "rterm", "pqual", "dqual", "aqual", "ndaqual", "pname", "other", "pfvar",
  "p80211", "type", "subtype", "type_subtype", "dir", "reason", "action",
  "relop", "irelop", "arth", "narth", "byteop", "pnum", "atmtype",
  "atmmultitype", "atmfield", "atmvalue", "atmfieldvalue", "atmlistvalue",
  "mtp2type", "mtp3field", "mtp3value", "mtp3fieldvalue", "mtp3listvalue", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-198)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-42)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -198,    34,   216,  -198,     1,    48,    61,  -198,  -198,  -198,
    -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,
    -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,    46,    54,
      81,    82,   -13,    58,  -198,  -198,  -198,  -198,  -198,  -198,
     -24,   -24,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,
    -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,
    -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,
    -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,
    -198,   530,  -198,   -54,   426,   426,  -198,   151,  -198,   618,
      13,  -198,  -198,   525,  -198,  -198,  -198,  -198,    52,  -198,
     102,  -198,  -198,   -90,  -198,  -198,  -198,  -198,  -198,  -198,
    -198,  -198,  -198,   -24,  -198,  -198,   530,   -19,  -198,  -198,
    -198,   321,   321,  -198,   -60,    12,    17,  -198,  -198,    -4,
      33,  -198,  -198,  -198,   151,   151,  -198,   -33,   -29,  -198,
    -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,   -12,    67,
     -11,  -198,  -198,  -198,  -198,   170,  -198,  -198,  -198,   530,
    -198,  -198,  -198,   530,   530,   530,   530,   530,   530,   530,
     530,  -198,  -198,  -198,   530,   530,  -198,   114,   115,   118,
    -198,  -198,  -198,   122,   123,   128,  -198,  -198,  -198,  -198,
    -198,  -198,  -198,   129,    17,   -44,  -198,   321,   321,  -198,
      16,  -198,  -198,  -198,  -198,  -198,   110,   133,   134,  -198,
    -198,    60,   -54,    17,   172,   181,   183,   185,  -198,  -198,
     143,  -198,  -198,  -198,  -198,  -198,  -198,   -51,    68,    68,
      78,    99,    -7,    -7,  -198,  -198,   -44,   -44,  -198,   -89,
    -198,  -198,  -198,    -5,  -198,  -198,  -198,   -52,  -198,  -198,
    -198,  -198,   151,   151,  -198,  -198,  -198,  -198,    -9,  -198,
     161,  -198,   114,  -198,   122,  -198,  -198,  -198,  -198,  -198,
      74,  -198,  -198,  -198
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       4,     0,    51,     1,     0,     0,     0,    69,    70,    68,
      71,    72,    73,    74,    75,    76,    77,    78,    79,    80,
      81,    82,    83,    85,    84,   166,   110,   111,     0,     0,
       0,     0,     0,     0,    67,   160,    86,    87,    88,    89,
     113,   115,   116,   117,    90,    91,   100,    92,    93,    94,
      95,    96,    97,    99,    98,   101,   102,   103,   168,   169,
     170,   171,   174,   175,   172,   173,   176,   177,   178,   179,
     180,   181,   104,   189,   190,   191,   192,   193,   194,   195,
      24,     0,    25,     2,    51,    51,     5,     0,    31,     0,
      50,    44,   118,     0,   147,   146,    45,    46,     0,    48,
       0,   107,   108,     0,   120,   121,   122,   123,   137,   138,
     124,   139,   125,     0,   112,   114,     0,     0,   158,    11,
      10,    51,    51,    32,     0,   147,   146,    15,    21,    18,
      20,    22,    39,    12,     0,     0,    13,    53,    52,    62,
      66,    63,    64,    65,    36,    37,   105,   106,     0,     0,
       0,    58,    59,    60,    61,    34,    35,    38,   119,     0,
     141,   143,   145,     0,     0,     0,     0,     0,     0,     0,
       0,   140,   142,   144,     0,     0,   186,     0,     0,     0,
      47,   182,   200,     0,     0,     0,    49,   196,   162,   161,
     164,   165,   163,     0,     0,     0,     7,    51,    51,     6,
     146,     9,     8,    40,   159,   167,     0,     0,     0,    23,
      26,    30,     0,    29,     0,     0,     0,     0,   130,   131,
     127,   134,   128,   135,   136,   129,    33,     0,   156,   157,
     155,   154,   150,   151,   152,   153,    42,    43,   187,     0,
     183,   184,   201,     0,   197,   198,   109,   146,    17,    16,
      19,    14,     0,     0,    55,    57,    54,    56,     0,   148,
       0,   185,     0,   199,     0,    27,    28,   132,   133,   126,
       0,   188,   202,   149
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -198,  -198,  -198,   197,    -6,  -197,   -86,  -121,     5,    -2,
    -198,  -198,   -81,  -198,  -198,  -198,  -198,    45,  -198,     7,
    -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,  -198,   -72,
     -47,   -22,   -83,  -198,   -35,  -198,  -198,  -198,  -198,  -169,
    -198,  -198,  -198,  -198,  -163,  -198
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
       0,     1,     2,   124,   121,   122,   209,   133,   134,   116,
     211,   212,    86,    87,    88,    89,   155,   156,   157,   117,
      91,    92,   158,   220,   269,   222,   225,   110,   112,   174,
     175,    93,    94,   193,    95,    96,    97,    98,   180,   181,
     239,    99,   100,   186,   187,   243
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      85,   132,   125,   123,   206,   114,   115,    84,   238,    90,
     163,   164,    25,   -41,   210,   253,   -13,   163,   164,   119,
     242,   188,   189,   108,   218,   223,   178,   267,   184,   261,
     190,   191,   192,   125,     3,   196,   201,   101,   113,   113,
     199,   202,   262,   109,   219,   224,   264,   268,   119,   120,
     126,   179,   136,   185,   119,   120,   -29,   -29,   203,   118,
     165,   166,   167,   168,   169,   170,   205,   165,   166,   167,
     168,   169,   170,   259,   260,   214,   215,   210,   194,   216,
     217,   126,    85,    85,   102,   135,   200,   200,   176,    84,
      84,    90,    90,   271,   195,    82,   177,   103,   183,   136,
     213,   272,   104,   119,   159,   160,   161,   162,   169,   170,
     105,   113,   207,   263,   111,   125,   123,   106,   107,   198,
     198,   -41,   -41,   221,   -13,   -13,   197,   197,    90,    90,
     204,   -41,   135,   113,   -13,   205,   159,   227,   182,   163,
     164,   228,   229,   230,   231,   232,   233,   234,   235,   208,
     176,   240,   236,   237,   241,   160,   161,   162,   182,   244,
     163,   164,   200,   247,   245,   246,   265,   266,   248,   249,
     250,    82,   171,   172,   173,   139,   254,   141,   251,   142,
     143,   167,   168,   169,   170,   255,   256,    25,   257,   258,
     166,   167,   168,   169,   170,   198,    85,   270,   273,    83,
     226,     0,   197,   197,    90,    90,   252,   127,   128,   129,
     130,   131,   167,   168,   169,   170,    -3,   136,   136,     0,
       0,    82,   171,   172,   173,     0,     0,     4,     5,     0,
       0,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
     135,   135,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    80,     0,     0,     0,     0,     0,     0,    34,     0,
      82,     0,     0,     0,     0,     0,     0,     0,     0,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    72,    73,    74,    75,
      76,    77,    78,    79,     0,     0,    80,     0,     0,     0,
      81,     0,     4,     5,     0,    82,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,     0,     0,    25,    26,    27,
      28,    29,    30,    31,    32,    33,     0,     0,     0,     0,
       0,     0,     0,    34,     0,     0,     0,   127,   128,   129,
     130,   131,     0,     0,    35,    36,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    72,    73,    74,    75,    76,    77,    78,    79,     0,
       0,    80,     0,     0,     0,    81,     0,     4,     5,     0,
      82,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
       0,     0,    25,    26,    27,    28,    29,    30,    31,    32,
      33,     0,     0,     0,     0,     0,     0,     0,    34,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    72,    73,    74,    75,
      76,    77,    78,    79,     0,     0,    80,     0,     0,     0,
      81,     0,     0,     0,     0,    82,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,     0,     0,    25,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   160,   161,
     162,     0,    34,     0,     0,     0,   163,   164,     0,     0,
       0,     0,     0,    35,    36,    37,    38,    39,     0,     0,
       0,     0,    44,    45,    46,    47,    48,    49,    50,    51,
      52,    53,    54,    55,    56,    57,     0,     0,     0,     0,
       0,   137,   138,   139,   140,   141,     0,   142,   143,     0,
      72,   144,   145,     0,     0,     0,   165,   166,   167,   168,
     169,   170,     0,     0,    81,   171,   172,   173,     0,    82,
       0,     0,   146,   147,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   148,   149,   150,   151,   152,   153,   154
};

static const yytype_int16 yycheck[] =
{
       2,    87,    85,    84,     8,    40,    41,     2,   177,     2,
      61,    62,    36,     0,   135,   212,     0,    61,    62,   108,
     183,   111,   112,    36,    36,    36,    98,    36,   100,   118,
     120,   121,   122,   116,     0,   121,   122,    36,    40,    41,
     121,   122,   239,    56,    56,    56,   243,    56,   108,   109,
      85,    98,    87,   100,   108,   109,   108,   109,   118,    81,
     111,   112,   113,   114,   115,   116,   118,   111,   112,   113,
     114,   115,   116,   124,   125,   108,   109,   198,   113,   108,
     109,   116,    84,    85,    36,    87,   121,   122,    36,    84,
      85,    84,    85,   262,   116,   119,    98,    36,   100,   134,
     135,   264,    56,   108,   123,    53,    54,    55,   115,   116,
      56,   113,   116,   118,    56,   198,   197,    36,    36,   121,
     122,   108,   109,    56,   108,   109,   121,   122,   121,   122,
     118,   118,   134,   135,   118,   118,   123,   159,    36,    61,
      62,   163,   164,   165,   166,   167,   168,   169,   170,   116,
      36,    36,   174,   175,    36,    53,    54,    55,    36,    36,
      61,    62,   197,   198,    36,    36,   252,   253,    58,    36,
      36,   119,   120,   121,   122,     5,     4,     7,   118,     9,
      10,   113,   114,   115,   116,     4,     3,    36,     3,    46,
     112,   113,   114,   115,   116,   197,   198,    36,   124,     2,
     155,    -1,   197,   198,   197,   198,   212,    56,    57,    58,
      59,    60,   113,   114,   115,   116,     0,   252,   253,    -1,
      -1,   119,   120,   121,   122,    -1,    -1,    11,    12,    -1,
      -1,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
     252,   253,    36,    37,    38,    39,    40,    41,    42,    43,
      44,   110,    -1,    -1,    -1,    -1,    -1,    -1,    52,    -1,
     119,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    63,
      64,    65,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    79,    80,    81,    82,    83,
      84,    85,    86,    87,    88,    89,    90,    91,    92,    93,
      94,    95,    96,    97,    98,    99,   100,   101,   102,   103,
     104,   105,   106,   107,    -1,    -1,   110,    -1,    -1,    -1,
     114,    -1,    11,    12,    -1,   119,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    -1,    -1,    36,    37,    38,
      39,    40,    41,    42,    43,    44,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    52,    -1,    -1,    -1,    56,    57,    58,
      59,    60,    -1,    -1,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,    73,    74,    75,    76,    77,    78,
      79,    80,    81,    82,    83,    84,    85,    86,    87,    88,
      89,    90,    91,    92,    93,    94,    95,    96,    97,    98,
      99,   100,   101,   102,   103,   104,   105,   106,   107,    -1,
      -1,   110,    -1,    -1,    -1,   114,    -1,    11,    12,    -1,
     119,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      -1,    -1,    36,    37,    38,    39,    40,    41,    42,    43,
      44,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    52,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    63,
      64,    65,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    79,    80,    81,    82,    83,
      84,    85,    86,    87,    88,    89,    90,    91,    92,    93,
      94,    95,    96,    97,    98,    99,   100,   101,   102,   103,
     104,   105,   106,   107,    -1,    -1,   110,    -1,    -1,    -1,
     114,    -1,    -1,    -1,    -1,   119,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    -1,    -1,    36,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    53,    54,
      55,    -1,    52,    -1,    -1,    -1,    61,    62,    -1,    -1,
      -1,    -1,    -1,    63,    64,    65,    66,    67,    -1,    -1,
      -1,    -1,    72,    73,    74,    75,    76,    77,    78,    79,
      80,    81,    82,    83,    84,    85,    -1,    -1,    -1,    -1,
      -1,     3,     4,     5,     6,     7,    -1,     9,    10,    -1,
     100,    13,    14,    -1,    -1,    -1,   111,   112,   113,   114,
     115,   116,    -1,    -1,   114,   120,   121,   122,    -1,   119,
      -1,    -1,    34,    35,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    45,    46,    47,    48,    49,    50,    51
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,   127,   128,     0,    11,    12,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    36,    37,    38,    39,    40,
      41,    42,    43,    44,    52,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    72,    73,    74,    75,    76,    77,
      78,    79,    80,    81,    82,    83,    84,    85,    86,    87,
      88,    89,    90,    91,    92,    93,    94,    95,    96,    97,
      98,    99,   100,   101,   102,   103,   104,   105,   106,   107,
     110,   114,   119,   129,   134,   135,   138,   139,   140,   141,
     145,   146,   147,   157,   158,   160,   161,   162,   163,   167,
     168,    36,    36,    36,    56,    56,    36,    36,    36,    56,
     153,    56,   154,   135,   160,   160,   135,   145,   157,   108,
     109,   130,   131,   138,   129,   158,   160,    56,    57,    58,
      59,    60,   132,   133,   134,   135,   160,     3,     4,     5,
       6,     7,     9,    10,    13,    14,    34,    35,    45,    46,
      47,    48,    49,    50,    51,   142,   143,   144,   148,   123,
      53,    54,    55,    61,    62,   111,   112,   113,   114,   115,
     116,   120,   121,   122,   155,   156,    36,   135,   155,   156,
     164,   165,    36,   135,   155,   156,   169,   170,   111,   112,
     120,   121,   122,   159,   160,   157,   132,   134,   135,   138,
     160,   132,   138,   118,   118,   118,     8,   116,   116,   132,
     133,   136,   137,   160,   108,   109,   108,   109,    36,    56,
     149,    56,   151,    36,    56,   152,   143,   157,   157,   157,
     157,   157,   157,   157,   157,   157,   157,   157,   165,   166,
      36,    36,   170,   171,    36,    36,    36,   160,    58,    36,
      36,   118,   130,   131,     4,     4,     3,     3,    46,   124,
     125,   118,   131,   118,   131,   132,   132,    36,    56,   150,
      36,   165,   170,   124
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_uint8 yyr1[] =
{
       0,   126,   127,   127,   128,   129,   129,   129,   129,   129,
     130,   131,   132,   132,   132,   133,   133,   133,   133,   133,
     133,   133,   133,   133,   134,   135,   136,   136,   136,   137,
     137,   138,   138,   139,   139,   139,   139,   139,   139,   140,
     140,   140,   140,   140,   140,   140,   140,   140,   140,   140,
     141,   141,   142,   142,   142,   142,   142,   142,   142,   142,
     142,   142,   143,   143,   143,   143,   144,   145,   145,   145,
     145,   145,   145,   145,   145,   145,   145,   145,   145,   145,
     145,   145,   145,   145,   145,   145,   145,   145,   145,   145,
     145,   145,   145,   145,   145,   145,   145,   145,   145,   145,
     145,   145,   145,   145,   145,   146,   146,   146,   146,   146,
     146,   146,   146,   146,   146,   146,   146,   146,   146,   146,
     147,   147,   147,   147,   147,   147,   148,   148,   148,   148,
     149,   149,   150,   150,   151,   152,   152,   153,   153,   154,
     155,   155,   155,   156,   156,   156,   157,   157,   158,   158,
     158,   158,   158,   158,   158,   158,   158,   158,   158,   158,
     158,   159,   159,   159,   159,   159,   160,   160,   161,   161,
     161,   161,   161,   161,   161,   161,   162,   162,   162,   162,
     163,   163,   164,   164,   164,   164,   165,   166,   166,   167,
     167,   167,   168,   168,   168,   168,   169,   169,   169,   169,
     170,   171,   171
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     1,     0,     1,     3,     3,     3,     3,
       1,     1,     1,     1,     3,     1,     3,     3,     1,     3,
       1,     1,     1,     2,     1,     1,     1,     3,     3,     1,
       1,     1,     2,     3,     2,     2,     2,     2,     2,     2,
       3,     1,     3,     3,     1,     1,     1,     2,     1,     2,
       1,     0,     1,     1,     3,     3,     3,     3,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     2,     2,     2,     4,
       1,     1,     2,     1,     2,     1,     1,     1,     1,     2,
       2,     2,     2,     2,     2,     2,     4,     2,     2,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     4,     6,
       3,     3,     3,     3,     3,     3,     3,     3,     2,     3,
       1,     1,     1,     1,     1,     1,     1,     3,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     2,     2,     3,     1,     1,     3,     1,
       1,     1,     1,     1,     1,     1,     1,     2,     2,     3,
       1,     1,     3
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2: /* prog: null expr  */
#line 305 "./grammar.y"
{
	finish_parse((yyvsp[0].blk).b);
}
#line 2047 "y.tab.c"
    break;

  case 4: /* null: %empty  */
#line 310 "./grammar.y"
                                { (yyval.blk).q = qerr; }
#line 2053 "y.tab.c"
    break;

  case 6: /* expr: expr and term  */
#line 313 "./grammar.y"
                                { gen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2059 "y.tab.c"
    break;

  case 7: /* expr: expr and id  */
#line 314 "./grammar.y"
                                { gen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2065 "y.tab.c"
    break;

  case 8: /* expr: expr or term  */
#line 315 "./grammar.y"
                                { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2071 "y.tab.c"
    break;

  case 9: /* expr: expr or id  */
#line 316 "./grammar.y"
                                { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2077 "y.tab.c"
    break;

  case 10: /* and: AND  */
#line 318 "./grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2083 "y.tab.c"
    break;

  case 11: /* or: OR  */
#line 320 "./grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2089 "y.tab.c"
    break;

  case 13: /* id: pnum  */
#line 323 "./grammar.y"
                                { (yyval.blk).b = gen_ncode(NULL, (sfbpf_u_int32)(yyvsp[0].i),
						   (yyval.blk).q = (yyvsp[-1].blk).q); }
#line 2096 "y.tab.c"
    break;

  case 14: /* id: paren pid ')'  */
#line 325 "./grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2102 "y.tab.c"
    break;

  case 15: /* nid: ID  */
#line 327 "./grammar.y"
                                { (yyval.blk).b = gen_scode((yyvsp[0].s), (yyval.blk).q = (yyvsp[-1].blk).q); }
#line 2108 "y.tab.c"
    break;

  case 16: /* nid: HID '/' NUM  */
#line 328 "./grammar.y"
                                { (yyval.blk).b = gen_mcode((yyvsp[-2].s), NULL, (yyvsp[0].i),
				    (yyval.blk).q = (yyvsp[-3].blk).q); }
#line 2115 "y.tab.c"
    break;

  case 17: /* nid: HID NETMASK HID  */
#line 330 "./grammar.y"
                                { (yyval.blk).b = gen_mcode((yyvsp[-2].s), (yyvsp[0].s), 0,
				    (yyval.blk).q = (yyvsp[-3].blk).q); }
#line 2122 "y.tab.c"
    break;

  case 18: /* nid: HID  */
#line 332 "./grammar.y"
                                {
				  /* Decide how to parse HID based on proto */
				  (yyval.blk).q = (yyvsp[-1].blk).q;
				  if ((yyval.blk).q.addr == Q_PORT)
				  	bpf_error("'port' modifier applied to ip host");
				  else if ((yyval.blk).q.addr == Q_PORTRANGE)
				  	bpf_error("'portrange' modifier applied to ip host");
				  else if ((yyval.blk).q.addr == Q_PROTO)
				  	bpf_error("'proto' modifier applied to ip host");
				  else if ((yyval.blk).q.addr == Q_PROTOCHAIN)
				  	bpf_error("'protochain' modifier applied to ip host");
				  (yyval.blk).b = gen_ncode((yyvsp[0].s), 0, (yyval.blk).q);
				}
#line 2140 "y.tab.c"
    break;

  case 19: /* nid: HID6 '/' NUM  */
#line 345 "./grammar.y"
                                {
#ifdef INET6
				  (yyval.blk).b = gen_mcode6((yyvsp[-2].s), NULL, (yyvsp[0].i),
				    (yyval.blk).q = (yyvsp[-3].blk).q);
#else
				  bpf_error("'ip6addr/prefixlen' not supported "
					"in this configuration");
#endif /*INET6*/
				}
#line 2154 "y.tab.c"
    break;

  case 20: /* nid: HID6  */
#line 354 "./grammar.y"
                                {
#ifdef INET6
				  (yyval.blk).b = gen_mcode6((yyvsp[0].s), 0, 128,
				    (yyval.blk).q = (yyvsp[-1].blk).q);
#else
				  bpf_error("'ip6addr' not supported "
					"in this configuration");
#endif /*INET6*/
				}
#line 2168 "y.tab.c"
    break;

  case 21: /* nid: EID  */
#line 363 "./grammar.y"
                                { 
				  (yyval.blk).b = gen_ecode((yyvsp[0].e), (yyval.blk).q = (yyvsp[-1].blk).q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free((yyvsp[0].e));
				}
#line 2182 "y.tab.c"
    break;

  case 22: /* nid: AID  */
#line 372 "./grammar.y"
                                {
				  (yyval.blk).b = gen_acode((yyvsp[0].e), (yyval.blk).q = (yyvsp[-1].blk).q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free((yyvsp[0].e));
				}
#line 2196 "y.tab.c"
    break;

  case 23: /* nid: not id  */
#line 381 "./grammar.y"
                                { gen_not((yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2202 "y.tab.c"
    break;

  case 24: /* not: '!'  */
#line 383 "./grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2208 "y.tab.c"
    break;

  case 25: /* paren: '('  */
#line 385 "./grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2214 "y.tab.c"
    break;

  case 27: /* pid: qid and id  */
#line 388 "./grammar.y"
                                { gen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2220 "y.tab.c"
    break;

  case 28: /* pid: qid or id  */
#line 389 "./grammar.y"
                                { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2226 "y.tab.c"
    break;

  case 29: /* qid: pnum  */
#line 391 "./grammar.y"
                                { (yyval.blk).b = gen_ncode(NULL, (sfbpf_u_int32)(yyvsp[0].i),
						   (yyval.blk).q = (yyvsp[-1].blk).q); }
#line 2233 "y.tab.c"
    break;

  case 32: /* term: not term  */
#line 396 "./grammar.y"
                                { gen_not((yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2239 "y.tab.c"
    break;

  case 33: /* head: pqual dqual aqual  */
#line 398 "./grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-2].i), (yyvsp[-1].i), (yyvsp[0].i)); }
#line 2245 "y.tab.c"
    break;

  case 34: /* head: pqual dqual  */
#line 399 "./grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), (yyvsp[0].i), Q_DEFAULT); }
#line 2251 "y.tab.c"
    break;

  case 35: /* head: pqual aqual  */
#line 400 "./grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].i)); }
#line 2257 "y.tab.c"
    break;

  case 36: /* head: pqual PROTO  */
#line 401 "./grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, Q_PROTO); }
#line 2263 "y.tab.c"
    break;

  case 37: /* head: pqual PROTOCHAIN  */
#line 402 "./grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, Q_PROTOCHAIN); }
#line 2269 "y.tab.c"
    break;

  case 38: /* head: pqual ndaqual  */
#line 403 "./grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].i)); }
#line 2275 "y.tab.c"
    break;

  case 39: /* rterm: head id  */
#line 405 "./grammar.y"
                                { (yyval.blk) = (yyvsp[0].blk); }
#line 2281 "y.tab.c"
    break;

  case 40: /* rterm: paren expr ')'  */
#line 406 "./grammar.y"
                                { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = (yyvsp[-2].blk).q; }
#line 2287 "y.tab.c"
    break;

  case 41: /* rterm: pname  */
#line 407 "./grammar.y"
                                { (yyval.blk).b = gen_proto_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2293 "y.tab.c"
    break;

  case 42: /* rterm: arth relop arth  */
#line 408 "./grammar.y"
                                { (yyval.blk).b = gen_relation((yyvsp[-1].i), (yyvsp[-2].a), (yyvsp[0].a), 0);
				  (yyval.blk).q = qerr; }
#line 2300 "y.tab.c"
    break;

  case 43: /* rterm: arth irelop arth  */
#line 410 "./grammar.y"
                                { (yyval.blk).b = gen_relation((yyvsp[-1].i), (yyvsp[-2].a), (yyvsp[0].a), 1);
				  (yyval.blk).q = qerr; }
#line 2307 "y.tab.c"
    break;

  case 44: /* rterm: other  */
#line 412 "./grammar.y"
                                { (yyval.blk).b = (yyvsp[0].rblk); (yyval.blk).q = qerr; }
#line 2313 "y.tab.c"
    break;

  case 45: /* rterm: atmtype  */
#line 413 "./grammar.y"
                                { (yyval.blk).b = gen_atmtype_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2319 "y.tab.c"
    break;

  case 46: /* rterm: atmmultitype  */
#line 414 "./grammar.y"
                                { (yyval.blk).b = gen_atmmulti_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2325 "y.tab.c"
    break;

  case 47: /* rterm: atmfield atmvalue  */
#line 415 "./grammar.y"
                                { (yyval.blk).b = (yyvsp[0].blk).b; (yyval.blk).q = qerr; }
#line 2331 "y.tab.c"
    break;

  case 48: /* rterm: mtp2type  */
#line 416 "./grammar.y"
                                { (yyval.blk).b = gen_mtp2type_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2337 "y.tab.c"
    break;

  case 49: /* rterm: mtp3field mtp3value  */
#line 417 "./grammar.y"
                                { (yyval.blk).b = (yyvsp[0].blk).b; (yyval.blk).q = qerr; }
#line 2343 "y.tab.c"
    break;

  case 51: /* pqual: %empty  */
#line 421 "./grammar.y"
                                { (yyval.i) = Q_DEFAULT; }
#line 2349 "y.tab.c"
    break;

  case 52: /* dqual: SRC  */
#line 424 "./grammar.y"
                                { (yyval.i) = Q_SRC; }
#line 2355 "y.tab.c"
    break;

  case 53: /* dqual: DST  */
#line 425 "./grammar.y"
                                { (yyval.i) = Q_DST; }
#line 2361 "y.tab.c"
    break;

  case 54: /* dqual: SRC OR DST  */
#line 426 "./grammar.y"
                                { (yyval.i) = Q_OR; }
#line 2367 "y.tab.c"
    break;

  case 55: /* dqual: DST OR SRC  */
#line 427 "./grammar.y"
                                { (yyval.i) = Q_OR; }
#line 2373 "y.tab.c"
    break;

  case 56: /* dqual: SRC AND DST  */
#line 428 "./grammar.y"
                                { (yyval.i) = Q_AND; }
#line 2379 "y.tab.c"
    break;

  case 57: /* dqual: DST AND SRC  */
#line 429 "./grammar.y"
                                { (yyval.i) = Q_AND; }
#line 2385 "y.tab.c"
    break;

  case 58: /* dqual: ADDR1  */
#line 430 "./grammar.y"
                                { (yyval.i) = Q_ADDR1; }
#line 2391 "y.tab.c"
    break;

  case 59: /* dqual: ADDR2  */
#line 431 "./grammar.y"
                                { (yyval.i) = Q_ADDR2; }
#line 2397 "y.tab.c"
    break;

  case 60: /* dqual: ADDR3  */
#line 432 "./grammar.y"
                                { (yyval.i) = Q_ADDR3; }
#line 2403 "y.tab.c"
    break;

  case 61: /* dqual: ADDR4  */
#line 433 "./grammar.y"
                                { (yyval.i) = Q_ADDR4; }
#line 2409 "y.tab.c"
    break;

  case 62: /* aqual: HOST  */
#line 436 "./grammar.y"
                                { (yyval.i) = Q_HOST; }
#line 2415 "y.tab.c"
    break;

  case 63: /* aqual: NET  */
#line 437 "./grammar.y"
                                { (yyval.i) = Q_NET; }
#line 2421 "y.tab.c"
    break;

  case 64: /* aqual: PORT  */
#line 438 "./grammar.y"
                                { (yyval.i) = Q_PORT; }
#line 2427 "y.tab.c"
    break;

  case 65: /* aqual: PORTRANGE  */
#line 439 "./grammar.y"
                                { (yyval.i) = Q_PORTRANGE; }
#line 2433 "y.tab.c"
    break;

  case 66: /* ndaqual: GATEWAY  */
#line 442 "./grammar.y"
                                { (yyval.i) = Q_GATEWAY; }
#line 2439 "y.tab.c"
    break;

  case 67: /* pname: LINK  */
#line 444 "./grammar.y"
                                { (yyval.i) = Q_LINK; }
#line 2445 "y.tab.c"
    break;

  case 68: /* pname: IP  */
#line 445 "./grammar.y"
                                { (yyval.i) = Q_IP; }
#line 2451 "y.tab.c"
    break;

  case 69: /* pname: ARP  */
#line 446 "./grammar.y"
                                { (yyval.i) = Q_ARP; }
#line 2457 "y.tab.c"
    break;

  case 70: /* pname: RARP  */
#line 447 "./grammar.y"
                                { (yyval.i) = Q_RARP; }
#line 2463 "y.tab.c"
    break;

  case 71: /* pname: SCTP  */
#line 448 "./grammar.y"
                                { (yyval.i) = Q_SCTP; }
#line 2469 "y.tab.c"
    break;

  case 72: /* pname: TCP  */
#line 449 "./grammar.y"
                                { (yyval.i) = Q_TCP; }
#line 2475 "y.tab.c"
    break;

  case 73: /* pname: UDP  */
#line 450 "./grammar.y"
                                { (yyval.i) = Q_UDP; }
#line 2481 "y.tab.c"
    break;

  case 74: /* pname: ICMP  */
#line 451 "./grammar.y"
                                { (yyval.i) = Q_ICMP; }
#line 2487 "y.tab.c"
    break;

  case 75: /* pname: IGMP  */
#line 452 "./grammar.y"
                                { (yyval.i) = Q_IGMP; }
#line 2493 "y.tab.c"
    break;

  case 76: /* pname: IGRP  */
#line 453 "./grammar.y"
                                { (yyval.i) = Q_IGRP; }
#line 2499 "y.tab.c"
    break;

  case 77: /* pname: PIM  */
#line 454 "./grammar.y"
                                { (yyval.i) = Q_PIM; }
#line 2505 "y.tab.c"
    break;

  case 78: /* pname: VRRP  */
#line 455 "./grammar.y"
                                { (yyval.i) = Q_VRRP; }
#line 2511 "y.tab.c"
    break;

  case 79: /* pname: ATALK  */
#line 456 "./grammar.y"
                                { (yyval.i) = Q_ATALK; }
#line 2517 "y.tab.c"
    break;

  case 80: /* pname: AARP  */
#line 457 "./grammar.y"
                                { (yyval.i) = Q_AARP; }
#line 2523 "y.tab.c"
    break;

  case 81: /* pname: DECNET  */
#line 458 "./grammar.y"
                                { (yyval.i) = Q_DECNET; }
#line 2529 "y.tab.c"
    break;

  case 82: /* pname: LAT  */
#line 459 "./grammar.y"
                                { (yyval.i) = Q_LAT; }
#line 2535 "y.tab.c"
    break;

  case 83: /* pname: SCA  */
#line 460 "./grammar.y"
                                { (yyval.i) = Q_SCA; }
#line 2541 "y.tab.c"
    break;

  case 84: /* pname: MOPDL  */
#line 461 "./grammar.y"
                                { (yyval.i) = Q_MOPDL; }
#line 2547 "y.tab.c"
    break;

  case 85: /* pname: MOPRC  */
#line 462 "./grammar.y"
                                { (yyval.i) = Q_MOPRC; }
#line 2553 "y.tab.c"
    break;

  case 86: /* pname: IPV6  */
#line 463 "./grammar.y"
                                { (yyval.i) = Q_IPV6; }
#line 2559 "y.tab.c"
    break;

  case 87: /* pname: ICMPV6  */
#line 464 "./grammar.y"
                                { (yyval.i) = Q_ICMPV6; }
#line 2565 "y.tab.c"
    break;

  case 88: /* pname: AH  */
#line 465 "./grammar.y"
                                { (yyval.i) = Q_AH; }
#line 2571 "y.tab.c"
    break;

  case 89: /* pname: ESP  */
#line 466 "./grammar.y"
                                { (yyval.i) = Q_ESP; }
#line 2577 "y.tab.c"
    break;

  case 90: /* pname: ISO  */
#line 467 "./grammar.y"
                                { (yyval.i) = Q_ISO; }
#line 2583 "y.tab.c"
    break;

  case 91: /* pname: ESIS  */
#line 468 "./grammar.y"
                                { (yyval.i) = Q_ESIS; }
#line 2589 "y.tab.c"
    break;

  case 92: /* pname: ISIS  */
#line 469 "./grammar.y"
                                { (yyval.i) = Q_ISIS; }
#line 2595 "y.tab.c"
    break;

  case 93: /* pname: L1  */
#line 470 "./grammar.y"
                                { (yyval.i) = Q_ISIS_L1; }
#line 2601 "y.tab.c"
    break;

  case 94: /* pname: L2  */
#line 471 "./grammar.y"
                                { (yyval.i) = Q_ISIS_L2; }
#line 2607 "y.tab.c"
    break;

  case 95: /* pname: IIH  */
#line 472 "./grammar.y"
                                { (yyval.i) = Q_ISIS_IIH; }
#line 2613 "y.tab.c"
    break;

  case 96: /* pname: LSP  */
#line 473 "./grammar.y"
                                { (yyval.i) = Q_ISIS_LSP; }
#line 2619 "y.tab.c"
    break;

  case 97: /* pname: SNP  */
#line 474 "./grammar.y"
                                { (yyval.i) = Q_ISIS_SNP; }
#line 2625 "y.tab.c"
    break;

  case 98: /* pname: PSNP  */
#line 475 "./grammar.y"
                                { (yyval.i) = Q_ISIS_PSNP; }
#line 2631 "y.tab.c"
    break;

  case 99: /* pname: CSNP  */
#line 476 "./grammar.y"
                                { (yyval.i) = Q_ISIS_CSNP; }
#line 2637 "y.tab.c"
    break;

  case 100: /* pname: CLNP  */
#line 477 "./grammar.y"
                                { (yyval.i) = Q_CLNP; }
#line 2643 "y.tab.c"
    break;

  case 101: /* pname: STP  */
#line 478 "./grammar.y"
                                { (yyval.i) = Q_STP; }
#line 2649 "y.tab.c"
    break;

  case 102: /* pname: IPX  */
#line 479 "./grammar.y"
                                { (yyval.i) = Q_IPX; }
#line 2655 "y.tab.c"
    break;

  case 103: /* pname: NETBEUI  */
#line 480 "./grammar.y"
                                { (yyval.i) = Q_NETBEUI; }
#line 2661 "y.tab.c"
    break;

  case 104: /* pname: RADIO  */
#line 481 "./grammar.y"
                                { (yyval.i) = Q_RADIO; }
#line 2667 "y.tab.c"
    break;

  case 105: /* other: pqual TK_BROADCAST  */
#line 483 "./grammar.y"
                                { (yyval.rblk) = gen_broadcast((yyvsp[-1].i)); }
#line 2673 "y.tab.c"
    break;

  case 106: /* other: pqual TK_MULTICAST  */
#line 484 "./grammar.y"
                                { (yyval.rblk) = gen_multicast((yyvsp[-1].i)); }
#line 2679 "y.tab.c"
    break;

  case 107: /* other: LESS NUM  */
#line 485 "./grammar.y"
                                { (yyval.rblk) = gen_less((yyvsp[0].i)); }
#line 2685 "y.tab.c"
    break;

  case 108: /* other: GREATER NUM  */
#line 486 "./grammar.y"
                                { (yyval.rblk) = gen_greater((yyvsp[0].i)); }
#line 2691 "y.tab.c"
    break;

  case 109: /* other: CBYTE NUM byteop NUM  */
#line 487 "./grammar.y"
                                { (yyval.rblk) = gen_byteop((yyvsp[-1].i), (yyvsp[-2].i), (yyvsp[0].i)); }
#line 2697 "y.tab.c"
    break;

  case 110: /* other: INBOUND  */
#line 488 "./grammar.y"
                                { (yyval.rblk) = gen_inbound(0); }
#line 2703 "y.tab.c"
    break;

  case 111: /* other: OUTBOUND  */
#line 489 "./grammar.y"
                                { (yyval.rblk) = gen_inbound(1); }
#line 2709 "y.tab.c"
    break;

  case 112: /* other: VLAN pnum  */
#line 490 "./grammar.y"
                                { (yyval.rblk) = gen_vlan((yyvsp[0].i)); }
#line 2715 "y.tab.c"
    break;

  case 113: /* other: VLAN  */
#line 491 "./grammar.y"
                                { (yyval.rblk) = gen_vlan(-1); }
#line 2721 "y.tab.c"
    break;

  case 114: /* other: MPLS pnum  */
#line 492 "./grammar.y"
                                { (yyval.rblk) = gen_mpls((yyvsp[0].i)); }
#line 2727 "y.tab.c"
    break;

  case 115: /* other: MPLS  */
#line 493 "./grammar.y"
                                { (yyval.rblk) = gen_mpls(-1); }
#line 2733 "y.tab.c"
    break;

  case 116: /* other: PPPOED  */
#line 494 "./grammar.y"
                                { (yyval.rblk) = gen_pppoed(); }
#line 2739 "y.tab.c"
    break;

  case 117: /* other: PPPOES  */
#line 495 "./grammar.y"
                                { (yyval.rblk) = gen_pppoes(); }
#line 2745 "y.tab.c"
    break;

  case 118: /* other: pfvar  */
#line 496 "./grammar.y"
                                { (yyval.rblk) = (yyvsp[0].rblk); }
#line 2751 "y.tab.c"
    break;

  case 119: /* other: pqual p80211  */
#line 497 "./grammar.y"
                                { (yyval.rblk) = (yyvsp[0].rblk); }
#line 2757 "y.tab.c"
    break;

  case 120: /* pfvar: PF_IFNAME ID  */
#line 500 "./grammar.y"
                                { (yyval.rblk) = gen_pf_ifname((yyvsp[0].s)); }
#line 2763 "y.tab.c"
    break;

  case 121: /* pfvar: PF_RSET ID  */
#line 501 "./grammar.y"
                                { (yyval.rblk) = gen_pf_ruleset((yyvsp[0].s)); }
#line 2769 "y.tab.c"
    break;

  case 122: /* pfvar: PF_RNR NUM  */
#line 502 "./grammar.y"
                                { (yyval.rblk) = gen_pf_rnr((yyvsp[0].i)); }
#line 2775 "y.tab.c"
    break;

  case 123: /* pfvar: PF_SRNR NUM  */
#line 503 "./grammar.y"
                                { (yyval.rblk) = gen_pf_srnr((yyvsp[0].i)); }
#line 2781 "y.tab.c"
    break;

  case 124: /* pfvar: PF_REASON reason  */
#line 504 "./grammar.y"
                                { (yyval.rblk) = gen_pf_reason((yyvsp[0].i)); }
#line 2787 "y.tab.c"
    break;

  case 125: /* pfvar: PF_ACTION action  */
#line 505 "./grammar.y"
                                { (yyval.rblk) = gen_pf_action((yyvsp[0].i)); }
#line 2793 "y.tab.c"
    break;

  case 126: /* p80211: TYPE type SUBTYPE subtype  */
#line 509 "./grammar.y"
                                { (yyval.rblk) = gen_p80211_type((yyvsp[-2].i) | (yyvsp[0].i),
					IEEE80211_FC0_TYPE_MASK |
					IEEE80211_FC0_SUBTYPE_MASK);
				}
#line 2802 "y.tab.c"
    break;

  case 127: /* p80211: TYPE type  */
#line 513 "./grammar.y"
                                { (yyval.rblk) = gen_p80211_type((yyvsp[0].i),
					IEEE80211_FC0_TYPE_MASK);
				}
#line 2810 "y.tab.c"
    break;

  case 128: /* p80211: SUBTYPE type_subtype  */
#line 516 "./grammar.y"
                                { (yyval.rblk) = gen_p80211_type((yyvsp[0].i),
					IEEE80211_FC0_TYPE_MASK |
					IEEE80211_FC0_SUBTYPE_MASK);
				}
#line 2819 "y.tab.c"
    break;

  case 129: /* p80211: DIR dir  */
#line 520 "./grammar.y"
                                { (yyval.rblk) = gen_p80211_fcdir((yyvsp[0].i)); }
#line 2825 "y.tab.c"
    break;

  case 131: /* type: ID  */
#line 524 "./grammar.y"
                                { (yyval.i) = str2tok((yyvsp[0].s), ieee80211_types);
				  if ((yyval.i) == -1)
				  	bpf_error("unknown 802.11 type name");
				}
#line 2834 "y.tab.c"
    break;

  case 133: /* subtype: ID  */
#line 531 "./grammar.y"
                                { const struct tok *types = NULL;
				  int i;
				  for (i = 0;; i++) {
				  	if (ieee80211_type_subtypes[i].tok == NULL) {
				  		/* Ran out of types */
						bpf_error("unknown 802.11 type");
						break;
					}
					if ((yyvsp[(-1) - (1)].i) == ieee80211_type_subtypes[i].type) {
						types = ieee80211_type_subtypes[i].tok;
						break;
					}
				  }

				  (yyval.i) = str2tok((yyvsp[0].s), types);
				  if ((yyval.i) == -1)
					bpf_error("unknown 802.11 subtype name");
				}
#line 2857 "y.tab.c"
    break;

  case 134: /* type_subtype: ID  */
#line 551 "./grammar.y"
                                { int i;
				  for (i = 0;; i++) {
				  	if (ieee80211_type_subtypes[i].tok == NULL) {
				  		/* Ran out of types */
						bpf_error("unknown 802.11 type name");
						break;
					}
					(yyval.i) = str2tok((yyvsp[0].s), ieee80211_type_subtypes[i].tok);
					if ((yyval.i) != -1) {
						(yyval.i) |= ieee80211_type_subtypes[i].type;
						break;
					}
				  }
				}
#line 2876 "y.tab.c"
    break;

  case 136: /* dir: ID  */
#line 568 "./grammar.y"
                                { if (sfbpf_strcasecmp((yyvsp[0].s), "nods") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_NODS;
				  else if (sfbpf_strcasecmp((yyvsp[0].s), "tods") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_TODS;
				  else if (sfbpf_strcasecmp((yyvsp[0].s), "fromds") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_FROMDS;
				  else if (sfbpf_strcasecmp((yyvsp[0].s), "dstods") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_DSTODS;
				  else
					bpf_error("unknown 802.11 direction");
				}
#line 2892 "y.tab.c"
    break;

  case 137: /* reason: NUM  */
#line 581 "./grammar.y"
                                { (yyval.i) = (yyvsp[0].i); }
#line 2898 "y.tab.c"
    break;

  case 138: /* reason: ID  */
#line 582 "./grammar.y"
                                { (yyval.i) = pfreason_to_num((yyvsp[0].s)); }
#line 2904 "y.tab.c"
    break;

  case 139: /* action: ID  */
#line 585 "./grammar.y"
                                { (yyval.i) = pfaction_to_num((yyvsp[0].s)); }
#line 2910 "y.tab.c"
    break;

  case 140: /* relop: '>'  */
#line 588 "./grammar.y"
                                { (yyval.i) = SFBPF_JGT; }
#line 2916 "y.tab.c"
    break;

  case 141: /* relop: GEQ  */
#line 589 "./grammar.y"
                                { (yyval.i) = SFBPF_JGE; }
#line 2922 "y.tab.c"
    break;

  case 142: /* relop: '='  */
#line 590 "./grammar.y"
                                { (yyval.i) = SFBPF_JEQ; }
#line 2928 "y.tab.c"
    break;

  case 143: /* irelop: LEQ  */
#line 592 "./grammar.y"
                                { (yyval.i) = SFBPF_JGT; }
#line 2934 "y.tab.c"
    break;

  case 144: /* irelop: '<'  */
#line 593 "./grammar.y"
                                { (yyval.i) = SFBPF_JGE; }
#line 2940 "y.tab.c"
    break;

  case 145: /* irelop: NEQ  */
#line 594 "./grammar.y"
                                { (yyval.i) = SFBPF_JEQ; }
#line 2946 "y.tab.c"
    break;

  case 146: /* arth: pnum  */
#line 596 "./grammar.y"
                                { (yyval.a) = gen_loadi((yyvsp[0].i)); }
#line 2952 "y.tab.c"
    break;

  case 148: /* narth: pname '[' arth ']'  */
#line 599 "./grammar.y"
                                        { (yyval.a) = gen_load((yyvsp[-3].i), (yyvsp[-1].a), 1); }
#line 2958 "y.tab.c"
    break;

  case 149: /* narth: pname '[' arth ':' NUM ']'  */
#line 600 "./grammar.y"
                                        { (yyval.a) = gen_load((yyvsp[-5].i), (yyvsp[-3].a), (yyvsp[-1].i)); }
#line 2964 "y.tab.c"
    break;

  case 150: /* narth: arth '+' arth  */
#line 601 "./grammar.y"
                                        { (yyval.a) = gen_arth(SFBPF_ADD, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 2970 "y.tab.c"
    break;

  case 151: /* narth: arth '-' arth  */
#line 602 "./grammar.y"
                                        { (yyval.a) = gen_arth(SFBPF_SUB, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 2976 "y.tab.c"
    break;

  case 152: /* narth: arth '*' arth  */
#line 603 "./grammar.y"
                                        { (yyval.a) = gen_arth(SFBPF_MUL, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 2982 "y.tab.c"
    break;

  case 153: /* narth: arth '/' arth  */
#line 604 "./grammar.y"
                                        { (yyval.a) = gen_arth(SFBPF_DIV, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 2988 "y.tab.c"
    break;

  case 154: /* narth: arth '&' arth  */
#line 605 "./grammar.y"
                                        { (yyval.a) = gen_arth(SFBPF_AND, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 2994 "y.tab.c"
    break;

  case 155: /* narth: arth '|' arth  */
#line 606 "./grammar.y"
                                        { (yyval.a) = gen_arth(SFBPF_OR, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3000 "y.tab.c"
    break;

  case 156: /* narth: arth LSH arth  */
#line 607 "./grammar.y"
                                        { (yyval.a) = gen_arth(SFBPF_LSH, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3006 "y.tab.c"
    break;

  case 157: /* narth: arth RSH arth  */
#line 608 "./grammar.y"
                                        { (yyval.a) = gen_arth(SFBPF_RSH, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3012 "y.tab.c"
    break;

  case 158: /* narth: '-' arth  */
#line 609 "./grammar.y"
                                        { (yyval.a) = gen_neg((yyvsp[0].a)); }
#line 3018 "y.tab.c"
    break;

  case 159: /* narth: paren narth ')'  */
#line 610 "./grammar.y"
                                        { (yyval.a) = (yyvsp[-1].a); }
#line 3024 "y.tab.c"
    break;

  case 160: /* narth: LEN  */
#line 611 "./grammar.y"
                                        { (yyval.a) = gen_loadlen(); }
#line 3030 "y.tab.c"
    break;

  case 161: /* byteop: '&'  */
#line 613 "./grammar.y"
                                { (yyval.i) = '&'; }
#line 3036 "y.tab.c"
    break;

  case 162: /* byteop: '|'  */
#line 614 "./grammar.y"
                                { (yyval.i) = '|'; }
#line 3042 "y.tab.c"
    break;

  case 163: /* byteop: '<'  */
#line 615 "./grammar.y"
                                { (yyval.i) = '<'; }
#line 3048 "y.tab.c"
    break;

  case 164: /* byteop: '>'  */
#line 616 "./grammar.y"
                                { (yyval.i) = '>'; }
#line 3054 "y.tab.c"
    break;

  case 165: /* byteop: '='  */
#line 617 "./grammar.y"
                                { (yyval.i) = '='; }
#line 3060 "y.tab.c"
    break;

  case 167: /* pnum: paren pnum ')'  */
#line 620 "./grammar.y"
                                { (yyval.i) = (yyvsp[-1].i); }
#line 3066 "y.tab.c"
    break;

  case 168: /* atmtype: LANE  */
#line 622 "./grammar.y"
                                { (yyval.i) = A_LANE; }
#line 3072 "y.tab.c"
    break;

  case 169: /* atmtype: LLC  */
#line 623 "./grammar.y"
                                { (yyval.i) = A_LLC; }
#line 3078 "y.tab.c"
    break;

  case 170: /* atmtype: METAC  */
#line 624 "./grammar.y"
                                { (yyval.i) = A_METAC;	}
#line 3084 "y.tab.c"
    break;

  case 171: /* atmtype: BCC  */
#line 625 "./grammar.y"
                                { (yyval.i) = A_BCC; }
#line 3090 "y.tab.c"
    break;

  case 172: /* atmtype: OAMF4EC  */
#line 626 "./grammar.y"
                                { (yyval.i) = A_OAMF4EC; }
#line 3096 "y.tab.c"
    break;

  case 173: /* atmtype: OAMF4SC  */
#line 627 "./grammar.y"
                                { (yyval.i) = A_OAMF4SC; }
#line 3102 "y.tab.c"
    break;

  case 174: /* atmtype: SC  */
#line 628 "./grammar.y"
                                { (yyval.i) = A_SC; }
#line 3108 "y.tab.c"
    break;

  case 175: /* atmtype: ILMIC  */
#line 629 "./grammar.y"
                                { (yyval.i) = A_ILMIC; }
#line 3114 "y.tab.c"
    break;

  case 176: /* atmmultitype: OAM  */
#line 631 "./grammar.y"
                                { (yyval.i) = A_OAM; }
#line 3120 "y.tab.c"
    break;

  case 177: /* atmmultitype: OAMF4  */
#line 632 "./grammar.y"
                                { (yyval.i) = A_OAMF4; }
#line 3126 "y.tab.c"
    break;

  case 178: /* atmmultitype: CONNECTMSG  */
#line 633 "./grammar.y"
                                { (yyval.i) = A_CONNECTMSG; }
#line 3132 "y.tab.c"
    break;

  case 179: /* atmmultitype: METACONNECT  */
#line 634 "./grammar.y"
                                { (yyval.i) = A_METACONNECT; }
#line 3138 "y.tab.c"
    break;

  case 180: /* atmfield: VPI  */
#line 637 "./grammar.y"
                                { (yyval.blk).atmfieldtype = A_VPI; }
#line 3144 "y.tab.c"
    break;

  case 181: /* atmfield: VCI  */
#line 638 "./grammar.y"
                                { (yyval.blk).atmfieldtype = A_VCI; }
#line 3150 "y.tab.c"
    break;

  case 183: /* atmvalue: relop NUM  */
#line 641 "./grammar.y"
                                { (yyval.blk).b = gen_atmfield_code((yyvsp[-2].blk).atmfieldtype, (sfbpf_int32)(yyvsp[0].i), (sfbpf_u_int32)(yyvsp[-1].i), 0); }
#line 3156 "y.tab.c"
    break;

  case 184: /* atmvalue: irelop NUM  */
#line 642 "./grammar.y"
                                { (yyval.blk).b = gen_atmfield_code((yyvsp[-2].blk).atmfieldtype, (sfbpf_int32)(yyvsp[0].i), (sfbpf_u_int32)(yyvsp[-1].i), 1); }
#line 3162 "y.tab.c"
    break;

  case 185: /* atmvalue: paren atmlistvalue ')'  */
#line 643 "./grammar.y"
                                 { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = qerr; }
#line 3168 "y.tab.c"
    break;

  case 186: /* atmfieldvalue: NUM  */
#line 645 "./grammar.y"
                   {
	(yyval.blk).atmfieldtype = (yyvsp[-1].blk).atmfieldtype;
	if ((yyval.blk).atmfieldtype == A_VPI ||
	    (yyval.blk).atmfieldtype == A_VCI)
		(yyval.blk).b = gen_atmfield_code((yyval.blk).atmfieldtype, (sfbpf_int32) (yyvsp[0].i), SFBPF_JEQ, 0);
	}
#line 3179 "y.tab.c"
    break;

  case 188: /* atmlistvalue: atmlistvalue or atmfieldvalue  */
#line 653 "./grammar.y"
                                        { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 3185 "y.tab.c"
    break;

  case 189: /* mtp2type: FISU  */
#line 656 "./grammar.y"
                                { (yyval.i) = M_FISU; }
#line 3191 "y.tab.c"
    break;

  case 190: /* mtp2type: LSSU  */
#line 657 "./grammar.y"
                                { (yyval.i) = M_LSSU; }
#line 3197 "y.tab.c"
    break;

  case 191: /* mtp2type: MSU  */
#line 658 "./grammar.y"
                                { (yyval.i) = M_MSU; }
#line 3203 "y.tab.c"
    break;

  case 192: /* mtp3field: SIO  */
#line 661 "./grammar.y"
                                { (yyval.blk).mtp3fieldtype = M_SIO; }
#line 3209 "y.tab.c"
    break;

  case 193: /* mtp3field: OPC  */
#line 662 "./grammar.y"
                                { (yyval.blk).mtp3fieldtype = M_OPC; }
#line 3215 "y.tab.c"
    break;

  case 194: /* mtp3field: DPC  */
#line 663 "./grammar.y"
                                { (yyval.blk).mtp3fieldtype = M_DPC; }
#line 3221 "y.tab.c"
    break;

  case 195: /* mtp3field: SLS  */
#line 664 "./grammar.y"
                                { (yyval.blk).mtp3fieldtype = M_SLS; }
#line 3227 "y.tab.c"
    break;

  case 197: /* mtp3value: relop NUM  */
#line 667 "./grammar.y"
                                { (yyval.blk).b = gen_mtp3field_code((yyvsp[-2].blk).mtp3fieldtype, (u_int)(yyvsp[0].i), (u_int)(yyvsp[-1].i), 0); }
#line 3233 "y.tab.c"
    break;

  case 198: /* mtp3value: irelop NUM  */
#line 668 "./grammar.y"
                                { (yyval.blk).b = gen_mtp3field_code((yyvsp[-2].blk).mtp3fieldtype, (u_int)(yyvsp[0].i), (u_int)(yyvsp[-1].i), 1); }
#line 3239 "y.tab.c"
    break;

  case 199: /* mtp3value: paren mtp3listvalue ')'  */
#line 669 "./grammar.y"
                                  { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = qerr; }
#line 3245 "y.tab.c"
    break;

  case 200: /* mtp3fieldvalue: NUM  */
#line 671 "./grammar.y"
                    {
	(yyval.blk).mtp3fieldtype = (yyvsp[-1].blk).mtp3fieldtype;
	if ((yyval.blk).mtp3fieldtype == M_SIO ||
	    (yyval.blk).mtp3fieldtype == M_OPC ||
	    (yyval.blk).mtp3fieldtype == M_DPC ||
	    (yyval.blk).mtp3fieldtype == M_SLS )
		(yyval.blk).b = gen_mtp3field_code((yyval.blk).mtp3fieldtype, (u_int) (yyvsp[0].i), SFBPF_JEQ, 0);
	}
#line 3258 "y.tab.c"
    break;

  case 202: /* mtp3listvalue: mtp3listvalue or mtp3fieldvalue  */
#line 681 "./grammar.y"
                                          { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 3264 "y.tab.c"
    break;


#line 3268 "y.tab.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 683 "./grammar.y"

