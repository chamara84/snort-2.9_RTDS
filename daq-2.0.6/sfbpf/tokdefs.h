/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

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

#line 303 "y.tab.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE sfbpf_lval;


int sfbpf_parse (void);


#endif /* !YY_SFBPF_Y_TAB_H_INCLUDED  */
