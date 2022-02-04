/* A Bison parser, made by GNU Bison 3.5.1.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.5.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         sfat_parse
#define yylex           sfat_lex
#define yyerror         sfat_error
#define yydebug         sfat_debug
#define yynerrs         sfat_nerrs
#define yylval          sfat_lval
#define yychar          sfat_char

/* First part of user prologue.  */
#line 33 "sf_attribute_table.y"

#ifdef TARGET_BASED
#include <stdlib.h>
#include <string.h>
#include "sftarget_reader.h"
#include "snort_debug.h"

#define YYSTACK_USE_ALLOCA 0

/* define the initial stack-sizes */

#ifdef YYMAXDEPTH
#undef YYMAXDEPTH
#define YYMAXDEPTH  70000
#else
#define YYMAXDEPTH  70000
#endif

extern ServiceClient sfat_client_or_service;
extern char *sfat_grammar_error;

extern int sfat_lex();
extern void sfat_error(char*);

#line 102 "y.tab.c"

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

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_SFAT_Y_TAB_H_INCLUDED
# define YY_SFAT_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int sfat_debug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    SF_AT_COMMENT = 258,
    SF_AT_WHITESPACE = 259,
    SF_START_SNORT_ATTRIBUTES = 260,
    SF_END_SNORT_ATTRIBUTES = 261,
    SF_AT_START_MAP_TABLE = 262,
    SF_AT_END_MAP_TABLE = 263,
    SF_AT_START_ENTRY = 264,
    SF_AT_END_ENTRY = 265,
    SF_AT_START_ENTRY_ID = 266,
    SF_AT_END_ENTRY_ID = 267,
    SF_AT_START_ENTRY_VALUE = 268,
    SF_AT_END_ENTRY_VALUE = 269,
    SF_AT_START_ATTRIBUTE_TABLE = 270,
    SF_AT_END_ATTRIBUTE_TABLE = 271,
    SF_AT_START_HOST = 272,
    SF_AT_END_HOST = 273,
    SF_AT_START_HOST_IP = 274,
    SF_AT_END_HOST_IP = 275,
    SF_AT_STRING = 276,
    SF_AT_NUMERIC = 277,
    SF_AT_IPv6 = 278,
    SF_AT_IPv6Cidr = 279,
    SF_AT_START_OS = 280,
    SF_AT_END_OS = 281,
    SF_AT_START_ATTRIBUTE_VALUE = 282,
    SF_AT_END_ATTRIBUTE_VALUE = 283,
    SF_AT_START_ATTRIBUTE_ID = 284,
    SF_AT_END_ATTRIBUTE_ID = 285,
    SF_AT_START_CONFIDENCE = 286,
    SF_AT_END_CONFIDENCE = 287,
    SF_AT_START_NAME = 288,
    SF_AT_END_NAME = 289,
    SF_AT_START_VENDOR = 290,
    SF_AT_END_VENDOR = 291,
    SF_AT_START_VERSION = 292,
    SF_AT_END_VERSION = 293,
    SF_AT_START_FRAG_POLICY = 294,
    SF_AT_END_FRAG_POLICY = 295,
    SF_AT_START_STREAM_POLICY = 296,
    SF_AT_END_STREAM_POLICY = 297,
    SF_AT_START_SERVICES = 298,
    SF_AT_END_SERVICES = 299,
    SF_AT_START_SERVICE = 300,
    SF_AT_END_SERVICE = 301,
    SF_AT_START_CLIENTS = 302,
    SF_AT_END_CLIENTS = 303,
    SF_AT_START_CLIENT = 304,
    SF_AT_END_CLIENT = 305,
    SF_AT_START_IPPROTO = 306,
    SF_AT_END_IPPROTO = 307,
    SF_AT_START_PORT = 308,
    SF_AT_END_PORT = 309,
    SF_AT_START_PROTOCOL = 310,
    SF_AT_END_PROTOCOL = 311,
    SF_AT_START_APPLICATION = 312,
    SF_AT_END_APPLICATION = 313
  };
#endif
/* Tokens.  */
#define SF_AT_COMMENT 258
#define SF_AT_WHITESPACE 259
#define SF_START_SNORT_ATTRIBUTES 260
#define SF_END_SNORT_ATTRIBUTES 261
#define SF_AT_START_MAP_TABLE 262
#define SF_AT_END_MAP_TABLE 263
#define SF_AT_START_ENTRY 264
#define SF_AT_END_ENTRY 265
#define SF_AT_START_ENTRY_ID 266
#define SF_AT_END_ENTRY_ID 267
#define SF_AT_START_ENTRY_VALUE 268
#define SF_AT_END_ENTRY_VALUE 269
#define SF_AT_START_ATTRIBUTE_TABLE 270
#define SF_AT_END_ATTRIBUTE_TABLE 271
#define SF_AT_START_HOST 272
#define SF_AT_END_HOST 273
#define SF_AT_START_HOST_IP 274
#define SF_AT_END_HOST_IP 275
#define SF_AT_STRING 276
#define SF_AT_NUMERIC 277
#define SF_AT_IPv6 278
#define SF_AT_IPv6Cidr 279
#define SF_AT_START_OS 280
#define SF_AT_END_OS 281
#define SF_AT_START_ATTRIBUTE_VALUE 282
#define SF_AT_END_ATTRIBUTE_VALUE 283
#define SF_AT_START_ATTRIBUTE_ID 284
#define SF_AT_END_ATTRIBUTE_ID 285
#define SF_AT_START_CONFIDENCE 286
#define SF_AT_END_CONFIDENCE 287
#define SF_AT_START_NAME 288
#define SF_AT_END_NAME 289
#define SF_AT_START_VENDOR 290
#define SF_AT_END_VENDOR 291
#define SF_AT_START_VERSION 292
#define SF_AT_END_VERSION 293
#define SF_AT_START_FRAG_POLICY 294
#define SF_AT_END_FRAG_POLICY 295
#define SF_AT_START_STREAM_POLICY 296
#define SF_AT_END_STREAM_POLICY 297
#define SF_AT_START_SERVICES 298
#define SF_AT_END_SERVICES 299
#define SF_AT_START_SERVICE 300
#define SF_AT_END_SERVICE 301
#define SF_AT_START_CLIENTS 302
#define SF_AT_END_CLIENTS 303
#define SF_AT_START_CLIENT 304
#define SF_AT_END_CLIENT 305
#define SF_AT_START_IPPROTO 306
#define SF_AT_END_IPPROTO 307
#define SF_AT_START_PORT 308
#define SF_AT_END_PORT 309
#define SF_AT_START_PROTOCOL 310
#define SF_AT_END_PROTOCOL 311
#define SF_AT_START_APPLICATION 312
#define SF_AT_END_APPLICATION 313

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 59 "sf_attribute_table.y"

  char stringValue[STD_BUF];
  uint32_t numericValue;
  AttributeData data;
  MapData mapEntry;

#line 277 "y.tab.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE sfat_lval;

int sfat_parse (void);

#endif /* !YY_SFAT_Y_TAB_H_INCLUDED  */



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
typedef yytype_uint8 yy_state_t;

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
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
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

#if ! defined yyoverflow || YYERROR_VERBOSE

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
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


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
#define YYFINAL  8
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   133

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  59
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  54
/* YYNRULES -- Number of rules.  */
#define YYNRULES  83
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  152

#define YYUNDEFTOK  2
#define YYMAXUTOK   313


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
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
      55,    56,    57,    58
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   144,   144,   150,   155,   162,   168,   171,   174,   182,
     185,   188,   195,   202,   210,   216,   219,   222,   232,   239,
     242,   247,   252,   257,   264,   275,   277,   277,   279,   279,
     279,   279,   279,   282,   290,   298,   306,   314,   322,   328,
     334,   340,   346,   366,   388,   394,   398,   404,   411,   418,
     424,   431,   437,   440,   446,   454,   461,   467,   471,   477,
     482,   487,   492,   497,   502,   509,   517,   525,   533,   540,
     549,   557,   563,   570,   576,   579,   585,   593,   600,   606,
     610,   616,   621,   626
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "SF_AT_COMMENT", "SF_AT_WHITESPACE",
  "SF_START_SNORT_ATTRIBUTES", "SF_END_SNORT_ATTRIBUTES",
  "SF_AT_START_MAP_TABLE", "SF_AT_END_MAP_TABLE", "SF_AT_START_ENTRY",
  "SF_AT_END_ENTRY", "SF_AT_START_ENTRY_ID", "SF_AT_END_ENTRY_ID",
  "SF_AT_START_ENTRY_VALUE", "SF_AT_END_ENTRY_VALUE",
  "SF_AT_START_ATTRIBUTE_TABLE", "SF_AT_END_ATTRIBUTE_TABLE",
  "SF_AT_START_HOST", "SF_AT_END_HOST", "SF_AT_START_HOST_IP",
  "SF_AT_END_HOST_IP", "SF_AT_STRING", "SF_AT_NUMERIC", "SF_AT_IPv6",
  "SF_AT_IPv6Cidr", "SF_AT_START_OS", "SF_AT_END_OS",
  "SF_AT_START_ATTRIBUTE_VALUE", "SF_AT_END_ATTRIBUTE_VALUE",
  "SF_AT_START_ATTRIBUTE_ID", "SF_AT_END_ATTRIBUTE_ID",
  "SF_AT_START_CONFIDENCE", "SF_AT_END_CONFIDENCE", "SF_AT_START_NAME",
  "SF_AT_END_NAME", "SF_AT_START_VENDOR", "SF_AT_END_VENDOR",
  "SF_AT_START_VERSION", "SF_AT_END_VERSION", "SF_AT_START_FRAG_POLICY",
  "SF_AT_END_FRAG_POLICY", "SF_AT_START_STREAM_POLICY",
  "SF_AT_END_STREAM_POLICY", "SF_AT_START_SERVICES", "SF_AT_END_SERVICES",
  "SF_AT_START_SERVICE", "SF_AT_END_SERVICE", "SF_AT_START_CLIENTS",
  "SF_AT_END_CLIENTS", "SF_AT_START_CLIENT", "SF_AT_END_CLIENT",
  "SF_AT_START_IPPROTO", "SF_AT_END_IPPROTO", "SF_AT_START_PORT",
  "SF_AT_END_PORT", "SF_AT_START_PROTOCOL", "SF_AT_END_PROTOCOL",
  "SF_AT_START_APPLICATION", "SF_AT_END_APPLICATION", "$accept",
  "AttributeGrammar", "SnortAttributes", "MappingTable",
  "ListOfMapEntries", "MapEntry", "MapEntryStart", "MapEntryEnd",
  "MapEntryData", "MapValue", "MapId", "AttributeTable", "ListOfHosts",
  "HostEntry", "HostEntryStart", "HostEntryEnd", "HostEntryData", "IpCidr",
  "HostOS", "OSAttributes", "OSAttribute", "OSName", "OSVendor",
  "OSVersion", "OSFragPolicy", "OSStreamPolicy", "AttributeInfo",
  "AttributeValueString", "AttributeValueNumber", "AttributeId",
  "AttributeConfidence", "ServiceList", "ServiceListStart",
  "ServiceListEnd", "ServiceListData", "Service", "ServiceStart",
  "ServiceEnd", "ServiceData", "ServiceDataRequired", "IPProtocol",
  "Protocol", "Port", "Application", "Version", "ClientList",
  "ClientListStart", "ClientListEnd", "ClientListData", "Client",
  "ClientStart", "ClientEnd", "ClientData", "ClientDataRequired", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313
};
# endif

#define YYPACT_NINF (-97)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int8 yypact[] =
{
       1,    25,     9,   -97,    28,   -97,    30,    41,   -97,   -97,
      43,    28,    51,    42,    57,   -97,   -97,   -97,    44,    54,
      52,   -97,   -97,   -97,    48,   -97,    56,   -97,   -97,    49,
     -97,    50,    55,    47,   -97,    60,    59,   -97,   -97,   -23,
      -4,   -97,   -97,    -7,    -7,    -7,    61,    62,   -22,   -97,
     -97,   -97,   -97,   -97,   -97,   -97,   -97,    22,    31,   -97,
      26,    13,    58,    53,    46,    46,    46,    45,    63,    64,
      65,   -97,   -97,   -97,   -97,    40,    31,    -9,   -97,    37,
      26,     2,    66,    67,   -97,    68,   -97,    69,   -97,   -97,
     -97,   -97,   -97,   -97,   -97,   -97,   -97,   -97,    -7,    -7,
      -7,    70,    29,   -32,   -15,     2,   -97,   -97,   -97,    33,
      38,    71,    29,   -97,   -97,   -97,    73,    72,    36,    74,
     -97,   -97,    -7,   -97,    39,    33,    39,    38,    33,    38,
     -97,   -97,   -97,   -97,   -97,   -97,   -97,   -97,   -97,   -34,
     -97,   -97,   -97,   -97,   -97,   -97,    -7,   -97,    35,    75,
     -97,   -97
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       0,     0,     0,     2,     6,    15,     0,     0,     1,     9,
       0,     6,     0,     0,     0,     4,     5,     7,     0,     0,
       0,    14,    18,    16,     0,     3,     0,    10,     8,     0,
      11,     0,     0,     0,    13,     0,     0,    19,    17,     0,
      23,    12,    24,     0,     0,     0,     0,     0,     0,    26,
      28,    29,    30,    32,    31,    50,    72,    22,    52,    21,
      74,     0,     0,     0,    38,    41,    43,     0,     0,     0,
       0,    25,    27,    20,    55,     0,    52,     0,    77,     0,
      74,     0,     0,     0,    45,     0,    33,     0,    39,    40,
      42,    34,    35,    36,    37,    51,    49,    53,     0,     0,
       0,     0,    57,     0,     0,     0,    73,    71,    75,     0,
      81,     0,    79,    44,    46,    47,     0,     0,     0,     0,
      56,    54,     0,    58,     0,     0,     0,     0,     0,     0,
      82,    83,    78,    76,    80,    48,    65,    67,    66,     0,
      59,    60,    61,    62,    64,    63,     0,    68,     0,     0,
      69,    70
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -97,   -97,   -97,   -97,    85,   -97,   -97,   -97,   -97,   -97,
     -97,    91,   -97,   -97,   -97,   -97,   -97,   -97,   -97,   -97,
      77,   -97,   -97,   -97,   -97,   -97,   -44,   -97,   -97,   -97,
      -5,   -97,   -97,   -97,    23,   -97,   -97,   -97,   -97,   -97,
     -79,   -76,   -96,   -12,   -97,    76,   -97,   -97,    32,   -97,
     -97,   -97,   -97,   -97
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,     3,     6,    10,    11,    12,    28,    19,    30,
      20,     7,    13,    23,    24,    38,    32,    33,    40,    48,
      49,    50,    51,    52,    53,    54,    63,    64,    65,    66,
      88,    57,    58,    96,    75,    76,    77,   121,   101,   102,
     103,   104,   105,   123,   148,    59,    60,   107,    79,    80,
      81,   133,   111,   112
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      67,    68,   109,   146,    71,   110,     1,   125,   127,     8,
      43,    43,    44,    44,    45,    45,    46,    46,    47,    47,
      61,    99,    62,   100,   147,   126,   128,   124,   140,   129,
     142,   131,     4,   130,    82,    83,    98,     9,    99,    55,
       5,    84,    98,    56,    99,     5,   100,    15,   143,   141,
     145,    16,   144,    98,   117,   118,   119,   100,    21,    22,
      89,    90,    18,    25,    27,    29,    26,    31,    34,    56,
      35,    36,    39,    37,    41,    78,    74,    87,   139,    42,
      85,    91,    69,    70,    95,   106,   122,    86,   100,    98,
     137,   116,    99,   150,   113,   114,    17,    14,   115,    97,
     134,    92,   149,     0,    93,   135,     0,    94,     0,     0,
       0,     0,   108,   151,     0,     0,   120,     0,     0,     0,
       0,   132,     0,     0,   136,    72,     0,     0,     0,     0,
     138,     0,     0,    73
};

static const yytype_int16 yycheck[] =
{
      44,    45,    81,    37,    26,    81,     5,   103,   104,     0,
      33,    33,    35,    35,    37,    37,    39,    39,    41,    41,
      27,    53,    29,    55,    58,   104,   105,   103,   124,   105,
     126,   110,     7,   109,    21,    22,    51,     9,    53,    43,
      15,    28,    51,    47,    53,    15,    55,     6,   127,   125,
     129,     8,   128,    51,    98,    99,   100,    55,    16,    17,
      65,    66,    11,     6,    10,    13,    22,    19,    12,    47,
      21,    21,    25,    18,    14,    49,    45,    31,   122,    20,
      22,    36,    21,    21,    44,    48,    57,    34,    55,    51,
      54,    22,    53,    58,    28,    28,    11,     6,    30,    76,
     112,    38,   146,    -1,    40,    32,    -1,    42,    -1,    -1,
      -1,    -1,    80,    38,    -1,    -1,    46,    -1,    -1,    -1,
      -1,    50,    -1,    -1,    52,    48,    -1,    -1,    -1,    -1,
      56,    -1,    -1,    57
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     5,    60,    61,     7,    15,    62,    70,     0,     9,
      63,    64,    65,    71,    70,     6,     8,    63,    11,    67,
      69,    16,    17,    72,    73,     6,    22,    10,    66,    13,
      68,    19,    75,    76,    12,    21,    21,    18,    74,    25,
      77,    14,    20,    33,    35,    37,    39,    41,    78,    79,
      80,    81,    82,    83,    84,    43,    47,    90,    91,   104,
     105,    27,    29,    85,    86,    87,    88,    85,    85,    21,
      21,    26,    79,   104,    45,    93,    94,    95,    49,   107,
     108,   109,    21,    22,    28,    22,    34,    31,    89,    89,
      89,    36,    38,    40,    42,    44,    92,    93,    51,    53,
      55,    97,    98,    99,   100,   101,    48,   106,   107,    99,
     100,   111,   112,    28,    28,    30,    22,    85,    85,    85,
      46,    96,    57,   102,   100,   101,    99,   101,    99,   100,
     100,    99,    50,   110,   102,    32,    52,    54,    56,    85,
     101,   100,   101,    99,   100,    99,    37,    58,   103,    85,
      58,    38
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int8 yyr1[] =
{
       0,    59,    60,    61,    61,    62,    63,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    71,    72,    73,    74,
      75,    75,    75,    75,    76,    77,    78,    78,    79,    79,
      79,    79,    79,    80,    81,    82,    83,    84,    85,    85,
      85,    85,    85,    85,    86,    87,    87,    88,    89,    90,
      91,    92,    93,    93,    94,    95,    96,    97,    97,    98,
      98,    98,    98,    98,    98,    99,   100,   101,   102,   102,
     103,   104,   105,   106,   107,   107,   108,   109,   110,   111,
     111,   112,   112,   112
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     1,     4,     3,     3,     0,     2,     3,     1,
       1,     2,     3,     3,     3,     0,     2,     3,     1,     1,
       4,     3,     3,     2,     3,     3,     1,     2,     1,     1,
       1,     1,     1,     3,     3,     3,     3,     3,     1,     2,
       2,     1,     2,     1,     3,     2,     3,     3,     3,     3,
       1,     1,     0,     2,     3,     1,     1,     1,     2,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     4,
       3,     3,     1,     1,     0,     2,     3,     1,     1,     1,
       2,     1,     2,     2
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


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

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



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

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YYUSE (yyoutput);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yytype], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyo, yytype, yyvaluep);
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
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, int yyrule)
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
                       yystos[+yyssp[yyi + 1 - yynrhs]],
                       &yyvsp[(yyi + 1) - (yynrhs)]
                                              );
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
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
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


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
#  else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                yy_state_t *yyssp, int yytoken)
{
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Actual size of YYARG. */
  int yycount = 0;
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[+*yyssp];
      YYPTRDIFF_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
      yysize = yysize0;
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYPTRDIFF_T yysize1
                    = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
                    yysize = yysize1;
                  else
                    return 2;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    /* Don't count the "%s"s in the final size, but reserve room for
       the terminator.  */
    YYPTRDIFF_T yysize1 = yysize + (yystrlen (yyformat) - 2 * yycount) + 1;
    if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
      yysize = yysize1;
    else
      return 2;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
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
    yy_state_fast_t yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss;
    yy_state_t *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYPTRDIFF_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
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

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
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
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
# undef YYSTACK_RELOCATE
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

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
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
  case 2:
#line 145 "sf_attribute_table.y"
  {
    YYACCEPT;
  }
#line 1589 "y.tab.c"
    break;

  case 3:
#line 151 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "SnortAttributes: Got Attribute Map & Table\n"););
  }
#line 1597 "y.tab.c"
    break;

  case 4:
#line 156 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "SnortAttributes: Got Attribute Table\n"););
  }
#line 1605 "y.tab.c"
    break;

  case 5:
#line 163 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Got Attribute Map\n"););
  }
#line 1613 "y.tab.c"
    break;

  case 6:
#line 168 "sf_attribute_table.y"
   {
     DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Empty Mapping Table\n"););
   }
#line 1621 "y.tab.c"
    break;

  case 8:
#line 175 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "MapEntry: Name: %s, Id %d\n",
        (yyvsp[-1].mapEntry).s_mapvalue, (yyvsp[-1].mapEntry).l_mapid););
    SFAT_AddMapEntry(&(yyvsp[-1].mapEntry));
  }
#line 1631 "y.tab.c"
    break;

  case 11:
#line 189 "sf_attribute_table.y"
  {
    (yyval.mapEntry).l_mapid = (yyvsp[-1].numericValue);
    SnortStrncpy((yyval.mapEntry).s_mapvalue, (yyvsp[0].stringValue), STD_BUF);
  }
#line 1640 "y.tab.c"
    break;

  case 12:
#line 196 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "MapValue: %s\n", (yyvsp[-1].stringValue));)
    SnortStrncpy((yyval.stringValue), (yyvsp[-1].stringValue), STD_BUF);
  }
#line 1649 "y.tab.c"
    break;

  case 13:
#line 203 "sf_attribute_table.y"
  {
    (yyval.numericValue) = (yyvsp[-1].numericValue);
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "MapId: %d\n", (yyvsp[-1].numericValue)););
  }
#line 1658 "y.tab.c"
    break;

  case 14:
#line 211 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Got Attribute Table\n"););
  }
#line 1666 "y.tab.c"
    break;

  case 15:
#line 216 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "EmptyHostEntry\n"););
  }
#line 1674 "y.tab.c"
    break;

  case 17:
#line 223 "sf_attribute_table.y"
  {
    if (SFAT_AddHostEntryToMap() != SFAT_OK)
    {
        YYABORT;
    }
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Host Added\n"););
  }
#line 1686 "y.tab.c"
    break;

  case 18:
#line 233 "sf_attribute_table.y"
  {
    /* Callback to create a host entry object */
    SFAT_CreateHostEntry();
  }
#line 1695 "y.tab.c"
    break;

  case 20:
#line 243 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "HostEntryData\n"););
  }
#line 1703 "y.tab.c"
    break;

  case 21:
#line 248 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "HostEntryData: No Services\n"););
  }
#line 1711 "y.tab.c"
    break;

  case 22:
#line 253 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "HostEntryData: No Clients\n"););
  }
#line 1719 "y.tab.c"
    break;

  case 23:
#line 258 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "HostEntryData: No Services or Clients\n"););
  }
#line 1727 "y.tab.c"
    break;

  case 24:
#line 265 "sf_attribute_table.y"
  {
    /* Convert IP/CIDR to Snort IPCidr Object */
    /* determine the number of bits (done in SetHostIp4) */
    if (SFAT_SetHostIp((yyvsp[-1].stringValue)) != SFAT_OK)
    {
        YYABORT;
    }
  }
#line 1740 "y.tab.c"
    break;

  case 33:
#line 283 "sf_attribute_table.y"
  {
    /* Copy OSName */
    DEBUG_WRAP(PrintAttributeData("OS:Name", &(yyvsp[-1].data)););
    SFAT_SetOSAttribute(&(yyvsp[-1].data), HOST_INFO_OS);
  }
#line 1750 "y.tab.c"
    break;

  case 34:
#line 291 "sf_attribute_table.y"
  {
    /* Copy OSVendor */
    DEBUG_WRAP(PrintAttributeData("OS:Vendor", &(yyvsp[-1].data)););
    SFAT_SetOSAttribute(&(yyvsp[-1].data), HOST_INFO_VENDOR);
  }
#line 1760 "y.tab.c"
    break;

  case 35:
#line 299 "sf_attribute_table.y"
  {
    /* Copy OSVersion */
    DEBUG_WRAP(PrintAttributeData("OS:Version", &(yyvsp[-1].data)););
    SFAT_SetOSAttribute(&(yyvsp[-1].data), HOST_INFO_VERSION);
  }
#line 1770 "y.tab.c"
    break;

  case 36:
#line 307 "sf_attribute_table.y"
  {
    /* Copy OSFragPolicy */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "OS:FragPolicy: %s\n", (yyvsp[-1].stringValue)););
    SFAT_SetOSPolicy((yyvsp[-1].stringValue), HOST_INFO_FRAG_POLICY);
  }
#line 1780 "y.tab.c"
    break;

  case 37:
#line 315 "sf_attribute_table.y"
  {
    /* Copy OSStreamPolicy */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "OS:StreamPolicy: %s\n", (yyvsp[-1].stringValue)););
    SFAT_SetOSPolicy((yyvsp[-1].stringValue), HOST_INFO_STREAM_POLICY);
  }
#line 1790 "y.tab.c"
    break;

  case 38:
#line 323 "sf_attribute_table.y"
  {
        (yyval.data).type = ATTRIBUTE_NAME; 
        (yyval.data).confidence = 100;
        SnortStrncpy((yyval.data).value.s_value, (yyvsp[0].stringValue), STD_BUF);
  }
#line 1800 "y.tab.c"
    break;

  case 39:
#line 329 "sf_attribute_table.y"
  {
        (yyval.data).type = ATTRIBUTE_NAME; 
        (yyval.data).confidence = (yyvsp[0].numericValue);
        SnortStrncpy((yyval.data).value.s_value, (yyvsp[-1].stringValue), STD_BUF);
  }
#line 1810 "y.tab.c"
    break;

  case 40:
#line 335 "sf_attribute_table.y"
  {
        (yyval.data).type = ATTRIBUTE_NAME; 
        (yyval.data).confidence = (yyvsp[0].numericValue);
        SnortSnprintf((yyval.data).value.s_value, STD_BUF, "%d", (yyvsp[-1].numericValue));
  }
#line 1820 "y.tab.c"
    break;

  case 41:
#line 341 "sf_attribute_table.y"
  {
        (yyval.data).type = ATTRIBUTE_NAME; 
        (yyval.data).confidence = 100;
        SnortSnprintf((yyval.data).value.s_value, STD_BUF, "%d", (yyvsp[0].numericValue));
  }
#line 1830 "y.tab.c"
    break;

  case 42:
#line 347 "sf_attribute_table.y"
  {
        char *mapped_name;
        (yyval.data).confidence = (yyvsp[0].numericValue);
        mapped_name = SFAT_LookupAttributeNameById((yyvsp[-1].numericValue));
        if (!mapped_name)
        {
            (yyval.data).type = ATTRIBUTE_ID; 
            (yyval.data).value.l_value = (yyvsp[-1].numericValue);
            //FatalError("Unknown/Invalid Attribute ID %d\n", $1);
            sfat_grammar_error = "Unknown/Invalid Attribute ID";
            YYABORT;
        }
        else
        {
            /* Copy String */
            (yyval.data).type = ATTRIBUTE_NAME; 
            SnortStrncpy((yyval.data).value.s_value, mapped_name, STD_BUF);
        }
  }
#line 1854 "y.tab.c"
    break;

  case 43:
#line 367 "sf_attribute_table.y"
  {
        char *mapped_name;
        (yyval.data).confidence = 100;
        mapped_name = SFAT_LookupAttributeNameById((yyvsp[0].numericValue));
        if (!mapped_name)
        {
            (yyval.data).type = ATTRIBUTE_ID; 
            (yyval.data).value.l_value = (yyvsp[0].numericValue);
            //FatalError("Unknown/Invalid Attribute ID %d\n", $1);
            sfat_grammar_error = "Unknown/Invalid Attribute ID";
            YYABORT;
        }
        else
        {
            /* Copy String */
            (yyval.data).type = ATTRIBUTE_NAME; 
            SnortStrncpy((yyval.data).value.s_value, mapped_name, STD_BUF);
        }
  }
#line 1878 "y.tab.c"
    break;

  case 44:
#line 389 "sf_attribute_table.y"
  {
        SnortStrncpy((yyval.stringValue), (yyvsp[-1].stringValue), STD_BUF);
  }
#line 1886 "y.tab.c"
    break;

  case 45:
#line 395 "sf_attribute_table.y"
  {
        (yyval.numericValue) = 0;
  }
#line 1894 "y.tab.c"
    break;

  case 46:
#line 399 "sf_attribute_table.y"
  {
        (yyval.numericValue) = (yyvsp[-1].numericValue);
  }
#line 1902 "y.tab.c"
    break;

  case 47:
#line 405 "sf_attribute_table.y"
      {
        /* Copy numeric */
        (yyval.numericValue) = (yyvsp[-1].numericValue);
      }
#line 1911 "y.tab.c"
    break;

  case 48:
#line 412 "sf_attribute_table.y"
  {
    /* Copy numeric */
    (yyval.numericValue) = (yyvsp[-1].numericValue);
  }
#line 1920 "y.tab.c"
    break;

  case 49:
#line 419 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "ServiceList (complete)\n"););
  }
#line 1928 "y.tab.c"
    break;

  case 50:
#line 425 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Start ServiceList\n"););
    sfat_client_or_service = ATTRIBUTE_SERVICE;
  }
#line 1937 "y.tab.c"
    break;

  case 51:
#line 432 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "End ServiceList\n"););
  }
#line 1945 "y.tab.c"
    break;

  case 52:
#line 437 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "EmptyService\n"););
  }
#line 1953 "y.tab.c"
    break;

  case 53:
#line 441 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service ServiceListData\n"););
  }
#line 1961 "y.tab.c"
    break;

  case 54:
#line 447 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Adding Complete\n"););
    SFAT_AddApplicationData();
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Added\n"););
  }
#line 1971 "y.tab.c"
    break;

  case 55:
#line 455 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Start\n"););
    SFAT_CreateApplicationEntry();
  }
#line 1980 "y.tab.c"
    break;

  case 56:
#line 462 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service End\n"););
  }
#line 1988 "y.tab.c"
    break;

  case 57:
#line 468 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data (no application)\n"););
  }
#line 1996 "y.tab.c"
    break;

  case 58:
#line 472 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data (application)\n"););
  }
#line 2004 "y.tab.c"
    break;

  case 59:
#line 478 "sf_attribute_table.y"
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (IPProto Proto Port)\n"););
  }
#line 2013 "y.tab.c"
    break;

  case 60:
#line 483 "sf_attribute_table.y"
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (IPProto Port Proto)\n"););
  }
#line 2022 "y.tab.c"
    break;

  case 61:
#line 488 "sf_attribute_table.y"
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (Proto IPProto Port)\n"););
  }
#line 2031 "y.tab.c"
    break;

  case 62:
#line 493 "sf_attribute_table.y"
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (Proto Port IPProto)\n"););
  }
#line 2040 "y.tab.c"
    break;

  case 63:
#line 498 "sf_attribute_table.y"
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (Port Proto IPProto)\n"););
  }
#line 2049 "y.tab.c"
    break;

  case 64:
#line 503 "sf_attribute_table.y"
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (Port IPProto Proto)\n"););
  }
#line 2058 "y.tab.c"
    break;

  case 65:
#line 510 "sf_attribute_table.y"
  {
    /* Store IPProto Info */
    DEBUG_WRAP(PrintAttributeData("IPProto", &(yyvsp[-1].data)););
    SFAT_SetApplicationAttribute(&(yyvsp[-1].data), APPLICATION_ENTRY_IPPROTO);
  }
#line 2068 "y.tab.c"
    break;

  case 66:
#line 518 "sf_attribute_table.y"
  {
    /* Store Protocol Info */
    DEBUG_WRAP(PrintAttributeData("Protocol", &(yyvsp[-1].data)););
    SFAT_SetApplicationAttribute(&(yyvsp[-1].data), APPLICATION_ENTRY_PROTO);
  }
#line 2078 "y.tab.c"
    break;

  case 67:
#line 526 "sf_attribute_table.y"
  {
    /* Store Port Info */
    DEBUG_WRAP(PrintAttributeData("Port", &(yyvsp[-1].data)););
    SFAT_SetApplicationAttribute(&(yyvsp[-1].data), APPLICATION_ENTRY_PORT);
  }
#line 2088 "y.tab.c"
    break;

  case 68:
#line 534 "sf_attribute_table.y"
  {
    /* Store Application Info */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Application\n"));
    DEBUG_WRAP(PrintAttributeData("Application", &(yyvsp[-1].data)););
    SFAT_SetApplicationAttribute(&(yyvsp[-1].data), APPLICATION_ENTRY_APPLICATION);
  }
#line 2099 "y.tab.c"
    break;

  case 69:
#line 541 "sf_attribute_table.y"
  {
    /* Store Application Info */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Application with Version\n"));
    DEBUG_WRAP(PrintAttributeData("Application", &(yyvsp[-2].data)););
    SFAT_SetApplicationAttribute(&(yyvsp[-2].data), APPLICATION_ENTRY_APPLICATION);
  }
#line 2110 "y.tab.c"
    break;

  case 70:
#line 550 "sf_attribute_table.y"
  {
    /* Store Version Info */
    DEBUG_WRAP(PrintAttributeData("Version", &(yyvsp[-1].data)););
    SFAT_SetApplicationAttribute(&(yyvsp[-1].data), APPLICATION_ENTRY_VERSION);
  }
#line 2120 "y.tab.c"
    break;

  case 71:
#line 558 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "ClientList (complete)\n"););
  }
#line 2128 "y.tab.c"
    break;

  case 72:
#line 564 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Start ClientList\n"););
    sfat_client_or_service = ATTRIBUTE_CLIENT;
  }
#line 2137 "y.tab.c"
    break;

  case 73:
#line 571 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "End ClientList\n"););
  }
#line 2145 "y.tab.c"
    break;

  case 74:
#line 576 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "EmptyClient\n"););
  }
#line 2153 "y.tab.c"
    break;

  case 75:
#line 580 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client ClientListData\n"););
  }
#line 2161 "y.tab.c"
    break;

  case 76:
#line 586 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Adding Complete\n"););
    SFAT_AddApplicationData();
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Added\n"););
  }
#line 2171 "y.tab.c"
    break;

  case 77:
#line 594 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Start\n"););
    SFAT_CreateApplicationEntry();
  }
#line 2180 "y.tab.c"
    break;

  case 78:
#line 601 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client End\n"););
  }
#line 2188 "y.tab.c"
    break;

  case 79:
#line 607 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data (no application)\n"););
  }
#line 2196 "y.tab.c"
    break;

  case 80:
#line 611 "sf_attribute_table.y"
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data (application)\n"););
  }
#line 2204 "y.tab.c"
    break;

  case 81:
#line 617 "sf_attribute_table.y"
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data Required (Proto)\n"););
  }
#line 2213 "y.tab.c"
    break;

  case 82:
#line 622 "sf_attribute_table.y"
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data Required (IPProto Proto)\n"););
  }
#line 2222 "y.tab.c"
    break;

  case 83:
#line 627 "sf_attribute_table.y"
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data Required (Proto IPProto)\n"););
  }
#line 2231 "y.tab.c"
    break;


#line 2235 "y.tab.c"

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
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

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
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *, YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
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

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
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
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif


/*-----------------------------------------------------.
| yyreturn -- parsing is finished, return the result.  |
`-----------------------------------------------------*/
yyreturn:
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
                  yystos[+*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 632 "sf_attribute_table.y"

/*
int yywrap(void)
{
    return 1;
}
*/
#endif /* TARGET_BASED */
