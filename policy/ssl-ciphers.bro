# $Id: ssl-ciphers.bro 5857 2008-06-26 23:00:03Z vern $

# --- constant definitions of the cipher specs ---

# --- sslv2 ---
const SSLv20_CK_RC4_128_WITH_MD5 = 0x010080;
const SSLv20_CK_RC4_128_EXPORT40_WITH_MD5 = 0x020080;
const SSLv20_CK_RC2_128_CBC_WITH_MD5 = 0x030080;
const SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080;
const SSLv20_CK_IDEA_128_CBC_WITH_MD5 = 0x050080;
const SSLv20_CK_DES_64_CBC_WITH_MD5 = 0x060040;
const SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5 = 0x0700C0;

# --- sslv3x ---

const SSLv3x_NULL_WITH_NULL_NULL  = 0x0000;

# The following CipherSuite definitions require that the server
# provide an RSA certificate that can be used for key exchange.  The
# server may request either an RSA or a DSS signature-capable
# certificate in the certificate request message.

const SSLv3x_RSA_WITH_NULL_MD5 = 0x0001;
const SSLv3x_RSA_WITH_NULL_SHA = 0x0002;
const SSLv3x_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003;
const SSLv3x_RSA_WITH_RC4_128_MD5 = 0x0004;
const SSLv3x_RSA_WITH_RC4_128_SHA = 0x0005;
const SSLv3x_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006;
const SSLv3x_RSA_WITH_IDEA_CBC_SHA = 0x0007;
const SSLv3x_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008;
const SSLv3x_RSA_WITH_DES_CBC_SHA = 0x0009;
const SSLv3x_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A;

# The following CipherSuite definitions are used for
# server-authenticated (and optionally client-authenticated)
# Diffie-Hellman.  DH denotes cipher suites in which the server's
# certificate contains the Diffie-Hellman parameters signed by the
# certificate authority (CA).  DHE denotes ephemeral Diffie-Hellman,
# where the Diffie-Hellman parameters are signed by a DSS or RSA
# certificate, which has been signed by the CA.  The signing
# algorithm used is specified after the DH or DHE parameter.  In all
# cases, the client must have the same type of certificate, and must
# use the Diffie-Hellman parameters chosen by the server.

const SSLv3x_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x000B;
const SSLv3x_DH_DSS_WITH_DES_CBC_SHA = 0x000C;
const SSLv3x_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D;
const SSLv3x_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x000E;
const SSLv3x_DH_RSA_WITH_DES_CBC_SHA = 0x000F;
const SSLv3x_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010;
const SSLv3x_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011;
const SSLv3x_DHE_DSS_WITH_DES_CBC_SHA = 0x0012;
const SSLv3x_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013;
const SSLv3x_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014;
const SSLv3x_DHE_RSA_WITH_DES_CBC_SHA = 0x0015;
const SSLv3x_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016;

#  The following cipher suites are used for completely anonymous
#  Diffie-Hellman communications in which neither party is
#  authenticated.  Note that this mode is vulnerable to
#  man-in-the-middle attacks and is therefore strongly discouraged.

const SSLv3x_DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x0017;
const SSLv3x_DH_anon_WITH_RC4_128_MD5 = 0x0018;
const SSLv3x_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019;
const SSLv3x_DH_anon_WITH_DES_CBC_SHA = 0x001A;
const SSLv3x_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B;

#   The final cipher suites are for the FORTEZZA token.

const SSLv3x_FORTEZZA_KEA_WITH_NULL_SHA = 0x001C;
const SSLv3x_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA = 0x001D;
# This seems to be assigned to a Kerberos cipher in TLS 1.1
#const SSLv3x_FORTEZZA_KEA_WITH_RC4_128_SHA = 0x001E; 


# Following are some newer ciphers defined in RFC 4346 (TLS 1.1)

# Kerberos ciphers

const SSLv3x_KRB5_WITH_DES_CBC_SHA           = 0x001E;
const SSLv3x_KRB5_WITH_3DES_EDE_CBC_SHA      = 0x001F;
const SSLv3x_KRB5_WITH_RC4_128_SHA           = 0x0020;
const SSLv3x_KRB5_WITH_IDEA_CBC_SHA          = 0x0021;
const SSLv3x_KRB5_WITH_DES_CBC_MD5           = 0x0022;
const SSLv3x_KRB5_WITH_3DES_EDE_CBC_MD5      = 0x0023;
const SSLv3x_KRB5_WITH_RC4_128_MD5           = 0x0024;
const SSLv3x_KRB5_WITH_IDEA_CBC_MD5          = 0x0025;

# Kerberos export ciphers

const SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026;
const SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027;
const SSLv3x_KRB5_EXPORT_WITH_RC4_40_SHA     = 0x0028;
const SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029;
const SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A;
const SSLv3x_KRB5_EXPORT_WITH_RC4_40_MD5     = 0x002B;


# AES ciphers

const SSLv3x_RSA_WITH_AES_128_CBC_SHA        = 0x002F;
const SSLv3x_DH_DSS_WITH_AES_128_CBC_SHA     = 0x0030;
const SSLv3x_DH_RSA_WITH_AES_128_CBC_SHA     = 0x0031;
const SSLv3x_DHE_DSS_WITH_AES_128_CBC_SHA    = 0x0032;
const SSLv3x_DHE_RSA_WITH_AES_128_CBC_SHA    = 0x0033;
const SSLv3x_DH_anon_WITH_AES_128_CBC_SHA    = 0x0034;
const SSLv3x_RSA_WITH_AES_256_CBC_SHA        = 0x0035;
const SSLv3x_DH_DSS_WITH_AES_256_CBC_SHA     = 0x0036;
const SSLv3x_DH_RSA_WITH_AES_256_CBC_SHA     = 0x0037;
const SSLv3x_DHE_DSS_WITH_AES_256_CBC_SHA    = 0x0038;
const SSLv3x_DHE_RSA_WITH_AES_256_CBC_SHA    = 0x0039;
const SSLv3x_DH_anon_WITH_AES_256_CBC_SHA    = 0x003A;

# Mostly more RFC defined suites
const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA      = 0x0041; # [RFC4132]
const TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA   = 0x0042; # [RFC4132]
const TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA   = 0x0043; # [RFC4132]
const TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA  = 0x0044; # [RFC4132]
const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA  = 0x0045; # [RFC4132]
const TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA  = 0x0046; # [RFC4132]

# The following are tagged as "Widely Deployed implementation":
const TLS_ECDH_ECDSA_WITH_NULL_SHA           = 0x0047;
const TLS_ECDH_ECDSA_WITH_RC4_128_SHA        = 0x0048;
const TLS_ECDH_ECDSA_WITH_DES_CBC_SHA        = 0x0049;
const TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA   = 0x004A;
const TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA    = 0x004B;
const TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA    = 0x004C;
const TLS_CK_RSA_EXPORT1024_WITH_RC4_56_MD5       = 0x0060;
const TLS_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5   = 0x0061;
const TLS_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA      = 0x0062;
const TLS_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA  = 0x0063;
const TLS_CK_RSA_EXPORT1024_WITH_RC4_56_SHA       = 0x0064;
const TLS_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA   = 0x0065;
const TLS_CK_DHE_DSS_WITH_RC4_128_SHA             = 0x0066;

const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA      = 0x0084; # [RFC4132]
const TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA   = 0x0085; # [RFC4132]
const TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA   = 0x0086; # [RFC4132]
const TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA  = 0x0087; # [RFC4132]
const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA  = 0x0088; # [RFC4132]
const TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA  = 0x0089; # [RFC4132]
const TLS_PSK_WITH_RC4_128_SHA               = 0x008A; # [RFC4279]
const TLS_PSK_WITH_3DES_EDE_CBC_SHA          = 0x008B; # [RFC4279]
const TLS_PSK_WITH_AES_128_CBC_SHA           = 0x008C; # [RFC4279]
const TLS_PSK_WITH_AES_256_CBC_SHA           = 0x008D; # [RFC4279]
const TLS_DHE_PSK_WITH_RC4_128_SHA           = 0x008E; # [RFC4279]
const TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA      = 0x008F; # [RFC4279]
const TLS_DHE_PSK_WITH_AES_128_CBC_SHA       = 0x0090; # [RFC4279]
const TLS_DHE_PSK_WITH_AES_256_CBC_SHA       = 0x0091; # [RFC4279]
const TLS_RSA_PSK_WITH_RC4_128_SHA           = 0x0092; # [RFC4279]
const TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA      = 0x0093; # [RFC4279]
const TLS_RSA_PSK_WITH_AES_128_CBC_SHA       = 0x0094; # [RFC4279]
const TLS_RSA_PSK_WITH_AES_256_CBC_SHA       = 0x0095; # [RFC4279]
const TLS_RSA_WITH_SEED_CBC_SHA              = 0x0096; # [RFC4162]
const TLS_DH_DSS_WITH_SEED_CBC_SHA           = 0x0097; # [RFC4162]
const TLS_DH_RSA_WITH_SEED_CBC_SHA           = 0x0098; # [RFC4162]
const TLS_DHE_DSS_WITH_SEED_CBC_SHA          = 0x0099; # [RFC4162]
const TLS_DHE_RSA_WITH_SEED_CBC_SHA          = 0x009A; # [RFC4162]
const TLS_DH_anon_WITH_SEED_CBC_SHA          = 0x009B; # [RFC4162]


# Cipher specifications native to TLS can be included in Version 2.0 client
# hello messages using the syntax below. Any V2CipherSpec element with its
# first byte equal to zero will be ignored by Version 2.0 servers. Clients
# sending any of the above V2CipherSpecs should also include the TLS equivalent
# (see Appendix A.5):
# V2CipherSpec (see TLS name) = { 0x00, CipherSuite };


# --- This is a table of all known cipher specs.
# --- It can be used for detecting unknown ciphers and for
# --- converting the cipher spec constants into a human readable format.

const ssl_cipher_desc: table[count] of string = {
	# --- sslv20 ---
	[SSLv20_CK_RC4_128_EXPORT40_WITH_MD5] =
		"SSLv20_CK_RC4_128_EXPORT40_WITH_MD5",
	[SSLv20_CK_RC4_128_WITH_MD5] = "SSLv20_CK_RC4_128_WITH_MD5",
	[SSLv20_CK_RC2_128_CBC_WITH_MD5] = "SSLv20_CK_RC2_128_CBC_WITH_MD5",
	[SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5] =
		"SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
	[SSLv20_CK_IDEA_128_CBC_WITH_MD5] = "SSLv20_CK_IDEA_128_CBC_WITH_MD5",
	[SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5] =
		"SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5",
	[SSLv20_CK_DES_64_CBC_WITH_MD5] = "SSLv20_CK_DES_64_CBC_WITH_MD5",

	# --- sslv3x ---
	[SSLv3x_NULL_WITH_NULL_NULL] = "SSLv3x_NULL_WITH_NULL_NULL",

	[SSLv3x_RSA_WITH_NULL_MD5] = "SSLv3x_RSA_WITH_NULL_MD5",
	[SSLv3x_RSA_WITH_NULL_SHA] = "SSLv3x_RSA_WITH_NULL_SHA",
	[SSLv3x_RSA_EXPORT_WITH_RC4_40_MD5] =
		"SSLv3x_RSA_EXPORT_WITH_RC4_40_MD5",
	[SSLv3x_RSA_WITH_RC4_128_MD5] = "SSLv3x_RSA_WITH_RC4_128_MD5",
	[SSLv3x_RSA_WITH_RC4_128_SHA] = "SSLv3x_RSA_WITH_RC4_128_SHA",
	[SSLv3x_RSA_EXPORT_WITH_RC2_CBC_40_MD5] =
		"SSLv3x_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	[SSLv3x_RSA_WITH_IDEA_CBC_SHA] = "SSLv3x_RSA_WITH_IDEA_CBC_SHA",
	[SSLv3x_RSA_EXPORT_WITH_DES40_CBC_SHA] =
		"SSLv3x_RSA_EXPORT_WITH_DES40_CBC_SHA",
	[SSLv3x_RSA_WITH_DES_CBC_SHA] = "SSLv3x_RSA_WITH_DES_CBC_SHA",
	[SSLv3x_RSA_WITH_3DES_EDE_CBC_SHA] = "SSLv3x_RSA_WITH_3DES_EDE_CBC_SHA",

	[SSLv3x_DH_DSS_EXPORT_WITH_DES40_CBC_SHA] =
		"SSLv3x_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	[SSLv3x_DH_DSS_WITH_DES_CBC_SHA] = "SSLv3x_DH_DSS_WITH_DES_CBC_SHA",
	[SSLv3x_DH_DSS_WITH_3DES_EDE_CBC_SHA] =
		"SSLv3x_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	[SSLv3x_DH_RSA_EXPORT_WITH_DES40_CBC_SHA] =
		"SSLv3x_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	[SSLv3x_DH_RSA_WITH_DES_CBC_SHA] = "SSLv3x_DH_RSA_WITH_DES_CBC_SHA",
	[SSLv3x_DH_RSA_WITH_3DES_EDE_CBC_SHA] =
		"SSLv3x_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	[SSLv3x_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA] =
		"SSLv3x_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	[SSLv3x_DHE_DSS_WITH_DES_CBC_SHA] = "SSLv3x_DHE_DSS_WITH_DES_CBC_SHA",
	[SSLv3x_DHE_DSS_WITH_3DES_EDE_CBC_SHA] =
		"SSLv3x_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	[SSLv3x_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA] =
		"SSLv3x_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	[SSLv3x_DHE_RSA_WITH_DES_CBC_SHA] = "SSLv3x_DHE_RSA_WITH_DES_CBC_SHA",
	[SSLv3x_DHE_RSA_WITH_3DES_EDE_CBC_SHA] =
		"SSLv3x_DHE_RSA_WITH_3DES_EDE_CBC_SHA",

	[SSLv3x_DH_anon_EXPORT_WITH_RC4_40_MD5] =
		"SSLv3x_DH_anon_EXPORT_WITH_RC4_40_MD5",
	[SSLv3x_DH_anon_WITH_RC4_128_MD5] = "SSLv3x_DH_anon_WITH_RC4_128_MD5",
	[SSLv3x_DH_anon_EXPORT_WITH_DES40_CBC_SHA] =
		"SSLv3x_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	[SSLv3x_DH_anon_WITH_DES_CBC_SHA] = "SSLv3x_DH_anon_WITH_DES_CBC_SHA",
	[SSLv3x_DH_anon_WITH_3DES_EDE_CBC_SHA] =
		"SSLv3x_DH_anon_WITH_3DES_EDE_CBC_SHA",

	[SSLv3x_FORTEZZA_KEA_WITH_NULL_SHA] =
		"SSLv3x_FORTEZZA_KEA_WITH_NULL_SHA",
	[SSLv3x_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA] =
		"SSLv3x_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
	[SSLv3x_KRB5_WITH_DES_CBC_SHA] =
		"SSLv3x_KRB5_WITH_DES_CBC_SHA",
	[SSLv3x_KRB5_WITH_3DES_EDE_CBC_SHA] =
		"SSLv3x_KRB5_WITH_3DES_EDE_CBC_SHA",
	[SSLv3x_KRB5_WITH_RC4_128_SHA] =
		"SSLv3x_KRB5_WITH_RC4_128_SHA",
	[SSLv3x_KRB5_WITH_IDEA_CBC_SHA] =
		"SSLv3x_KRB5_WITH_IDEA_CBC_SHA",
	[SSLv3x_KRB5_WITH_DES_CBC_MD5] =
		"SSLv3x_KRB5_WITH_DES_CBC_MD5",
	[SSLv3x_KRB5_WITH_3DES_EDE_CBC_MD5] =
		"SSLv3x_KRB5_WITH_3DES_EDE_CBC_MD5",
	[SSLv3x_KRB5_WITH_RC4_128_MD5] =
		"SSLv3x_KRB5_WITH_RC4_128_MD5",
	[SSLv3x_KRB5_WITH_IDEA_CBC_MD5] =
		"SSLv3x_KRB5_WITH_IDEA_CBC_MD5",
	[SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_SHA] =
		"SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
	[SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_SHA] =
		"SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
	[SSLv3x_KRB5_EXPORT_WITH_RC4_40_SHA] =
		"SSLv3x_KRB5_EXPORT_WITH_RC4_40_SHA",
	[SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_MD5] =
		"SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
	[SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_MD5] =
		"SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
	[SSLv3x_KRB5_EXPORT_WITH_RC4_40_MD5] =
		"SSLv3x_KRB5_EXPORT_WITH_RC4_40_MD5",
	[SSLv3x_RSA_WITH_AES_128_CBC_SHA] =
		"SSLv3x_RSA_WITH_AES_128_CBC_SHA",
	[SSLv3x_DH_DSS_WITH_AES_128_CBC_SHA] =
		"SSLv3x_DH_DSS_WITH_AES_128_CBC_SHA",
	[SSLv3x_DH_RSA_WITH_AES_128_CBC_SHA] =
		"SSLv3x_DH_RSA_WITH_AES_128_CBC_SHA",
	[SSLv3x_DHE_DSS_WITH_AES_128_CBC_SHA] =
		"SSLv3x_DHE_DSS_WITH_AES_128_CBC_SHA",
	[SSLv3x_DHE_RSA_WITH_AES_128_CBC_SHA] =
		"SSLv3x_DHE_RSA_WITH_AES_128_CBC_SHA",
	[SSLv3x_DH_anon_WITH_AES_128_CBC_SHA] =
		"SSLv3x_DH_anon_WITH_AES_128_CBC_SHA",
	[SSLv3x_RSA_WITH_AES_256_CBC_SHA] =
		"SSLv3x_RSA_WITH_AES_256_CBC_SHA",
	[SSLv3x_DH_DSS_WITH_AES_256_CBC_SHA] =
		"SSLv3x_DH_DSS_WITH_AES_256_CBC_SHA",
	[SSLv3x_DH_RSA_WITH_AES_256_CBC_SHA] =
		"SSLv3x_DH_RSA_WITH_AES_256_CBC_SHA",
	[SSLv3x_DHE_DSS_WITH_AES_256_CBC_SHA] =
		"SSLv3x_DHE_DSS_WITH_AES_256_CBC_SHA",
	[SSLv3x_DHE_RSA_WITH_AES_256_CBC_SHA] =
		"SSLv3x_DHE_RSA_WITH_AES_256_CBC_SHA",
	[SSLv3x_DH_anon_WITH_AES_256_CBC_SHA] =
		"SSLv3x_DH_anon_WITH_AES_256_CBC_SHA",
		
    [TLS_RSA_WITH_CAMELLIA_128_CBC_SHA] = 
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    [TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA] = 
        "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
    [TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA] = 
        "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
    [TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA] = 
        "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
    [TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA] = 
        "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    [TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA] = 
        "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
    [TLS_ECDH_ECDSA_WITH_NULL_SHA] = 
        "TLS_ECDH_ECDSA_WITH_NULL_SHA",
    [TLS_ECDH_ECDSA_WITH_RC4_128_SHA] = 
        "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    [TLS_ECDH_ECDSA_WITH_DES_CBC_SHA] = 
        "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA",
    [TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA] = 
        "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    [TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA] = 
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    [TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA] = 
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    [TLS_CK_RSA_EXPORT1024_WITH_RC4_56_MD5] = 
        "TLS_CK_RSA_EXPORT1024_WITH_RC4_56_MD5",
    [TLS_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5] = 
        "TLS_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
    [TLS_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA] = 
        "TLS_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA",
    [TLS_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA] = 
        "TLS_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
    [TLS_CK_RSA_EXPORT1024_WITH_RC4_56_SHA] = 
        "TLS_CK_RSA_EXPORT1024_WITH_RC4_56_SHA",
    [TLS_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA] = 
        "TLS_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
    [TLS_CK_DHE_DSS_WITH_RC4_128_SHA] = 
        "TLS_CK_DHE_DSS_WITH_RC4_128_SHA",
    [TLS_RSA_WITH_CAMELLIA_256_CBC_SHA] = 
        "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    [TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA] = 
        "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
    [TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA] = 
        "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
    [TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA] = 
        "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    [TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA] = 
        "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    [TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA] = 
        "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
    [TLS_PSK_WITH_RC4_128_SHA] = 
        "TLS_PSK_WITH_RC4_128_SHA",
    [TLS_PSK_WITH_3DES_EDE_CBC_SHA] = 
        "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    [TLS_PSK_WITH_AES_128_CBC_SHA] = 
        "TLS_PSK_WITH_AES_128_CBC_SHA",
    [TLS_PSK_WITH_AES_256_CBC_SHA] = 
        "TLS_PSK_WITH_AES_256_CBC_SHA",
    [TLS_DHE_PSK_WITH_RC4_128_SHA] = 
        "TLS_DHE_PSK_WITH_RC4_128_SHA",
    [TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA] = 
        "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
    [TLS_DHE_PSK_WITH_AES_128_CBC_SHA] = 
        "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    [TLS_DHE_PSK_WITH_AES_256_CBC_SHA] = 
        "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    [TLS_RSA_PSK_WITH_RC4_128_SHA] = 
        "TLS_RSA_PSK_WITH_RC4_128_SHA",
    [TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA] = 
        "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
    [TLS_RSA_PSK_WITH_AES_128_CBC_SHA] = 
        "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    [TLS_RSA_PSK_WITH_AES_256_CBC_SHA] = 
        "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
    [TLS_RSA_WITH_SEED_CBC_SHA] = 
        "TLS_RSA_WITH_SEED_CBC_SHA",
    [TLS_DH_DSS_WITH_SEED_CBC_SHA] = 
        "TLS_DH_DSS_WITH_SEED_CBC_SHA",
    [TLS_DH_RSA_WITH_SEED_CBC_SHA] = 
        "TLS_DH_RSA_WITH_SEED_CBC_SHA",
    [TLS_DHE_DSS_WITH_SEED_CBC_SHA] = 
        "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
    [TLS_DHE_RSA_WITH_SEED_CBC_SHA] = 
        "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    [TLS_DH_anon_WITH_SEED_CBC_SHA] = 
        "TLS_DH_anon_WITH_SEED_CBC_SHA"
};


# --- the following sets are provided for convenience

# --- this set holds all EXPORT ciphers
const ssl_cipherset_EXPORT: set[count] = {
	SSLv20_CK_RC4_128_EXPORT40_WITH_MD5,
	SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	SSLv3x_RSA_EXPORT_WITH_RC4_40_MD5,
	SSLv3x_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	SSLv3x_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DH_anon_EXPORT_WITH_RC4_40_MD5,
	SSLv3x_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
	SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
	SSLv3x_KRB5_EXPORT_WITH_RC4_40_SHA,
	SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
	SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
	SSLv3x_KRB5_EXPORT_WITH_RC4_40_MD5
};

# --- this set holds all DES ciphers
const ssl_cipherset_DES: set[count] = {
	SSLv20_CK_DES_64_CBC_WITH_MD5,
	SSLv3x_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_RSA_WITH_DES_CBC_SHA,
	SSLv3x_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DH_DSS_WITH_DES_CBC_SHA,
	SSLv3x_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DH_RSA_WITH_DES_CBC_SHA,
	SSLv3x_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DHE_DSS_WITH_DES_CBC_SHA,
	SSLv3x_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DHE_RSA_WITH_DES_CBC_SHA,
	SSLv3x_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
	SSLv3x_DH_anon_WITH_DES_CBC_SHA,
	SSLv3x_KRB5_WITH_DES_CBC_SHA,
	SSLv3x_KRB5_WITH_DES_CBC_MD5,
	SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
	SSLv3x_KRB5_EXPORT_WITH_DES_CBC_40_MD5
};


# --- this set holds all 3DES ciphers
const ssl_cipherset_3DES: set[count] = {
	SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5,
	SSLv3x_DH_DSS_WITH_3DES_EDE_CBC_SHA,
	SSLv3x_DH_RSA_WITH_3DES_EDE_CBC_SHA,
	SSLv3x_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	SSLv3x_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	SSLv3x_DH_anon_WITH_3DES_EDE_CBC_SHA,
	SSLv3x_KRB5_WITH_3DES_EDE_CBC_SHA,
	SSLv3x_KRB5_WITH_3DES_EDE_CBC_MD5
};

# --- this set holds all RC2 ciphers
const ssl_cipherset_RC2: set[count] = {
	SSLv20_CK_RC2_128_CBC_WITH_MD5,
	SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	SSLv3x_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
	SSLv3x_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
};

# --- this set holds all RC4 ciphers
const ssl_cipherset_RC4: set[count] = {
	SSLv20_CK_RC4_128_WITH_MD5,
	SSLv20_CK_RC4_128_EXPORT40_WITH_MD5,
	SSLv3x_RSA_EXPORT_WITH_RC4_40_MD5,
	SSLv3x_RSA_WITH_RC4_128_MD5,
	SSLv3x_RSA_WITH_RC4_128_SHA,
	SSLv3x_DH_anon_EXPORT_WITH_RC4_40_MD5,
	SSLv3x_DH_anon_WITH_RC4_128_MD5,
	SSLv3x_KRB5_WITH_RC4_128_SHA,
	SSLv3x_KRB5_WITH_RC4_128_MD5,
	SSLv3x_KRB5_EXPORT_WITH_RC4_40_SHA,
	SSLv3x_KRB5_EXPORT_WITH_RC4_40_MD5
};

# --- this set holds all IDEA ciphers
const ssl_cipherset_IDEA: set[count] = {
	SSLv20_CK_IDEA_128_CBC_WITH_MD5,
	SSLv3x_RSA_WITH_IDEA_CBC_SHA,
	SSLv3x_KRB5_WITH_IDEA_CBC_SHA,
	SSLv3x_KRB5_WITH_IDEA_CBC_MD5
};

# --- this set holds all AES ciphers
const ssl_cipherset_AES: set[count] = {
	SSLv3x_RSA_WITH_AES_128_CBC_SHA,
	SSLv3x_DH_DSS_WITH_AES_128_CBC_SHA,
	SSLv3x_DH_RSA_WITH_AES_128_CBC_SHA,
	SSLv3x_DHE_DSS_WITH_AES_128_CBC_SHA,
	SSLv3x_DHE_RSA_WITH_AES_128_CBC_SHA,
	SSLv3x_DH_anon_WITH_AES_128_CBC_SHA,
	SSLv3x_RSA_WITH_AES_256_CBC_SHA,
	SSLv3x_DH_DSS_WITH_AES_256_CBC_SHA,
	SSLv3x_DH_RSA_WITH_AES_256_CBC_SHA,
	SSLv3x_DHE_DSS_WITH_AES_256_CBC_SHA,
	SSLv3x_DHE_RSA_WITH_AES_256_CBC_SHA,
	SSLv3x_DH_anon_WITH_AES_256_CBC_SHA
};
