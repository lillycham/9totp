#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

static int 
base32val(char c) 
{
	if (c >= 'A' && c <= 'Z') 
		return c - 'A';

	if (c >= '2' && c <= '7') 
		return c - '2' + 26;

	return -1;
}


/*
 * Decode RFC 4648 Base 32 String
 * in     : input string
 * inlen  : input length
 * out    : output buf
 * outlen : output no. of decoded bytes
 *
 * Returns 0 on success, -1 on error.
 */
int
base32_decode(char *in, int inlen, uchar *out, int *outlen)
{
	ulong buf = 0;
	int bits = 0;
	int i, v; 
	int n = 0;

	for (i = 0; i < inlen; i++) {
		if (in[i] == '=') 
			break;

		v = base32val(in[i]);
		
		if (v < 0)
			return -1;
		
		buf = (buf << 5) | v;
		bits += 5;

		if (bits >= 8) {
			out[n++] = (buf >> (bits - 8)) & 0xFF;
			bits -= 8;
		}
	}

	*outlen = n;

	return 0;
	
}

void
unixtime_to_bytes(vlong time, uchar out[8])
{
	int i;
	
	for (i = 7; i >= 0; i--) {
		out[i] = time & 0xFF;
		time >>= 8;
	}
}

vlong 
counter_now(vlong time_interval)
{
	return time(nil) / time_interval;
}

ulong 
dynamic_truncate(uchar digest[SHA1dlen])
{
	int offset;
	ulong code;
	
	offset = digest[SHA1dlen - 1] & 0x0F;

	code = ((ulong)(digest[offset]     & 0x7F)) << 24;
	code |= ((ulong)digest[offset + 1] & 0xFF) << 16;
	code |= ((ulong)digest[offset + 2] & 0xFF) << 8;
	code |= ((ulong)digest[offset + 3] & 0xFF);

	return code;
}

ulong
truncate_hmac(uchar digest[SHA1dlen])
{
 	ulong code = dynamic_truncate(digest);

	return code % 1000000;
}

void printhex(uchar *p, int n)
{
	int i;
	for(i = 0; i < n; i++)
		print("%02ux ", p[i]);
	
	print("\n");
}

/* 
 * Generate a TOTP Key
 * vlong period : The interval between TOTP keys, typically 30
 * char* secret : pointer to a string containing a B32 encoded 
 * 		TOTP secret
 */
ulong
gen_totp(vlong period, char* secret) 
{
	// Spec says we should support changing the interval period, but this is
	// essentially never used in practice. A variable is used to enable this
	// to be changed in future if necessary.

	// Additionally, it is technically supported to use a different initial 
	// timestamp to 0, but this is never used in practice.
	// vlong initial_time = 0;

	vlong counter = counter_now(period);

	// We then need to convert the timestamp to a char string.
	uchar b[8];
	unixtime_to_bytes(counter, b);

	// Now decode the base32 string
	uchar decoded[32];
	int n;
	
	if (base32_decode(secret, strlen((char*)secret), decoded, &n) < 0)
		sysfatal("decode failed");

	printhex(decoded, 32);
	
	//DigestState *s;
	uchar digest[SHA1dlen];
	
	hmac_sha1(b, 8, decoded, n, digest, nil);

	printhex(digest, SHA1dlen);

	// Now we need to truncate the HMAC(C, K, Sha1).
	ulong otp = truncate_hmac(digest);

	return otp;
}


void
main()
{
	vlong period = 30;

	// auto char secret[] = "";

	// ulong otp = gen_totp(period, secret);

	// print("%lud\n", otp);

	exits(0);
}