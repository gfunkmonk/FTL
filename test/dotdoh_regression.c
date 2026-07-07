/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Standalone regression harness for the dotdoh leaf units
*
*  #includes the self-contained implementation .c files directly (URI parser,
*  DoT/DoH framing). Built only on request via -DBUILD_DOTDOH_REGRESSION=ON.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "dotdoh/upstream_uri.c"
#include "dotdoh/framing.c"
#include "dotdoh/registry.c"

static int failures = 0;

// Does haystack[hn] contain the C-string needle?
static bool contains(const uint8_t *hay, size_t hn, const char *needle)
{
	size_t nn = strlen(needle);
	if(nn == 0 || nn > hn) return false;
	for(size_t i = 0; i + nn <= hn; i++)
		if(memcmp(hay + i, needle, nn) == 0) return true;
	return false;
}

#define EXPECT(cond, ...) do { \
	if(!(cond)) { \
		failures++; \
		fprintf(stderr, "  FAIL: "); \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, " (%s:%d)\n", __FILE__, __LINE__); \
	} \
} while(0)

// Assert a URI parses to the expected fields.
static void ok(const char *in, enum ustype type, const char *connect,
               const char *verify, int port, const char *path)
{
	struct upstream_uri u;
	memset(&u, 0xAA, sizeof(u));
	bool r = parse_upstream_uri(in, &u);
	EXPECT(r, "\"%s\" expected to parse", in);
	if(!r) return;
	EXPECT(u.type == type, "\"%s\" type %d != %d", in, u.type, type);
	EXPECT(strcmp(u.connect_host, connect) == 0,
	       "\"%s\" connect_host \"%s\" != \"%s\"", in, u.connect_host, connect);
	if(type != UST_PLAIN)
	{
		EXPECT(strcmp(u.verify_name, verify) == 0,
		       "\"%s\" verify_name \"%s\" != \"%s\"", in, u.verify_name, verify);
		EXPECT(u.port == port, "\"%s\" port %d != %d", in, u.port, port);
	}
	if(type == UST_DOH)
		EXPECT(strcmp(u.doh_path, path) == 0,
		       "\"%s\" doh_path \"%s\" != \"%s\"", in, u.doh_path, path);
}

// Assert a URI is rejected.
static void bad(const char *in)
{
	struct upstream_uri u;
	bool r = parse_upstream_uri(in, &u);
	EXPECT(!r, "\"%s\" expected to be rejected", in);
}

static void test_plain(void)
{
	ok("9.9.9.9",       UST_PLAIN, "9.9.9.9",  "", 0, "");
	ok("9.9.9.9#5335",  UST_PLAIN, "9.9.9.9#5335", "", 0, "");
	ok("docker-resolver", UST_PLAIN, "docker-resolver", "", 0, "");
}

static void test_dot(void)
{
	ok("tls://one.one.one.one",        UST_DOT, "one.one.one.one", "one.one.one.one", 853, "");
	ok("tls://dns.quad9.net#853",      UST_DOT, "dns.quad9.net",   "dns.quad9.net",   853, "");
	ok("tls://dns.quad9.net#8853",     UST_DOT, "dns.quad9.net",   "dns.quad9.net",   8853, "");
	ok("tls://one.one.one.one@1.1.1.1", UST_DOT, "1.1.1.1",        "one.one.one.one", 853, "");
	ok("tls://1.1.1.1",                UST_DOT, "1.1.1.1",         "1.1.1.1",         853, "");
	ok("tls://[2606:4700:4700::1111]#853", UST_DOT, "2606:4700:4700::1111", "2606:4700:4700::1111", 853, "");
	// sni@[ipv6] pinning, as emitted for the suggested DoT servers
	ok("tls://dns.google@[2001:4860:4860::8888]", UST_DOT, "2001:4860:4860::8888", "dns.google", 853, "");
}

static void test_doh(void)
{
	ok("https://cloudflare-dns.com/dns-query", UST_DOH, "cloudflare-dns.com", "cloudflare-dns.com", 443, "/dns-query");
	ok("https://cloudflare-dns.com",           UST_DOH, "cloudflare-dns.com", "cloudflare-dns.com", 443, "/dns-query");
	ok("https://one.one.one.one@1.1.1.1/dns-query", UST_DOH, "1.1.1.1", "one.one.one.one", 443, "/dns-query");
	// sni@[ipv6] pinning, as emitted for the suggested DoH servers
	ok("https://dns.google@[2001:4860:4860::8888]/dns-query", UST_DOH, "2001:4860:4860::8888", "dns.google", 443, "/dns-query");
	ok("https://doh.example#8443/q",           UST_DOH, "doh.example", "doh.example", 8443, "/q");
}

static void test_reject(void)
{
	bad("tls://"); // empty host
	bad("https://"); // empty host
	bad("tls://host\r\nx"); // CRLF injection
	bad("tls://ho st"); // space
	bad("tls://host#0"); // port 0
	bad("tls://host#99999"); // port out of range
	bad("tls://host#abc"); // non-numeric port
	bad("http://x"); // unknown scheme (not https)
	bad("ftp://x"); // unknown scheme
	bad("tls://@1.1.1.1"); // empty verify name
	bad("tls://name@"); // empty connect host
	bad(NULL); // NULL input
	bad(""); // empty input
}

static void test_dot_framing(void)
{
	uint8_t out[16];
	ssize_t n = dot_frame((const uint8_t *)"abc", 3, out, sizeof(out));
	EXPECT(n == 5, "dot_frame len");
	EXPECT(out[0] == 0 && out[1] == 3, "dot_frame prefix");
	EXPECT(memcmp(out + 2, "abc", 3) == 0, "dot_frame body");
	EXPECT(dot_frame((const uint8_t *)"abc", 3, out, 4) == -1, "dot_frame out too small");
	EXPECT(dot_frame((const uint8_t *)"x", 65536, out, sizeof(out)) == -1, "dot_frame oversized");
	EXPECT(dot_frame((const uint8_t *)"", 0, out, sizeof(out)) == -1, "dot_frame empty");

	uint8_t b[8] = { 0, 3, 'a', 'b', 'c' };
	size_t off = 0;
	EXPECT(dot_deframe(b, 5, &off) == 3 && off == 2, "dot_deframe full");
	EXPECT(dot_deframe(b, 4, &off) == 0, "dot_deframe partial body");
	EXPECT(dot_deframe(b, 1, &off) == 0, "dot_deframe partial prefix");
	uint8_t z[4] = { 0, 0, 9, 9 };
	EXPECT(dot_deframe(z, 4, &off) == -1, "dot_deframe zero length");
}

static void test_doh_request(void)
{
	uint8_t req[512];
	ssize_t n = doh_build_request("cloudflare-dns.com", "/dns-query",
	                              (const uint8_t *)"xy", 2, req, sizeof(req));
	EXPECT(n > 0, "doh_build_request ok");
	if(n > 0)
	{
		EXPECT(contains(req, (size_t)n, "POST /dns-query HTTP/1.1\r\n"), "doh request line");
		EXPECT(contains(req, (size_t)n, "Host: cloudflare-dns.com\r\n"), "doh host header");
		EXPECT(contains(req, (size_t)n, "Content-Type: application/dns-message\r\n"), "doh content-type");
		EXPECT(contains(req, (size_t)n, "Content-Length: 2\r\n"), "doh content-length");
		EXPECT((size_t)n >= 6 && memcmp(req + n - 6, "\r\n\r\nxy", 6) == 0, "doh body appended");
	}
	EXPECT(doh_build_request("h", "/p", (const uint8_t *)"xy", 2, req, 10) == -1, "doh out too small");
	EXPECT(doh_build_request("h\r\nX", "/p", (const uint8_t *)"xy", 2, req, sizeof(req)) == -1, "doh CRLF host rejected");
	EXPECT(doh_build_request("h", "/p\r\nx", (const uint8_t *)"xy", 2, req, sizeof(req)) == -1, "doh CRLF path rejected");
	EXPECT(doh_build_request("h", "/dns query", (const uint8_t *)"xy", 2, req, sizeof(req)) == -1, "doh space in path rejected");
}

static void test_doh_response(void)
{
	size_t bo = 0, bl = 0;
	const char *r1 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nAB";
	ssize_t c = doh_parse_response((const uint8_t *)r1, strlen(r1), &bo, &bl);
	EXPECT(c == (ssize_t)strlen(r1), "doh resp consumed");
	EXPECT(bl == 2 && memcmp(r1 + bo, "AB", 2) == 0, "doh resp body");

	EXPECT(doh_parse_response((const uint8_t *)"HTTP/1.1 200 OK\r\n", 17, &bo, &bl) == 0, "doh resp partial headers");
	const char *r2 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r2, strlen(r2), &bo, &bl) == 0, "doh resp partial body");
	const char *r3 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
	EXPECT(doh_parse_response((const uint8_t *)r3, strlen(r3), &bo, &bl) == -1, "doh resp non-200");
	const char *r4 = "HTTP/1.1 200 OK\r\nFoo: bar\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r4, strlen(r4), &bo, &bl) == -1, "doh resp missing content-length");
	const char *r5 = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r5, strlen(r5), &bo, &bl) == (ssize_t)strlen(r5), "doh resp case-insensitive");
	const char *r6 = "HTTP/1.1 200 OK\r\nContent-Length: 70000\r\n\r\n";
	EXPECT(doh_parse_response((const uint8_t *)r6, strlen(r6), &bo, &bl) == -1, "doh resp oversized");
	const char *r7 = "HTTP/1.1 200 OK\r\nX-Content-Length: 9\r\nContent-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r7, strlen(r7), &bo, &bl) == (ssize_t)strlen(r7) && bl == 2, "doh resp ignores X-Content-Length prefix");
	const char *r8 = "HTTP/1.1 200 OK\r\nX-Content-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r8, strlen(r8), &bo, &bl) == -1, "doh resp X-Content-Length is not Content-Length");
	// Stricter status-line and Content-Length parsing (locked in against regressions).
	const char *r9 = "HTTP/1.1 2000 OK\r\nContent-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r9, strlen(r9), &bo, &bl) == -1, "doh resp rejects 4-digit status code");
	const char *r10 = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
	EXPECT(doh_parse_response((const uint8_t *)r10, strlen(r10), &bo, &bl) == -1, "doh resp rejects zero Content-Length");
	const char *r11 = "HTTP/1.1 200 OK\r\nContent-Length: 2x\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r11, strlen(r11), &bo, &bl) == -1, "doh resp rejects trailing junk in Content-Length");
	const char *r12 = "220 smtp ready\r\nContent-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r12, strlen(r12), &bo, &bl) == -1, "doh resp rejects non-HTTP status line");
	const char *r13 = "HTTP/1.1 200 OK\r\nContent-Length: 2 \r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r13, strlen(r13), &bo, &bl) == (ssize_t)strlen(r13), "doh resp tolerates trailing OWS in Content-Length");
	// Message-smuggling shapes must be rejected so leftover bytes cannot desync
	// the pooled connection for later queries.
	const char *r14 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 300\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r14, strlen(r14), &bo, &bl) == -1, "doh resp rejects duplicate Content-Length");
	const char *r15 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r15, strlen(r15), &bo, &bl) == -1, "doh resp rejects Transfer-Encoding");
}

// Occupy ip:port with a socket of the given type; returns fd or -1.
static int occupy(const char *ip, int port, int socktype)
{
	int fd = socket(AF_INET, socktype, 0);
	if(fd < 0) return -1;
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	inet_pton(AF_INET, ip, &sa.sin_addr);
	if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		close(fd);
		return -1;
	}
	if(socktype == SOCK_STREAM)
		listen(fd, 1);
	return fd;
}

static void test_registry(void)
{
	struct proxy_listener l0, l1, l2;

	EXPECT(proxy_listener_bind(0, &l0), "bind slot 0");
	EXPECT(strcmp(l0.ip, "127.47.11.1") == 0, "slot 0 ip %s", l0.ip);
	EXPECT(l0.port == DOTDOH_PORT_BASE + 1, "slot 0 preferred port %d", l0.port);
	EXPECT(l0.udp_fd >= 0 && l0.tcp_fd >= 0, "slot 0 fds");

	EXPECT(proxy_listener_bind(1, &l1), "bind slot 1");
	EXPECT(strcmp(l1.ip, "127.47.11.2") == 0, "slot 1 ip %s", l1.ip);

	// Squat the deterministic TCP tuple of slot 2 -> bind must now FAIL (the port
	// is fixed, so there is no iteration); the upstream is left disabled.
	int occ = occupy("127.47.11.3", DOTDOH_PORT_BASE + 3, SOCK_STREAM);
	EXPECT(occ >= 0, "occupy deterministic tuple of slot 2");
	EXPECT(!proxy_listener_bind(2, &l2), "bind slot 2 fails when its tuple is squatted");

	// Bind-first / exclusivity: our owned tuple cannot be co-bound.
	int again = occupy(l0.ip, l0.port, SOCK_STREAM);
	EXPECT(again < 0, "owned tuple is exclusive (no SO_REUSEADDR)");
	if(again >= 0) close(again);

	proxy_listener_close(&l0);
	proxy_listener_close(&l1);
	proxy_listener_close(&l2);
	if(occ >= 0) close(occ);
}

int main(void)
{
	test_plain();
	test_dot();
	test_doh();
	test_reject();
	test_dot_framing();
	test_doh_request();
	test_doh_response();
	test_registry();

	if(failures == 0)
		printf("dotdoh_regression: all tests passed\n");
	else
		printf("dotdoh_regression: %d failure(s)\n", failures);
	return failures ? 1 : 0;
}
