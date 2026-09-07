/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Tests for the value_data_t API
 *
 * @file src/tests/api/value_tests.c
 *
 * Covers the public functions of src/lib/value.c:
 *
 * - value_data_cmp()
 * - value_data_cmp_op()
 * - value_data_from_str()
 * - value_data_cast()
 * - value_data_copy()
 * - value_data_prints()
 * - value_data_aprints()
 *
 * Note that v3 keeps the type and the length outside the value, so every
 * call passes a PW_TYPE and a length alongside the value_data_t.  This is
 * unlike the self-describing fr_value_box_t of later versions.
 *
 * @copyright 2026 The FreeRADIUS server project
 */
#include <freeradius-devel/libradius.h>

#include "acutest_common_init.h"
#include "acutest_helpers.h"

static TALLOC_CTX *autofree;

static void test_init(void) __attribute__((constructor));
static void test_init(void)
{
DIAG_OFF(deprecated-declarations)
	autofree = talloc_autofree_context();
DIAG_ON(deprecated-declarations)
	if (!autofree) {
		fr_perror("value_tests");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on.
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("value_tests");
		exit(EXIT_FAILURE);
	}
}

/*
 *	value_data_cmp()
 *
 *	Returns -1, 0 or 1, and -2 when the values cannot be compared.
 */
static void test_cmp_integer(void)
{
	value_data_t a, b;

	a.integer = 42;
	b.integer = 42;
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), 0);

	b.integer = 43;
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_INTEGER, &b, 4, PW_TYPE_INTEGER, &a, 4), 1);
}

static void test_cmp_byte(void)
{
	value_data_t a, b;

	a.byte = 0;
	b.byte = 255;

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_BYTE, &a, 1, PW_TYPE_BYTE, &b, 1), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_BYTE, &b, 1, PW_TYPE_BYTE, &a, 1), 1);

	b.byte = 0;
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_BYTE, &a, 1, PW_TYPE_BYTE, &b, 1), 0);
}

static void test_cmp_short(void)
{
	value_data_t a, b;

	a.ushort = 1;
	b.ushort = 65535;

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_SHORT, &a, 2, PW_TYPE_SHORT, &b, 2), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_SHORT, &b, 2, PW_TYPE_SHORT, &a, 2), 1);
}

static void test_cmp_signed(void)
{
	value_data_t a, b;

	/*
	 *	A signed comparison, so the negative value must sort first.
	 *	Comparing these as unsigned would give the opposite answer.
	 */
	a.sinteger = -1;
	b.sinteger = 1;

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_SIGNED, &a, 4, PW_TYPE_SIGNED, &b, 4), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_SIGNED, &b, 4, PW_TYPE_SIGNED, &a, 4), 1);
}

static void test_cmp_integer64(void)
{
	value_data_t a, b;

	a.integer64 = 0;
	b.integer64 = UINT64_C(0xffffffffffffffff);

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_INTEGER64, &a, 8, PW_TYPE_INTEGER64, &b, 8), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_INTEGER64, &b, 8, PW_TYPE_INTEGER64, &a, 8), 1);
}

static void test_cmp_date(void)
{
	value_data_t a, b;

	a.date = 1000;
	b.date = 2000;

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_DATE, &a, 4, PW_TYPE_DATE, &b, 4), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_DATE, &b, 4, PW_TYPE_DATE, &a, 4), 1);
}

static void test_cmp_string(void)
{
	value_data_t a, b;

	a.strvalue = "apple";
	b.strvalue = "banana";

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_STRING, &a, 5, PW_TYPE_STRING, &b, 6), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_STRING, &b, 6, PW_TYPE_STRING, &a, 5), 1);

	b.strvalue = "apple";
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_STRING, &a, 5, PW_TYPE_STRING, &b, 5), 0);
}

static void test_cmp_string_embedded_nul(void)
{
	value_data_t a, b;

	/*
	 *	Comparison is done with memcmp() rather than strcmp(), so
	 *	the bytes after an embedded NUL still count.
	 */
	a.strvalue = "a\0b";
	b.strvalue = "a\0c";

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_STRING, &a, 3, PW_TYPE_STRING, &b, 3), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_STRING, &b, 3, PW_TYPE_STRING, &a, 3), 1);
}

static void test_cmp_octets(void)
{
	value_data_t a, b;

	a.octets = (uint8_t const *)"\x01\x02";
	b.octets = (uint8_t const *)"\x01\x03";

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_OCTETS, &a, 2, PW_TYPE_OCTETS, &b, 2), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_OCTETS, &b, 2, PW_TYPE_OCTETS, &a, 2), 1);
}

static void test_cmp_octets_length(void)
{
	value_data_t a, b;

	/*
	 *	Same leading bytes, different lengths.  The shorter value
	 *	sorts first, i.e. "0x00" is smaller than "0x0000".
	 */
	a.octets = (uint8_t const *)"\x01";
	b.octets = (uint8_t const *)"\x01\x02";

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_OCTETS, &a, 1, PW_TYPE_OCTETS, &b, 2), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_OCTETS, &b, 2, PW_TYPE_OCTETS, &a, 1), 1);
}

static void test_cmp_octets_zero_length(void)
{
	value_data_t a, b;

	a.octets = (uint8_t const *)"";
	b.octets = (uint8_t const *)"";

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_OCTETS, &a, 0, PW_TYPE_OCTETS, &b, 0), 0);
}

static void test_cmp_ipaddr(void)
{
	value_data_t a, b;

	a.ipaddr.s_addr = htonl(0x7f000001);	/* 127.0.0.1 */
	b.ipaddr.s_addr = htonl(0x7f000002);	/* 127.0.0.2 */

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_IPV4_ADDR, &a, 4, PW_TYPE_IPV4_ADDR, &b, 4), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_IPV4_ADDR, &b, 4, PW_TYPE_IPV4_ADDR, &a, 4), 1);

	b.ipaddr.s_addr = htonl(0x7f000001);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_IPV4_ADDR, &a, 4, PW_TYPE_IPV4_ADDR, &b, 4), 0);
}

static void test_cmp_ether(void)
{
	value_data_t a, b;

	memcpy(a.ether, "\x00\x01\x02\x03\x04\x05", 6);
	memcpy(b.ether, "\x00\x01\x02\x03\x04\x06", 6);

	TEST_CHECK_RET(value_data_cmp(PW_TYPE_ETHERNET, &a, 6, PW_TYPE_ETHERNET, &b, 6), -1);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_ETHERNET, &b, 6, PW_TYPE_ETHERNET, &a, 6), 1);

	memcpy(b.ether, a.ether, 6);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_ETHERNET, &a, 6, PW_TYPE_ETHERNET, &b, 6), 0);
}

static void test_cmp_different_types(void)
{
	value_data_t a, b;

	a.integer = 42;
	b.integer64 = 42;

	/*
	 *	Values of differing types cannot be compared, in either
	 *	direction, even when they hold the same number.
	 */
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER64, &b, 8), -2);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_INTEGER64, &b, 8, PW_TYPE_INTEGER, &a, 4), -2);
}

/*
 *	value_data_cmp_op()
 *
 *	Returns 1 for true, 0 for false and -1 on error.
 */
static void test_cmp_op_eq(void)
{
	value_data_t a, b;

	a.integer = 42;
	b.integer = 42;
	TEST_CHECK_RET(value_data_cmp_op(T_OP_CMP_EQ, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), 1);

	b.integer = 43;
	TEST_CHECK_RET(value_data_cmp_op(T_OP_CMP_EQ, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), 0);
}

static void test_cmp_op_ne(void)
{
	value_data_t a, b;

	a.integer = 42;
	b.integer = 43;
	TEST_CHECK_RET(value_data_cmp_op(T_OP_NE, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), 1);

	b.integer = 42;
	TEST_CHECK_RET(value_data_cmp_op(T_OP_NE, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), 0);
}

static void test_cmp_op_lt(void)
{
	value_data_t a, b;

	a.integer = 1;
	b.integer = 2;
	TEST_CHECK_RET(value_data_cmp_op(T_OP_LT, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), 1);
	TEST_CHECK_RET(value_data_cmp_op(T_OP_LT, PW_TYPE_INTEGER, &b, 4, PW_TYPE_INTEGER, &a, 4), 0);

	/* Not less than itself */
	TEST_CHECK_RET(value_data_cmp_op(T_OP_LT, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &a, 4), 0);
}

static void test_cmp_op_gt(void)
{
	value_data_t a, b;

	a.integer = 2;
	b.integer = 1;
	TEST_CHECK_RET(value_data_cmp_op(T_OP_GT, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), 1);
	TEST_CHECK_RET(value_data_cmp_op(T_OP_GT, PW_TYPE_INTEGER, &b, 4, PW_TYPE_INTEGER, &a, 4), 0);

	TEST_CHECK_RET(value_data_cmp_op(T_OP_GT, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &a, 4), 0);
}

static void test_cmp_op_le(void)
{
	value_data_t a, b;

	a.integer = 1;
	b.integer = 2;
	TEST_CHECK_RET(value_data_cmp_op(T_OP_LE, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), 1);
	TEST_CHECK_RET(value_data_cmp_op(T_OP_LE, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &a, 4), 1);
	TEST_CHECK_RET(value_data_cmp_op(T_OP_LE, PW_TYPE_INTEGER, &b, 4, PW_TYPE_INTEGER, &a, 4), 0);
}

static void test_cmp_op_ge(void)
{
	value_data_t a, b;

	a.integer = 2;
	b.integer = 1;
	TEST_CHECK_RET(value_data_cmp_op(T_OP_GE, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &b, 4), 1);
	TEST_CHECK_RET(value_data_cmp_op(T_OP_GE, PW_TYPE_INTEGER, &a, 4, PW_TYPE_INTEGER, &a, 4), 1);
	TEST_CHECK_RET(value_data_cmp_op(T_OP_GE, PW_TYPE_INTEGER, &b, 4, PW_TYPE_INTEGER, &a, 4), 0);
}

static void test_cmp_op_string(void)
{
	value_data_t a, b;

	a.strvalue = "apple";
	b.strvalue = "banana";

	TEST_CHECK_RET(value_data_cmp_op(T_OP_LT, PW_TYPE_STRING, &a, 5, PW_TYPE_STRING, &b, 6), 1);
	TEST_CHECK_RET(value_data_cmp_op(T_OP_CMP_EQ, PW_TYPE_STRING, &a, 5, PW_TYPE_STRING, &b, 6), 0);
	TEST_CHECK_RET(value_data_cmp_op(T_OP_NE, PW_TYPE_STRING, &a, 5, PW_TYPE_STRING, &b, 6), 1);
}

/*
 *	value_data_from_str()
 *
 *	Returns the length of the parsed data, or -1 on error.  Note that
 *	src_type is in/out; a COMBO_IP may be rewritten to a concrete type.
 */
static void test_from_str_integer(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_INTEGER;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "12345", -1, '\0'), 4);
	TEST_CHECK(dst.integer == 12345);
	TEST_MSG("Expected 12345, got %u", dst.integer);
}

/** Non-numeric input is silently accepted as an integer
 *
 * This pins current behaviour, which is wrong.  The trailing-garbage check
 * in the PW_TYPE_INTEGER case is gated on src_enumv being non-NULL, so with
 * no enumeration to consult the parser keeps whatever fr_strtoul() produced
 * and reports success.  "not-a-number" therefore becomes 0, and "42abc"
 * becomes 42.
 *
 * PW_TYPE_INTEGER64, immediately below it in value.c, uses sscanf() and does
 * return -1 for the same input, so the two types disagree.
 *
 * If value.c is fixed to reject this, these checks should become -1.
 */
static void test_from_str_integer_bad(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_INTEGER;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "not-a-number", -1, '\0'), 4);
	TEST_CHECK(dst.integer == 0);

	type = PW_TYPE_INTEGER;
	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "42abc", -1, '\0'), 4);
	TEST_CHECK(dst.integer == 42);

	/* By contrast, integer64 rejects it */
	type = PW_TYPE_INTEGER64;
	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "not-a-number", -1, '\0'), -1);
}

static void test_from_str_byte(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_BYTE;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "255", -1, '\0'), 1);
	TEST_CHECK(dst.byte == 255);

	/* Out of range for a byte */
	type = PW_TYPE_BYTE;
	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "256", -1, '\0'), -1);
}

static void test_from_str_short(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_SHORT;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "65535", -1, '\0'), 2);
	TEST_CHECK(dst.ushort == 65535);

	type = PW_TYPE_SHORT;
	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "65536", -1, '\0'), -1);
}

static void test_from_str_signed(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_SIGNED;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "-12345", -1, '\0'), 4);
	TEST_CHECK(dst.sinteger == -12345);
	TEST_MSG("Expected -12345, got %d", dst.sinteger);
}

static void test_from_str_integer64(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_INTEGER64;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "18446744073709551615", -1, '\0'), 8);
	TEST_CHECK(dst.integer64 == UINT64_C(0xffffffffffffffff));
}

static void test_from_str_string(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_STRING;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "hello", -1, '\0'), 5);
	TEST_CHECK_STRCMP(dst.strvalue, "hello");
}

static void test_from_str_string_length(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_STRING;

	/*
	 *	An explicit length stops the copy short, rather than
	 *	running to the NUL.
	 */
	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "hello world", 5, '\0'), 5);
	TEST_CHECK_STRCMP(dst.strvalue, "hello");
}

static void test_from_str_octets_hex(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_OCTETS;

	/* A 0x prefix means the rest is hex, so four characters give two bytes */
	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "0x0102", -1, '\0'), 2);
	if (dst.octets) {
		TEST_CHECK(dst.octets[0] == 0x01);
		TEST_CHECK(dst.octets[1] == 0x02);
	}
}

static void test_from_str_octets_verbatim(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_OCTETS;

	/* Without the 0x prefix the string is copied as-is */
	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "abc", -1, '\0'), 3);
	if (dst.octets) TEST_CHECK(memcmp(dst.octets, "abc", 3) == 0);
}

static void test_from_str_octets_odd_hex(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_OCTETS;

	/* An odd number of hex digits cannot be turned into whole bytes */
	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "0x010", -1, '\0'), -1);
}

static void test_from_str_ipaddr(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_IPV4_ADDR;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "192.0.2.1", -1, '\0'), 4);
	TEST_CHECK(dst.ipaddr.s_addr == htonl(0xc0000201));
}

static void test_from_str_ipaddr_bad(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_IPV4_ADDR;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "999.0.2.1", -1, '\0'), -1);
}

static void test_from_str_ipv6addr(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_IPV6_ADDR;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "2001:db8::1", -1, '\0'), 16);
}

static void test_from_str_ether(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_ETHERNET;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "00:01:02:03:04:05", -1, '\0'), 6);
	TEST_CHECK(dst.ether[0] == 0x00);
	TEST_CHECK(dst.ether[5] == 0x05);
}

/** A short Ethernet address is accepted, leaving trailing bytes uninitialised
 *
 * This pins current behaviour, which is a memory-safety bug.  The parse loop
 * consumes however many colon-separated octets it is given and never checks
 * that it filled all six.  The return value comes from the type size table
 * and is always 6, so the caller is told six bytes are valid when only five
 * were written.  The sixth byte below is the poison value this test wrote,
 * proving the parser did not touch it.
 *
 * If value.c is fixed to require six octets, this should become -1.
 */
static void test_from_str_ether_short(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_ETHERNET;

	memset(&dst, 0xAA, sizeof(dst));

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "00:01:02:03:04", -1, '\0'), 6);
	TEST_CHECK(dst.ether[4] == 0x04);
	TEST_CHECK(dst.ether[5] == 0xAA);
	TEST_MSG("Byte 6 should be untouched poison, got 0x%02x", dst.ether[5]);
}

/** A non-hex Ethernet address is rejected
 *
 * The parse loop does reject characters which are not hex digits, so this
 * error path works.  Only the length check is missing.
 */
static void test_from_str_ether_bad(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_ETHERNET;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "zz:01:02:03:04:05", -1, '\0'), -1);
}

/** An integer is converted to an Ethernet address, but loses its low bytes
 *
 * This pins current behaviour, which is wrong.  is_integer() short-circuits
 * the colon parsing, and the value is byte-swapped into a 64 bit integer and
 * then memcpy()d from its *first* six bytes.  For a big-endian 64 bit value
 * those are the high-order bytes, which are zero for any address that fits in
 * 48 bits, so the address that actually mattered is discarded.  The copy
 * should start two bytes in.
 */
static void test_from_str_ether_from_integer(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_ETHERNET;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, "12345", -1, '\0'), 6);
	TEST_CHECK(memcmp(dst.ether, "\x00\x00\x00\x00\x00\x00", 6) == 0);
	TEST_MSG("12345 should give 00:00:00:00:30:39, but the low bytes are dropped");
}

static void test_from_str_null(void)
{
	value_data_t	dst;
	PW_TYPE		type = PW_TYPE_STRING;

	TEST_CHECK_SLEN(value_data_from_str(autofree, &dst, &type, NULL, NULL, -1, '\0'), -1);
}

/*
 *	value_data_cast()
 *
 *	Note that casting to the same type trips an assertion, so there is
 *	deliberately no same-type test here.
 */
static void test_cast_integer_to_integer64(void)
{
	value_data_t	src, dst;

	src.integer = 12345;

	TEST_CHECK_SLEN(value_data_cast(autofree, &dst, PW_TYPE_INTEGER64, NULL,
					PW_TYPE_INTEGER, NULL, &src, 4), 8);
	TEST_CHECK(dst.integer64 == 12345);
}

static void test_cast_byte_to_integer(void)
{
	value_data_t	src, dst;

	src.byte = 200;

	TEST_CHECK_SLEN(value_data_cast(autofree, &dst, PW_TYPE_INTEGER, NULL,
					PW_TYPE_BYTE, NULL, &src, 1), 4);
	TEST_CHECK(dst.integer == 200);
}

static void test_cast_short_to_integer(void)
{
	value_data_t	src, dst;

	src.ushort = 4096;

	TEST_CHECK_SLEN(value_data_cast(autofree, &dst, PW_TYPE_INTEGER, NULL,
					PW_TYPE_SHORT, NULL, &src, 2), 4);
	TEST_CHECK(dst.integer == 4096);
}

static void test_cast_integer_to_string(void)
{
	value_data_t	src, dst;

	src.integer = 12345;

	/* Serialising to a string returns the string length */
	TEST_CHECK_SLEN(value_data_cast(autofree, &dst, PW_TYPE_STRING, NULL,
					PW_TYPE_INTEGER, NULL, &src, 4), 5);
	TEST_CHECK_STRCMP(dst.strvalue, "12345");
}

static void test_cast_string_to_integer(void)
{
	value_data_t	src, dst;

	src.strvalue = "12345";

	/* Casting from a string is a parse, so it goes via from_str */
	TEST_CHECK_SLEN(value_data_cast(autofree, &dst, PW_TYPE_INTEGER, NULL,
					PW_TYPE_STRING, NULL, &src, 5), 4);
	TEST_CHECK(dst.integer == 12345);
}

/** Casting a non-numeric string to an integer silently succeeds
 *
 * Casting from a string is implemented by calling value_data_from_str(), so
 * this inherits the laxness documented on test_from_str_integer_bad().
 * Casting the same string to an integer64 does fail.
 */
static void test_cast_string_to_integer_bad(void)
{
	value_data_t	src, dst;

	src.strvalue = "banana";

	TEST_CHECK_SLEN(value_data_cast(autofree, &dst, PW_TYPE_INTEGER, NULL,
					PW_TYPE_STRING, NULL, &src, 6), 4);
	TEST_CHECK(dst.integer == 0);

	TEST_CHECK_SLEN(value_data_cast(autofree, &dst, PW_TYPE_INTEGER64, NULL,
					PW_TYPE_STRING, NULL, &src, 6), -1);
}

static void test_cast_integer_to_octets(void)
{
	value_data_t	src, dst;

	src.integer = 0x01020304;

	/* Casting to octets is a straight network-order copy */
	TEST_CHECK_SLEN(value_data_cast(autofree, &dst, PW_TYPE_OCTETS, NULL,
					PW_TYPE_INTEGER, NULL, &src, 4), 4);
	if (dst.octets) {
		TEST_CHECK(dst.octets[0] == 0x01);
		TEST_CHECK(dst.octets[3] == 0x04);
	}
}

static void test_cast_ipaddr_to_string(void)
{
	value_data_t	src, dst;

	src.ipaddr.s_addr = htonl(0xc0000201);

	TEST_CHECK(value_data_cast(autofree, &dst, PW_TYPE_STRING, NULL,
				   PW_TYPE_IPV4_ADDR, NULL, &src, 4) > 0);
	TEST_CHECK_STRCMP(dst.strvalue, "192.0.2.1");
}

static void test_cast_string_to_ipaddr(void)
{
	value_data_t	src, dst;

	src.strvalue = "192.0.2.1";

	TEST_CHECK_SLEN(value_data_cast(autofree, &dst, PW_TYPE_IPV4_ADDR, NULL,
					PW_TYPE_STRING, NULL, &src, 9), 4);
	TEST_CHECK(dst.ipaddr.s_addr == htonl(0xc0000201));
}

/*
 *	value_data_copy()
 */
static void test_copy_integer(void)
{
	value_data_t	src, dst;

	src.integer = 12345;

	TEST_CHECK_SLEN(value_data_copy(autofree, &dst, PW_TYPE_INTEGER, &src, 4), 4);
	TEST_CHECK(dst.integer == 12345);
}

static void test_copy_string(void)
{
	value_data_t	src, dst;

	src.strvalue = "hello";

	TEST_CHECK_SLEN(value_data_copy(autofree, &dst, PW_TYPE_STRING, &src, 5), 5);
	TEST_CHECK_STRCMP(dst.strvalue, "hello");

	/* A copy, not an alias: the buffers must differ */
	TEST_CHECK(dst.strvalue != src.strvalue);
}

static void test_copy_octets(void)
{
	value_data_t	src, dst;

	src.octets = (uint8_t const *)"\x01\x02\x03";

	TEST_CHECK_SLEN(value_data_copy(autofree, &dst, PW_TYPE_OCTETS, &src, 3), 3);
	TEST_CHECK(dst.octets != src.octets);
	if (dst.octets) TEST_CHECK(memcmp(dst.octets, "\x01\x02\x03", 3) == 0);
}

static void test_copy_string_embedded_nul(void)
{
	value_data_t	src, dst;

	src.strvalue = "a\0b";

	/* The length is what matters, so the trailing byte survives */
	TEST_CHECK_SLEN(value_data_copy(autofree, &dst, PW_TYPE_STRING, &src, 3), 3);
	if (dst.strvalue) TEST_CHECK(memcmp(dst.strvalue, "a\0b", 3) == 0);
}

/*
 *	value_data_prints()
 *
 *	Returns the number of bytes it would have written, so that
 *	truncation can be detected.
 */
static void test_prints_integer(void)
{
	value_data_t	data;
	char		buff[64];

	data.integer = 12345;

	TEST_CHECK_LEN(value_data_prints(buff, sizeof(buff), PW_TYPE_INTEGER, NULL, &data, 4, '\0'), 5);
	TEST_CHECK_STRCMP(buff, "12345");
}

static void test_prints_signed_negative(void)
{
	value_data_t	data;
	char		buff[64];

	data.sinteger = -12345;

	TEST_CHECK_LEN(value_data_prints(buff, sizeof(buff), PW_TYPE_SIGNED, NULL, &data, 4, '\0'), 6);
	TEST_CHECK_STRCMP(buff, "-12345");
}

static void test_prints_string(void)
{
	value_data_t	data;
	char		buff[64];

	data.strvalue = "hello";

	TEST_CHECK_LEN(value_data_prints(buff, sizeof(buff), PW_TYPE_STRING, NULL, &data, 5, '\0'), 5);
	TEST_CHECK_STRCMP(buff, "hello");
}

static void test_prints_string_quoted(void)
{
	value_data_t	data;
	char		buff[64];

	data.strvalue = "hello";

	/* A quote character means the printer adds the quotes itself */
	TEST_CHECK(value_data_prints(buff, sizeof(buff), PW_TYPE_STRING, NULL, &data, 5, '"') > 0);
	TEST_CHECK_STRCMP(buff, "\"hello\"");
}

static void test_prints_octets(void)
{
	value_data_t	data;
	char		buff[64];

	data.octets = (uint8_t const *)"\x01\x02";

	/* Octets print as hex with a 0x prefix */
	TEST_CHECK(value_data_prints(buff, sizeof(buff), PW_TYPE_OCTETS, NULL, &data, 2, '\0') > 0);
	TEST_CHECK_STRCMP(buff, "0x0102");
}

static void test_prints_ipaddr(void)
{
	value_data_t	data;
	char		buff[64];

	data.ipaddr.s_addr = htonl(0xc0000201);

	TEST_CHECK(value_data_prints(buff, sizeof(buff), PW_TYPE_IPV4_ADDR, NULL, &data, 4, '\0') > 0);
	TEST_CHECK_STRCMP(buff, "192.0.2.1");
}

static void test_prints_ether(void)
{
	value_data_t	data;
	char		buff[64];

	memcpy(data.ether, "\x00\x01\x02\x03\x04\x05", 6);

	TEST_CHECK(value_data_prints(buff, sizeof(buff), PW_TYPE_ETHERNET, NULL, &data, 6, '\0') > 0);
	TEST_CHECK_STRCMP(buff, "00:01:02:03:04:05");
}

static void test_prints_truncation(void)
{
	value_data_t	data;
	char		buff[4];

	data.integer = 12345;

	/*
	 *	The return value reports what was needed, not what fit, so a
	 *	caller can tell that the output was truncated.
	 */
	TEST_CHECK_LEN(value_data_prints(buff, sizeof(buff), PW_TYPE_INTEGER, NULL, &data, 4, '\0'), 5);
}

/*
 *	value_data_aprints()
 */
static void test_aprints_integer(void)
{
	value_data_t	data;
	char		*out;

	data.integer = 12345;

	out = value_data_aprints(autofree, PW_TYPE_INTEGER, NULL, &data, 4, '\0');
	TEST_CHECK(out != NULL);
	if (!out) return;

	TEST_CHECK_STRCMP(out, "12345");
	talloc_free(out);
}

static void test_aprints_string(void)
{
	value_data_t	data;
	char		*out;

	data.strvalue = "hello";

	out = value_data_aprints(autofree, PW_TYPE_STRING, NULL, &data, 5, '\0');
	TEST_CHECK(out != NULL);
	if (!out) return;

	TEST_CHECK_STRCMP(out, "hello");
	talloc_free(out);
}

static void test_aprints_octets(void)
{
	value_data_t	data;
	char		*out;

	data.octets = (uint8_t const *)"\xde\xad\xbe\xef";

	out = value_data_aprints(autofree, PW_TYPE_OCTETS, NULL, &data, 4, '\0');
	TEST_CHECK(out != NULL);
	if (!out) return;

	TEST_CHECK_STRCMP(out, "0xdeadbeef");
	talloc_free(out);
}

/*
 *	Round trips.  Parsing and printing should be inverses of each other.
 */
static void test_round_trip_integer(void)
{
	value_data_t	data;
	PW_TYPE		type = PW_TYPE_INTEGER;
	char		buff[64];

	TEST_CHECK_SLEN_RETURN(value_data_from_str(autofree, &data, &type, NULL, "4294967295", -1, '\0'), 4);
	TEST_CHECK(value_data_prints(buff, sizeof(buff), PW_TYPE_INTEGER, NULL, &data, 4, '\0') > 0);
	TEST_CHECK_STRCMP(buff, "4294967295");
}

static void test_round_trip_signed(void)
{
	value_data_t	data;
	PW_TYPE		type = PW_TYPE_SIGNED;
	char		buff[64];

	TEST_CHECK_SLEN_RETURN(value_data_from_str(autofree, &data, &type, NULL, "-2147483648", -1, '\0'), 4);
	TEST_CHECK(value_data_prints(buff, sizeof(buff), PW_TYPE_SIGNED, NULL, &data, 4, '\0') > 0);
	TEST_CHECK_STRCMP(buff, "-2147483648");
}

static void test_round_trip_ipaddr(void)
{
	value_data_t	data;
	PW_TYPE		type = PW_TYPE_IPV4_ADDR;
	char		buff[64];

	TEST_CHECK_SLEN_RETURN(value_data_from_str(autofree, &data, &type, NULL, "10.11.12.13", -1, '\0'), 4);
	TEST_CHECK(value_data_prints(buff, sizeof(buff), PW_TYPE_IPV4_ADDR, NULL, &data, 4, '\0') > 0);
	TEST_CHECK_STRCMP(buff, "10.11.12.13");
}

static void test_round_trip_ether(void)
{
	value_data_t	data;
	PW_TYPE		type = PW_TYPE_ETHERNET;
	char		buff[64];

	TEST_CHECK_SLEN_RETURN(value_data_from_str(autofree, &data, &type, NULL, "aa:bb:cc:dd:ee:ff", -1, '\0'), 6);
	TEST_CHECK(value_data_prints(buff, sizeof(buff), PW_TYPE_ETHERNET, NULL, &data, 6, '\0') > 0);
	TEST_CHECK_STRCMP(buff, "aa:bb:cc:dd:ee:ff");
}

static void test_round_trip_octets(void)
{
	value_data_t	data;
	PW_TYPE		type = PW_TYPE_OCTETS;
	char		buff[64];

	TEST_CHECK_SLEN_RETURN(value_data_from_str(autofree, &data, &type, NULL, "0xdeadbeef", -1, '\0'), 4);
	TEST_CHECK(value_data_prints(buff, sizeof(buff), PW_TYPE_OCTETS, NULL, &data, 4, '\0') > 0);
	TEST_CHECK_STRCMP(buff, "0xdeadbeef");
}

static void test_round_trip_cast_integer_string(void)
{
	value_data_t	a, b, c;

	a.integer = 987654;

	/* integer -> string -> integer must land back on the same number */
	TEST_CHECK(value_data_cast(autofree, &b, PW_TYPE_STRING, NULL, PW_TYPE_INTEGER, NULL, &a, 4) > 0);
	TEST_CHECK_SLEN(value_data_cast(autofree, &c, PW_TYPE_INTEGER, NULL,
					PW_TYPE_STRING, NULL, &b, strlen(b.strvalue)), 4);
	TEST_CHECK(c.integer == a.integer);
	TEST_MSG("Expected %u, got %u", a.integer, c.integer);
}

static void test_round_trip_copy_cmp(void)
{
	value_data_t	src, dst;

	src.strvalue = "round trip";

	/* A copy must compare equal to its original */
	TEST_CHECK_SLEN(value_data_copy(autofree, &dst, PW_TYPE_STRING, &src, 10), 10);
	TEST_CHECK_RET(value_data_cmp(PW_TYPE_STRING, &src, 10, PW_TYPE_STRING, &dst, 10), 0);
}

TEST_LIST = {
	/*
	 *	value_data_cmp()
	 */
	{ "cmp_integer",			test_cmp_integer },
	{ "cmp_byte",				test_cmp_byte },
	{ "cmp_short",				test_cmp_short },
	{ "cmp_signed",				test_cmp_signed },
	{ "cmp_integer64",			test_cmp_integer64 },
	{ "cmp_date",				test_cmp_date },
	{ "cmp_string",				test_cmp_string },
	{ "cmp_string_embedded_nul",		test_cmp_string_embedded_nul },
	{ "cmp_octets",				test_cmp_octets },
	{ "cmp_octets_length",			test_cmp_octets_length },
	{ "cmp_octets_zero_length",		test_cmp_octets_zero_length },
	{ "cmp_ipaddr",				test_cmp_ipaddr },
	{ "cmp_ether",				test_cmp_ether },
	{ "cmp_different_types",		test_cmp_different_types },

	/*
	 *	value_data_cmp_op()
	 */
	{ "cmp_op_eq",				test_cmp_op_eq },
	{ "cmp_op_ne",				test_cmp_op_ne },
	{ "cmp_op_lt",				test_cmp_op_lt },
	{ "cmp_op_gt",				test_cmp_op_gt },
	{ "cmp_op_le",				test_cmp_op_le },
	{ "cmp_op_ge",				test_cmp_op_ge },
	{ "cmp_op_string",			test_cmp_op_string },

	/*
	 *	value_data_from_str()
	 */
	{ "from_str_integer",			test_from_str_integer },
	{ "from_str_integer_bad",		test_from_str_integer_bad },
	{ "from_str_byte",			test_from_str_byte },
	{ "from_str_short",			test_from_str_short },
	{ "from_str_signed",			test_from_str_signed },
	{ "from_str_integer64",			test_from_str_integer64 },
	{ "from_str_string",			test_from_str_string },
	{ "from_str_string_length",		test_from_str_string_length },
	{ "from_str_octets_hex",		test_from_str_octets_hex },
	{ "from_str_octets_verbatim",		test_from_str_octets_verbatim },
	{ "from_str_octets_odd_hex",		test_from_str_octets_odd_hex },
	{ "from_str_ipaddr",			test_from_str_ipaddr },
	{ "from_str_ipaddr_bad",		test_from_str_ipaddr_bad },
	{ "from_str_ipv6addr",			test_from_str_ipv6addr },
	{ "from_str_ether",			test_from_str_ether },
	{ "from_str_ether_short",		test_from_str_ether_short },
	{ "from_str_ether_bad",			test_from_str_ether_bad },
	{ "from_str_ether_from_integer",	test_from_str_ether_from_integer },
	{ "from_str_null",			test_from_str_null },

	/*
	 *	value_data_cast()
	 */
	{ "cast_integer_to_integer64",		test_cast_integer_to_integer64 },
	{ "cast_byte_to_integer",		test_cast_byte_to_integer },
	{ "cast_short_to_integer",		test_cast_short_to_integer },
	{ "cast_integer_to_string",		test_cast_integer_to_string },
	{ "cast_string_to_integer",		test_cast_string_to_integer },
	{ "cast_string_to_integer_bad",		test_cast_string_to_integer_bad },
	{ "cast_integer_to_octets",		test_cast_integer_to_octets },
	{ "cast_ipaddr_to_string",		test_cast_ipaddr_to_string },
	{ "cast_string_to_ipaddr",		test_cast_string_to_ipaddr },

	/*
	 *	value_data_copy()
	 */
	{ "copy_integer",			test_copy_integer },
	{ "copy_string",			test_copy_string },
	{ "copy_octets",			test_copy_octets },
	{ "copy_string_embedded_nul",		test_copy_string_embedded_nul },

	/*
	 *	value_data_prints()
	 */
	{ "prints_integer",			test_prints_integer },
	{ "prints_signed_negative",		test_prints_signed_negative },
	{ "prints_string",			test_prints_string },
	{ "prints_string_quoted",		test_prints_string_quoted },
	{ "prints_octets",			test_prints_octets },
	{ "prints_ipaddr",			test_prints_ipaddr },
	{ "prints_ether",			test_prints_ether },
	{ "prints_truncation",			test_prints_truncation },

	/*
	 *	value_data_aprints()
	 */
	{ "aprints_integer",			test_aprints_integer },
	{ "aprints_string",			test_aprints_string },
	{ "aprints_octets",			test_aprints_octets },

	/*
	 *	Round trips
	 */
	{ "round_trip_integer",			test_round_trip_integer },
	{ "round_trip_signed",			test_round_trip_signed },
	{ "round_trip_ipaddr",			test_round_trip_ipaddr },
	{ "round_trip_ether",			test_round_trip_ether },
	{ "round_trip_octets",			test_round_trip_octets },
	{ "round_trip_cast_integer_string",	test_round_trip_cast_integer_string },
	{ "round_trip_copy_cmp",		test_round_trip_copy_cmp },

	TEST_TERMINATOR
};
