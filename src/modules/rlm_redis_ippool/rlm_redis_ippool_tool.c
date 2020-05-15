/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file rlm_redis_ippool_tool.c
 * @brief IP population tool.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 The FreeRADIUS server project
 */
RCSID("$Id$")
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/util/debug.h>

#include "base.h"
#include "cluster.h"
#include "redis_ippool.h"

/** Pool management actions
 *
 */
typedef enum ippool_tool_action {
	IPPOOL_TOOL_ADD,			//!< Add one or more IP addresses.
	IPPOOL_TOOL_DELETE,			//!< Delete one or more IP addresses.
	IPPOOL_TOOL_MODIFY,			//!< Modify attributes of one or more IP addresses.
	IPPOOL_TOOL_RELEASE,			//!< Release one or more IP addresses.
	IPPOOL_TOOL_SHOW			//!< Show one or more IP addresses.
} ippool_tool_action_t;

/** A single pool operation
 *
 */
typedef struct {
	char const		*name;		//!< Original range or CIDR string.

	uint8_t const		*pool;		//!< Pool identifier.
	size_t			pool_len;	//!< Length of the pool identifier.

	uint8_t const		*range;		//!< Range identifier.
	size_t			range_len;	//!< Length of the range identifier.

	fr_ipaddr_t		start;		//!< Start address.
	fr_ipaddr_t		end;		//!< End address.
	uint8_t			prefix;		//!< Prefix - The bits between the address mask, and the prefix
						//!< form the addresses to be modified in the pool.
	ippool_tool_action_t	action;		//!< What to do to the leases described by net/prefix.
} ippool_tool_operation_t;

typedef struct {
	fr_redis_conf_t			conf;		//!< Connection parameters for the Redis server.
	fr_redis_cluster_t		*cluster;

	uint32_t			wait_num;
	fr_time_delta_t			wait_timeout;

	const char			*lua_preamble_file;
	redis_ippool_lua_script_t	lua_add;
	redis_ippool_lua_script_t	lua_delete;
	redis_ippool_lua_script_t	lua_modify;
	redis_ippool_lua_script_t	lua_release_tool;
	redis_ippool_lua_script_t	lua_show;
	redis_ippool_lua_script_t	lua_stats;
} redis_driver_conf_t;

static CONF_PARSER redis_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER driver_config[] = {
	{ FR_CONF_OFFSET("wait_num", FR_TYPE_UINT32, redis_driver_conf_t, wait_num) },
	{ FR_CONF_OFFSET("wait_timeout", FR_TYPE_TIME_DELTA, redis_driver_conf_t, wait_timeout) },

	{ FR_CONF_OFFSET("lua_preamble", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, redis_driver_conf_t, lua_preamble_file), .dflt = "${modconfdir}/redis_ippool/preamble.lua" },
	{ FR_CONF_OFFSET("lua_add", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, redis_driver_conf_t, lua_add.file), .dflt = "${modconfdir}/redis_ippool/add.lua" },
	{ FR_CONF_OFFSET("lua_delete", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, redis_driver_conf_t, lua_delete.file), .dflt = "${modconfdir}/redis_ippool/delete.lua" },
	{ FR_CONF_OFFSET("lua_modify", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, redis_driver_conf_t, lua_modify.file), .dflt = "${modconfdir}/redis_ippool/modify.lua" },
	{ FR_CONF_OFFSET("lua_release_tool", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, redis_driver_conf_t, lua_release_tool.file), .dflt = "${modconfdir}/redis_ippool/release_tool.lua" },
	{ FR_CONF_OFFSET("lua_show", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, redis_driver_conf_t, lua_show.file), .dflt = "${modconfdir}/redis_ippool/show.lua" },
	{ FR_CONF_OFFSET("lua_stats", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, redis_driver_conf_t, lua_stats.file), .dflt = "${modconfdir}/redis_ippool/stats.lua" },

	/*
	 *	Split out to allow conversion to universal ippool module with
	 *	minimum of config changes.
	 */
	{ FR_CONF_POINTER("redis", FR_TYPE_SUBSECTION, NULL), .subcs = redis_config },
	CONF_PARSER_TERMINATOR
};

typedef struct {
	void			*driver;
	CONF_SECTION		*cs;
} ippool_tool_t;

typedef int (*redis_ippool_queue_t)(redis_driver_conf_t *inst, fr_redis_conn_t *conn,
				    uint8_t const *key_prefix, size_t key_prefix_len,
				    uint8_t const *range, size_t range_len,
				    fr_ipaddr_t *ipaddr, uint8_t prefix);

typedef int (*redis_ippool_process_t)(void *out, fr_ipaddr_t const *ipaddr, redisReply const *reply);

static char const *name;

static void NEVER_RETURNS usage(int ret) {
	INFO("Usage: %s -adrsm range... [-p prefix_len]... [-x]... [-oShf] server[:port] [pool] [range id]", name);
	INFO("Pool management:");
	INFO("  -a range	       Add address(es)/prefix(es) to the pool.");
	INFO("  -d range	       Delete address(es)/prefix(es) in this range.");
	INFO("  -r range	       Release address(es)/prefix(es) in this range.");
	INFO("  -s range	       Show addresses/prefix in this range.");
	INFO("  -p prefix_len	  Length of prefix to allocate (defaults to 32/128)");
	INFO("			 This is used primarily for IPv6 where a prefix is");
	INFO("			 allocated to an intermediary router, which in turn");
	INFO("			 allocates sub-prefixes to the devices it serves.");
	INFO("			 This argument changes the prefix_len for the previous");
	INFO("			 instance of an -adrsm argument, only.");
	INFO("  -m range	       Change the range id to the one specified for addresses");
	INFO("			 in this range.");
	INFO("  -l		     List available pools.");
//	INFO("  -L		     List available ranges in pool [NYI]");
//	INFO("  -i file		Import entries from ISC lease file [NYI]");
	INFO(" ");	/* -Werror=format-zero-length */
//	INFO("Pool status:");
//	INFO("  -I		     Output active entries in ISC lease file format [NYI]");
	INFO("  -S		     Print pool statistics");
	INFO(" ");	/* -Werror=format-zero-length */
	INFO("Configuration:");
	INFO("  -h		     Print this help message and exit");
	INFO("  -x		     Increase the verbosity level");
//	INFO("  -o attr=value	  Set option, these are specific to the backends [NYI]");
	INFO("  -D raddb	       Set configuration directory (defaults to " RADDBDIR ")");
	INFO("  -f file		Load connection options from a FreeRADIUS format config file");
	INFO("			 This file should contain a pool { ... } section and one or more");
	INFO("			 `server = <fqdn>` pairs`");
	INFO(" ");
	INFO("<range> is range \"127.0.0.1-127.0.0.254\" or CIDR network \"127.0.0.1/24\" or host \"127.0.0.1\"");
	INFO("CIDR host bits set start address, e.g. 127.0.0.200/24 -> 127.0.0.200-127.0.0.254");
	fr_exit_now(ret);
}

static uint32_t uint32_gen_mask(uint8_t bits)
{
	if (bits >= 32) return 0xffffffff;
	return (1 << bits) - 1;
}

/** Iterate over range of IP addresses
 *
 * Mutates the ipaddr passed in, adding one to the prefix bits on each call.
 *
 * @param[in,out] ipaddr to increment.
 * @param[in] end ipaddr to stop at.
 * @param[in] prefix Length of the prefix.
 * @return
 *	- true if the prefix bits are not high (continue).
 *	- false if the prefix bits are high (stop).
 */
static bool ipaddr_next(fr_ipaddr_t *ipaddr, fr_ipaddr_t const *end, uint8_t prefix)
{
	switch (ipaddr->af) {
	default:
	case AF_UNSPEC:
		fr_assert(0);
		return false;

	case AF_INET6:
	{
		uint128_t ip_curr, ip_end;

		if (!fr_cond_assert((prefix > 0) && (prefix <= 128))) return false;

		/* Don't be tempted to cast */
		memcpy(&ip_curr, ipaddr->addr.v6.s6_addr, sizeof(ip_curr));
		memcpy(&ip_end, end->addr.v6.s6_addr, sizeof(ip_curr));

		ip_curr = ntohlll(ip_curr);
		ip_end = ntohlll(ip_end);

		/* We're done */
		if (uint128_eq(ip_curr, ip_end)) return false;

		/* Increment the prefix */
		ip_curr = uint128_add(ip_curr, uint128_lshift(uint128_new(0, 1), (128 - prefix)));
		ip_curr = htonlll(ip_curr);
		memcpy(&ipaddr->addr.v6.s6_addr, &ip_curr, sizeof(ipaddr->addr.v6.s6_addr));
		return true;
	}

	case AF_INET:
	{
		uint32_t ip_curr, ip_end;

		if (!fr_cond_assert((prefix > 0) && (prefix <= 32))) return false;

		ip_curr = ntohl(ipaddr->addr.v4.s_addr);
		ip_end = ntohl(end->addr.v4.s_addr);

		/* We're done */
		if (ip_curr == ip_end) return false;

		/* Increment the prefix */
		ip_curr += 1 << (32 - prefix);
		ipaddr->addr.v4.s_addr = htonl(ip_curr);
		return true;
	}
	}
}

/**
 * Add a lease
 */
static int64_t lease_add(redis_driver_conf_t *inst, ippool_tool_operation_t const *op, char const *ip_buff)
{
	REQUEST			*request;
	fr_redis_rcode_t	status;
	redisReply		*reply = NULL;
	int64_t			ret = IPPOOL_RCODE_FAIL;

	DEBUG("Adding lease %s to pool \"%s\" (range: \"%s\")", ip_buff, op->pool, op->range);

	request = request_alloc(inst);

	status = op->range_len
			? fr_redis_script(&reply, request, inst->cluster,
			       op->pool, op->pool_len,
			       inst->wait_num, inst->wait_timeout,
			       inst->lua_add.script,
			       "EVALSHA %s 1 %b %s %b",
			       inst->lua_add.digest,
			       op->pool, op->pool_len,
			       ip_buff,
			       op->range, op->range_len)
			: fr_redis_script(&reply, request, inst->cluster,
			       op->pool, op->pool_len,
			       inst->wait_num, inst->wait_timeout,
			       inst->lua_add.script,
			       "EVALSHA %s 1 %b %s",
			       inst->lua_add.digest,
			       op->pool, op->pool_len,
			       ip_buff);

	talloc_free(request);

	if (status != REDIS_RCODE_SUCCESS)
		goto err;

	if (reply->type != REDIS_REPLY_ARRAY) goto err;
	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		goto err;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		goto err;
	}

	/* errors are not important, they just result in a noop */
	if (reply->element[0]->integer != IPPOOL_RCODE_SUCCESS) {
		ret = 0;
		goto err;
	}
	if (reply->elements < 2) goto err;
	if (reply->element[1]->type != REDIS_REPLY_INTEGER) goto err;

	ret = reply->element[1]->integer;

	fr_redis_reply_free(&reply);

	return ret;

err:
	fr_redis_reply_free(&reply);
	return ret;
}

/**
 * Delete a lease
 */
static int64_t lease_delete(redis_driver_conf_t *inst, ippool_tool_operation_t const *op, char const *ip_buff)
{
	REQUEST			*request;
	fr_redis_rcode_t	status;
	redisReply		*reply = NULL;
	int64_t			ret = IPPOOL_RCODE_FAIL;

	DEBUG("Deleting lease %s from pool \"%s\"", ip_buff, op->pool);

	request = request_alloc(inst);

	status = fr_redis_script(&reply, request, inst->cluster,
			       op->pool, op->pool_len,
			       inst->wait_num, inst->wait_timeout,
			       inst->lua_delete.script,
			       "EVALSHA %s 1 %b %s",
			       inst->lua_delete.digest,
			       op->pool, op->pool_len,
			       ip_buff);

	talloc_free(request);

	if (status != REDIS_RCODE_SUCCESS)
		goto err;

	if (reply->type != REDIS_REPLY_ARRAY) goto err;
	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		goto err;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		goto err;
	}

	/* errors are not important, they just result in a noop */
	if (reply->element[0]->integer != IPPOOL_RCODE_SUCCESS) {
		ret = 0;
		goto err;
	}
	if (reply->elements < 2) goto err;
	if (reply->element[1]->type != REDIS_REPLY_INTEGER) goto err;

	ret = reply->element[1]->integer;

	fr_redis_reply_free(&reply);

	return ret;

err:
	fr_redis_reply_free(&reply);
	return ret;
}

/**
 * Modify the range on a lease
 */
static int lease_modify(redis_driver_conf_t *inst, ippool_tool_operation_t const *op, char const *ip_buff)
{
	REQUEST			*request;
	fr_redis_rcode_t	status;
	redisReply		*reply = NULL;
	int64_t			ret = IPPOOL_RCODE_FAIL;

	DEBUG("Modifying lease %s to pool \"%s\" (range: \"%s\")", ip_buff, op->pool, op->range);

	request = request_alloc(inst);

	status = fr_redis_script(&reply, request, inst->cluster,
			       op->pool, op->pool_len,
			       inst->wait_num, inst->wait_timeout,
			       inst->lua_modify.script,
			       "EVALSHA %s 1 %b %s %b",
			       inst->lua_modify.digest,
			       op->pool, op->pool_len,
			       ip_buff,
			       op->range, op->range_len);

	talloc_free(request);

	if (status != REDIS_RCODE_SUCCESS)
		goto err;

	if (reply->type != REDIS_REPLY_ARRAY) goto err;
	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		goto err;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		goto err;
	}

	/* errors are not important, they just result in a noop */
	if (reply->element[0]->integer != IPPOOL_RCODE_SUCCESS) {
		ret = 0;
		goto err;
	}
	if (reply->elements < 2) goto err;
	if (reply->element[1]->type != REDIS_REPLY_INTEGER) goto err;

	ret = reply->element[1]->integer;

	fr_redis_reply_free(&reply);

	return ret;

err:
	fr_redis_reply_free(&reply);
	return ret;
}

/**
 * Release a lease
 */
static int lease_release(redis_driver_conf_t *inst, ippool_tool_operation_t const *op, char const *ip_buff)
{
	REQUEST			*request;
	fr_redis_rcode_t	status;
	redisReply		*reply = NULL;
	int64_t			ret = IPPOOL_RCODE_FAIL;

	DEBUG("Releasing lease %s from pool \"%s\"", op->name, op->pool);

	request = request_alloc(inst);

	status = fr_redis_script(&reply, request, inst->cluster,
			       op->pool, op->pool_len,
			       inst->wait_num, inst->wait_timeout,
			       inst->lua_release_tool.script,
			       "EVALSHA %s 1 %b %s",
			       inst->lua_release_tool.digest,
			       op->pool, op->pool_len,
			       ip_buff);

	talloc_free(request);

	if (status != REDIS_RCODE_SUCCESS)
		goto err;

	if (reply->type != REDIS_REPLY_ARRAY) goto err;
	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		goto err;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		goto err;
	}

	/* errors are not important, they just result in a noop */
	if (reply->element[0]->integer != IPPOOL_RCODE_SUCCESS) {
		ret = 0;
		goto err;
	}
	if (reply->elements < 2) goto err;
	if (reply->element[1]->type != REDIS_REPLY_INTEGER) goto err;

	ret = reply->element[1]->integer;

	fr_redis_reply_free(&reply);

	return ret;

err:
	fr_redis_reply_free(&reply);
	return ret;
}

/**
 * Show information about a lease
 */
static int lease_show(redis_driver_conf_t *inst, ippool_tool_operation_t const *op, char const *ip_buff)
{
	REQUEST			*request;
	fr_redis_rcode_t	status;
	redisReply		*reply = NULL;
	char			time_buff[30];
	struct			tm tm;
	struct			timeval now;
	char			*device = NULL;
	char			*gateway = NULL;
	char			*range = NULL;
	bool			is_active;
	time_t			next_event;

	DEBUG("Retrieving lease info for %s from pool \"%s\"", ip_buff, op->pool);

	request = request_alloc(inst);

	status = fr_redis_script(&reply, request, inst->cluster,
			       op->pool, op->pool_len,
			       inst->wait_num, inst->wait_timeout,
			       inst->lua_show.script,
			       "EVALSHA %s 1 %b %s",
			       inst->lua_show.digest,
			       op->pool, op->pool_len,
			       ip_buff);

	talloc_free(request);

	if (status != REDIS_RCODE_SUCCESS)
		goto err;

	/*
	 *	The exec command is the only one that produces an array.
	 */
	if (reply->type != REDIS_REPLY_ARRAY) goto err;
	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		goto err;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		goto err;
	}

	if (reply->element[0]->integer != IPPOOL_RCODE_SUCCESS)
		goto err;

	if (reply->elements < 5) goto err;

	if (reply->element[1]->type == REDIS_REPLY_NIL) return 0;	/* A nil result (IP didn't exist) */
	if (reply->element[1]->type != REDIS_REPLY_STRING) goto err;	/* Something bad */

	next_event = reply->element[1]->integer;
	if (reply->element[2]->type == REDIS_REPLY_STRING)
		device = talloc_memdup(NULL, reply->element[2]->str, reply->element[2]->len);
	if (reply->element[3]->type == REDIS_REPLY_STRING)
		gateway = talloc_memdup(NULL, reply->element[3]->str, reply->element[3]->len);
	if (reply->element[4]->type == REDIS_REPLY_STRING)
		range = talloc_memdup(NULL, reply->element[4]->str, reply->element[4]->len);

	now = fr_time_to_timeval(fr_time());
	is_active = now.tv_sec <= next_event;
	if (next_event) {
		strftime(time_buff, sizeof(time_buff), "%b %e %Y %H:%M:%S %Z",
			 localtime_r(&(next_event), &tm));
	} else {
		time_buff[0] = '\0';
	}

	INFO("--");
	if (range) INFO("range	        : %s", range);
	INFO("address/prefix  : %s", ip_buff);
	INFO("active	        : %s", is_active ? "yes" : "no");

	if (is_active) {
		if (*time_buff) INFO("lease expires   : %s", time_buff);
		if (device) INFO("device id       : %s", device);
		if (gateway) INFO("gateway id      : %s", gateway);
	} else {
		if (*time_buff) INFO("lease expired   : %s", time_buff);
		if (device) INFO("last device id  : %s", device);
		if (gateway) INFO("last gateway id : %s", gateway);
	}

	talloc_free(range);
	talloc_free(gateway);
	talloc_free(device);
	fr_redis_reply_free(&reply);

	return 0;

err:
	fr_redis_reply_free(&reply);
	return IPPOOL_RCODE_FAIL;
}

/**
 * Pool stats
 */
static int pool_stats(redis_driver_conf_t *inst, uint8_t const *pool)
{
	REQUEST			*request;
	fr_redis_rcode_t	status;
	redisReply		*reply = NULL;
	size_t			i;
	uint64_t		acum = 0;

#define STATS_OFFSETS 4

	DEBUG("Fetching pool stats for pool \"%s\"", pool);

	request = request_alloc(inst);

	status = fr_redis_script(&reply, request, inst->cluster,
			         pool, talloc_array_length(pool),
			         inst->wait_num, inst->wait_timeout,
			         inst->lua_stats.script,
			         "EVALSHA %s 1 %s %u %u %u %u",
			         inst->lua_stats.digest,
			         pool,
				 60, 60 * 30, 60 * 60, 60 * 60 * 24);

	talloc_free(request);

	if (status != REDIS_RCODE_SUCCESS)
		goto err;

	fr_assert(reply);
	if (reply->type != REDIS_REPLY_ARRAY) {
		REDEBUG("Expected result to be array got \"%s\"",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		goto err2;
	}

	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		goto err2;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		goto err2;
	}

	if (reply->element[0]->integer != IPPOOL_RCODE_SUCCESS)
		goto err2;

	if (reply->elements == 2 + STATS_OFFSETS) {
		REDEBUG("Expected %u results, received %zu in array", 2 + STATS_OFFSETS, reply->elements);
		goto err2;
	}

	for (i = 1; i < 2 + STATS_OFFSETS; i++)
		fr_assert(reply->element[i]->type == REDIS_REPLY_INTEGER);

	INFO("total            : %llu", reply->element[1]->integer);
	INFO("free             : %llu", reply->element[2]->integer);
	INFO("used             : %llu", reply->element[1]->integer - reply->element[2]->integer);
	INFO("used (%%)         : %.2Lf", reply->element[1]->integer == 0 ? 0 : ((long double)(reply->element[1]->integer - reply->element[2]->integer) / (long double)reply->element[1]->integer) * 100);
	INFO("expiring 0-1m    : %llu", reply->element[3]->integer - reply->element[2]->integer);
	acum += reply->element[3]->integer - reply->element[2]->integer;
	INFO("expiring 1-30m   : %llu", reply->element[4]->integer - reply->element[2]->integer - acum);
	acum += reply->element[4]->integer - reply->element[2]->integer;
	INFO("expiring 30m-1h  : %llu", reply->element[5]->integer - reply->element[2]->integer - acum);
	acum += reply->element[5]->integer - reply->element[2]->integer;
	INFO("expiring 1h-1d   : %llu", reply->element[6]->integer - reply->element[2]->integer - acum);
	INFO("--");

	fr_redis_reply_free(&reply);

	return 0;

err2:
	fr_redis_reply_free(&reply);
err:
	return IPPOOL_RCODE_FAIL;
}


/** Compare two pool names
 *
 */
static int8_t pool_cmp(void const *a, void const *b)
{
	size_t len_a;
	size_t len_b;
	int ret;

	len_a = talloc_array_length((uint8_t const *)a);
	len_b = talloc_array_length((uint8_t const *)b);

	ret = (len_a > len_b) - (len_a < len_b);
	if (ret != 0) return ret;

	ret = memcmp(a, b, len_a);
	return (ret > 0) - (ret < 0);
}

/** Return the pools available across the cluster
 *
 * @param[in] ctx to allocate range names in.
 * @param[out] out Array of pool names.
 * @param[in] instance Driver specific instance data.
 * @return
 *	- < 0 on failure.
 *	- >= 0 the number of ranges in the array we allocated.
 */
static ssize_t driver_get_pools(TALLOC_CTX *ctx, uint8_t **out[], void *instance)
{
	fr_socket_addr_t	*master;
	size_t			k;
	ssize_t			ret, i, used = 0;
	fr_redis_conn_t		*conn = NULL;
	redis_driver_conf_t	*inst = talloc_get_type_abort(instance, redis_driver_conf_t);
	uint8_t			key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t			*key_p = key;
	REQUEST			*request;
	uint8_t 		**result;

	request = request_alloc(inst);

	IPPOOL_BUILD_KEY(key, key_p, "*}:pool", 1);

	*out = NULL;	/* Initialise output pointer */

	/*
	 *	Get the addresses of all masters in the pool
	 */
	ret = fr_redis_cluster_node_addr_by_role(ctx, &master, inst->cluster, true, false);
	if (ret <= 0) {
		result = NULL;
		return ret;
	}

	result = talloc_zero_array(ctx, uint8_t *, 1);
	if (!result) {
		ERROR("Failed allocating array of pool names");
		talloc_free(master);
		return -1;
	}

	/*
	 *	Iterate over the masters, getting the pools on each
	 */
	for (i = 0; i < ret; i++) {
		fr_pool_t	*pool;
		redisReply		*reply;
		char const		*p;
		size_t			len;
		char			cursor[19] = "0";

		if (fr_redis_cluster_pool_by_node_addr(&pool, inst->cluster, &master[i], false) < 0) {
			ERROR("Failed retrieving pool for node");
		error:
			TALLOC_FREE(result);
			talloc_free(master);
			talloc_free(request);
			return -1;
		}

		conn = fr_pool_connection_get(pool, request);
		if (!conn) goto error;
		do {
			/*
			 *	Break up the scan so we don't block any single
			 *	Redis node too long.
			 */
			reply = redisCommand(conn->handle, "SCAN %s MATCH %b COUNT 20", cursor, key, key_p - key);
			if (!reply) {
				ERROR("Failed reading reply");
				fr_pool_connection_release(pool, request, conn);
				goto error;
			}
			fr_redis_reply_print(L_DBG_LVL_3, reply, request, 0);
			if (fr_redis_command_status(conn, reply) != REDIS_RCODE_SUCCESS) {
				PERROR("Error retrieving keys %s", cursor);

			reply_error:
				fr_pool_connection_release(pool, request, conn);
				fr_redis_reply_free(&reply);
				goto error;
			}

			if (reply->type != REDIS_REPLY_ARRAY) {
				ERROR("Failed retrieving result, expected array got %s",
				      fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));

				goto reply_error;
			}

			if (reply->elements != 2) {
				ERROR("Failed retrieving result, expected array with two elements, got %zu elements",
				      reply->elements);
				fr_redis_reply_free(&reply);
				goto reply_error;
			}

			if (reply->element[0]->type != REDIS_REPLY_STRING) {
				ERROR("Failed retrieving result, expected string got %s",
				      fr_table_str_by_value(redis_reply_types, reply->element[0]->type, "<UNKNOWN>"));
				goto reply_error;
			}

			if (reply->element[1]->type != REDIS_REPLY_ARRAY) {
				ERROR("Failed retrieving result, expected array got %s",
				      fr_table_str_by_value(redis_reply_types, reply->element[1]->type, "<UNKNOWN>"));
				goto reply_error;
			}

			if ((talloc_array_length(result) - used) < reply->element[1]->elements) {
				MEM(result = talloc_realloc(ctx, result, uint8_t *,
							    used + reply->element[1]->elements));
				if (!result) {
					ERROR("Failed expanding array of pool names");
					goto reply_error;
				}
			}
			strlcpy(cursor, reply->element[0]->str, sizeof(cursor));

			for (k = 0; k < reply->element[1]->elements; k++) {
				redisReply *pool_key = reply->element[1]->element[k];

				/*
				 *	Skip over things which are not pool names
				 */
				if (pool_key->len < 7) continue; /* { + [<name>] + }:pool */

				if ((pool_key->str[0]) != '{') continue;
				p = memchr(pool_key->str + 1, '}', pool_key->len - 1);
				if (!p) continue;

				len = (pool_key->len - ((p + 1) - pool_key->str));
				if (len != (sizeof(IPPOOL_POOL_KEY) - 1) + 1) continue;
				if (memcmp(p + 1, ":" IPPOOL_POOL_KEY, (sizeof(IPPOOL_POOL_KEY) - 1) + 1) != 0) {
					continue;
				}

				/*
				 *	String between the curly braces is the pool name
				 */
				result[used++] = talloc_memdup(result, pool_key->str + 1, (p - pool_key->str) - 1);
			}

			fr_redis_reply_free(&reply);
		} while (!((cursor[0] == '0') && (cursor[1] == '\0')));	/* Cursor value of 0 means no more results */

		fr_pool_connection_release(pool, request, conn);
	}

	if (used == 0) {
		*out = NULL;
		talloc_free(result);
		return 0;
	}

	/*
	 *	Sort the results
	 */
	{
		uint8_t const **to_sort;

		memcpy(&to_sort, &result, sizeof(to_sort));

		fr_quick_sort((void const **)to_sort, 0, used, pool_cmp);
	}

	*out = talloc_array(ctx, uint8_t *, used);
	if (!*out) {
		ERROR("Failed allocating file pool name array");
		talloc_free(result);
		return -1;
	}

	/*
	 *	SCAN can produce duplicates, remove them here
	 */
	i = 0;
	k = 0;
	do {	/* stop before last entry */
		(*out)[k++] = talloc_steal(*out, result[i++]);
		while ((i < used) && (pool_cmp(result[i - 1], result[i]) == 0)) i++;
	} while (i < used);

	talloc_free(request);
	talloc_free(result);

	return used;
}

/** Driver initialization function
 *
 */
static int driver_init(TALLOC_CTX *ctx, CONF_SECTION *conf, void **inst)
{
	redis_driver_conf_t	*this;
	CONF_SECTION		*redis_cs;
	int			ret;

	*inst = NULL;

	if (cf_section_rules_push(conf, driver_config) < 0) goto err;

	this = talloc_zero(ctx, redis_driver_conf_t);
	if (!this) goto err;

	ret = cf_section_parse(this, &this->conf, conf);
	if (ret < 0) {
		talloc_free(this);
		goto err;
	}

	redis_cs = cf_section_find(conf, "redis", NULL);

	this->cluster = fr_redis_cluster_alloc(this, redis_cs, &this->conf, false,
					       "rlm_redis_ippool_tool", NULL, NULL);
	if (!this->cluster) {
		talloc_free(this);
		goto err;
	}
	*inst = this;

	redis_ippool_lua_script_t lua_preamble = {
		.file   = this->lua_preamble_file,
		.script = NULL
	};

	if (fr_redis_ippool_loadscript_buf(conf, NULL, &lua_preamble) == -1)
		goto err;

	if (fr_redis_ippool_loadscript(conf, &lua_preamble, &this->lua_add))
		goto err2;
	if (fr_redis_ippool_loadscript(conf, &lua_preamble, &this->lua_modify))
		goto err3;
	if (fr_redis_ippool_loadscript(conf, &lua_preamble, &this->lua_release_tool))
		goto err4;
	if (fr_redis_ippool_loadscript(conf, &lua_preamble, &this->lua_delete))
		goto err5;
	if (fr_redis_ippool_loadscript(conf, &lua_preamble, &this->lua_show))
		goto err6;
	if (fr_redis_ippool_loadscript(conf, &lua_preamble, &this->lua_stats))
		goto err7;

	talloc_free(lua_preamble.script);

	return 0;

err7:
	talloc_free(this->lua_show.script);
err6:
	talloc_free(this->lua_delete.script);
err5:
	talloc_free(this->lua_release_tool.script);
err4:
	talloc_free(this->lua_modify.script);
err3:
	talloc_free(this->lua_add.script);
err2:
	talloc_free(lua_preamble.script);
err:
	return -1;
}

/** Convert an IP range or CIDR mask to a start and stop address
 *
 * @param[out] start_out Where to write the start address.
 * @param[out] end_out Where to write the end address.
 * @param[in] ip_str Unparsed IP string.
 * @param[in] prefix length of prefixes we'll be allocating.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int parse_ip_range(fr_ipaddr_t *start_out, fr_ipaddr_t *end_out, char const *ip_str, uint8_t prefix)
{
	fr_ipaddr_t	start, end;
	bool		ex_broadcast;
	char const	*p;

	p = strchr(ip_str, '-');
	if (p) {
		char	start_buff[INET6_ADDRSTRLEN + 4];
		char	end_buff[INET6_ADDRSTRLEN + 4];
		size_t	len;

		if ((size_t)(p - ip_str) >= sizeof(start_buff)) {
			ERROR("Start address too long");
			return -1;
		}

		len = strlcpy(start_buff, ip_str, (p - ip_str) + 1);
		if (is_truncated(len, sizeof(start_buff))) {
			ERROR("Start address too long");
			return -1;
		}

		len = strlcpy(end_buff, p + 1, sizeof(end_buff));
		if (is_truncated(len, sizeof(end_buff))) {
			ERROR("End address too long");
			return -1;
		}

		if (fr_inet_pton(&start, start_buff, -1, AF_UNSPEC, false, true) < 0) {
			PERROR("Failed parsing \"%s\" as start address", start_buff);
			return -1;
		}

		if (fr_inet_pton(&end, end_buff, -1, AF_UNSPEC, false, true) < 0) {
			PERROR("Failed parsing \"%s\" end address", end_buff);
			return -1;
		}

		if (start.af != end.af) {
			ERROR("Start and end address must be of the same address family");
			return -1;
		}

		if (!prefix) prefix = IPADDR_LEN(start.af);

		/*
		 *	IPv6 addresses
		 */
		if (start.af == AF_INET6) {
			uint128_t start_int, end_int;

			memcpy(&start_int, start.addr.v6.s6_addr, sizeof(start_int));
			memcpy(&end_int, end.addr.v6.s6_addr, sizeof(end_int));
			if (uint128_gt(ntohlll(start_int), ntohlll(end_int))) {
				ERROR("End address must be greater than or equal to start address");
				return -1;
			}
		/*
		 *	IPv4 addresses
		 */
		} else {
			if (ntohl((uint32_t)(start.addr.v4.s_addr)) >
			    ntohl((uint32_t)(end.addr.v4.s_addr))) {
			 	ERROR("End address must be greater than or equal to start address");
			 	return -1;
			}
		}

		/*
		 *	Mask start and end so we can do prefix ranges too
		 */
		fr_ipaddr_mask(&start, prefix);
		fr_ipaddr_mask(&end, prefix);
		start.prefix = prefix;
		end.prefix = prefix;

		*start_out = start;
		*end_out = end;

		return 0;
	}

	if (fr_inet_pton(&start, ip_str, -1, AF_UNSPEC, false, false) < 0) {
		ERROR("Failed parsing \"%s\" as IPv4/v6 subnet", ip_str);
		return -1;
	}

	if (!prefix) prefix = IPADDR_LEN(start.af);

	if (prefix < start.prefix) {
		ERROR("-p must be greater than or equal to /<mask> (%u)", start.prefix);
		return -1;
	}
	if (prefix > IPADDR_LEN(start.af)) {
		ERROR("-p must be less than or equal to address length (%u)", IPADDR_LEN(start.af));
		return -1;
	}

	if ((prefix - start.prefix) > 64) {
		ERROR("-p must be less than or equal to %u", start.prefix + 64);
		return -1;
	}

	/*
	 *	Exclude the broadcast address only if we're dealing with IPv4 addresses
	 *	if we're allocating IPv6 addresses or prefixes we don't need to.
	 */
	ex_broadcast = (start.af == AF_INET) && (IPADDR_LEN(start.af) == prefix);

	/*
	 *	Excluding broadcast, 31/32 or 127/128 start/end are the same
	 */
	if (ex_broadcast && (start.prefix >= (IPADDR_LEN(start.af) - 1))) {
		*start_out = start;
		*end_out = start;
		return 0;
	}

	/*
	 *	Set various fields (we only overwrite the IP later)
	 */
	end = start;

	if (start.af == AF_INET6) {
		uint128_t ip, p_mask;

		/* cond assert to satisfy clang scan */
		if (!fr_cond_assert((prefix > 0) && (prefix <= 128))) return -1;

		/* Don't be tempted to cast */
		memcpy(&ip, start.addr.v6.s6_addr, sizeof(ip));
		ip = ntohlll(ip);

		/* Generate a mask that covers the prefix bits, and sets them high */
		p_mask = uint128_lshift(uint128_gen_mask(prefix - start.prefix), (128 - prefix));
		ip = htonlll(uint128_bor(p_mask, ip));

		/* Decrement by one */
		if (ex_broadcast) ip = uint128_sub(ip, uint128_new(0, 1));
		memcpy(&end.addr.v6.s6_addr, &ip, sizeof(end.addr.v6.s6_addr));
	} else {
		uint32_t ip;

		/* cond assert to satisfy clang scan */
		if (!fr_cond_assert((prefix > 0) && (prefix <= 32))) return -1;

		ip = ntohl(start.addr.v4.s_addr);

		/* Generate a mask that covers the prefix bits and sets them high */
		ip |= uint32_gen_mask(prefix - start.prefix) << (32 - prefix);

		/* Decrement by one */
		if (ex_broadcast) ip--;
		end.addr.v4.s_addr = htonl(ip);
	}

	*start_out = start;
	*end_out = end;

	return 0;
}

static ippool_tool_t *conf_init(char const *hostname, char const *raddb_dir, char const *filename)
{
	ippool_tool_t	*conf;
	CONF_PAIR	*cp;
	CONF_SECTION	*redis_cs, *pool_cs;

	conf = talloc_zero(NULL, ippool_tool_t);
	conf->cs = cf_section_alloc(conf, NULL, "main", NULL);
	if (!conf->cs) exit(EXIT_FAILURE);

	cp = cf_pair_alloc(conf->cs, "confdir", raddb_dir, T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(conf->cs, cp);

// FIXME double expansion not working
//      cp = cf_pair_alloc(conf->cs, "modconfdir", "${confdir}/mods-config", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	char *modconfdir = talloc_typed_asprintf(conf, "%s/mods-config", raddb_dir);
	cp = cf_pair_alloc(conf->cs, "modconfdir", modconfdir, T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(conf->cs, cp);
	talloc_free(modconfdir);

	redis_cs = cf_section_alloc(conf->cs, conf->cs, "redis", NULL);

	fr_ipaddr_t addr;
	uint16_t nport;
	char server[FR_IPADDR_STRLEN], *port;
	int ret = fr_inet_pton_port(&addr, &nport, hostname, -1, AF_UNSPEC, true, true);
	if (ret || fr_inet_ntop(server, sizeof(server), &addr) == NULL)
		exit(EXIT_FAILURE);
	port = talloc_asprintf(conf->cs, "%u", nport);

	cp = cf_pair_alloc(redis_cs, "server", server, T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(redis_cs, cp);

	cp = cf_pair_alloc(redis_cs, "port", port, T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(redis_cs, cp);

	talloc_free(port);

	/*
	 *      Set some alternative default pool settings
	 */
	pool_cs = cf_section_find(redis_cs, "pool", NULL);
	if (!pool_cs) {
		pool_cs = cf_section_alloc(redis_cs, redis_cs, "pool", NULL);
	}
	cp = cf_pair_find(pool_cs, "start");
	if (!cp) {
		cp = cf_pair_alloc(pool_cs, "start", "1", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);   // needs to be "1"...whatever
		cf_pair_add(pool_cs, cp);
	}
	cp = cf_pair_find(pool_cs, "spare");
	if (!cp) {
		cp = cf_pair_alloc(pool_cs, "spare", "0", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
		cf_pair_add(pool_cs, cp);
	}
	cp = cf_pair_find(pool_cs, "min");
	if (!cp) {
		cp = cf_pair_alloc(pool_cs, "min", "0", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
		cf_pair_add(pool_cs, cp);
	}

	/*
	 *      Read configuration files if necessary.
	 */
	if (filename && (cf_file_read(conf->cs, filename) < 0 || (cf_section_pass2(conf->cs) < 0))) {
		exit(EXIT_FAILURE);
	}

	return conf;
}

int main(int argc, char *argv[])
{
	static ippool_tool_operation_t	ops[128];
	ippool_tool_operation_t		*p = ops, *end = ops + (NUM_ELEMENTS(ops));

	int				c;

	uint8_t				*range_arg = NULL;
	uint8_t				*pool_arg = NULL;
	bool				do_export = false, print_stats = false, list_pools = false;
	bool				need_pool = false;
	char				*do_import = NULL;
	char const			*raddb_dir = RADDBDIR;
	char const			*filename = NULL;

	ippool_tool_t			*conf;
	redis_driver_conf_t		*inst;

	fr_debug_lvl = 0;
	name = argv[0];

	conf = talloc_zero(NULL, ippool_tool_t);
	conf->cs = cf_section_alloc(conf, NULL, "main", NULL);
	if (!conf->cs) fr_exit_now(EXIT_FAILURE);

#define ADD_ACTION(_action) \
do { \
	if (p >= end) { \
		ERROR("Too many actions, max is " STRINGIFY(sizeof(ops))); \
		usage(64); \
	} \
	p->action = _action; \
	p->name = optarg; \
	p++; \
	need_pool = true; \
} while (0);

	while ((c = getopt(argc, argv, "a:d:m:r:s:Sp:ilLhxo:D:f:")) != -1) switch (c) {
		case 'a':
			ADD_ACTION(IPPOOL_TOOL_ADD);
			break;

		case 'd':
			ADD_ACTION(IPPOOL_TOOL_DELETE);
			break;

		case 'm':
			ADD_ACTION(IPPOOL_TOOL_MODIFY);
			break;

		case 'r':
			ADD_ACTION(IPPOOL_TOOL_RELEASE);
			break;

		case 's':
			ADD_ACTION(IPPOOL_TOOL_SHOW);
			break;

		case 'p':
		{
			unsigned long tmp;
			char *q;

			if (p == ops) {
				ERROR("Prefix may only be specified after a pool management action");
				usage(64);
			}

			tmp = strtoul(optarg, &q, 10);
			if (q != (optarg + strlen(optarg))) {
				ERROR("Prefix must be an integer value");

			}

			(p - 1)->prefix = (uint8_t)tmp & 0xff;
		}
			break;

		case 'i':
			do_import = optarg;
			break;

		case 'I':
			do_export = true;
			break;

		case 'l':
			if (list_pools) usage(1);	/* Only allowed once */
			list_pools = true;
			break;

		case 'S':
			print_stats = true;
			break;

		case 'h':
			usage(0);

		case 'x':
			fr_debug_lvl++;
			break;

		case 'o':
			break;

		case 'D':
			raddb_dir = optarg;
			break;

		case 'f':
			filename = optarg;
			break;

		default:
			usage(1);
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		ERROR("Need server address/port");
		usage(64);
	}
	if ((argc == 1) && need_pool) {
		ERROR("Need pool to operate on");
		usage(64);
	}
	if (argc > 3) usage(64);

	conf = conf_init(argv[0], raddb_dir, filename);

	/*
	 *	Unescape sequences in the pool name
	 */
	if (argv[1] && (argv[1][0] != '\0')) {
		uint8_t	*arg;
		size_t	len;

		/*
		 *	Be forgiving about zero length strings...
		 */
		len = strlen(argv[1]);
		MEM(arg = talloc_array(conf, uint8_t, len));
		len = fr_value_str_unescape(arg, argv[1], len, '"');
		fr_assert(len);

		MEM(pool_arg = talloc_realloc(conf, arg, uint8_t, len));
	}

	if (argc >= 3 && (argv[2][0] != '\0')) {
		uint8_t	*arg;
		size_t	len;

		len = strlen(argv[2]);
		MEM(arg = talloc_array(conf, uint8_t, len));
		len = fr_value_str_unescape(arg, argv[2], len, '"');
		fr_assert(len);

		MEM(range_arg = talloc_realloc(conf, arg, uint8_t, len));
	}

	if (!do_import && !do_export && !list_pools && !print_stats && (p == ops)) {
		ERROR("Nothing to do!");
		fr_exit_now(EXIT_FAILURE);
	}

	if (driver_init(conf, conf->cs, &conf->driver) < 0) {
		ERROR("Driver initialisation failed");
		fr_exit_now(EXIT_FAILURE);
	}

	inst = talloc_get_type_abort(conf->driver, redis_driver_conf_t);

	if (do_import) {
		ERROR("NOT YET IMPLEMENTED");
	}

	if (do_export) {
		ERROR("NOT YET IMPLEMENTED");
	}

	if (print_stats) {
		uint8_t			**pools;
		ssize_t			slen;
		size_t			i;

		if (pool_arg) {
			pools = talloc_zero_array(conf, uint8_t *, 1);
			slen = 1;
			pools[0] = pool_arg;
		} else {
			slen = driver_get_pools(conf, &pools, conf->driver);
			if (slen < 0) fr_exit_now(EXIT_FAILURE);
		}

		for (i = 0; i < (size_t)slen; i++) {
			if (pool_stats(inst, pools[i]) < 0) {
				fr_exit_now(EXIT_FAILURE);
			}
		}

		talloc_free(pools);
	}

	if (list_pools) {
		ssize_t		slen;
		size_t		i;
		uint8_t 	**pools;

		slen = driver_get_pools(conf, &pools, conf->driver);
		if (slen < 0) fr_exit_now(EXIT_FAILURE);
		if (slen > 0) {
			for (i = 0; i < (size_t)slen; i++) {
				char *pool_str;

				pool_str = fr_asprint(conf, (char *)pools[i], talloc_array_length(pools[i]), '"');
				INFO("%s", pool_str);
				talloc_free(pool_str);
			}
			INFO("--");
		}

		talloc_free(pools);
	}

	end = p;
	for (p = ops; p < end; p++) {
		uint64_t count = 0;

		if (parse_ip_range(&p->start, &p->end, p->name, p->prefix) < 0) usage(64);
		if (p->start.af == AF_UNSPEC) continue;
		if (!p->prefix) p->prefix = IPADDR_LEN(p->start.af);

		if (!p->pool) {
			p->pool = pool_arg;
			p->pool_len = talloc_array_length(pool_arg);
		}
		if (!p->range && range_arg) {
			p->range = range_arg;
			p->range_len = talloc_array_length(range_arg);
		}

		fr_ipaddr_t ipaddr = p->start;

		do {
			char ip_buff[FR_IPADDR_PREFIX_STRLEN];
			int64_t ret;

			IPPOOL_SPRINT_IP(ip_buff, &ipaddr, p->prefix);

			switch (p->action) {
			case IPPOOL_TOOL_ADD:
				if ((ret = lease_add(inst, p, ip_buff)) < 0)
					fr_exit_now(EXIT_FAILURE);
				count += ret;
				break;

			case IPPOOL_TOOL_DELETE:
				if ((ret = lease_delete(inst, p, ip_buff)) < 0)
					fr_exit_now(EXIT_FAILURE);
				count += ret;
				break;

			case IPPOOL_TOOL_MODIFY:
				if ((ret = lease_modify(inst, p, ip_buff)) < 0)
					fr_exit_now(EXIT_FAILURE);
				count += ret;
				break;

			case IPPOOL_TOOL_RELEASE:
				if ((ret = lease_release(inst, p, ip_buff)) < 0)
					fr_exit_now(EXIT_FAILURE);
				count += ret;
				break;

			case IPPOOL_TOOL_SHOW:
				if (lease_show(inst, p, ip_buff) < 0)
					fr_exit_now(EXIT_FAILURE);
				break;
			}
		} while (ipaddr_next(&ipaddr, &p->end, p->prefix));

		switch (p->action) {
		case IPPOOL_TOOL_ADD:
			INFO("Added %" PRIu64 " address(es)/prefix(es)", count);
			break;

		case IPPOOL_TOOL_DELETE:
			INFO("Deleted %" PRIu64 " address(es)/prefix(es)", count);
			break;

		case IPPOOL_TOOL_MODIFY:
			INFO("Modified %" PRIu64 " address(es)/prefix(es)", count);
			break;

		case IPPOOL_TOOL_RELEASE:
			INFO("Released %" PRIu64 " address(es)/prefix(es)", count);
			break;

		default:
			do {} while (0);
		}
	}

	talloc_free(conf);

	return 0;
}
