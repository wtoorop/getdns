#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

getdns_dict *
ipaddr_dict(char *ipstr)
{
	getdns_return_t r;
	getdns_dict *a = getdns_dict_create();
	char *s = strchr(ipstr, '%'), *scope_id_str = "";
	char *p = strchr(ipstr, '@'), *portstr = "";
	uint8_t buf[sizeof(struct in6_addr)];
	getdns_bindata addr;

	addr.data = buf;

	if (s) {
		*s = 0;
		scope_id_str = s + 1;
	}
	if (p) {
		*p = 0;
		portstr = p + 1;
	}
	if (! a)
		fprintf(stderr, "Error creating address dict\n");

	else if (strchr(ipstr, ':')) {
		getdns_dict_util_set_string(a, "address_type", "IPv6");
		addr.size = 16;
		if (inet_pton(AF_INET6, ipstr, buf) <= 0) {
			fprintf(stderr, "Error converting IPv6 address\n");
			getdns_dict_destroy(a);
			return NULL;
		}
	} else {
		getdns_dict_util_set_string(a, "address_type", "IPv4");
		addr.size = 4;
		if (inet_pton(AF_INET, ipstr, buf) <= 0) {
			fprintf(stderr, "Error converting IPv4 address\n");
			getdns_dict_destroy(a);
			return NULL;
		}
	}
	if ((r = getdns_dict_set_bindata(a, "address_data", &addr)))
		fprintf(stderr, "Could not set address_data: %s\n",
		    getdns_get_errorstr_by_id(r));
	else
		return a;

	getdns_dict_destroy(a);
	return NULL;
}

int main(int argc, char **argv)
{
	getdns_return_t r = GETDNS_RETURN_GENERIC_ERROR;
	getdns_context *ctxt = NULL;
	getdns_dict *listen_dict = NULL;
	getdns_dict *root_hint = NULL;
	getdns_list *root_hints = NULL;
	getdns_bindata *listen_bin;
	uint32_t port = 53;
	struct sockaddr_in listen_in;
	struct sockaddr_storage remote_in;
	struct sockaddr_in6 listen_in6;
	uint8_t buf[8192];
	socklen_t addrlen;
	ssize_t msg_len;
	getdns_dict *dns_msg;
	int s;
	getdns_bindata *qname;
	char *qname_str = NULL;
	uint32_t qtype, qid;
	getdns_dict *response;
	uint8_t str_buf[20];

	if (argc != 3)
		fprintf(stderr, "usage: %s <listen addr> <root hints address>\n",
		    argv[0]);

	else if ((r = getdns_context_create(&ctxt, 1)))
		fprintf(stderr, "Could not create context: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if (!(listen_dict = ipaddr_dict(argv[1]))) {
		r = GETDNS_RETURN_GENERIC_ERROR;
		fprintf(stderr, "Error parsing listen address\n");

	} else if ((r = getdns_dict_get_bindata(listen_dict, "address_data",
	    &listen_bin)))
		fprintf(stderr, "Could not get address_data: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if (!(root_hint = ipaddr_dict(argv[2]))) {
		r = GETDNS_RETURN_GENERIC_ERROR;
		fprintf(stderr, "Error parsing root hint address\n");

	} else if (!(root_hints = getdns_list_create())) {
		r = GETDNS_RETURN_GENERIC_ERROR;
		fprintf(stderr, "Could not create root hints list\n");

	} else if ((r = getdns_list_set_dict(root_hints, 0, root_hint)))
		fprintf(stderr, "Could not append root hint: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r = getdns_context_set_dns_root_servers(ctxt, root_hints)))
		fprintf(stderr, "Could not set root hints: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((s = socket((listen_bin->size == 4 ? AF_INET : AF_INET6),
		    SOCK_DGRAM, 0)) == -1) {

		r = GETDNS_RETURN_GENERIC_ERROR;
		perror("Could not create socket");
	} else {
		(void) getdns_dict_get_int(listen_dict, "port", &port);
		if (listen_bin->size == 4) {
			(void)memset((void *)&listen_in, 0, sizeof(listen_in));
			listen_in.sin_family = AF_INET;
			listen_in.sin_port = htons(port);
			(void)memcpy((void *)&listen_in.sin_addr,
			    listen_bin->data, 4);
			if (bind(s, (struct sockaddr *)&listen_in,
			    sizeof(listen_in)) == -1) {
				r = GETDNS_RETURN_GENERIC_ERROR;
				perror("bind");
			}
		} else {
			(void)memset((void *)&listen_in6,0,sizeof(listen_in6));
			listen_in6.sin6_family = AF_INET;
			listen_in6.sin6_port = htons(port);
			(void)memcpy((void *)&listen_in6.sin6_addr,
			    listen_bin->data, 16);
			if (bind(s, (struct sockaddr *)&listen_in6,
			    sizeof(listen_in6)) == -1) {
				r = GETDNS_RETURN_GENERIC_ERROR;
				perror("bind");
			}
		}
	};
	while (r == GETDNS_RETURN_GOOD) {
		addrlen = sizeof(remote_in);
		if ((msg_len = recvfrom(s, buf, sizeof(buf), 0,
		    (struct sockaddr *)&remote_in, &addrlen)) == -1) {
			r = GETDNS_RETURN_GENERIC_ERROR;
			perror("recvfrom");
			break;
		}
		if ((r = getdns_wire2msg_dict(buf, msg_len, &dns_msg)))
			fprintf(stderr, "Error converting dns msg: %s\n",
			    getdns_get_errorstr_by_id(r));

		else if ((r = getdns_dict_get_bindata(dns_msg,
		    "/question/qname", &qname)))
			fprintf(stderr, "Could not get qname: %s\n",
			    getdns_get_errorstr_by_id(r));

		else if ((r=getdns_convert_dns_name_to_fqdn(qname,&qname_str)))
			fprintf(stderr, "Could not convert qname: %s\n",
			    getdns_get_errorstr_by_id(r));

		else if ((r = getdns_dict_get_int(dns_msg,
		    "/question/qtype", &qtype)))
			fprintf(stderr, "Could get qtype: %s\n",
			    getdns_get_errorstr_by_id(r));

		else if ((r = getdns_dict_get_int(dns_msg,"/header/id",&qid)))
			fprintf(stderr, "Could get qid: %s\n",
			    getdns_get_errorstr_by_id(r));

		/*
		fprintf(stderr, "Received packet len: %zd, from %d == %d\n",
		    msg_len, (int)addrlen, (int)sizeof(listen_in));
		fprintf(stderr, "%d %d %s\n",
		    (int)((struct sockaddr_in *)&remote_in)->sin_family,
		    (int)ntohs(((struct sockaddr_in *)&remote_in)->sin_port),
		    inet_ntop(AF_INET, (void *)&((struct sockaddr_in *)&remote_in)->sin_addr, str_buf, (socklen_t)sizeof(str_buf)));
		*/

		getdns_dict_destroy(dns_msg);
		dns_msg = NULL;
		if (r) break;
		if ((r = getdns_general_sync(ctxt, qname_str, qtype, NULL,
		    &response)))
			fprintf(stderr, "Could get forward query: %s\n",
			    getdns_get_errorstr_by_id(r));
		free(qname_str);
		qname_str = NULL;
		if (r) break;
		else if ((r = getdns_dict_set_int(response,
		    "/replies_tree/0/header/id", qid))) {
			fprintf(stderr, "Could not set qid: %s\n",
			    getdns_get_errorstr_by_id(r));
			break;
		}
		msg_len = sizeof(buf);
		if ((r = getdns_msg_dict2wire_buf(response,buf,&msg_len)))
			fprintf(stderr, "Could not convert reply: %s\n",
			    getdns_get_errorstr_by_id(r));

		if (!r && sendto(s,buf,msg_len,0,(struct sockaddr *)&remote_in,
		    addrlen) == -1) {
			r = GETDNS_RETURN_GENERIC_ERROR;
			perror("sendto");
		}
		getdns_dict_destroy(response);
		response = NULL;
	}
	free(qname_str);
	getdns_dict_destroy(dns_msg);
	getdns_list_destroy(root_hints);
	getdns_dict_destroy(root_hint);
	getdns_dict_destroy(listen_dict);
	getdns_context_destroy(ctxt);
	exit(r ? EXIT_FAILURE : EXIT_SUCCESS);
}
