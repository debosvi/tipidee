#
# This file has been generated by tools/gen-deps.sh
#

src/include/tipidee/conf.h: src/include/tipidee/resattr.h src/include/tipidee/uri.h
src/include/tipidee/log.h: src/include/tipidee/headers.h src/include/tipidee/resattr.h src/include/tipidee/rql.h
src/include/tipidee/response.h: src/include/tipidee/headers.h src/include/tipidee/rql.h
src/include/tipidee/rql.h: src/include/tipidee/method.h src/include/tipidee/uri.h
src/include/tipidee/tipidee.h: src/include/tipidee/conf.h src/include/tipidee/config.h src/include/tipidee/headers.h src/include/tipidee/log.h src/include/tipidee/method.h src/include/tipidee/resattr.h src/include/tipidee/response.h src/include/tipidee/rql.h src/include/tipidee/uri.h src/include/tipidee/util.h
src/tipideed/tipideed-internal.h: src/include/tipidee/tipidee.h
src/config/conftree.o src/config/conftree.lo: src/config/conftree.c src/config/tipidee-config-internal.h
src/config/defaults.o src/config/defaults.lo: src/config/defaults.c src/config/tipidee-config-internal.h src/include/tipidee/log.h
src/config/headers.o src/config/headers.lo: src/config/headers.c src/config/tipidee-config-internal.h src/include/tipidee/config.h
src/config/lexparse.o src/config/lexparse.lo: src/config/lexparse.c src/config/tipidee-config-internal.h src/include/tipidee/config.h src/include/tipidee/log.h
src/config/node.o src/config/node.lo: src/config/node.c src/config/tipidee-config-internal.h
src/config/repo.o src/config/repo.lo: src/config/repo.c src/config/tipidee-config-internal.h
src/config/resattr.o src/config/resattr.lo: src/config/resattr.c src/config/tipidee-config-internal.h
src/config/tipidee-config-preprocess.o src/config/tipidee-config-preprocess.lo: src/config/tipidee-config-preprocess.c
src/config/tipidee-config.o src/config/tipidee-config.lo: src/config/tipidee-config.c src/config/tipidee-config-internal.h src/include/tipidee/config.h
src/config/util.o src/config/util.lo: src/config/util.c src/config/tipidee-config-internal.h
src/libtipidee/tipidee_conf_free.o src/libtipidee/tipidee_conf_free.lo: src/libtipidee/tipidee_conf_free.c src/include/tipidee/conf.h
src/libtipidee/tipidee_conf_get.o src/libtipidee/tipidee_conf_get.lo: src/libtipidee/tipidee_conf_get.c src/include/tipidee/conf.h
src/libtipidee/tipidee_conf_get_argv.o src/libtipidee/tipidee_conf_get_argv.lo: src/libtipidee/tipidee_conf_get_argv.c src/include/tipidee/conf.h
src/libtipidee/tipidee_conf_get_content_type.o src/libtipidee/tipidee_conf_get_content_type.lo: src/libtipidee/tipidee_conf_get_content_type.c src/include/tipidee/conf.h
src/libtipidee/tipidee_conf_get_errorfile.o src/libtipidee/tipidee_conf_get_errorfile.lo: src/libtipidee/tipidee_conf_get_errorfile.c src/include/tipidee/conf.h
src/libtipidee/tipidee_conf_get_redirection.o src/libtipidee/tipidee_conf_get_redirection.lo: src/libtipidee/tipidee_conf_get_redirection.c src/include/tipidee/conf.h
src/libtipidee/tipidee_conf_get_resattr.o src/libtipidee/tipidee_conf_get_resattr.lo: src/libtipidee/tipidee_conf_get_resattr.c src/include/tipidee/conf.h src/include/tipidee/resattr.h
src/libtipidee/tipidee_conf_get_resattr1.o src/libtipidee/tipidee_conf_get_resattr1.lo: src/libtipidee/tipidee_conf_get_resattr1.c src/include/tipidee/conf.h src/include/tipidee/resattr.h
src/libtipidee/tipidee_conf_get_responseheaders.o src/libtipidee/tipidee_conf_get_responseheaders.lo: src/libtipidee/tipidee_conf_get_responseheaders.c src/include/tipidee/conf.h
src/libtipidee/tipidee_conf_get_string.o src/libtipidee/tipidee_conf_get_string.lo: src/libtipidee/tipidee_conf_get_string.c src/include/tipidee/conf.h
src/libtipidee/tipidee_conf_get_uint32.o src/libtipidee/tipidee_conf_get_uint32.lo: src/libtipidee/tipidee_conf_get_uint32.c src/include/tipidee/conf.h
src/libtipidee/tipidee_conf_init.o src/libtipidee/tipidee_conf_init.lo: src/libtipidee/tipidee_conf_init.c src/include/tipidee/conf.h
src/libtipidee/tipidee_headers_get_content_length.o src/libtipidee/tipidee_headers_get_content_length.lo: src/libtipidee/tipidee_headers_get_content_length.c src/include/tipidee/headers.h
src/libtipidee/tipidee_headers_init.o src/libtipidee/tipidee_headers_init.lo: src/libtipidee/tipidee_headers_init.c src/include/tipidee/headers.h
src/libtipidee/tipidee_headers_parse.o src/libtipidee/tipidee_headers_parse.lo: src/libtipidee/tipidee_headers_parse.c src/include/tipidee/headers.h
src/libtipidee/tipidee_headers_search.o src/libtipidee/tipidee_headers_search.lo: src/libtipidee/tipidee_headers_search.c src/include/tipidee/headers.h
src/libtipidee/tipidee_log_answer.o src/libtipidee/tipidee_log_answer.lo: src/libtipidee/tipidee_log_answer.c src/include/tipidee/log.h
src/libtipidee/tipidee_log_exit.o src/libtipidee/tipidee_log_exit.lo: src/libtipidee/tipidee_log_exit.c src/include/tipidee/log.h
src/libtipidee/tipidee_log_request.o src/libtipidee/tipidee_log_request.lo: src/libtipidee/tipidee_log_request.c src/include/tipidee/headers.h src/include/tipidee/log.h src/include/tipidee/method.h
src/libtipidee/tipidee_log_resource.o src/libtipidee/tipidee_log_resource.lo: src/libtipidee/tipidee_log_resource.c src/include/tipidee/log.h
src/libtipidee/tipidee_log_start.o src/libtipidee/tipidee_log_start.lo: src/libtipidee/tipidee_log_start.c src/include/tipidee/log.h
src/libtipidee/tipidee_method.o src/libtipidee/tipidee_method.lo: src/libtipidee/tipidee_method.c src/include/tipidee/method.h
src/libtipidee/tipidee_response_error_nofile.o src/libtipidee/tipidee_response_error_nofile.lo: src/libtipidee/tipidee_response_error_nofile.c src/include/tipidee/method.h src/include/tipidee/response.h
src/libtipidee/tipidee_response_file.o src/libtipidee/tipidee_response_file.lo: src/libtipidee/tipidee_response_file.c src/include/tipidee/conf.h src/include/tipidee/method.h src/include/tipidee/response.h src/include/tipidee/rql.h src/include/tipidee/util.h
src/libtipidee/tipidee_response_header_date.o src/libtipidee/tipidee_response_header_date.lo: src/libtipidee/tipidee_response_header_date.c src/include/tipidee/response.h
src/libtipidee/tipidee_response_header_date_fmt.o src/libtipidee/tipidee_response_header_date_fmt.lo: src/libtipidee/tipidee_response_header_date_fmt.c src/include/tipidee/response.h
src/libtipidee/tipidee_response_header_lastmodified.o src/libtipidee/tipidee_response_header_lastmodified.lo: src/libtipidee/tipidee_response_header_lastmodified.c src/include/tipidee/response.h
src/libtipidee/tipidee_response_header_preparebuiltin.o src/libtipidee/tipidee_response_header_preparebuiltin.lo: src/libtipidee/tipidee_response_header_preparebuiltin.c src/include/tipidee/response.h
src/libtipidee/tipidee_response_header_writeall.o src/libtipidee/tipidee_response_header_writeall.lo: src/libtipidee/tipidee_response_header_writeall.c src/include/tipidee/response.h
src/libtipidee/tipidee_response_header_writemerge.o src/libtipidee/tipidee_response_header_writemerge.lo: src/libtipidee/tipidee_response_header_writemerge.c src/include/tipidee/headers.h src/include/tipidee/response.h
src/libtipidee/tipidee_response_status.o src/libtipidee/tipidee_response_status.lo: src/libtipidee/tipidee_response_status.c src/include/tipidee/response.h
src/libtipidee/tipidee_rql_read.o src/libtipidee/tipidee_rql_read.lo: src/libtipidee/tipidee_rql_read.c src/include/tipidee/method.h src/include/tipidee/rql.h src/include/tipidee/uri.h
src/libtipidee/tipidee_uri_parse.o src/libtipidee/tipidee_uri_parse.lo: src/libtipidee/tipidee_uri_parse.c src/include/tipidee/uri.h
src/libtipidee/tipidee_util_chunked_read.o src/libtipidee/tipidee_util_chunked_read.lo: src/libtipidee/tipidee_util_chunked_read.c src/include/tipidee/util.h
src/libtipidee/tipidee_util_defaulttext.o src/libtipidee/tipidee_util_defaulttext.lo: src/libtipidee/tipidee_util_defaulttext.c src/include/tipidee/util.h
src/libtipidee/tipidee_util_httpdate.o src/libtipidee/tipidee_util_httpdate.lo: src/libtipidee/tipidee_util_httpdate.c src/include/tipidee/util.h
src/tipideed/cgi.o src/tipideed/cgi.lo: src/tipideed/cgi.c src/include/tipidee/tipidee.h src/tipideed/tipideed-internal.h
src/tipideed/harden.o src/tipideed/harden.lo: src/tipideed/harden.c src/tipideed/tipideed-internal.h
src/tipideed/options.o src/tipideed/options.lo: src/tipideed/options.c src/include/tipidee/log.h src/include/tipidee/response.h src/tipideed/tipideed-internal.h
src/tipideed/regular.o src/tipideed/regular.lo: src/tipideed/regular.c src/include/tipidee/log.h src/include/tipidee/method.h src/include/tipidee/response.h src/tipideed/tipideed-internal.h
src/tipideed/responses.o src/tipideed/responses.lo: src/tipideed/responses.c src/include/tipidee/log.h src/include/tipidee/response.h src/include/tipidee/util.h src/tipideed/tipideed-internal.h
src/tipideed/send_file.o src/tipideed/send_file.lo: src/tipideed/send_file.c src/tipideed/tipideed-internal.h
src/tipideed/tipideed.o src/tipideed/tipideed.lo: src/tipideed/tipideed.c src/include/tipidee/tipidee.h src/tipideed/tipideed-internal.h
src/tipideed/trace.o src/tipideed/trace.lo: src/tipideed/trace.c src/include/tipidee/log.h src/include/tipidee/method.h src/include/tipidee/response.h src/tipideed/tipideed-internal.h

tipidee-config: EXTRA_LIBS := -lskarnet ${SPAWN_LIB}
tipidee-config: src/config/tipidee-config.o src/config/util.o src/config/node.o src/config/repo.o src/config/conftree.o src/config/headers.o src/config/defaults.o src/config/lexparse.o
tipidee-config-preprocess: EXTRA_LIBS := -lskarnet
tipidee-config-preprocess: src/config/tipidee-config-preprocess.o

ifeq ($(strip $(STATIC_LIBS_ARE_PIC)),)
libtipidee.a.xyzzy: src/libtipidee/tipidee_conf_free.o src/libtipidee/tipidee_conf_get.o src/libtipidee/tipidee_conf_get_argv.o src/libtipidee/tipidee_conf_get_content_type.o src/libtipidee/tipidee_conf_get_errorfile.o src/libtipidee/tipidee_conf_get_redirection.o src/libtipidee/tipidee_conf_get_resattr.o src/libtipidee/tipidee_conf_get_resattr1.o src/libtipidee/tipidee_conf_get_responseheaders.o src/libtipidee/tipidee_conf_get_string.o src/libtipidee/tipidee_conf_get_uint32.o src/libtipidee/tipidee_conf_init.o src/libtipidee/tipidee_headers_get_content_length.o src/libtipidee/tipidee_headers_init.o src/libtipidee/tipidee_headers_parse.o src/libtipidee/tipidee_headers_search.o src/libtipidee/tipidee_log_answer.o src/libtipidee/tipidee_log_exit.o src/libtipidee/tipidee_log_resource.o src/libtipidee/tipidee_log_request.o src/libtipidee/tipidee_log_start.o src/libtipidee/tipidee_method.o src/libtipidee/tipidee_response_error_nofile.o src/libtipidee/tipidee_response_file.o src/libtipidee/tipidee_response_header_date.o src/libtipidee/tipidee_response_header_date_fmt.o src/libtipidee/tipidee_response_header_lastmodified.o src/libtipidee/tipidee_response_header_preparebuiltin.o src/libtipidee/tipidee_response_header_writeall.o src/libtipidee/tipidee_response_header_writemerge.o src/libtipidee/tipidee_response_status.o src/libtipidee/tipidee_rql_read.o src/libtipidee/tipidee_uri_parse.o src/libtipidee/tipidee_util_chunked_read.o src/libtipidee/tipidee_util_defaulttext.o src/libtipidee/tipidee_util_httpdate.o
else
libtipidee.a.xyzzy: src/libtipidee/tipidee_conf_free.lo src/libtipidee/tipidee_conf_get.lo src/libtipidee/tipidee_conf_get_argv.lo src/libtipidee/tipidee_conf_get_content_type.lo src/libtipidee/tipidee_conf_get_errorfile.lo src/libtipidee/tipidee_conf_get_redirection.lo src/libtipidee/tipidee_conf_get_resattr.lo src/libtipidee/tipidee_conf_get_resattr1.lo src/libtipidee/tipidee_conf_get_responseheaders.lo src/libtipidee/tipidee_conf_get_string.lo src/libtipidee/tipidee_conf_get_uint32.lo src/libtipidee/tipidee_conf_init.lo src/libtipidee/tipidee_headers_get_content_length.lo src/libtipidee/tipidee_headers_init.lo src/libtipidee/tipidee_headers_parse.lo src/libtipidee/tipidee_headers_search.lo src/libtipidee/tipidee_log_answer.lo src/libtipidee/tipidee_log_exit.lo src/libtipidee/tipidee_log_resource.lo src/libtipidee/tipidee_log_request.lo src/libtipidee/tipidee_log_start.lo src/libtipidee/tipidee_method.lo src/libtipidee/tipidee_response_error_nofile.lo src/libtipidee/tipidee_response_file.lo src/libtipidee/tipidee_response_header_date.lo src/libtipidee/tipidee_response_header_date_fmt.lo src/libtipidee/tipidee_response_header_lastmodified.lo src/libtipidee/tipidee_response_header_preparebuiltin.lo src/libtipidee/tipidee_response_header_writeall.lo src/libtipidee/tipidee_response_header_writemerge.lo src/libtipidee/tipidee_response_status.lo src/libtipidee/tipidee_rql_read.lo src/libtipidee/tipidee_uri_parse.lo src/libtipidee/tipidee_util_chunked_read.lo src/libtipidee/tipidee_util_defaulttext.lo src/libtipidee/tipidee_util_httpdate.lo
endif

libtipidee.so.xyzzy: EXTRA_LIBS := -lskarnet
libtipidee.so.xyzzy: src/libtipidee/tipidee_conf_free.lo src/libtipidee/tipidee_conf_get.lo src/libtipidee/tipidee_conf_get_argv.lo src/libtipidee/tipidee_conf_get_content_type.lo src/libtipidee/tipidee_conf_get_errorfile.lo src/libtipidee/tipidee_conf_get_redirection.lo src/libtipidee/tipidee_conf_get_resattr.lo src/libtipidee/tipidee_conf_get_resattr1.lo src/libtipidee/tipidee_conf_get_responseheaders.lo src/libtipidee/tipidee_conf_get_string.lo src/libtipidee/tipidee_conf_get_uint32.lo src/libtipidee/tipidee_conf_init.lo src/libtipidee/tipidee_headers_get_content_length.lo src/libtipidee/tipidee_headers_init.lo src/libtipidee/tipidee_headers_parse.lo src/libtipidee/tipidee_headers_search.lo src/libtipidee/tipidee_log_answer.lo src/libtipidee/tipidee_log_exit.lo src/libtipidee/tipidee_log_resource.lo src/libtipidee/tipidee_log_request.lo src/libtipidee/tipidee_log_start.lo src/libtipidee/tipidee_method.lo src/libtipidee/tipidee_response_error_nofile.lo src/libtipidee/tipidee_response_file.lo src/libtipidee/tipidee_response_header_date.lo src/libtipidee/tipidee_response_header_date_fmt.lo src/libtipidee/tipidee_response_header_lastmodified.lo src/libtipidee/tipidee_response_header_preparebuiltin.lo src/libtipidee/tipidee_response_header_writeall.lo src/libtipidee/tipidee_response_header_writemerge.lo src/libtipidee/tipidee_response_status.lo src/libtipidee/tipidee_rql_read.lo src/libtipidee/tipidee_uri_parse.lo src/libtipidee/tipidee_util_chunked_read.lo src/libtipidee/tipidee_util_defaulttext.lo src/libtipidee/tipidee_util_httpdate.lo

# websocket lib
src/libtipideews/ws_manage_websocket.o src/libtipideews/ws_manage_websocket.lo: src/libtipideews/ws_manage_websocket.c src/include/tipidee/conf.h
src/libtipideews/ws_compute_sec_ws_accept.o src/libtipideews/ws_compute_sec_ws_accept.lo: src/libtipideews/ws_compute_sec_ws_accept.c src/include/tipidee/conf.h
src/libtipideews/ws_exec_helper.o src/libtipideews/ws_exec_helper.lo: src/libtipideews/ws_exec_helper.c src/include/tipidee/conf.h
src/libtipideews/ws_data_mask.o src/libtipideews/ws_data_mask.lo: src/libtipideews/ws_data_mask.c src/include/tipidee/conf.h
src/libtipideews/ws_handshake.o src/libtipideews/ws_handshake.lo: src/libtipideews/ws_handshake.c src/include/tipidee/conf.h
src/libtipideews/ws_mainstream.o src/libtipideews/ws_mainstream.lo: src/libtipideews/ws_mainstream.c src/include/tipidee/conf.h

ifeq ($(strip $(STATIC_LIBS_ARE_PIC)),)
libtipideews.a.xyzzy: src/libtipideews/ws_manage_websocket.o src/libtipideews/ws_compute_sec_ws_accept.o src/libtipideews/ws_exec_helper.o src/libtipideews/ws_data_mask.o src/libtipideews/ws_handshake.o src/libtipideews/ws_mainstream.lo
else
libtipideews.a.xyzzy: src/libtipideews/ws_manage_websocket.lo src/libtipideews/ws_compute_sec_ws_accept.lo src/libtipideews/ws_exec_helper.lo src/libtipideews/ws_data_mask.lo src/libtipideews/ws_handshake.lo src/libtipideews/ws_mainstream.lo
endif

tipideed: EXTRA_LIBS := -lskarnet
tipideed: \
	src/tipideed/tipideed.o \
	src/tipideed/cgi.o \
	src/tipideed/harden.o \
	src/tipideed/log.o \
	src/tipideed/options.o \
	src/tipideed/regular.o \
	src/tipideed/responses.o \
	src/tipideed/send_file.o \
	src/tipideed/trace.o \
	libtipidee.a.xyzzy

websocketd: EXTRA_LIBS := -lskarnet
websocketd: \
	src/websocketd/websocketd.o \
	src/websocketd/log.o \
	src/websocketd/responses.o \
	src/websocketd/trace.o \
	libtipidee.a.xyzzy \
	libtipideews.a.xyzzy

INTERNAL_LIBS :=
