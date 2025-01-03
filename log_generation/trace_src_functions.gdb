# Helper function to set rbreak and attach commands to it
define set_rbreak_with_commands
    rbreak $arg0
    commands
        if $_function
            printf "Function: %s, Address: %p\n", $_function, $pc - 0x555555554005
        else
            printf "Function: [unknown], Address: %p\n", $pc - 0x555555554005
        end
        backtrace 10
        continue
    end
end

# Log the base address
break main
commands
    printf "Base address: %p\n", $pc
end

# Set breakpoints on all functions in grep’s src directory
# set_rbreak_with_commands grep.c:.
# set_rbreak_with_commands dfasearch.c:.
# set_rbreak_with_commands kwsearch.c:.
# set_rbreak_with_commands kwset.c:.
# set_rbreak_with_commands pcresearch.c:.
# set_rbreak_with_commands searchutils.c:.

# Set breakpoints on all functions in nginx's src directory
set_rbreak_with_commands core/nginx.c:.
set_rbreak_with_commands core/ngx_array.c:.
set_rbreak_with_commands core/ngx_buf.c:.
set_rbreak_with_commands core/ngx_conf_file.c:.
set_rbreak_with_commands core/ngx_connection.c:.
set_rbreak_with_commands core/ngx_cpuinfo.c:.
set_rbreak_with_commands core/ngx_crc32.c:.
set_rbreak_with_commands core/ngx_crypt.c:.
set_rbreak_with_commands core/ngx_cycle.c:.
set_rbreak_with_commands core/ngx_file.c:.
set_rbreak_with_commands core/ngx_hash.c:.
set_rbreak_with_commands core/ngx_inet.c:.
set_rbreak_with_commands core/ngx_list.c:.
set_rbreak_with_commands core/ngx_log.c:.
set_rbreak_with_commands core/ngx_md5.c:.
set_rbreak_with_commands core/ngx_module.c:.
set_rbreak_with_commands core/ngx_murmurhash.c:.
set_rbreak_with_commands core/ngx_open_file_cache.c:.
set_rbreak_with_commands core/ngx_output_chain.c:.
set_rbreak_with_commands core/ngx_palloc.c:.
set_rbreak_with_commands core/ngx_parse.c:.
set_rbreak_with_commands core/ngx_parse_time.c:.
set_rbreak_with_commands core/ngx_proxy_protocol.c:.
set_rbreak_with_commands core/ngx_queue.c:.
set_rbreak_with_commands core/ngx_radix_tree.c:.
set_rbreak_with_commands core/ngx_rbtree.c:.
set_rbreak_with_commands core/ngx_regex.c:.
set_rbreak_with_commands core/ngx_resolver.c:.
set_rbreak_with_commands core/ngx_rwlock.c:.
set_rbreak_with_commands core/ngx_sha1.c:.
set_rbreak_with_commands core/ngx_shmtx.c:.
set_rbreak_with_commands core/ngx_slab.c:.
set_rbreak_with_commands core/ngx_spinlock.c:.
set_rbreak_with_commands core/ngx_string.c:.
set_rbreak_with_commands core/ngx_syslog.c:.
set_rbreak_with_commands core/ngx_thread_pool.c:.
set_rbreak_with_commands core/ngx_times.c:.
set_rbreak_with_commands event/modules/ngx_devpoll_module.c:.
set_rbreak_with_commands event/modules/ngx_epoll_module.c:.
set_rbreak_with_commands event/modules/ngx_eventport_module.c:.
set_rbreak_with_commands event/modules/ngx_iocp_module.c:.
set_rbreak_with_commands event/modules/ngx_kqueue_module.c:.
set_rbreak_with_commands event/modules/ngx_poll_module.c:.
set_rbreak_with_commands event/modules/ngx_select_module.c:.
set_rbreak_with_commands event/modules/ngx_win32_poll_module.c:.
set_rbreak_with_commands event/modules/ngx_win32_select_module.c:.
set_rbreak_with_commands event/ngx_event.c:.
set_rbreak_with_commands event/ngx_event_accept.c:.
set_rbreak_with_commands event/ngx_event_acceptex.c:.
set_rbreak_with_commands event/ngx_event_connect.c:.
set_rbreak_with_commands event/ngx_event_connectex.c:.
set_rbreak_with_commands event/ngx_event_openssl.c:.
set_rbreak_with_commands event/ngx_event_openssl_stapling.c:.
set_rbreak_with_commands event/ngx_event_pipe.c:.
set_rbreak_with_commands event/ngx_event_posted.c:.
set_rbreak_with_commands event/ngx_event_timer.c:.
set_rbreak_with_commands event/ngx_event_udp.c:.
set_rbreak_with_commands http/modules/ngx_http_access_module.c:.
set_rbreak_with_commands http/modules/ngx_http_addition_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_auth_basic_module.c:.
set_rbreak_with_commands http/modules/ngx_http_auth_request_module.c:.
set_rbreak_with_commands http/modules/ngx_http_autoindex_module.c:.
set_rbreak_with_commands http/modules/ngx_http_browser_module.c:.
set_rbreak_with_commands http/modules/ngx_http_charset_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_chunked_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_dav_module.c:.
set_rbreak_with_commands http/modules/ngx_http_degradation_module.c:.
set_rbreak_with_commands http/modules/ngx_http_empty_gif_module.c:.
set_rbreak_with_commands http/modules/ngx_http_fastcgi_module.c:.
set_rbreak_with_commands http/modules/ngx_http_flv_module.c:.
set_rbreak_with_commands http/modules/ngx_http_geo_module.c:.
set_rbreak_with_commands http/modules/ngx_http_geoip_module.c:.
set_rbreak_with_commands http/modules/ngx_http_grpc_module.c:.
set_rbreak_with_commands http/modules/ngx_http_gunzip_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_gzip_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_gzip_static_module.c:.
set_rbreak_with_commands http/modules/ngx_http_headers_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_image_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_index_module.c:.
set_rbreak_with_commands http/modules/ngx_http_limit_conn_module.c:.
set_rbreak_with_commands http/modules/ngx_http_limit_req_module.c:.
set_rbreak_with_commands http/modules/ngx_http_log_module.c:.
set_rbreak_with_commands http/modules/ngx_http_map_module.c:.
set_rbreak_with_commands http/modules/ngx_http_memcached_module.c:.
set_rbreak_with_commands http/modules/ngx_http_mirror_module.c:.
set_rbreak_with_commands http/modules/ngx_http_mp4_module.c:.
set_rbreak_with_commands http/modules/ngx_http_not_modified_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_proxy_module.c:.
set_rbreak_with_commands http/modules/ngx_http_random_index_module.c:.
set_rbreak_with_commands http/modules/ngx_http_range_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_realip_module.c:.
set_rbreak_with_commands http/modules/ngx_http_referer_module.c:.
set_rbreak_with_commands http/modules/ngx_http_rewrite_module.c:.
set_rbreak_with_commands http/modules/ngx_http_scgi_module.c:.
set_rbreak_with_commands http/modules/ngx_http_secure_link_module.c:.
set_rbreak_with_commands http/modules/ngx_http_slice_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_split_clients_module.c:.
set_rbreak_with_commands http/modules/ngx_http_ssi_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_ssl_module.c:.
set_rbreak_with_commands http/modules/ngx_http_static_module.c:.
set_rbreak_with_commands http/modules/ngx_http_stub_status_module.c:.
set_rbreak_with_commands http/modules/ngx_http_sub_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_try_files_module.c:.
set_rbreak_with_commands http/modules/ngx_http_upstream_hash_module.c:.
set_rbreak_with_commands http/modules/ngx_http_upstream_ip_hash_module.c:.
set_rbreak_with_commands http/modules/ngx_http_upstream_keepalive_module.c:.
set_rbreak_with_commands http/modules/ngx_http_upstream_least_conn_module.c:.
set_rbreak_with_commands http/modules/ngx_http_upstream_random_module.c:.
set_rbreak_with_commands http/modules/ngx_http_upstream_zone_module.c:.
set_rbreak_with_commands http/modules/ngx_http_userid_filter_module.c:.
set_rbreak_with_commands http/modules/ngx_http_uwsgi_module.c:.
set_rbreak_with_commands http/modules/ngx_http_xslt_filter_module.c:.
set_rbreak_with_commands http/modules/perl/ngx_http_perl_module.c:.
set_rbreak_with_commands http/ngx_http.c:.
set_rbreak_with_commands http/ngx_http_copy_filter_module.c:.
set_rbreak_with_commands http/ngx_http_core_module.c:.
set_rbreak_with_commands http/ngx_http_file_cache.c:.
set_rbreak_with_commands http/ngx_http_header_filter_module.c:.
set_rbreak_with_commands http/ngx_http_huff_decode.c:.
set_rbreak_with_commands http/ngx_http_huff_encode.c:.
set_rbreak_with_commands http/ngx_http_parse.c:.
set_rbreak_with_commands http/ngx_http_postpone_filter_module.c:.
set_rbreak_with_commands http/ngx_http_request.c:.
set_rbreak_with_commands http/ngx_http_request_body.c:.
set_rbreak_with_commands http/ngx_http_script.c:.
set_rbreak_with_commands http/ngx_http_special_response.c:.
set_rbreak_with_commands http/ngx_http_upstream.c:.
set_rbreak_with_commands http/ngx_http_upstream_round_robin.c:.
set_rbreak_with_commands http/ngx_http_variables.c:.
set_rbreak_with_commands http/ngx_http_write_filter_module.c:.
set_rbreak_with_commands http/v2/ngx_http_v2.c:.
set_rbreak_with_commands http/v2/ngx_http_v2_encode.c:.
set_rbreak_with_commands http/v2/ngx_http_v2_filter_module.c:.
set_rbreak_with_commands http/v2/ngx_http_v2_module.c:.
set_rbreak_with_commands http/v2/ngx_http_v2_table.c:.
set_rbreak_with_commands mail/ngx_mail.c:.
set_rbreak_with_commands mail/ngx_mail_auth_http_module.c:.
set_rbreak_with_commands mail/ngx_mail_core_module.c:.
set_rbreak_with_commands mail/ngx_mail_handler.c:.
set_rbreak_with_commands mail/ngx_mail_imap_handler.c:.
set_rbreak_with_commands mail/ngx_mail_imap_module.c:.
set_rbreak_with_commands mail/ngx_mail_parse.c:.
set_rbreak_with_commands mail/ngx_mail_pop3_handler.c:.
set_rbreak_with_commands mail/ngx_mail_pop3_module.c:.
set_rbreak_with_commands mail/ngx_mail_proxy_module.c:.
set_rbreak_with_commands mail/ngx_mail_realip_module.c:.
set_rbreak_with_commands mail/ngx_mail_smtp_handler.c:.
set_rbreak_with_commands mail/ngx_mail_smtp_module.c:.
set_rbreak_with_commands mail/ngx_mail_ssl_module.c:.
set_rbreak_with_commands misc/ngx_google_perftools_module.c:.
set_rbreak_with_commands os/unix/ngx_alloc.c:.
set_rbreak_with_commands os/unix/ngx_channel.c:.
set_rbreak_with_commands os/unix/ngx_daemon.c:.
set_rbreak_with_commands os/unix/ngx_darwin_init.c:.
set_rbreak_with_commands os/unix/ngx_darwin_sendfile_chain.c:.
set_rbreak_with_commands os/unix/ngx_dlopen.c:.
set_rbreak_with_commands os/unix/ngx_errno.c:.
set_rbreak_with_commands os/unix/ngx_file_aio_read.c:.
set_rbreak_with_commands os/unix/ngx_files.c:.
set_rbreak_with_commands os/unix/ngx_freebsd_init.c:.
set_rbreak_with_commands os/unix/ngx_freebsd_sendfile_chain.c:.
set_rbreak_with_commands os/unix/ngx_linux_aio_read.c:.
set_rbreak_with_commands os/unix/ngx_linux_init.c:.
set_rbreak_with_commands os/unix/ngx_linux_sendfile_chain.c:.
set_rbreak_with_commands os/unix/ngx_posix_init.c:.
set_rbreak_with_commands os/unix/ngx_process.c:.
set_rbreak_with_commands os/unix/ngx_process_cycle.c:.
set_rbreak_with_commands os/unix/ngx_readv_chain.c:.
set_rbreak_with_commands os/unix/ngx_recv.c:.
set_rbreak_with_commands os/unix/ngx_send.c:.
set_rbreak_with_commands os/unix/ngx_setaffinity.c:.
set_rbreak_with_commands os/unix/ngx_setproctitle.c:.
set_rbreak_with_commands os/unix/ngx_shmem.c:.
set_rbreak_with_commands os/unix/ngx_socket.c:.
set_rbreak_with_commands os/unix/ngx_solaris_init.c:.
set_rbreak_with_commands os/unix/ngx_solaris_sendfilev_chain.c:.
set_rbreak_with_commands os/unix/ngx_thread_cond.c:.
set_rbreak_with_commands os/unix/ngx_thread_id.c:.
set_rbreak_with_commands os/unix/ngx_thread_mutex.c:.
set_rbreak_with_commands os/unix/ngx_time.c:.
set_rbreak_with_commands os/unix/ngx_udp_recv.c:.
set_rbreak_with_commands os/unix/ngx_udp_send.c:.
set_rbreak_with_commands os/unix/ngx_udp_sendmsg_chain.c:.
set_rbreak_with_commands os/unix/ngx_user.c:.
set_rbreak_with_commands os/unix/ngx_writev_chain.c:.
set_rbreak_with_commands os/win32/ngx_alloc.c:.
set_rbreak_with_commands os/win32/ngx_dlopen.c:.
set_rbreak_with_commands os/win32/ngx_errno.c:.
set_rbreak_with_commands os/win32/ngx_event_log.c:.
set_rbreak_with_commands os/win32/ngx_files.c:.
set_rbreak_with_commands os/win32/ngx_process.c:.
set_rbreak_with_commands os/win32/ngx_process_cycle.c:.
set_rbreak_with_commands os/win32/ngx_service.c:.
set_rbreak_with_commands os/win32/ngx_shmem.c:.
set_rbreak_with_commands os/win32/ngx_socket.c:.
set_rbreak_with_commands os/win32/ngx_stat.c:.
set_rbreak_with_commands os/win32/ngx_thread.c:.
set_rbreak_with_commands os/win32/ngx_time.c:.
set_rbreak_with_commands os/win32/ngx_udp_wsarecv.c:.
set_rbreak_with_commands os/win32/ngx_user.c:.
set_rbreak_with_commands os/win32/ngx_win32_init.c:.
set_rbreak_with_commands os/win32/ngx_wsarecv.c:.
set_rbreak_with_commands os/win32/ngx_wsarecv_chain.c:.
set_rbreak_with_commands os/win32/ngx_wsasend.c:.
set_rbreak_with_commands os/win32/ngx_wsasend_chain.c:.
set_rbreak_with_commands stream/ngx_stream.c:.
set_rbreak_with_commands stream/ngx_stream_access_module.c:.
set_rbreak_with_commands stream/ngx_stream_core_module.c:.
set_rbreak_with_commands stream/ngx_stream_geo_module.c:.
set_rbreak_with_commands stream/ngx_stream_geoip_module.c:.
set_rbreak_with_commands stream/ngx_stream_handler.c:.
set_rbreak_with_commands stream/ngx_stream_limit_conn_module.c:.
set_rbreak_with_commands stream/ngx_stream_log_module.c:.
set_rbreak_with_commands stream/ngx_stream_map_module.c:.
set_rbreak_with_commands stream/ngx_stream_proxy_module.c:.
set_rbreak_with_commands stream/ngx_stream_realip_module.c:.
set_rbreak_with_commands stream/ngx_stream_return_module.c:.
set_rbreak_with_commands stream/ngx_stream_script.c:.
set_rbreak_with_commands stream/ngx_stream_set_module.c:.
set_rbreak_with_commands stream/ngx_stream_split_clients_module.c:.
set_rbreak_with_commands stream/ngx_stream_ssl_module.c:.
set_rbreak_with_commands stream/ngx_stream_ssl_preread_module.c:.
set_rbreak_with_commands stream/ngx_stream_upstream.c:.
set_rbreak_with_commands stream/ngx_stream_upstream_hash_module.c:.
set_rbreak_with_commands stream/ngx_stream_upstream_least_conn_module.c:.
set_rbreak_with_commands stream/ngx_stream_upstream_random_module.c:.
set_rbreak_with_commands stream/ngx_stream_upstream_round_robin.c:.
set_rbreak_with_commands stream/ngx_stream_upstream_zone_module.c:.
set_rbreak_with_commands stream/ngx_stream_variables.c:.
set_rbreak_with_commands stream/ngx_stream_write_filter_module.c:.


# Run the program
run
