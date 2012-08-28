##scaninfo:pgsql:
insert into
scan  (s_time, e_time, targetstr, portstr, scanmode, pps, active_plgroups, pcapfilter, dronestr, fingerprint, iptos, ipttl, ipoffset, tcpflags, srcport, repeats, listener_flags, sender_flags, master_flags)
values(%lld, %lld, %llu, '%s', '%s', %u, %u, %u, '%s', '%s', %u, %u, %u, %u, %u, %d, %u, %u, %u, %u);
select currval('scan_id_seq');
##scaninfo:mysql:
insert into
scan  (s_time, e_time, targetstr, portstr, scanmode, pps, active_plgroups, pcapfilter, dronestr, fingerprint, iptos, ipttl, ipoffset, tcpflags, srcport, repeats, listener_flags, sender_flags, master_flags)
values(%lld, %lld, %llu, '%s', '%s', %u, %u, %u, '%s', '%s', %u, %u, %u, %u, %u, %d, %u, %u, %u, %u)
##scantrans:pgsql:
begin;
##scantrans:mysql:
##scandata:pgsql:
insert into scan_bucket(scan_id, protocol, type, subtype, dport, sport, ttl, host_addr, trace_addr, u_tstamp, u_utstamp)
values(%lld, %u, %u, %u, %u, %u, %u, %u, %u, %lld, %llu);
select currval('scan_bucket_id_seq') as myid;
##scandata:mysql:
insert into scan_bucket(scan_id, protocol, type, subtype, dport, sport, ttl, host_addr, trace_addr, u_tstamp, u_utstamp)
values(%lld, %u, %u, %u, %u, %u, %u, %u, %u, %lld, %llu)
##scandata_b:pgsql:
insert into banner(scan_bucket_id, banner) values(%llu, '%s');
##scandata_b:mysql:
insert into banner(scan_bucket_id, banner) values(%llu, '%s')
##scandata_o:pgsql:
insert into os_fingerprint(scan_bucket_id, os) values(%llu, '%s');
##scandata_o:mysql:
insert into os_fingerprint(scan_bucket_id, os) values(%llu, '%s')
##scanfini:pgsql:
update scan set e_time=%lld where scan_id=%lld;
##scanfini:mysql:
update scan set e_time=%lld where scan_id=%lld
##scantransfini:pgsql:
commit;
##scantransfini:mysql:
