alter table "scan_bucket"
	drop constraint bktFK_scan_id;

alter table "banner"
        drop constraint bnrFK_scan_bucket_id;

alter table "os_fingerprint"
        drop constraint osfnrFK_scan_bucket_id;

drop sequence scan_bucket_id_seq;
drop sequence scan_id_seq;
drop sequence scan_queue_id_seq;

drop table "os_fingerprint";
drop table "banner";
drop table "scan_bucket";
drop table "scan";

create sequence scan_id_seq;
create table "scan"
(
	"scan_id"	int8 not null default nextval('scan_id_seq'),
	"s_time"	int8 not null,
	"e_time"	int8 not null,
	"targetstr"	varchar(200) not null,
	"portstr"	varchar(200) not null,
	"send_ip"	int8 not null,
	"scanmode"	int2 not null,
	"pps"		int8 not null,
	"srcport"	int4 not null,
	"fingerprint"	int4 not null,
	"tcpflags"	int4 not null,
	"active_plgroups"int2 not null,
	"dronestr"	varchar(200) not null,
	"minttl"	int2 not null,
	"maxttl"	int2 not null,
	"iptos"		int2 not null,
	"ipoffset"	int4 not null,
	"repeats"	int8 default null,
	"pcapfilter"	varchar(200) not null,
	"listener_flags"int4 not null,
	"sender_flags"	int4 not null,
	"master_flags"	int4 not null,
	primary key("scan_id")
);

create sequence scan_bucket_id_seq;
create table "scan_bucket"
(
	"scan_bucket_id"int8 not null default nextval('scan_bucket_id_seq'),
        "scan_id"	int8 not null,
	"protocol"	int2 not null,
        "host_addr"	int8 not null, 		-- ipv4 only obviously
        "trace_addr"    int8 not null,
        "dport"         int4 not null,
        "sport"         int4 not null,
        "type"		int4 not null,
        "subtype"       int4 not null,
        "ttl"           int2 not null,
        "u_tstamp"	int8 not null,
        "u_utstamp"	int8 not null,
	"seq"		int8 not null,
	"window"	int8 not null,
	primary key ("scan_bucket_id")
);

create table "os_fingerprint"
(
	"scan_bucket_id"int8 not null,
	"os"	varchar(200) not null
);

create table "banner"
(
	"scan_bucket_id"int8 not null,
	"banner"	varchar(200) not null
);

alter table "banner"
	add constraint bnrFK_scan_bucket_id foreign key("scan_bucket_id")
	references "scan_bucket"("scan_bucket_id");

alter table "os_fingerprint"
	add constraint osfnrFK_scan_bucket_id foreign key("scan_bucket_id")
	references "scan_bucket"("scan_bucket_id");
