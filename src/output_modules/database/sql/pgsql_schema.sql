drop table "uni_sworkunits";
drop table "uni_lworkunits";
drop table "uni_workunitstats";
drop table "uni_output";
drop table "uni_ipreportdata";
drop table "uni_ippackets";
drop table "uni_arppackets";
drop table "uni_ipreport";
drop sequence "uni_ipreport_id_seq";
drop table "uni_arpreport";
drop sequence "uni_arpreport_id_seq";
drop table "uni_scans";
drop sequence "uni_scans_id_seq";

create sequence "uni_scans_id_seq";
-- MASTER INFORMATION
create table "uni_scans" (
	"scans_id"	int8 not null default nextval('uni_scans_id_seq'),
	"s_time"	int8 not null,
	"e_time"	int8 not null,
	"est_e_time"	int8 not null,
	"senders"	int2 not null,
	"listeners"	int2 not null,
	"scan_iter"	int2 not null,
	"profile"	varchar(200) not null,
	"options"	int4 not null,
	"payload_group"	int2 not null,
	"dronestr"	varchar(200) not null,
	"covertness"	int2 not null,
	"modules"	varchar(200) not null,
	"user"		varchar(200) not null,
	"pcap_dumpfile"	varchar(200),
	"pcap_readfile"	varchar(200),
	"tickrate"	int4 not null,
	"num_hosts"	double precision not null,
	"num_packets"	double precision not null,
	primary key("scans_id")
);

--- WORKUNITS
create table "uni_sworkunits" (
	"magic"		int8 not null,
	"scans_id"	int8 not null,
	"repeats"	int2 not null,
	"send_opts"	int4 not null,
	"pps"		int8 not null,
	"delay_type"	int2 not null,
	"myaddr"	inet not null,
	"mymask"	inet not null,
	"macaddr"	macaddr not null,
	"mtu"		int4 not null,
	"target"	inet not null,
	"targetmask"	inet not null,
	"tos"		int2 not null,
	"minttl"	int2 not null,
	"maxttl"	int2 not null,
	"fingerprint"	int2 not null,
	"src_port"	int4 not null,
	"ip_off"	int4 not null,
	"ipoptions"	bytea null,
	"tcpflags"	int4 not null,
	"tcpoptions"	bytea null,
	"window_size"	int4 not null,
	"syn_key"	int8 not null,
	"port_str"	text,
	-- tracking information
	"wid"		int8 not null,
	"status"	int2 not null
);

alter table "uni_sworkunits"
	add constraint uni_sworkunit_uniq_comp_LK
	unique ("scans_id", "wid");

alter table "uni_sworkunits"
	add constraint uni_sworkunit_uni_scans_FK
	foreign key("scans_id")
	references "uni_scans"("scans_id");

create table "uni_lworkunits" (
	"magic"		int8 not null,
	"scans_id"	int8 not null,
	"recv_timeout"	int2 not null,
	"ret_layers"	int2 not null,
	"recv_opts"	int4 not null,
	"window_size"	int8 not null,
	"syn_key"	int8 not null,
	"pcap_str"	text,
	-- tracking information
	"wid"		int8 not null,
	"status"	int2 not null
);

alter table "uni_lworkunits"
	add constraint uni_lworkunit_uniq_comp_LK
	unique ("scans_id", "wid");

alter table "uni_lworkunits"
	add constraint uni_lworkunit_uni_scans_FK
	foreign key("scans_id")
	references "uni_scans"("scans_id");

-- MISC INFO
create table "uni_workunitstats" (
	"wid"		int8 not null,
	"scans_id"	int8 not null,
	"msg"		text not null
);

alter table "uni_workunitstats"
	add constraint uni_workunitstats_uni_scans_FK
	foreign key("scans_id")
	references "uni_scans"("scans_id");

create table "uni_output" (
	"scans_id"	int8 not null,
	"msg"		text not null
);

alter table "uni_output"
	add constraint uni_output_uni_scans_FK
	foreign key("scans_id")
	references "uni_scans"("scans_id");

create sequence "uni_ipreport_id_seq";

create table "uni_ipreport" (
	"ipreport_id"	int8 not null default nextval('uni_ipreport_id_seq'),
	"scans_id"	int8 not null,
	"magic"		int8 not null,
	"sport"		int4 not null,
	"dport"		int4 not null,
	"proto"		int2 not null,
	"type"		int4 not null,
	"subtype"	int4 not null,
	"send_addr"	inet not null,
	"host_addr"	inet not null,
	"trace_addr"	inet not null,
	"ttl"		int2 not null,
	"tstamp"	int8 not null,
	"utstamp"	int8 not null,
	"flags"		int4 not null,
	"mseq"		int8 not null,
	"tseq"		int8 not null,
	"window_size"	int4 not null,
	"t_tstamp"	int8 not null,
	"m_tstamp"	int8 not null,
	primary key ("ipreport_id")
);

alter table "uni_ipreport"
	add constraint uni_ipreport_uni_scans_FK
	foreign key ("scans_id")
	references "uni_scans"("scans_id");

create index uni_ipreport_scansid_idx on uni_ipreport("scans_id");

create sequence "uni_arpreport_id_seq";

create table "uni_arpreport" (
	"arpreport_id"	int8 not null default nextval('uni_arpreport_id_seq'),
	"scans_id"	int8 not null,
	"magic"		int8 not null,
	"host_addr"	inet not null,
	"hwaddr"	macaddr not null,
	"tstamp"	int8 not null,
	"utstamp"	int8 not null,
	primary key ("arpreport_id")
);

alter table "uni_arpreport"
	add constraint uni_arpreport_uni_scans_FK
	foreign key ("scans_id")
	references "uni_scans"("scans_id");

create index uni_arpreport_scansid_idx on uni_arpreport("scans_id");

create table "uni_ipreportdata" (
	"ipreport_id"	int8 not null,
	"type"		int2 not null,
	"data"		text
);

alter table "uni_ipreportdata"
	add constraint uni_reportdata_uni_ipreport_FK
	foreign key("ipreport_id")
	references "uni_ipreport"("ipreport_id");

create table "uni_ippackets" (
	"ipreport_id"	int8 not null,
	"packet"	bytea not null
);

alter table "uni_ippackets"
	add constraint uni_ippackets_uni_ipreport_FK
	foreign key("ipreport_id")
	references "uni_ipreport"("ipreport_id");

create table "uni_arppackets" (
	"arpreport_id"	int8 not null,
	"packet"	bytea not null
);

alter table "uni_arppackets"
	add constraint uni_arppackets_uni_arpreport_FK
	foreign key("arpreport_id")
	references "uni_arpreport"("arpreport_id");
