drop table "uni_session";

create table "uni_session" (
	"sessid"	varchar(64) not null,
	"c_time"	int8	not null,
	"m_time"	int8	not null default -1,
	"a_time"	int8	not null,
	"uid"		int4 not null,
	"gid"		int4 not null,
	"remote_addr"	inet not null,
	"remote_host"	varchar(200) null,
	"user_agent"	varchar(200) null,
	"data"		text null,
	primary key("sessid")
);
