--                              scan_id  protocol ha_min   ha_max   
-- tr_min   tr_max   dp_min   dp_max   sp_min   sp_max   ty_min   ty_max
-- st_min   st_max   ttl_min  ttl_max  tsmp_min tsmp_max os banner 


drop function search_scanbucket(integer, integer, integer, integer,
   integer, integer, integer, integer, integer, integer, integer, integer, 
   integer, integer, integer, integer, integer, integer, char, char);

-- scan_id $1 protocol $2
-- host_addr_min $3 host_addr_max $4
-- trace_addr_min $5 trace_addr_max $6
-- dport_min $7 dport_max $8
-- sport_min $9 sport_max $10
-- type_min $11 type_max $12
-- subtype_min $13 subtype_max $14
-- ttl_min $15 ttl_max $16
-- tstamp_min $17 tstamp_max $18
-- os $19
-- banner $20
create function search_scanbucket(integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, char, char) returns char as
'declare
	from_tbls varchar(128);
	sel_cols varchar(64);
	join_stmt varchar(256);
	my_query varchar(1024);
begin
	sel_cols := \'s.*\';
	from_tbls := \'scan_bucket s\';
	if $1 > 0 then
		join_stmt := \' s.scan_id=\' || $1 || \' \';
	else
		join_stmt := \' s.scan_id > 0 \';
	end if;

	if $19 != \'\' then
		from_tbls := from_tbls || \', os_fingerprint o\';
		sel_cols := sel_cols || \', o.os\';
		join_stmt := join_stmt || \' and o.scan_bucket_id=s.scan_bucket_id and upper(o.os) ~ upper(\'\'\' || $18 || \'\'\')\';
	end if;

	if $20 != '''' then
		from_tbls := from_tbls || '', banner b'';
		sel_cols := sel_cols || '', b.banner'';
		join_stmt := join_stmt || \' and b.scan_bucket_id=s.scan_bucket_id and upper(b.banner) ~ upper(\'\'\' || $19 || \'\'\')\';
	end if;

	my_query := ''select '' || sel_cols || '' from '' || from_tbls || '' where '' || join_stmt;

	return my_query;
end;
' language plpgsql;


