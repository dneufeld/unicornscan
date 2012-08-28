<?php

	function get_short_scan($scanarr, $doform) {
		global $PHPLIB, $db;
		static $rowtgl=0;

		$ret="";

		$stime=strftime($PHPLIB["time_format"], (int )$scanarr["s_time"]);
		if ($scanarr["e_time"] == 0) {
			$etime="Incomplete";
		}
		else {
			$etime=strftime($PHPLIB["time_format"], (int )$scanarr["e_time"]);
		}
		$est_e_time=strftime($PHPLIB["time_format"], (int )$scanarr["est_e_time"]);
		$num_hosts=(int )$scanarr["num_hosts"];
		$num_packets=(int )$scanarr["num_packets"];
		$scans_id=(int )$scanarr["scans_id"];

		$type="";
		$pps="";
		$tgtstr="";

		for ($j1=0; $j1 < count($scanarr["sworkunits"]); $j1++) {
			$cur=$scanarr["sworkunits"][$j1];

			if (strlen($type) < 1) {
				$type .= sworkunit_magictostr($cur["magic"]);
			}
			else {
				$type .= ", ".sworkunit_magictostr($cur["magic"]);
			}

			if (strlen($pps) < 1) {
				$pps .= (int )$cur["pps"];
			}
			else {
				$pps .= ", ".(int )$cur["pps"];
			}

			/* XXX CHEESY */
			$target=htmlspecialchars($cur["target"]);
			$query="select masklen('".$cur["targetmask"]."') as tgtmsk";
			$db->aquerydb($query);
			if ($db->numrows == 1) {
				$db->data_step();
				$tmask=$db->resultarr[0];
			}
			else {
				$tmask="32";
			}

			if ($tmask == "32") {
				$append="";
			}
			else {
				$append="/".$tmask;
			}

			if (strlen($tgtstr) < 1) {
				$tgtstr=$target.$append;
			}
			else {
				$tgtstr .= ", ".$target.$append;
			}
		}

		if ($rowtgl == 0) {
			$class="tblrow1";
			$rowtgl=1;
		}
		else {
			$class="tblrow2";
			$rowtgl=0;
		}

		$ret=<<<EOF
 <tr class="$class">
  <td>
EOF;
		if ($doform) {
			$ret .=<<<EOF
   $scans_id
   <input type="checkbox" name="scan_$scans_id">
EOF;
		}
		else {
			$ret .=<<<EOF
   $scans_id
EOF;
		}
		$ret .=<<<EOF
  </td>
  <td>
   $stime
  </td>
  <td>
   $est_e_time
  </td>
  <td>
   $etime
  </td>
  <td>
   $num_hosts
  </td>
  <td>
   $num_packets
  </td>
  <td>
   $type $pps
  </td>
  <td>
   $tgtstr
  </td>
 </tr>

EOF;

		return $ret;
	}

	function display_scan($scanarr) {
		global $PHPLIB, $db;

		$stime=strftime($PHPLIB["time_format"], $scanarr["s_time"]);
		$etime=strftime($PHPLIB["time_format"], $scanarr["e_time"]);
		$senders=(int )$scanarr["senders"];
		$listeners=(int )$scanarr["listeners"];
		$iterations=(int )$scanarr["scan_iter"];
		$profile=htmlspecialchars($scanarr["profile"]);
		$options=options_tostr($scanarr["options"]);
		$sopts=sendopts_tostr($scanarr["send_opts"]);
		$lopts=recvopts_tostr($scanarr["recv_opts"]);
		$payload_group=(int )$scanarr["payload_group"];
		$dronestr=htmlspecialchars($scanarr["dronestr"]);
		if (!(strlen($dronestr))) {
			$dronestr="none";
		}
		$covt=(int )$scanarr["covertness"];
		$modules=$scanarr["modules"];
		$num_hosts=$scanarr["num_hosts"];
		$num_packets=$scanarr["num_packets"];

		print <<<EOF

<table border="1" width="100%" class="tableclass">
 <tr class="tblrow1">
  <td>
   Start: $stime End: $etime
  </td>
  <td>
   $senders Senders $listeners Listeners Scan Iterations $iterations
  </td>
  <td>
   Profile $profile covertness $covt modules $modules
  </td>
 </tr>
 <tr class="tblrow2">
  <td>
   Master $options Sender $sopts Listener $lopts
  </td>
  <td>
   Payload Group $payload_group Drones $dronestr
  </td>
  <td>
   Hosts $num_hosts Packets $num_packets
  </td>
 </tr>
EOF;

		for ($j1=0; $j1 < count($scanarr["sworkunits"]); $j1++) {
			$cur=$scanarr["sworkunits"][$j1];

			$type=sworkunit_magictostr($cur["magic"]);
			$repeats=(int )$cur["repeats"];
			$pps=(int )$cur["pps"];
			$delay_type=delay_tostr($cur["delay_type"]);
			$myaddr=htmlspecialchars($cur["myaddr"]);

			$query="select masklen('".$cur["mymask"]."') as mymask";
			$db->aquerydb($query);
			$db->data_step();
			if ($db->resultarr[0] != "32") {
				$myaddr .= "/".$db->resultarr[0];
			}

			$mtu=(int )$cur["mtu"];
			$target=htmlspecialchars($cur["target"]);
			$query="select masklen('".$cur["targetmask"]."') as tgtmask";
			$db->aquerydb($query);
			$db->data_step();
			if ($db->resultarr[0] != "32") {
				$target .= "/".$db->resultarr[0];
			}

			$tcpflags=tcpflags_tostr($cur["tcpflags"]);
			$tos=(int )$cur["tos"];
			$ttllow=(int )$cur["minttl"];
			$ttlhigh=(int )$cur["maxttl"];

			print <<<EOF
 <tr class="tblrow1">
  <td> 
   Type $type Repeats $repeats PPS $pps delay $delay_type
  </td>
  <td>
   Myaddr $myaddr Target $target mtu $mtu
  </td>
  <td>
   TcpFlags $tcpflags tos $tos TTL $ttllow-$ttlhigh
  </td>
 </tr>
EOF;
		} /* send workunits */

		for ($j1=0; $j1 < count($scanarr["lworkunits"]); $j1++) {
			$cur=$scanarr["lworkunits"][$j1];

			$recv_timeout=(int )$cur["recv_timeout"];
			$ret_layers=(int )$cur["ret_layers"];
			$pcap_str=htmlspecialchars($cur["pcap_str"]);

			print <<<EOF
 <tr class="tblrow1">
  <td colspan="1"> 
   Recv Timeout $recv_timeout Return Layers $ret_layers
  </td>
  <td colspan="2">
   Pcap Filter $pcap_str
  </td>
 </tr>
EOF;
		} /* listen workunits */

		print <<<EOF

</table>
EOF;

	}

	function display_scandata($scanid = -1) {
		global $db, $PHPLIB, $cookieupdate;
		$scansel="";

		$filt="";

		if (is_array($scanid)) {
			print "<strong>Displaying Scan(s) ";

			$filt .= "&amp;_scansel=".implode(",", $scanid);

			for ($j=0; $j < count($scanid); $j++) {
				print (int )$scanid[$j]." ";
				if (strlen($scansel) < 1) {
					$scansel=(int )$scanid[$j];
				}
				else {
					$scansel .= ",".(int )$scanid[$j];
				}

				if (strlen($where) > 0) {
					$where .= " or scans_id=".$scanid[$j];
				}
				else {
					$where  = " (scans_id=".$scanid[$j];
				}
			}
			if (strlen($where)) {
				$where .= ")";
			}
			print "</strong>\n";

		}
		else {
			$where=" true ";
			print "<strong> Displaying All Scans</strong>\n";
		}

		$f=new formclass();
		$f->new_title("Scan Data");
		$f->new_row();

		$sel="";
		$f->new_desc("scans");
		if (strlen($scansel) > 0) {
			$f->set_default("_scansel", $scansel);
		}
		$f->new_input("text", "_scansel", "int,0,100", array("input_size"=>"50"));
		$f->new_row();

		$rproto=get_var("_proto");
		$f->new_desc("protocol");
		if ($rproto == false) {
			$f->set_default("_proto", "");
		}
		$f->new_input("select", "_proto", "1:ICMP,6:TCP,17:UDP,");
		$f->new_desc("time");
		$f->new_input("text", "_tstamp", "string,0,100");
		$f->new_row();

		$f->new_desc("type");
		$f->new_input("text", "_type", "string,0,100", array("input_size"=>"50"));
		$f->new_row();

		$f->new_desc("local port");
		$f->new_input("text", "_dport", "string,0,100");
		$f->new_desc("remote port");
		$f->new_input("text", "_sport", "string,0,100");
		$f->new_row();

		$f->new_desc("send_addr");
		$f->new_input("text", "_send_addr", "string,0,100");
		$f->new_desc("host_addr");
		$f->new_input("text", "_host_addr", "string,0,100");
		$f->new_row();

		$f->new_desc("trace_addr");
		$f->new_input("text", "_trace_addr", "string,0,100");
		$f->new_desc("ttl");
		$f->new_input("text", "_ttl", "string,0,100");
		$f->new_row();

		$f->new_desc("flags");
		$f->new_input("text", "_flags", "string,0,100");
		$f->new_desc("window_size");
		$f->new_input("text", "_window_size", "string,0,100");
		$f->new_row();

		$rsb=get_var("_sortby");

		if ($rsb == false) {
			$f->set_default("_sortby", "9");
			$sb=9;
		}
		else {
			$f->set_default("_sortby", (int )$rsb);
			$sb=(int )$rsb;
		}

		$f->new_desc("sort by");
		$f->new_input("select", "_sortby", "0:scans_id,1:proto,2:sport:3:dport,4:type,6:host_addr,7:trace_addr,8:ttl,9:tstamp,10:tseq,11:window_size,12:t_tstamp");
		$f->new_row();

		$rorder=get_var("_order");
		if ($rorder == false) {
			$f->set_default("_order", "1");
			$rorder=1;
		}
		$f->new_desc("order");
		$f->new_input("select", "_order", "2:asc,1:desc");

		$rlimit=get_var("_limit");
		if ($rlimit == false) {
			$f->set_default("_limit", "30");
		}
		$f->new_desc("limit");
		$f->new_input("text", "_limit", "int,0,10");
		$f->new_row();

		$f->new_desc("banner");
		$f->new_input("text", "_banner", "string,0,1000");
		$f->new_row();

		$f->new_desc("os");
		$f->new_input("text", "_os", "string,0,1000");
		$f->new_row();

		$f->add_hidden("action", "viewdata");

		$query="select * from uni_ipreport ";

		if ($rproto != false) {

			$filt .= "&amp;_proto=".(int )$rproto;
			$where .= " and proto=".(int )$rproto;
		}

		$rtype=get_var("_type");

		if ($rtype != false) {

			$filt .= "&amp;_type=".urlencode($rtype);
			$where .= getsql_resptype($rtype);
		}

		if ($rlimit != false) {

			$filt .= "&amp;_limit=".(int )$rlimit;
			$limit=(int )$rlimit;
		}
		else {
			$limit=30;
		}

		$roffset=get_var("_offset");

		if ($roffset != false) {
			$offset=(int )$roffset;
		}
		else {
			$offset=0;
		}

		$rbanner=get_var("_banner");
		if ($rbanner != false) {

			$filt .= "&amp;_banner=".urlencode($rbanner);
			$where .= " and ipreport_id in (select ipreport_id from uni_ipreportdata where type=1 and data ~ '".$db->_escape_string($rbanner)."')";
		}

		$ros=get_var("_os");
		if ($ros != false) {

			$filt .= "&amp;_os=".urlencode($ros);
			$where .= " and ipreport_id in (select ipreport_id from uni_ipreportdata where type=2 and data ~ '".$db->_escape_string($ros)."')";
		}

		$rtstamp=get_var("_tstamp");
		if ($rtstamp != false) {

			$filt .= "&amp;_tstamp=".urlencode($rtstamp);
			$where .= getsql_time($rtstamp, "tstamp");
		}

		$rhost_addr=get_var("_host_addr");
		if ($rhost_addr != false) {

			$filt .= "&amp;_host_addr=".urlencode($rhost_addr);
			$where .= getsql_inet($rhost_addr, "host_addr");

		}

		$rtrace_addr=get_var("_trace_addr");
		if ($rtrace_addr != false) {

			$filt .= "&amp;_trace_addr=".urlencode($rtrace_addr);
			$where .= getsql_inet($rtrace_addr, "trace_addr");
		}

		$rsend_addr=get_var("_send_addr");
		if ($rsend_addr != false) {

			$filt .= "&amp;_send_addr=".urlencode($rsend_addr);
			$where .= getsql_inet($rsend_addr, "send_addr");
		}

		$rttl=get_var("_ttl");
		if ($rttl != false) {

			$filt .= "&amp;_ttl=".urlencode($rttl);
			$where .= getsql_numeric($rttl, "ttl");
		}

		$rwindow_size=get_var("_window_size");
		if ($rwindow_size != false) {

			$filt .= "&amp;_window_size=".urlencode($rwindow_size);
			$where .= getsql_numeric($rwindow_size, "window_size");
		}

		$rsport=get_var("_sport");
		if ($rsport != false) {

			$filt .= "&amp;_sport=".urlencode($rsport);
			$where .= getsql_numeric($rsport, "sport");
		}

		$rdport=get_var("_dport");
		if ($rdport != false) {

			$filt .= "&amp;_dport=".urlencode($rdport);
			$where .= getsql_numeric($rdport, "dport");
		}

		switch ($sb) {
			case 0:
				$order_by="scans_id";
				break;
			case 1:
				$order_by="proto";
				break;
			case 2:
				$order_by="sport";
				break;
			case 3:
				$order_by="dport";
				break;
			case 4:
				$order_by="type";
				break;
			case 6:
				$order_by="host_addr";
				break;
			case 7:
				$order_by="trace_addr";
				break;
			case 8:
				$order_by="ttl";
				break;
			case 9:
				$order_by="tstamp, utstamp";
				break;
			case 10:
				$order_by="tseq";
				break;
			case 11:
				$order_by="window_size";
				break;
			case 12:
				$order_by="t_tstamp";
				break;
			default:
				$order_by="tstamp";
				break;
		}

		if ($rorder == 2) {
			$query .= " where ".$where." order by ".$order_by." asc limit ".$limit." offset ".$offset;
			$oorder="&amp;_order=1";
		}
		else {
			$query .= " where ".$where." order by ".$order_by." desc limit ".$limit." offset ".$offset;
			$oorder="&amp;_order=2";
		}

		$f->add_hidden("searchdb", "1");
		$f->print_form();

		$rsearchdb=get_var("searchdb");
		if ($rsearchdb != false) {
			print "<br/>Search Query `".htmlspecialchars($query)."'<br/>\n";
			$filt .= "&amp;searchdb=1";
			$db->aquerydb($query);
			$nr=$db->numrows;
		}
		else {
			$nr=0;
		}


		$t=new tableclass();
		$t->set_width("96%");

		$link="<a href=\"index.php?action=viewdata".$filt;
		$elink="</a>";

		if ($sb == 0) {
			$_1=$link."&amp;_sortby=0".$oorder."\"> scanid".$elink;
		}
		else {
			$_1=$link."&amp;_sortby=0\"> scanid".$elink;
		}

		if ($sb == 2) {
			$_2=$link."&amp;_sortby=2".$oorder."\"> port". $elink;
		}
		else {
			$_2=$link."&amp;_sortby=2\"> port". $elink;
		}

		if ($sb == 4) {
			$_3=$link."&amp;_sortby=4".$oorder."\"> type". $elink;
		}
		else {
			$_3=$link."&amp;_sortby=4\"> type". $elink;
		}

		if ($sb == 6) {
			$_4=$link."&amp;_sortby=6".$oorder."\"> host". $elink;
		}
		else {
			$_4=$link."&amp;_sortby=6\"> host". $elink;
		}

		if ($sb == 7) {
			$_5=$link."&amp;_sortby=7".$oorder."\"> trace". $elink;
		}
		else {
			$_5=$link."&amp;_sortby=7\"> trace". $elink;
		}

		if ($sb == 8) {
			$_6=$link."&amp;_sortby=8".$oorder."\"> ttl". $elink;
		}
		else {
			$_6=$link."&amp;_sortby=8\"> ttl". $elink;
		}

		if ($sb == 9) {
			$_7=$link."&amp;_sortby=9".$oorder."\"> tstamp". $elink;
		}
		else {
			$_7=$link."&amp;_sortby=9\"> tstamp". $elink;
		}

		if ($sb == 10) {
			$_8=$link."&amp;_sortby=10".$oorder."\"> seq". $elink;
		}
		else {
			$_8=$link."&amp;_sortby=10\"> seq". $elink;
		}

		if ($sb == 11) {
			$_9=$link."&amp;_sortby=11".$oorder."\"> win". $elink;
		}
		else {
			$_9=$link."&amp;_sortby=11\"> win". $elink;
		}

		$t->add_header("View",
			$_1,
			$_2,
			$_3,
			$_4,
			$_5,
			$_6,
			$_7,
			$_8,
			$_9,
			"banner",
			"os"
		);

		for ($j=0; $j < $nr; $j++) {
			$db->data_step();
			$ret[$j]=$db->resultarr;
		}

		for ($j=0; $j < $nr; $j++) {

			$ipreportid=$ret[$j]["ipreport_id"];

			$query="select data, type from uni_ipreportdata where ipreport_id=".$ipreportid;

			$banner="";
			$os="";

			$db->aquerydb($query);
			for ($j1=0; $j1 < $db->numrows; $j1++) {
				$db->data_step();
				if ($db->resultarr[1] == "1") {
					$banner=htmlspecialchars($db->resultarr[0]);
				}
				else if ($db->resultarr[1] == "2") {
					$os=htmlspecialchars($db->resultarr[0]);
				}
			}

			$query="select ipreport_id from uni_ippackets where ipreport_id=".$ret[$j]["ipreport_id"];
			$db->aquerydb($query);

			if ($db->numrows == 1) {
				$link="<a href=\"index.php?action=displayrecord&amp;ipreport_id=".
				(int )$ret[$j]["ipreport_id"]."\">Pkt</a>&nbsp;".
				"<a href=\"index.php?action=delrecord&amp;ipreport_id=".
				(int )$ret[$j]["ipreport_id"]."\">Del</a>";
			}
			else {
				$link="&nbsp;";
			}
			if (strcmp($ret[$j]["host_addr"], $ret[$j]["trace_addr"]) == 0) {
				$taddr="...";
			}
			else {
				$taddr=$ret[$j]["trace_addr"];
			}

			$ha="<a href=\"index.php?action=viewhost&amp;_ipaddr=";
			$ha .= urlencode($ret[$j]["host_addr"]);
			$ha .= "\">";
			$hb="</a>";

			$t->add_row(
				$link,
				(int )$ret[$j]["scans_id"],
				(int )$ret[$j]["sport"],
				type_tostr($ret[$j]["type"], $ret[$j]["subtype"], $ret[$j]["proto"]),
				$ha.htmlspecialchars($ret[$j]["host_addr"]).$hb,
				htmlspecialchars($taddr),
				(int )$ret[$j]["ttl"],
				strftime($PHPLIB["time_format"], (int )$ret[$j]["tstamp"]),
				sprintf("0x%08x", $ret[$j]["tseq"]),
				(int )$ret[$j]["window_size"],
				$banner,
				$os
			);
		}

		print "<div align=\"center\">\n";
		$t->print_tbl();
		print "</div>\n";
	}

	function get_var($var) {
		if (isset($_REQUEST[$var])) {
			$_SESSION[$var]=$_REQUEST[$var];
			return $_REQUEST[$var];
		}
		else if (isset($_SESSION[$var])) {
			return $_SESSION[$var];
		}

		return false;
	}

	function delete_record($id) {
		global $db, $PHPLIB;

		$query="select * from uni_ipreport where ipreport_id=".(int )$id;
		$db->aquerydb($query);
		if ($db->numrows != 1) {
			print "cant find that record<br/>\n";
			return;
		}

		$query="delete from uni_ippackets where ipreport_id=".(int )$id;
		$db->aquerydb($query);

		$query="delete from uni_ipreportdata where ipreport_id=".(int )$id;
		$db->aquerydb($query);

		$query="delete from uni_ipreport where ipreport_id=".(int )$id;
		$db->aquerydb($query);

		print <<<EOF
<strong>Deleted iprecord $id </strong>
<meta http-equiv="refresh" content="2; index.php?action=viewdata">

EOF;
	}

	function get_ouiname($e, $f, $g) {

		$device_type="Unknown";

		$fp=fopen("/usr/local/etc/unicornscan/oui.txt", "r");
		if ($fp) {
			while ($tmpstr=fgets($fp)) {
				if (sscanf($tmpstr, "%02x-%02x-%02x:%[^\n]", $a, $b, $c, $d) == 4) {
					if ($e == $a && $f == $b && $g == $c) {
			
						$device_type=$d;
					}
				}
			}
			fclose($fp);
		}

		return $device_type;
	}

	function display_host($ip) {
		global $db, $PHPLIB, $cookieupdate;

		$scansel="";
		$filt="";

		$device_type="unknown";
		$mac="";

		$slink="<a href=\"index.php?action=viewhost&amp;_ipaddr=";

		if (! stristr($ip, "mac:")) {
			$query="select distinct hwaddr from uni_arpreport where host_addr = '".$db->_escape_string($ip)."'";
			$db->aquerydb($query);
		}
		else {
			$rest=substr($ip, 4);
			if (sscanf($ip, "mac:%02x:%02x:%02x", $e, $f, $g) == 3) {
				$device_type=$slink."mac:".urlencode(sprintf("%02x:%02x:%02x", $e, $f, $g))."\">".get_ouiname($e, $f, $g)." </a>\n";
			}
		}

		if ($db->numrows == 1) {
			$db->data_step();

			if (sscanf($db->resultarr[0], "%02x:%02x:%02x:%02x:%02x:%02x", $e, $f, $g, $h, $i, $j) != 6) {
				$mac=", bad";
			}
			else {
				$device_type=$slink."mac:".urlencode(sprintf("%02x:%02x:%02x", $e, $f, $g))."\">".get_ouiname($e, $f, $g)." </a>\n";
				$mac=", ".$slink."mac:".urlencode($db->resultarr[0])."\">".htmlspecialchars($db->resultarr[0]). "</a>\n";
			}
		}

		print "<div align='center'><strong>Host ".htmlspecialchars($ip)." (".$device_type." ".$mac.") </strong></div>\n";

		$query="select * from uni_ipreport ";

		if (strncasecmp($ip, "mac:", 4) == 0) {
			$where="host_addr in (select distinct host_addr from uni_arpreport where hwaddr::varchar like '".$db->_escape_string(substr($ip, 4))."%')";
		}
		else {
			$where="host_addr <<= '".$db->_escape_string($ip)."'";
		}

		$rsb=get_var("_sortby");
		if ($rsb == false) {
			$sb=9;
		}
		else {
			$sb=(int )$rsb;
		}

		$rorder=get_var("_order");
		if ($rorder == false) {
			$rorder=1;
		}

		$rlimit=get_var("_limit");
		if ($rlimit != false) {
			$limit=(int )$rlimit;
		}
		else {
			$limit=30;
		}

		$roffset=get_var("_offset");
		if ($roffset != false) {
			$offset=(int )$roffset;
		}
		else {
			$offset=0;
		}

		switch ($sb) {
			case 0:
				$order_by="scans_id";
				break;
			case 1:
				$order_by="proto";
				break;
			case 2:
				$order_by="sport";
				break;
			case 3:
				$order_by="dport";
				break;
			case 4:
				$order_by="type";
				break;
			case 6:
				$order_by="host_addr";
				break;
			case 7:
				$order_by="trace_addr";
				break;
			case 8:
				$order_by="ttl";
				break;
			case 9:
				$order_by="tstamp, utstamp";
				break;
			case 10:
				$order_by="tseq";
				break;
			case 11:
				$order_by="window_size";
				break;
			case 12:
				$order_by="t_tstamp";
				break;
			default:
				$order_by="tstamp";
				break;
		}

		if ($rorder == 2) {
			$query .= " where ".$where." order by ".$order_by." asc limit ".$limit." offset ".$offset;
			$oorder="&amp;_order=1";
		}
		else {
			$query .= " where ".$where." order by ".$order_by." desc limit ".$limit." offset ".$offset;
			$oorder="&amp;_order=2";
		}

		print "<br/>Search Query `".htmlspecialchars($query)."'<br/>\n";
		$db->aquerydb($query);
		$nr=$db->numrows;

		$t=new tableclass();
		$t->set_width("96%");

		$link="<a href=\"index.php?action=viewhost&amp;_ipaddr=".$ip.$filt;
		$elink="</a>";

		if ($sb == 0) {
			$_1=$link."&amp;_sortby=0".$oorder."\"> scanid".$elink;
		}
		else {
			$_1=$link."&amp;_sortby=0\"> scanid".$elink;
		}

		if ($sb == 2) {
			$_2=$link."&amp;_sortby=2".$oorder."\"> port". $elink;
		}
		else {
			$_2=$link."&amp;_sortby=2\"> port". $elink;
		}

		if ($sb == 4) {
			$_3=$link."&amp;_sortby=4".$oorder."\"> type". $elink;
		}
		else {
			$_3=$link."&amp;_sortby=4\"> type". $elink;
		}

		if ($sb == 6) {
			$_4=$link."&amp;_sortby=6".$oorder."\"> host". $elink;
		}
		else {
			$_4=$link."&amp;_sortby=6\"> host". $elink;
		}

		if ($sb == 7) {
			$_5=$link."&amp;_sortby=7".$oorder."\"> trace". $elink;
		}
		else {
			$_5=$link."&amp;_sortby=7\"> trace". $elink;
		}

		if ($sb == 8) {
			$_6=$link."&amp;_sortby=8".$oorder."\"> ttl". $elink;
		}
		else {
			$_6=$link."&amp;_sortby=8\"> ttl". $elink;
		}

		if ($sb == 9) {
			$_7=$link."&amp;_sortby=9".$oorder."\"> tstamp". $elink;
		}
		else {
			$_7=$link."&amp;_sortby=9\"> tstamp". $elink;
		}

		if ($sb == 10) {
			$_8=$link."&amp;_sortby=10".$oorder."\"> seq". $elink;
		}
		else {
			$_8=$link."&amp;_sortby=10\"> seq". $elink;
		}

		if ($sb == 11) {
			$_9=$link."&amp;_sortby=11".$oorder."\"> win". $elink;
		}
		else {
			$_9=$link."&amp;_sortby=11\"> win". $elink;
		}

		$t->add_header("View",
			$_1,
			$_2,
			$_3,
			$_4,
			$_5,
			$_6,
			$_7,
			$_8,
			$_9,
			"banner",
			"os"
		);

		for ($j=0; $j < $nr; $j++) {
			$db->data_step();
			$ret[$j]=$db->resultarr;
		}

		for ($j=0; $j < $nr; $j++) {

			$ipreportid=$ret[$j]["ipreport_id"];

			$query="select data, type from uni_ipreportdata where ipreport_id=".$ipreportid;

			$banner="";
			$os="";

			$db->aquerydb($query);
			for ($j1=0; $j1 < $db->numrows; $j1++) {
				$db->data_step();
				if ($db->resultarr[1] == "1") {
					$banner=htmlspecialchars($db->resultarr[0]);
				}
				else if ($db->resultarr[1] == "2") {
					$os=htmlspecialchars($db->resultarr[0]);
				}
			}

			$query="select ipreport_id from uni_ippackets where ipreport_id=".$ret[$j]["ipreport_id"];
			$db->aquerydb($query);

			if ($db->numrows == 1) {
				$link="<a href=\"index.php?action=displayrecord&amp;ipreport_id=".
				(int )$ret[$j]["ipreport_id"]."\">Pkt</a>&nbsp;".
				"<a href=\"index.php?action=delrecord&amp;ipreport_id=".
				(int )$ret[$j]["ipreport_id"]."\">Del</a>";
			}
			else {
				$link="&nbsp;";
			}
			if (strcmp($ret[$j]["host_addr"], $ret[$j]["trace_addr"]) == 0) {
				$taddr="...";
			}
			else {
				$taddr=$ret[$j]["trace_addr"];
			}

			$ha="<a href=\"index.php?action=viewhost&amp;_ipaddr=";
			$ha .= urlencode($ret[$j]["host_addr"]);
			$ha .= "\">";
			$hb="</a>";

			$t->add_row(
				$link,
				(int )$ret[$j]["scans_id"],
				(int )$ret[$j]["sport"],
				type_tostr($ret[$j]["type"], $ret[$j]["subtype"], $ret[$j]["proto"]),
				$ha.htmlspecialchars($ret[$j]["host_addr"]).$hb,
				htmlspecialchars($taddr),
				(int )$ret[$j]["ttl"],
				strftime($PHPLIB["time_format"], (int )$ret[$j]["tstamp"]),
				sprintf("0x%08x", $ret[$j]["tseq"]),
				(int )$ret[$j]["window_size"],
				$banner,
				$os
			);
		}

		print "<div align=\"center\">\n";
		$t->print_tbl();
	}

	function display_except($scanids) {
		global $db;

		$query="";

		$scan_str="";
		for ($j=0; $j < count($scanids); $j++) {
			$scan_str .= " ".$scanids[$j];
		}

		print "Differences from scans <i>".$scan_str."</i><br/>\n";

		for ($j=0; $j < count($scanids); $j++) {
			if (strlen($query) == 0) {
				$query="select distinct sport, type, subtype, proto, host_addr, trace_addr  from uni_ipreport where scans_id=".(int )$scanids[$j]." ";
			}
			else {
				$query .= " except select distinct sport, type, subtype, proto, host_addr, trace_addr  from uni_ipreport where scans_id=".(int )$scanids[$j]." ";
			}
		}

		print htmlspecialchars($query);
		$db->agetassarr($query);
		$nr=$db->numrows;

		$t=new tableclass();
		$t->add_header("Port", "Host", "Type", "Trace");

		for ($j=0; $j < $nr; $j++) {
			$db->data_step();
			$t->add_row(
				$db->resultarr["sport"],
				$db->resultarr["host_addr"],
				type_tostr($db->resultarr["type"], $db->resultarr["subtype"], $db->resultarr["proto"]),
				$db->resultarr["trace_addr"]
			);
		}

		$t->print_tbl();
/*
select distinct sport, scans_id, type, subtype, proto, host_addr, trace_addr  from uni_ipreport where scans_id=
*/
	}

	function display_record($id, $dele) {
		global $db, $PHPLIB;

		$query="select * from uni_ipreport where ipreport_id=".(int )$id;
		$db->aquerydb($query);
		if ($db->numrows != 1) {
			print "cant find that record<br/>\n";
			return;
		}
		$db->data_step();

		$scans_id=(int )$db->resultarr["scans_id"];
		$sport=(int )$db->resultarr["sport"];
		$dport=(int )$db->resultarr["dport"];
		$type=type_tostr($db->resultarr["type"], $db->resultarr["subtype"], $db->resultarr["proto"]);
		$send_addr=$db->resultarr["send_addr"];
		$host_addr=$db->resultarr["host_addr"];
		$trace_addr=$db->resultarr["trace_addr"];

		if ($db->resultarr["proto"] == IPPROTO_ICMP) {
			$type .= " (".icmp_tostr($db->resultarr["type"], $db->resultarr["subtype"]).")";
		}

		$ttl=(int )$db->resultarr["ttl"];
		$tstamp=(int )$db->resultarr["tstamp"];
		$utstamp=(int )$db->resultarr["utstamp"];
		$seq=sprintf("0x%08x", $db->resultarr["tseq"]);
		$window_size=(int )$db->resultarr["window_size"];

		$tstr=strftime($PHPLIB["time_format"], $tstamp);

		print <<<EOF
<pre>
ScanID: $scans_id
Source: $send_addr:$dport
Dest:   $host_addr:$sport (trace $trace_addr)
Type:   $type
TTL:    $ttl
Time:   $tstamp.$utstamp ($tstr)
Seq:    $seq
Win:    $window_size

</pre>

EOF;
		$query="select packet from uni_ippackets where ipreport_id=".(int )$id;
		$db->aquerydb($query);
		if ($db->numrows != 1) {
			return;
		}
		$db->data_step();

		$data=pg_unescape_bytea($db->resultarr[0]);

		$arr=unpack('C*', $data);

		$hex=""; $cnt=0;
		for ($j=3, $cnt=0; $j < count($arr); $j++, $cnt++) {
			if ($cnt != 0 && ($cnt % 16) == 0) {
				$hex .= "\n";
			}
			$hex .= sprintf("%02x ", $arr[$j]);
		}

		for ($j=3, $cnt=0; $j < count($arr); $j++, $cnt++) {
			if ($cnt != 0 && ($cnt % 16) == 0) {
				$ascii .= "\n";
			}
			if (ctype_graph($arr[$j])) {
				$ascii .= htmlspecialchars(sprintf("%c", $arr[$j]));
			}
			else {
				$ascii .= ".";
			}
		}

		print <<<EOF

<pre class="hexdump">
 <table class="hexdump" cellspacing="1" cellpadding="4" border="1">
  <tr class="hexdump">
   <td class="hexdump">$hex</td>
   <td class="hexdump">$ascii</td>
  </tr>
 </table>

</pre>

EOF;

		if ($dele == 1) {
			$f2=new formclass();
			$f2->new_title("delete record");
			$f2->new_desc("are you sure");
			$f2->set_default("action", "viewdata");
			$f2->new_input("select", "action", "delrecordsure:yes,viewdata:no");
			$f2->add_hidden("ipreport_id", $id);
			$f2->print_form();
		}
		else {
			print <<<EOF
<div align="center">
 <a href="index.php?action=delrecord&amp;ipreport_id=$id"> Delete </a>
</div>
EOF;
		}
	}

	function display_dbstats() {
		global $db, $PHPLIB;

		$query="select distinct host_addr from uni_ipreport where host_addr not in (select distinct host_addr from uni_arpreport)";
		$db->aquerydb($query);

		$t=new tableclass();

		$t->add_header("Hosts with no known mac address");
		for ($j=0; $j < $db->numrows; $j++) {
			$db->data_step();
			$t->add_row(htmlspecialchars($db->resultarr[0]));
		}

		$t->print_tbl();

		return;
	}
?>
