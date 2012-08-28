<?php
	require("./header.php");
	require("./lib/connect_todb.php");
	require("./lib/formclass2.php");

	require("./lib/unidata.php");
	require("./lib/unimisc.php");
	require("./lib/trange.php");

	require("./display.php");


	$scanid_off=0;
	$action=$_REQUEST["action"];

	while (list($key, $value)=each($_REQUEST)) {
		if ($value == "on") {
			if (sscanf($key, "scan_%u", $r_scans_id) == 1) {
				$scanids[$scanid_off++]=$r_scans_id;
			}
		}
		else if ($key == "_scansel") {
			for ($tok=strtok($value, ","); strlen($tok) > 0; $tok=strtok(",")) {
				$scanids[$scanid_off++]=(int )$tok;
			}
		}
	}

	if (strlen($action)) {
		if ($action == "view") {
			$scans=get_scans($scanids);
			display_scans($scans);
		}
		else if ($action == "delete") {
			$f=new formclass();
			$f->new_title("Delete Scan Data");
			$f->new_row();
			$f->new_desc("are you sure?");
			$f->new_input("select", "action", "view:no,delete_2:yes");	

			$f->new_row();
			for ($j=0; $j < count($scanids); $j++) {
				$f->add_hidden("scan_".$scanids[$j], "on");
			}
			$f->print_form();

			$scans=get_scans($scanids);
			display_shortscans($scans, 0);
		}
		else if ($action == "delete_2") {
			for ($j=0; $j < count($scanids); $j++) {
				print "Deleting Scan ".$scanids[$j]."<br/>\n";
				delete_scandata((int )$scanids[$j]);
			}
			print "<meta http-equiv=\"refresh\" content=\"2; index.php\">\n";
		}
		else if ($action == "viewdata") {
			display_scandata($scanids);
		}
		else if ($action == "displayrecord") {
			display_record($_REQUEST["ipreport_id"], 0);
		}
		else if ($action == "delrecord") {
			display_record($_REQUEST["ipreport_id"], 1);
		}
		else if ($action == "delrecordsure") {
			delete_record($_REQUEST["ipreport_id"]);
		}
		else if ($action == "viewhost") {
			display_host($_REQUEST["_ipaddr"]);
		}
		else if ($action == "except") {
			display_except($scanids);
		}
		else if ($action == "stats") {
			display_dbstats();
		}
		else {
			print "Error, dont know what to do?<br/>\n";
		}
	}
	else {
		$scans=get_scans();
		display_shortscans($scans, 1);
	}

	require("./trailer.php");
	exit;

	function display_scans($scans) {
		for ($j=0; $j < count($scans); $j++) {
			print "<h2> scan ".$scans[$j]["scans_id"]." </h2>\n";
			display_scan($scans[$j]);
		}
	}

	function display_shortscans($scans, $doform) {

		print <<<EOF

<div align="center">
EOF;
		if ($doform) {
			print <<<EOF

<form method="post" action="index.php" class="form">
EOF;
		}

		print <<<EOF
<table class="scanstbl">
 <tr class="tblhdr">
  <th>
  </th>
  <th>
   Start Time
  </th>
  <th>
   Est End Time
  </th>
  <th>
   End Time
  </th>
  <th>
   Hosts
  </th>
  <th>
   Packets
  </th>
  <th>
   Type/PPS
  </th>
  <th>
   Hosts
  </th>
 </tr>
EOF;

		for ($j=0; $j < count($scans); $j++) {
			print get_short_scan($scans[$j], $doform);
		}

		if ($doform) {
			print <<<EOF
 <tr class="tblhdr">
  <td colspan="2">
   <input type="submit" value="view" name="action" class="formsubmit">
  </td>
  <td colspan="2">
   <input type="submit" value="viewdata" name="action" class="formsubmit">
  </td>
  <td colspan="2">
   <input type="submit" value="except" name="action" class="formsubmit">
  </td>
  <td colspan="2">
   <input type="submit" value="delete" name="action" class="formsubmit">
  </td>
 </tr>
</table>
</form>
EOF;
		}
		print <<<EOF
</div>
EOF;
	} /* display short scans */
?>
