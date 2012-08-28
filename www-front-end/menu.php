<?php
	require($PHPLIB["filesystem_phplib"]."tableclass.php");

	$me=new tableclass();

	$me->set_width("100%");

	$ctime=time();

	$me->add_header(
			"<a href=\"index.php\"> Show Scans </a>",
			"<a href=\"index.php?action=viewdata\"> Show Scan Data </a>",
			"<div align=\"right\">Time &nbsp;".strftime($PHPLIB["time_format"], $ctime)."</div>"
	);

	$me->print_tbl();

	print "<br/>\n";

?>
