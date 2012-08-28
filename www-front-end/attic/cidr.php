<?php

if (!(defined("CIDR_PHP"))) {
	define("CIDR_PHP", 1);

$c_tbl=array( 0 => 0x00000000,
1  => 0x80000000, 2  => 0xc0000000, 3  => 0xe0000000, 4  => 0xf0000000,
5  => 0xf8000000, 6  => 0xfc000000, 7  => 0xfe000000, 8  => 0xff000000,
9  => 0xff800000, 10 => 0xffc00000, 11 => 0xffe00000, 12 => 0xfff00000,
13 => 0xfff80000, 14 => 0xfffc0000, 15 => 0xfffe0000, 16 => 0xffff0000,
17 => 0xffff8000, 18 => 0xffffc000, 19 => 0xffffe000, 20 => 0xfffff000,
21 => 0xfffff800, 22 => 0xfffffc00, 23 => 0xfffffe00, 24 => 0xffffff00,
25 => 0xffffff80, 26 => 0xffffffc0, 27 => 0xffffffe0, 28 => 0xfffffff0,
29 => 0xfffffff8, 30 => 0xfffffffc, 31 => 0xfffffffe, 32 => 0xffffffff);

	function cidr_pair($hoststr, &$low, &$high) {
		$host="";
		$mask=32;
		$netlow=0; $nethigh=0;
		global $c_tbl;

                if (strstr($hoststr, "/")) {
			sscanf($hoststr, "%[^/]/%d", $host, $mask);
		}
		else {
			$host=$hoststr;
			$mask=32;
		}

		if ($mask < 0 || $mask > 32) trigger_error("netmask out of range");

		$ip=gethostbyname($host);

		$low=sprintf("%u", (ip2long($ip) & $c_tbl[$mask]));
		$high=sprintf("%u", (ip2long($ip) | (0xffffffff ^ $c_tbl[$mask])));
	}

}
?>
