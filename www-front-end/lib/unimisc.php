<?php
	define(S_SHUFFLE_PORTS,		1);
	define(S_SRC_OVERRIDE,		2);
	define(S_RND_SRCIP,		4);
	define(S_DEFAULT_PAYLOAD,	8);
	define(S_BROKEN_TRANS,		16);
	define(S_BROKEN_NET,		32);
	define(S_SENDER_INTR,		64);

	define(IPPROTO_ICMP,		1);
	define(IPPROTO_TCP,		6);
	define(IPPROTO_UDP,		17);

	define(TH_FIN,			0x01);
	define(TH_SYN,			0x02);
	define(TH_RST,			0x04);
	define(TH_PSH,			0x08);
	define(TH_ACK,			0x10);
	define(TH_URG,			0x20);
	define(TH_ECE,			0x40);
	define(TH_CWR,			0x80);

	function delay_tostr($type) {

		switch ($type) {
			case 1:
				return "TSC";
			default:
				break;
		}

		return "?";
	}

	function sworkunit_magictostr($type) {
		switch ($type) {
			case 0x1a1b1c1d:
				return "TCP";

			case 0x2a2b2c2d:
				return "UDP";

			default:
				break;
		}
		return "?";
	}

	function options_tostr($flags) {

		$ret="";

		if ($flags & S_SHUFFLE_PORTS) {
			$ret="shuffle ports,";
		}
		else {
			$ret="no port shuffle,";
		}

		if ($flags & S_SRC_OVERRIDE) {
			$ret .= " SrcIP specified,";
		}
		else {
			$ret .= " SrcIP not-specified,";
		}

		if ($flags & S_DEFAULT_PAYLOAD) {
			$ret .= " defpayload enabled";
		}
		else {
			$ret .= " defpayload disabled";
		}

		return $ret;
	}

	function ipproto_tostr($ipproto) {
		switch ($ipproto) {
			case IPPROTO_ICMP:
				return "ICMP";
			case IPPROTO_TCP:
				return "TCP";
			case IPPROTO_UDP:
				return "UDP";
			default:
				break;
		}
		return "UNKNOWN".(int )$ipproto;
	}

	function sendopts_tostr($flags) {
		return "";
	}

	function recvopts_tostr($flags) {
		return "";
	}

	function tcpflags_tostr($num) {

		$str="--------";

		if ($num & TH_FIN) $str[0]="F";
		if ($num & TH_SYN) $str[1]="S";
		if ($num & TH_RST) $str[2]="R";
		if ($num & TH_PSH) $str[3]="P";
		if ($num & TH_ACK) $str[4]="A";
		if ($num & TH_URG) $str[5]="U";
		if ($num & TH_ECE) $str[6]="E";
		if ($num & TH_CWR) $str[7]="C";

		return $str;
	}


	function type_tostr($type, $subtype, $protocol) {
		switch ($protocol) {
			case 1:
				$str=sprintf("ICMP T%02xC%02x", (integer)$type, (integer)$subtype); break;
			case 6:
				$str=sprintf("TCP %s", tcpflags_tostr((integer)$type)); break;
			case 17:
				$str="UDP ";
		}

		return $str;
	}

	function icmp_tostr($type, $subtype) {
		switch ($type) {
			case 0:
				$ret="echo reply";
				if ($subtype != 0) {
					$ret .= ", with strange code ".(int )$subtype;
				}
				return $ret;
			case 3:
				$ret="dest unreachable";
				switch ($subtype) {
					case 0:
						$ret .= ", net unreachable";
						break;
					case 1:
						$ret .= ", host unreachable";
						break;
					case 2:
						$ret .= ", protocol unreachable";
						break;
					case 3:
						$ret .= ", port unreachable";
						break;
					case 4:
						$ret .= ", fragmentation needed and dont fragment was set";
						break;
					case 5:
						$ret .= ", source route failed";
						break;
					case 6:
						$ret .= ", destination network unknown";
						break;
					case 7:
						$ret .= ", destination host unknown";
						break;
					case 8:
						$ret .= ", source host isolated";
						break;
					case 9:
						$ret .= ", communication with destination network is administratively prohibited";
						break;
					case 10:
						$ret .= ", communication with destination host is administratively prohibited";
						break;
					case 11:
						$ret .= ", destination network unreachable for yype of service";
						break;
					case 12:
						$ret .= ", destination host unreachable for type of service";
						break;
					case 13:
						$ret .= ", communication administratively prohibited [<a href=\"http://www.faqs.org/rfcs/rfc1812.html\">RFC1812</a>]";
						break;
					case 14:
						$ret .= ", host precedence violation [<a href=\"http://www.faqs.org/rfcs/rfc1812.html\">RFC1812</a>]";
						break;
					case 15:
						$ret .= ", precedence cutoff in effect [<a href=\"http://www.faqs.org/rfcs/rfc1812.html\">RFC1812</a>]";
						break;
					default:
						$ret .= ", unknown reason ".(int )$subtype;
				}
				return $ret;
			case 4:
				$ret="source quench";
				if ($subtype != 0) {
					$ret .= ", with strange code ".(int )$subtype;
				}
				return $ret;
			case 5:
				$ret="redirect";
				switch ($subtype) {
					case 0:
						$ret .= ", redirect datagram for the network/subnet";
						break;
					case 1:
						$ret .= ", redirect datagram for the host";
						break;
					case 2:
						$ret .= ", redirect datagram for the yype of service and network";
						break;
					case 3:
						$ret .= ", redirect datagram for the type of service and host";
						break;
					default:
						$ret .= ", unknown reason ".(int )$subtype;
						break;
				}
				return $ret;
			case 6:
				$ret="alternate host address";
				switch ($subtype) {
					case 0:
						$ret .= ", alternate address for host";
						break;
					default:
						$ret .= ", unknown reason ".(int )$subtype;
						break;
				}
				return $ret;

			case 8:
				$ret="echo request";
				if ($subtype != 0) {
					$ret .= ", with strange code ".(int )$subtype;
				}
				return $ret;

			case 9:
				$ret="router advertisement";
				switch ($subtype) {
					case 0:
						$ret .= ", normal router advertisement";
						break;
					case 16:
						$ret .= ", does not route common traffic";
						break;
					default:
						$ret .= ", type unknown ".(int )$subtype;
						break;
				}
				return $ret;

			case 10:
				$ret="router selection";
				if ($subtype != 0) {
					$ret .= ", with strange code ".(int )$subtype;
				}
				return $ret;

			case 11:
				$ret="time exceeded";
				switch ($subtype) {
					case 0:
						$ret .= ", time to live exceeded in transit";
						break;
					case 1:
						$ret .= ", fragment reassembly time exceeded";
						break;
					default:
						$ret .= ", unknown ".(int )$subtype;
						break;
				}
				return $ret;

			case 1:
			case 2:
			case 7:
				$ret="unassigned [".(int )$type."]";
				if ($subtype != 0) {
					$ret .= ", with strange code ".(int )$subtype;
				}
				return $ret;

			default:
				break;
		}

		$ret="Unknown type ".(int )$type;
		if ($subtype != 0) {
			$ret .= ", with code ".(int )$subtype;
		}
		return $ret;
	}

	function getsql_resptype($data) {

		$add="";
		$not=0;
		$added=0;

		for ($tok=strtok(trim($data), ","); strlen($tok) > 0; $tok=strtok(",")) {

			if (strlen($add) < 1) {
				$add=" and (";
			}

			$ctok=trim($tok);

			if ($ctok[0] == "!") {
				$ctok=trim(substr($ctok, 1));
				$not=1;
			}
			else {
				$not=0;
			}

			if (strncasecmp($ctok, "tcp", 3) == 0) {
				$tcpflag_val=0;

				$ctok=substr($ctok, 3);

				for ($j=0 ; $j < strlen($ctok) ; $j++) {
					if (ctype_space($ctok[$j])) {
						continue;
					}
					switch ($ctok[$j]) {
						case 'F':
							$tcpflag_val |= 0x01;
							break;
						case 'S':
							$tcpflag_val |= 0x02;
							break;
						case 'R':
							$tcpflag_val |= 0x04;
							break;
						case 'P':
							$tcpflag_val |= 0x08;
							break;
						case 'A':
							$tcpflag_val |= 0x10;
							break;
						case 'U':
							$tcpflag_val |= 0x20;
							break;
						case 'E':
							$tcpflag_val |= 0x40;
							break;
						case 'C':
							$tcpflag_val |= 0x80;
							break;
						default:
							print "Error: unknown tcpflag `".$ctok[$j]."'<br/>\n";
							break;
					}
				}

				if ($tcpflag_val != 0) {
					if      ($not == 0 && $added == 0) {
						$add .= " (proto=6 and type=".(int )$tcpflag_val.")";
					}
					else if ($not == 0 && $added == 1) {
						$add .= " or (proto=6 and type=".(int )$tcpflag_val.")";
					}
					else if ($not == 1 && $added == 0) {
						$add .= " not (proto=6 and type=".(int )$tcpflag_val.")";
					}
					else {
						$add .= " and not (proto=6 and type=".(int )$tcpflag_val.")";
					}
				}
				else {
					if      ($not == 0 && $added == 0) {
						$add .= " proto=6 ";
					}
					else if ($not == 0 && $added == 1) {
						$add .= " or proto=6 ";
					}
					else if ($not == 1 && $added == 0) {
						$add .= " not proto=6 ";
					}
					else {
						$add .= " and not proto=6 ";
					}
				}
			} /* TCP */
			else if (strcasecmp($ctok, "udp") == 0) {
				if      ($not == 0 && $added == 0) {
					$add .= " proto=17 ";
				}
				else if ($not == 0 && $added == 1) {
					$add .= " or proto=17 ";
				}
				else if ($not == 1 && $added == 0) {
					$add .= " not proto=17 ";
				}
				else {
					$add .= " and not proto=17 ";
				}
			}
			else if (strcasecmp($ctok, "icmp") == 0) {
				if      ($not == 0 && $added == 0) {
					$add .= " proto=1 ";
				}
				else if ($not == 0 && $added == 1) {
					$add .= " or proto=1 ";
				}
				else if ($not == 1 && $added == 0) {
					$add .= " not proto=1 ";
				}
				else {
					$add .= " and not proto=1 ";
				}
			}
			else {
				print "<strong> mis-understood type filter ".htmlspecialchars($ctok).", ignoring </strong>";
			}

			$added=1;

		} /* for , item */

		return $add." ) ";
	}

	/*
	 * generate a SQL statement for filtering based upon a PostGreSQL inet type
	 * DO NOT PUT USER DATA INSIDE FNAME
	 */

	function getsql_inet($data, $fname) {
		global $db; /* for escaping data */

		$add="";
		$rest="";
		$not=0;
		$added=0;

		for ($tok=strtok($data, ","); strlen($tok) > 0; $tok=strtok(",")) {
			$ctok=trim($tok);

			if (strlen($add) < 1) {
				$add=" and ( ";
			}

			if ($ctok[0] == "!") {
				$rest=trim(substr($ctok, 1));
				$not=1;
			}
			else {
				$rest=$ctok;
				$not=0;
			}

			if (strncasecmp($rest, "mac:", 4) == 0) {
				if ($added == 1 && $not == 0) {
					$add .= " or ".$fname." in (select distinct ".$fname." from uni_arpreport where hwaddr::varchar like '".substr($rest, 4)."%') ";
				}
				else if ($added == 1 && $not == 1) {
					$add .= " and not ".$fname." in (select distinct ".$fname." from uni_arpreport where hwaddr::varchar like '".substr($rest, 4)."%') ";
				}
				else if ($added == 0 && $not == 0) {
					$add .= " ".$fname." in (select distinct ".$fname." from uni_arpreport where hwaddr::varchar like '".substr($rest, 4)."%') ";
				}
				else {
					$add .= " not ".$fname." in (select distinct ".$fname." from uni_arpreport where hwaddr::varchar like '".substr($rest, 4)."%') ";
				}
			}
			else if ($added == 1 && $not == 0) {
				$add .= " or ".$fname." <<= inet '".trim($db->_escape_string($rest))."' ";
			}
			else if ($added == 1 && $not == 1) {
				$add .= " and not ".$fname." <<= inet '".trim($db->_escape_string($rest))."' ";
			}
			else if ($added == 0 && $not == 0) {
				$add .= " ".$fname." <<= inet '".trim($db->_escape_string($rest))."' ";
			}
			else {
				$add .= " not ".$fname." <<= inet '".trim($db->_escape_string($rest))."' ";
			}

			$added=1;
		}

		return $add." ) ";
	}

	/*
	 * generate a SQL statement for filtering based upon a PostGreSQL numeric type
	 * DO NOT PUT USER DATA INSIDE FNAME
	 */
	function getsql_numeric($data, $fname) {
		$add="";
		$rest="";
		$not=0;
		$added=0;

		for ($tok=strtok($data, ","); strlen($tok) > 0; $tok=strtok(",")) {
			$ctok=trim($tok);

			if (strlen($add) < 1) {
				$add=" and ( ";
			}

			if ($ctok[0] == "!") {
				$rest=trim(substr($ctok, 1));
				$not=1;
			}
			else {
				$rest=$ctok;
				$not=0;
			}

			if ($rest[0] == ">") {
				$oper=">";
				$rest=trim(substr($rest, 1));
			}
			else if ($rest[0] == "<") {
				$oper="<";
				$rest=trim(substr($rest, 1));
			}
			else {
				$oper="=";
			}

			if ($added == 1 && $not == 0) {
				$add .= " or ".$fname." ".$oper." ".(int )$rest." ";
			}
			else if ($added == 1 && $not == 1) {
				$add .= " and not ".$fname." ".$oper." ".(int )$rest." ";
			}
			else if ($added == 0 && $not == 0) {
				$add .= " ".$fname." ".$oper." ".(int )$rest." ";
			}
			else {
				$add .= " not ".$fname." ".$oper." ".(int )$rest." ";
			}

			$added=1;
		}

		return $add." ) ";
	}

	function getsql_time($data, $fname) {

		$added=0;
		$not=0;
		$add="";

		for ($tok=strtok($data, ","); strlen($tok) > 0; $tok=strtok(",")) {

			$ctok=trim($tok);

			$low_ts=0;
			$high_ts=0;

			if (strlen($add) < 1) {
				$add=" and (";
			}

			if ($ctok[0] == "!") {
				$ctok=trim(substr($ctok, 1));
				$not=1;
			}

			time_pair($ctok, $low_ts, $high_ts);

			if      ($not == 0 && $added == 0) {
				$add .= " (tstamp >= $low_ts and tstamp <= $high_ts) ";
			}
			else if ($not == 1 && $added == 0) {
				$add .= " (tstamp <= $low_ts or tstamp >= $high_ts)";
			}
			else if ($not == 0 && $added == 1) {
				$add .= " and (tstamp >= $low_ts or tstamp <= $high_ts)";
			}
			else { /* not == 1     added == 1 */ 
				$add .= " and (tstamp <= $low_ts or tstamp >= $high_ts)";
			}

			$added=1;
		}

		return $add." ) ";
	}
?>
