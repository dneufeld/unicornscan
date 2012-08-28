<?php

	function get_scans($scans_ids = -1) {
		global $db;

		$query="select * from uni_scans";

		if ($scans_ids != -1) {
			for ($j=0; $j < count($scans_ids); $j++) {
				if (strlen($where) < 1) {
					$where=" where scans_id=".(int )$scans_ids[$j];
				}
				else {
					$where .= " or scans_id=".(int )$scans_ids[$j];
				}
			}
			$query .= $where;
		}

		$query .= " order by scans_id, s_time";
		$db->aquerydb($query);
		$nr=$db->numrows;

		for ($j=0; $j < $nr; $j++) {
			$db->data_step();
			$ret[$j]=$db->resultarr;
		}

		for ($j=0; $j < $nr; $j++) {
			$ret[$j]["sworkunits"]=get_sworkunits((int )$ret[$j]["scans_id"]);
			$ret[$j]["lworkunits"]=get_lworkunits((int )$ret[$j]["scans_id"]);
		}

		return $ret;
	}

	function get_sworkunits($scan_id) {
		global $db;

		$query="select * from uni_sworkunits where scans_id=".$scan_id;

		$db->agetassarr($query);
		for ($j=0; $j < $db->numrows; $j++) {
			$db->data_step();

			$workunits[$j]=$db->resultarr;
		}

		return $workunits;
	}

	function get_lworkunits($scan_id) {
		global $db;

		$query="select * from uni_lworkunits where scans_id=".$scan_id;

		$db->agetassarr($query);
		for ($j=0; $j < $db->numrows; $j++) {
			$db->data_step();

			$workunits[$j]=$db->resultarr;
		}

		return $workunits;
	}

	function delete_scandata($scan_id) {
		global $db;

		$query="delete from uni_ippackets where ipreport_id in (select ipreport_id from uni_ipreport where scans_id=".$scan_id.")";
		$db->aquerydb($query);

		$query="delete from uni_arppackets where arpreport_id in (select arpreport_id from uni_arpreport where scans_id=".$scan_id.")";
		$db->aquerydb($query);

		$query="delete from uni_ipreportdata where ipreport_id in (select ipreport_id from uni_ipreport where scans_id=".$scan_id.")";
		$db->aquerydb($query);

		$query="delete from uni_arpreport where arpreport_id in (select arpreport_id from uni_arpreport where scans_id=".$scan_id.")";
		$db->aquerydb($query);

		$query="delete from uni_ipreport where scans_id=".$scan_id;
		$db->aquerydb($query);

		$query="delete from uni_output where scans_id=".$scan_id;
		$db->aquerydb($query);

		$query="delete from uni_workunitstats where scans_id=".$scan_id;
		$db->aquerydb($query);

		$query="delete from uni_lworkunits where scans_id=".$scan_id;
		$db->aquerydb($query);

		$query="delete from uni_sworkunits where scans_id=".$scan_id;
		$db->aquerydb($query);

		$query="delete from uni_scans where scans_id=".$scan_id;
		$db->aquerydb($query);
	}
?>
