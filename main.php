<?php

//my ip
$myip = $argv[1]; //your ip or mask from where you want to access the server
$mode = $argv[2];  //A to add rules, //D to delete rules
$cc = $argv[3]; //country code
$action = $argv[4]; //DROP or ACCEPT
$state = isset($argv[5])?$argv[5]:"";

echo "iptables -A INPUT -m state --state INVALID -j DROP\n";
echo "iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n";
echo "iptables -A INPUT -i lo -j ACCEPT\n";
echo "iptables -A INPUT -s $myip -j ACCEPT\n";

$row = 1;

if (($handle = fopen("IP2LOCATION-LITE-DB3.CSV", "r")) !== FALSE) {
    while (($data = fgetcsv($handle, 1000, ",")) !== FALSE) {
        //  echo "d2." . $data[2] . "\n";
		if ($cc == $data[2]) {
			$num = count($data);
			$row++;
			//multiport --dports 80,443
			$rule = "iptables -A INPUT -p tcp  -m iprange --src-range  " . long2ip($data[0])."-". long2ip($data[1]) . " -j " . $action . "\n";
			if ( $state == "" ) {
				//echo "range: " . long2ip($data[0]) . " - " . long2ip($data[1]) . " netmask: " . long2ip($data[0] - $data[1]) . "\n";			
				echo $rule;
				//echo "d3." . $data[3] . "\n";
				//echo "d4." . $data[4] . "\n";
				//echo "d5." . $data[5] . "\n";				
			}
			elseif ($state == $data[4]) {
				//echo "d3." . $data[3] . "\n";
				//echo "d4." . $data[4] . "\n";
				//echo "d5." . $data[5] . "\n";
				echo $rule;
			}
		}
    }
    fclose($handle);
	//lM1xI6pJ1sgP
}

if ($action == "ACCEPT") {
	echo "iptables -P INPUT DROP\n"; # Drop everything we don't accept
}
?>
