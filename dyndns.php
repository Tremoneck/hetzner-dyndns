<?php
//echo($_SERVER['REMOTE_ADDR']);
$ipv4 = $_GET['ipv4']; //Your ipv4 from your router
$ipv6 = $_GET['prefix']; //Your ipv6 prefix
$auth_token = $_GET["password"]; //One auth token from the hetzner api
$zone = $_GET["zone"]; //The zone which you can get from the hetzner api
$host = $_GET["host"]; //The name of the record like * or www
// get cURL resource
$ch = curl_init();

// set url
curl_setopt($ch, CURLOPT_URL, 'https://dns.hetzner.com/api/v1/records?zone_id=' . $zone);

// set method
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');

// return the transfer as a string
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

// set headers
curl_setopt($ch, CURLOPT_HTTPHEADER, [
  'Auth-API-Token: ' . $auth_token,
]);

// send the request and save response to $response
$response = curl_exec($ch);

// stop if fails
if (!$response) {
  die('Error: "' . curl_error($ch) . '" - Code: ' . curl_errno($ch));
}


$json = json_decode($response, true);

//Setup variables to store our needed records
$ipv4_zone = "";
$ipv6_zone = "";
$current_ipv6 = "";

//Filter out the id's we need
foreach($json["records"] as $record) {
  if ($record["name"] != $host)
    continue;
  if ($record["type"] == "AAAA") {
    $ipv6_zone = $record["id"];
    $current_ipv6 = $record["value"];
  }
  if ($record["type"] == "A") {
    $ipv4_zone = $record["id"];
  }
}

//Send next request to the bulk endpoint
curl_setopt($ch, CURLOPT_URL, 'https://dns.hetzner.com/api/v1/records/bulk');

// set method
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

$updates = array();

if (!empty($ipv4_zone) && !empty($ipv4)) {
  $updates[] = create_update($ipv4_zone, $host, "A", $ipv4, $zone);
}

if (!empty($ipv6_zone) && !empty($current_ipv6) && !empty($ipv6)) {
  $ipv6 = patch_ipv6($ipv6, $current_ipv6);
  $updates[] = create_update($ipv6_zone, $host, "AAAA", $ipv6, $zone);
}

$body = json_encode(array("records" => $updates));
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);

//echo $body;

$response = curl_exec($ch);

// stop if fails
if (!$response) {
  die('Error: "' . curl_error($ch) . '" - Code: ' . curl_errno($ch));
}


echo "OK";

// close curl resource to free up system resources 
curl_close($ch);

function patch_ipv6($prefix, $dest) {
  $parts = explode("/", $prefix, 2);
  $prefix = $parts[0];
  $length = $parts[1];
  $prefix = bin2hex(inet_pton($prefix));
  $dest = bin2hex(inet_pton($dest));
  $result = substr($prefix, 0, 64/4) . substr($dest, 64/4, 32);
  $result = substr(chunk_split($result, 4, ':'), 0, - 1);
  return $result;
}

function create_update($id, $name, $type, $value, $zone) {
  return array(
    "id" => $id,
    "name" => $name,
    "type" => $type,
    "value" => $value,
    "zone_id" => $zone,
    "ttl" => 60);
}

?>