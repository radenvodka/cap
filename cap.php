<?php
//tshark.exe -i Wi-Fi -T pdml > "D:\cap\asu.txt"
error_reporting(0);
function sdata($url = null, $custom = null , $delCookies = null , $debug = null){
    $gLog = file_get_contents("last.txt");
    $gLog = explode("\r\n",$gLog);

    if(!in_array($url,$gLog)){
     
      $x = fopen("last.txt", "a+");
      fwrite($x, $url."\r\n");
      fclose($x);

      $ch = curl_init();
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_HEADER, false);
      if($custom[uagent]){
        curl_setopt($ch, CURLOPT_USERAGENT, $custom[uagent]);
      }else{
      curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20100101 Firefox/15.0.1");
      }
      curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

      curl_setopt($ch, CURLOPT_CONNECTTIMEOUT ,0);
      if($custom[rto]){
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
      }else{
        curl_setopt($ch, CURLOPT_TIMEOUT, 1);
      }
      if($custom[header]){
        curl_setopt($ch, CURLOPT_HTTPHEADER, $custom[header]);
      }
      curl_setopt($ch, CURLOPT_COOKIEJAR,  getcwd().'/cookijem.txt');
      curl_setopt($ch, CURLOPT_COOKIEFILE, getcwd().'/cookijem.txt');
      curl_setopt($ch, CURLOPT_VERBOSE, false);
      if($custom[post]){
        if(is_array($custom[post])){
          $query = http_build_query($custom[post]);
          }else{
          $query = $custom[post];
        }
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $query);
      }
      $data           = curl_exec($ch);
      $httpcode       = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      $info           = curl_getinfo($ch);
      curl_close($ch);
      if($delCookies != false){
          unlink("cookijem.txt");
      }
      return array(
        'url'     => $info['url'],
        'ip'      => $info['primary_ip'],
        'data'    => $data,
        'decode'  => json_decode($data , true),
        'httpcode'  => $httpcode
      );
    }
} 
function search($domain){
  $domain = parse_url($domain, PHP_URL_HOST);
  $h  = array('rto' => 3);
  $s  = sdata("https://api.shodan.io/dns/resolve?hostnames=".$domain."&key=FBZp5j6UcLiMJpo1cgmpd19PtMepczCA",$h);
  $data = $s['decode'][$domain]." ".$domain."\r\n";
  whitelist($data);
  echo "[Host] ".$domain." ==> Domain Has been Safe | Real Ip : ".$s['decode'][$domain]."\r\n";
}
function whitelist($data){
  $fh = fopen("C:\\Windows\\System32\\drivers\\etc\\hosts", 'a') or die("can't open file");
  fwrite($fh, "\r\n");
  fwrite($fh, $data);
  fclose($fh);
}
function is_valid_domain_name($domain_name)
{
    return (preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $domain_name) //valid chars check
            && preg_match("/^.{1,253}$/", $domain_name) //overall length check
            && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domain_name)   ); //length of each label
}
function follow($file){
    $size = 0;
    $last = 0;
    $ip   = 0;
    $alt  = 0;
    while (true) {
        //unlink("asu.txt");
        clearstatcache();
        $currentSize = filesize($file);
        if ($size == $currentSize) {
            usleep(1);
            continue;
        }
        $fh = fopen($file, "r");
        fseek($fh, $size);
        while ($d = fgets($fh)) {
          
          

          preg_match_all('/<field name="ssl.handshake.extensions_server_name" showname="Server Name: (.*?)" size="(.*?)" pos="(.*?)" show="(.*?)" value="(.*?)"\/>/', $d , $infos1);
          preg_match_all('/ <field name="http.host" showname="Host: (.*?)\\\\r\\\\n"/', $d , $infos2);
          preg_match_all('/<field name="dns.qry.name" showname="Name: www.(.*?)" size="(.*?)" pos="54" show="(.*?)" value="(.*?)"\/>/', $d, $infos3);
          preg_match_all('/<field name="dns.qry.name" showname="Name: (.*?)" size="(.*?)" pos="54" show="(.*?)" value="(.*?)"\/>/', $d, $infos4);



          if(!preg_match("/uzone.id|google|preyproject|alexa|github|gstatic|shodan/", $infos1[1][0])){
          if(!preg_match("/uzone.id|google|preyproject|alexa|github|gstatic|shodan/", $infos2[1][0])){
          if(!preg_match("/uzone.id|google|preyproject|alexa|github|gstatic|shodan/", $infos3[1][0])){
          if(!preg_match("/uzone.id|google|preyproject|alexa|github|gstatic|shodan/", $infos4[1][0])){

            if(is_valid_domain_name($infos4[1][0])){
             if(!preg_match("/arpa/", $infos4[1][0])){
                  echo "[Live Host] ".$infos4[1][0]." ==> ";
                  $i = sdata($infos4[1][0]);
                if($i['ip'] == "36.86.63.185"){
                  echo "Domain Has been Blocked\r\n";
                  search($i['url']);
                }else{
                  echo "Domain Safe\r\n";
                }
              }
            }

            if($infos1[1][0]){
                echo "[Live Host] ".$infos1[1][0]." ==> ";
                $i = sdata($infos1[1][0]);
              if($i['ip'] == "36.86.63.185"){
                echo "Domain Has been Blocked\r\n";
                search($i['url']);
              }else{
                echo "Domain Safe\r\n";
              }
            }
            if($infos2[1][0]){
              echo "[Live Host] ".$infos2[1][0]." ==> ";
                $i = sdata($infos2[1][0]);
              if($i['ip'] == "36.86.63.185"){
                echo "Domain Has been Blocked\r\n";
                $save = search($i['url']);
              }else{
                echo "Domain Safe\r\n";
              }
            }
            if($infos3[1][0]){
              echo "[Live Host] ".$infos3[1][0]." ==> ";
                $i = sdata($infos3[1][0]);
              if($i['ip'] == "36.86.63.185"){
                echo "Domain Has been Blocked\r\n";
                $save = search($i['url']);
              }else{
                echo "Domain Safe\r\n";
              }
            }
          }}}};
        }
        fclose($fh);
        $size = $currentSize;
    }
}
follow('D:\cap\asu.txt');
