<?php 
  require_once('wp-includes/class-phpass.php');

  print( "Submitted. " );
  $user = $_POST["user"];

  print( "Got password: " . $user["password"] . "<br>" );
  
  // print_r( $user["password"] );

  // "12345678" - salt
  print( "CMAC: " . sgx_cmac( $user["password"] + "12345678" ) );

?>
