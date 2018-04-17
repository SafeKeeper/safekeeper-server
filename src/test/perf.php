<?php 
  require_once('wp-includes/class-phpass.php');
  require_once('wp-includes/class-phpass-original.php');

  function generate_random_string($length) {
      $output = "";
      do {
          $output .= chr(rand(65,90));
      } while( --$length );
  }

  $wp_hasher_sgx = new PasswordHashSgx(8, TRUE);
  $wp_hasher = new PasswordHash(8, TRUE);

  $passwords = array();
  $pass_num = 1000;
  for( $i = 0; $i < $pass_num; $i++ ) {
      $passwords[$i] = generate_random_string(24);
  }

  print( "Hashed with phpass-original\n" );
  print( $wp_hasher->HashPassword("asd123456789") );

  $random_string = chr(rand(65,90)) . chr(rand(65,90)) . chr(rand(65,90)) . chr(rand(65,90)) . chr(rand(65,90));

  print( "\nHashed with phpass-sgx\n" );
  print( $wp_hasher_sgx->HashPassword("asd123456789") );

  print( "\n" );
  print( $random_string );

  $start = microtime(true);
  for( $i = 0; $i < $pass_num; $i++ ) {
      $wp_hasher_sgx->HashPassword($passwords[$i]);
  }
  $time_elapsed_secs = microtime(true) - $start;
  print( "\nWith SGX enabled PHPass: " . $time_elapsed_secs );

  $start = microtime(true);
  for( $i = 0; $i < $pass_num; $i++ ) {
      $wp_hasher->HashPassword($passwords[$i]);
  }
  $time_elapsed_secs = microtime(true) - $start;
  print( "\nDefault PHPass: " . $time_elapsed_secs );
  print( "\n" );
?>
