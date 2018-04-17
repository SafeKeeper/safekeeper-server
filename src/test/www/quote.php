<?php 
  require_once('wp-includes/class-phpass.php');

  $quote = sgx_get_quote();

  $quote = str_replace(["\r", "\n", "\r\n"], '', $quote);

  $quote_header = "X-SafeKeeper-SGX-Quote: " . $quote;
  header( $quote_header );
?>
