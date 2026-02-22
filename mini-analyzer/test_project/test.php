<?php
$vulnCode = $_GET['code'];
eval($vulnCode);

$id = $_GET['id'];
$conn->query("SELECT * FROM users WHERE id = $_GET['id']");

mysql_query("SELECT * FROM users WHERE id = $id");

$pass = md5("password123");
?>
