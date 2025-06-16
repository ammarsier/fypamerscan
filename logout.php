<?php
session_start(); // Start the session

// Destroy the session
session_unset();
session_destroy();

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Redirect to login page
header("Location: login.html");
exit();
?>