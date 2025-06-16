<?php
session_start();

// Check if CSRF token is valid
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF validation failed. Please reload the page.');
}

// Get user inputs
$id = $_POST['id'] ?? '';
$pass = $_POST['pass'] ?? '';

// Dummy validation example
$valid_id = 'student01';
$valid_pass = 'mypassword123';

// Simple validation for demo purposes (replace with DB in real app)
if ($id === $valid_id && $pass === $valid_pass) {
    echo "<h2>Login successful. Welcome, " . htmlspecialchars($id) . "!</h2>";
    // Redirect to dashboard or set session login flag
} else {
    echo "<h2>Login failed. Invalid ID or password.</h2>";
    echo "<a href='login.php'>Try again</a>";
}
?>
