<?php
session_start();

// Check if student_id is set in the session
if (!isset($_SESSION['student_id'])) {
    die("Error: student_id is not set in the session.");
}

$student_id = $_SESSION['student_id']; // Get student_id from the session

// Database credentials
$host = "localhost";
$user = "root";
$pass = "";
$db = "fyp";

// Database connection
$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch unread notifications for the student
$query = "SELECT message FROM notifications WHERE student_id = ? AND is_read = 0";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $student_id);
$stmt->execute();
$result = $stmt->get_result();

$notifications = [];
while ($row = $result->fetch_assoc()) {
    $notifications[] = $row;
}

$stmt->close();
$conn->close();

echo json_encode($notifications);
?>