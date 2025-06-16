<?php
session_start(); // Start the session

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Check if the form was submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['mark_done'])) {
    // Retrieve the appointment ID from the form
    $appointment_id = $_POST['appointment_id'];

    // Database connection
    $conn = new mysqli("localhost", "root", "", "fyp");
    if ($conn->connect_error) {
        die("Database connection failed: " . $conn->connect_error);
    }

    // Update the appointment status to 'done'
    $stmt = $conn->prepare("UPDATE appointments SET status = 'done' WHERE id = ?");
    $stmt->bind_param("i", $appointment_id);
    if ($stmt->execute()) {
        echo "<script>alert('Appointment marked as done successfully!');</script>";
    } else {
        echo "<script>alert('Error marking appointment as done: " . $stmt->error . "');</script>";
    }
    $stmt->close();
    $conn->close();

    // Redirect back to the advisor dashboard
    header("Location: advismainpage.php");
    exit();
}
?>
