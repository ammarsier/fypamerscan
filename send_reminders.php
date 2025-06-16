<?php
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

// Get current time and time 30 minutes from now
$current_time = new DateTime();
$reminder_time = (new DateTime())->modify('+30 minutes');

// Fetch appointments 30 minutes from now
$query = "SELECT a.student_id, s.email, s.student_name, a.advisor_name, a.appointment_date, a.appointment_time 
          FROM appointments a
          JOIN student s ON a.student_id = s.student_id
          WHERE a.appointment_date = ? AND a.appointment_time = ?";
$stmt = $conn->prepare($query);
$appointment_date = $reminder_time->format('Y-m-d');
$appointment_time = $reminder_time->format('H:i:s');
$stmt->bind_param("ss", $appointment_date, $appointment_time);
$stmt->execute();
$result = $stmt->get_result();

while ($row = $result->fetch_assoc()) {
    $student_id = $row['student_id'];
    $student_email = $row['email'];
    $student_name = $row['student_name'];
    $advisor_name = $row['advisor_name'];
    $appointment_date = $row['appointment_date'];
    $appointment_time = $row['appointment_time'];

    // Send reminder email
    $subject = "Appointment Reminder";
    $body = "Dear $student_name,\n\nThis is a reminder for your appointment with $advisor_name on $appointment_date at $appointment_time.\n\nBest Regards,\nEduConsult Team";
    mail($student_email, $subject, $body, "From: no-reply@educonsult.com");
}

$stmt->close();
$conn->close();