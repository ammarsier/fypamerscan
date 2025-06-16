<?php
include 'session_check.php';
session_start(); // Start the session

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Check if student_id is set in the session
if (!isset($_SESSION['student_id'])) {
    die("Error: student_id is not set in the session.");
}

$student_id = $_SESSION['student_id']; // Get student_id from the session
$student_id = trim($student_id); // Trim any leading or trailing spaces

// Database connection details
$host = "localhost";
$user = "root";
$pass = "";
$db = "fyp";

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch completed sessions for the student (where status = 'done')
$completed_sessions = [];
$query = "SELECT id, advisor_name, appointment_date, appointment_time, notes FROM appointments WHERE student_id = ? AND status = 'done' ORDER BY appointment_date, appointment_time";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $student_id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $completed_sessions[] = $row;
}
$stmt->close();
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EduConsult - Student History</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: Arial, sans-serif;
        }

        body {
            background: #f4f4f9;
            color: #000;
            min-height: 100vh;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            background: #fff;
            border-bottom: 2px solid #ddd;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .logo {
            display: flex;
            align-items: center;
            font-size: 1.5rem;
            font-weight: bold;
        }

        .logo img {
            margin-right: 10px;
            width: 50px;
            height: 50px;
        }

        nav a {
            text-decoration: none;
            color: #333;
            font-weight: bold;
            margin-right: 15px;
            transition: color 0.3s;
        }

        nav a:hover {
            color: #A32753;
        }

        .container {
            padding: 40px;
        }

        h1, h2 {
            font-size: 2.5rem;
            color: #A32753;
            margin-bottom: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            table-layout: fixed; /* Ensure the table columns are of equal width */
        }

        table th, table td {
            border: 1px solid #ddd;
            padding: 15px;
            text-align: center;
            word-wrap: break-word; /* Allow long words to break */
        }

        table th {
            background-color: #A32753;
            color: #fff;
        }

        .btn {
            padding: 5px 15px;
            color: #fff;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            margin: 0 5px;
            display: inline-block;
        }

        .btn-note {
            background-color: #3498db;
        }

        form {
            margin-top: 20px;
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .form-group {
            margin-bottom: 15px;
        }

        label {
            display: block;
            font-weight: bold;
            margin-bottom: 5px;
        }

        input, textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }

        textarea {
            resize: vertical;
        }

        button {
            background-color: #A32753;
            color: #fff;
            padding: 10px 15px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        button:hover {
            background-color: #82213F;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
        }

        .modal-content {
            background-color: #fefefe;
            margin: 15% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 80%;
            max-width: 500px;
            border-radius: 8px;
        }

        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }

        .close:hover {
            color: black;
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header>
        <div class="logo">
            <img src="logouniten.png" alt="Logo">
            <span>EduConsult</span>
        </div>
        <nav>
            <a href="mainpage.php">Dashboard</a>
            <a href="appointment.php">Appointments</a>
            <a href="studhistory.php">History</a>
            <a href="studprofile.php">Profile</a>
            <a href="logout.php">Logout</a>
        </nav>
    </header>

    <!-- Main Content -->
    <div class="container">
        <h1>Completed Sessions</h1>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Advisor Name</th>
                    <th>Date</th>
                    <th>Time</th>
                    <th>Notes</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($completed_sessions as $session): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($session['id']); ?></td>
                        <td><?php echo htmlspecialchars($session['advisor_name']); ?></td>
                        <td><?php echo htmlspecialchars($session['appointment_date']); ?></td>
                        <td><?php echo htmlspecialchars($session['appointment_time']); ?></td>
                        <td><?php echo htmlspecialchars($session['notes']); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>