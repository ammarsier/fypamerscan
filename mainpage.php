<?php
include 'session_check.php';
session_start(); // Start the session

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Check if user is logged in
if (!isset($_SESSION['UserID'])) {
    header('Location: login.html'); // Redirect to login page if not logged in
    exit();
}

$user_id = $_SESSION['UserID']; // Get user ID from the session

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

// Fetch booked appointments
$appointments = [];
$query = "SELECT advisor_name, appointment_date, appointment_time, status FROM appointments WHERE student_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $user_id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $appointments[] = $row;
}
$stmt->close();
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EduConsult</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: Arial, sans-serif;
        }

        body {
            background: #f8f9fa;
            color: #000;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            border-bottom: 2px solid #000;
            background-color: #fff;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            display: flex;
            align-items: center;
        }

        nav {
            display: flex;
            gap: 30px;
        }

        nav a {
            text-decoration: none;
            color: #000;
            font-weight: bold;
        }

        nav a:hover {
            color: #A32753;
        }

        .main-content {
            padding: 50px;
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 40px;
            flex-grow: 1;
        }

        .section {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .section h2 {
            margin-bottom: 10px;
            color: #A32753;
        }

        .btn {
            margin-top: 10px;
            display: inline-block;
            background: #A32753;
            color: #fff;
            padding: 10px 20px;
            border-radius: 5px;
            text-decoration: none;
        }

        .btn:hover {
            background: #801E40;
        }

        footer {
            text-align: center;
            padding: 20px;
            background-color: #000;
            color: #fff;
            margin-top: auto;
        }

        .popup {
            display: none;
            position: fixed;
            left: 50%;
            top: 50%;
            transform: translate(-50%, -50%);
            background-color: white;
            padding: 20px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            z-index: 1000;
            border-radius: 8px;
            width: 80%;
            max-width: 400px;
        }

        .popup h3 {
            margin-bottom: 10px;
        }

        .popup p {
            margin-bottom: 20px;
        }

        .popup .close-btn {
            display: inline-block;
            background: #A32753;
            color: #fff;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
        }

        .popup .close-btn:hover {
            background: #801E40;
        }

        .overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 999;
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header>
        <div class="logo">
            <img src="logouniten.png" alt="Logo" width="50" height="50">
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
    <section class="main-content">
        <div class="section">
            <h2>📅 Schedule an Appointment</h2>
            <p>Quickly book appointments with advisors.</p>
            <a href="appointment.php" class="btn">Schedule Now</a>
        </div>
        <div class="section">
            <h2>📊 View Your Advisory History</h2>
            <p>Track previous consultations and decisions.</p>
            <a href="studhistory.php" class="btn">View History</a>
        </div>

        <div class="section">
            <h2>🔒 Secure Platform</h2>
            <p>Your data is safe and protected with EduConsult.</p>
        </div>
    </section>

    <!-- Notification Popup -->
    <div class="overlay" id="overlay"></div>
    <div class="popup" id="notification-popup">
        <h3>Notifications</h3>
        <p>You have new notifications.</p>
        <a href="#" class="close-btn" id="close-popup">Close</a>
    </div>

    <!-- Footer -->
    <footer>
        <p>&copy; 2024 EduConsult. All Rights Reserved.</p>
    </footer>

    <script>
        document.getElementById('notification-btn').addEventListener('click', function() {
            document.getElementById('notification-popup').style.display = 'block';
            document.getElementById('overlay').style.display = 'block';
        });

        document.getElementById('close-popup').addEventListener('click', function() {
            document.getElementById('notification-popup').style.display = 'none';
            document.getElementById('overlay').style.display = 'none';
        });

        document.getElementById('overlay').addEventListener('click', function() {
            document.getElementById('notification-popup').style.display = 'none';
            document.getElementById('overlay').style.display = 'none';
        });
    </script>
</body>
</html>