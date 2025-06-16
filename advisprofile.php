<?php
include 'session_check.php';
session_start(); // Start the session

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Check if user is logged in
if (!isset($_SESSION['UserID'])) {
    header('Location: Login.html'); // Redirect to login page if not logged in
    exit();
}

$user_id = $_SESSION['UserID']; // Get the UserID from session

// Database connection details
$host = "localhost";
$user = "root";
$pass = "";  // Enter your DB password if any
$db = "fyp";  // Database name

// Create connection
$conn = new mysqli($host, $user, $pass, $db);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch current profile data
$query = "SELECT * FROM advisor WHERE advisor_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$tutor_data = $result->fetch_assoc();

// Close connection
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="profile.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Raleway:wght@700&display=swap" rel="stylesheet">
    <title>Profile</title>
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
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            background: #fff;
            border-bottom: 2px solid #ddd;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            width: 100%;
            border-bottom: 2px solid #000;
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

        nav {
            display: flex;
            gap: 30px;
        }

        nav a {
            text-decoration: none;
            color: #333;
            font-weight: bold;
            transition: color 0.3s;
        }

        nav a:hover {
            color: #A32753;
        }

        .container {
            padding: 40px;
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 600px;
            margin-top: 40px;
        }

        h1 {
            font-size: 2.5rem;
            color: #A32753;
            margin-bottom: 20px;
            text-align: center;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 0 auto;
        }

        table th, table td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }

        table th {
            background-color: #A32753;
            color: #fff;
            width: 30%;
        }

        table tr:nth-child(even) {
            background-color: #f9f9f9;
        }

        .btn {
            display: inline-block;
            padding: 10px 15px;
            margin-top: 20px;
            background: #A32753;
            color: #fff;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }

        .btn:hover {
            background: #801E40;
        }
    </style>
</head>
<body>
    <!-- Header Section -->
    <header>
        <div class="logo">
            <img src="logouniten.png" alt="Logo">
            <span>EduConsult</span>
        </div>
        <nav>
            <a href="advismainpage.php">Dashboard</a>
            <a href="advisavailability.php">Appointments</a>
            <a href="history.php">History</a>
            <a href="advisprofile.php">Profile</a>
            <a href="logout.php">Logout</a>
        </nav>
    </header>

    <!-- Main Content Area -->
    <div class="container">
        <h1>Your Profile</h1>
        <table>
            <tr>
                <th>Name</th>
                <td><?php echo htmlspecialchars($tutor_data['advisor_name']); ?></td>
            </tr>
            <tr>
                <th>Email</th>
                <td><?php echo htmlspecialchars($tutor_data['email']); ?></td>
            </tr>
            <tr>
                <th>ID</th>
                <td><?php echo htmlspecialchars($tutor_data['advisor_id']); ?></td>
            </tr>
            <tr>
                <th>Password</th>
                <td>********</td> <!-- Password hidden -->
            </tr>
        </table>

        <a href="edit_advisprofile.php" class="btn">Edit Profile</a>
    </div>
</body>
</html>