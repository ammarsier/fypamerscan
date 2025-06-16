<?php
include 'session_check.php';
session_start(); // Start the session

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Check if admin is logged in
if (!isset($_SESSION['admin_id'])) {
    header('Location: login.php');
    exit();
}

// Declare DB connection variables
$host = "localhost";
$user = "root";
$pass = "";  // Enter your password if any
$db = "fyp";  // Database name

// Create connection with the database
$conn = new mysqli($host, $user, $pass, $db);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch advisors
$advisors = [];
$result = $conn->query("SELECT * FROM advisor");
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $advisors[] = $row;
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advisor Names</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            margin: 0;
            padding: 0;
            display: flex;
            height: 100vh;
        }

        header {
            background: #A32753;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 1.5rem;
            width: 100%;
            position: fixed;
            top: 0;
            z-index: 1000;
        }

        .sidebar {
            width: 220px;
            background: #2c3e50;
            color: white;
            height: 100%;
            padding-top: 60px;
            position: fixed;
            top: 0;
            left: 0;
            z-index: 999;
            transition: all 0.3s;
        }

        .sidebar a {
            display: block;
            color: white;
            padding: 15px 20px;
            text-decoration: none;
            transition: background 0.3s, padding-left 0.3s;
        }

        .sidebar a:hover {
            background-color: #34495e;
            padding-left: 30px;
        }

        .container {
            margin-left: 220px;
            padding: 80px 20px 20px 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            width: calc(100% - 220px);
            min-height: 100vh;
            transition: all 0.3s;
        }

        .table-container {
            max-width: 800px;
            margin: 0 auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        table th, table td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: center;
        }

        table th {
            background-color: #A32753;
            color: white;
        }

        table tr:nth-child(even) {
            background-color: #f9f9f9;
        }

        .btn{
            display: inline-block;
            margin-bottom: 20px;
            padding: 10px 15px;
            background-color: #A32753;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            text-align: center;
            transition: background 0.3s;
        }
        
        .logout-btn {
            display: block;
            margin: 20px;
            padding: 10px 15px;
            background-color: #A32753;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            text-align: center;
            transition: background 0.3s;
        }

        .btn:hover, .logout-btn:hover {
            background-color: #801E40;
        }

        h1 {
            font-size: 2rem;
            color: #333;
        }

        p {
            font-size: 1rem;
            color: #666;
        }
    </style>
</head>
<body>
    <header>Admin Dashboard</header>
    <div class="sidebar">
        <a href="adminstud.php">Student Names</a>
        <a href="adminadvis.php">Advisor Names</a>
        <a href="adminavail.php">Advisor Availability</a>
        <a href="adminapp.php">Student Appointments</a>
        <a href="adminassign.php">Assign Students</a>
        <a href="logout.php" class="logout-btn">Logout</a>
    </div>

    <div class="container">
        <a href="adminmainpage.php" class="btn">Back to Dashboard</a>
        <h1>Advisor Names</h1>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Advisor ID</th>
                        <th>Advisor Name</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($advisors as $advisor): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($advisor['advisor_id']); ?></td>
                        <td><?php echo htmlspecialchars($advisor['advisor_name']); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>