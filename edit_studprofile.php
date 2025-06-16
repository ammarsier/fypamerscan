<?php
// Start session
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
$query = "SELECT * FROM student WHERE student_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$student_data = $result->fetch_assoc();

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $student_name = $_POST['student_name'];
    $email = $_POST['email'];
    $old_pass = $_POST['old_pass'];
    $new_pass = $_POST['new_pass'];

    // Verify the old password
    if ($old_pass === $student_data['pass']) {
        // Update profile data
        $update_query = "UPDATE student SET student_name = ?, email = ?, pass = ? WHERE student_id = ?";
        $update_stmt = $conn->prepare($update_query);
        $update_stmt->bind_param("ssss", $student_name, $email, $new_pass, $user_id);

        if ($update_stmt->execute()) {
            echo "<script>alert('Password changed successfully.');</script>";
            header('Location: studprofile.php'); // Redirect to profile page after update
            exit();
        } else {
            echo "<script>alert('Error updating profile: " . $conn->error . "');</script>";
        }
    } else {
        echo "<script>alert('Old password is incorrect.');</script>";
    }
}

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
    <title>Edit Profile</title>
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

        form {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        label {
            font-weight: bold;
        }

        input[type="text"], input[type="email"], input[type="password"] {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            width: 100%;
        }

        .btn {
            padding: 10px 15px;
            background: #A32753;
            color: #fff;
            text-decoration: none;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }

        .btn:hover {
            background: #801E40;
        }
    </style>
</head>
<body>
    <!-- Header Section -->
    <header class="header">
        <div class="logo">
            <img src="logouniten.png" alt="University Logo">
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

    <!-- Main Content Area -->
    <div class="container">
        <h1>Edit Profile</h1>
        <form method="post" action="">
            <input type="hidden" name="student_id" value="<?php echo htmlspecialchars($student_data['student_id']); ?>">

            <label for="student_name">Name</label>
            <input type="text" id="student_name" name="student_name" value="<?php echo htmlspecialchars($student_data['student_name']); ?>" required>

            <label for="email">Email</label>
            <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($student_data['email']); ?>" required>

            <label for="old_pass">Old Password</label>
            <input type="password" id="old_pass" name="old_pass" required>

            <label for="new_pass">New Password</label>
            <input type="password" id="new_pass" name="new_pass" required>

            <button type="submit" class="btn">Save Changes</button>
        </form>
    </div>
</body>
</html>