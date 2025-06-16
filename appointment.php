<?php
include 'session_check.php'; // Include session check
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

// Initialize variables for advisor and availability data
$advisor_id = '';
$advisor_name = '';
$availability_data = [];
$advisor_assigned = false;

if (isset($_SESSION['student_name']) && isset($_SESSION['student_id'])) {
    $student_id = $_SESSION['student_id'];
    
    // Fetch the assigned advisor for the student
    $query = "SELECT a.advisor_id, a.advisor_name 
              FROM advisor a 
              JOIN advisor_student ast ON a.advisor_id = ast.advisor_id 
              WHERE ast.student_id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $student_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $advisor = $result->fetch_assoc();
    $stmt->close();

    if ($advisor) {
        $advisor_id = $advisor['advisor_id'];
        $advisor_name = $advisor['advisor_name'];
        $advisor_assigned = true;

        // Fetch the availability of the assigned advisor
        $query = "SELECT id, advisor_id, advisor_name, available_date, available_time 
                  FROM availability 
                  WHERE advisor_id = ? AND is_booked = 0 
                  ORDER BY available_date, available_time";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("s", $advisor_id);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $availability_data[] = $row;
        }
        $stmt->close();
    }
}

// Fetch booked appointments for the student
$booked_appointments = [];
$query = "SELECT id, advisor_id, advisor_name, appointment_date, appointment_time, status 
          FROM appointments 
          WHERE student_id = ? AND status = 'pending' 
          ORDER BY appointment_date, appointment_time";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $student_id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $booked_appointments[] = $row;
}
$stmt->close();

$conn->close();

// Handle appointment booking
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['book_appointment'])) {
    // Retrieve student details from session
    $student_name = $_SESSION['student_name'];
    $student_id = $_SESSION['student_id'];
    $advisor_id = $_POST['advisor_id'];
    $advisor_name = $_POST['advisor_name'];
    $appointment_date = $_POST['appointment_date'];
    $appointment_time = $_POST['appointment_time'];
    $availability_id = $_POST['availability_id'];

    // Database connection
    $conn = new mysqli($host, $user, $pass, $db);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Insert into appointments table
    $query = "INSERT INTO appointments (student_name, student_id, advisor_id, advisor_name, appointment_date, appointment_time, status) 
              VALUES (?, ?, ?, ?, ?, ?, 'pending')";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ssssss", $student_name, $student_id, $advisor_id, $advisor_name, $appointment_date, $appointment_time);
    if ($stmt->execute()) {
        // Update availability to mark as booked
        $update_query = "UPDATE availability SET is_booked = 1 WHERE id = ?";
        $update_stmt = $conn->prepare($update_query);
        $update_stmt->bind_param("i", $availability_id);
        $update_stmt->execute();
        $update_stmt->close();

        echo "<script>alert('Appointment successfully booked!'); window.location.href = window.location.href;</script>";
    } else {
        echo "<script>alert('Error booking appointment.');</script>";
    }
    $stmt->close();
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Advisor Availability</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            margin: 0;
            padding: 0;
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

        .container {
            margin: 30px auto;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            max-width: 900px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); /* Add shadow to table */
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

        button {
            padding: 8px 15px;
            background-color: #A32753;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }

        button:hover {
            background-color: #801E40;
        }

        .back-btn {
            display: inline-block;
            margin-bottom: 20px;
            padding: 10px 15px;
            background-color: #A32753;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            text-align: center;
        }

        .back-btn:hover {
            background-color: #801E40;
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

    <div class="container">
        <a href="mainpage.php" class="back-btn">Back to Main Page</a> <!-- Back to Main Page Button -->
        <h2>Available Advisors</h2>
        <table>
            <thead>
                <tr>
                    <th>Advisor ID</th>
                    <th>Advisor Name</th>
                    <th>Date</th>
                    <th>Time</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php if (!$advisor_assigned): ?>
                    <tr>
                        <td colspan="5">You are not assigned to any advisor yet.</td>
                    </tr>
                <?php elseif (empty($availability_data)): ?>
                    <tr>
                        <td colspan="5">Your advisor hasn't set any availability yet.</td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($availability_data as $data): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($data['advisor_id']); ?></td>
                        <td><?php echo htmlspecialchars($data['advisor_name']); ?></td>
                        <td><?php echo htmlspecialchars($data['available_date']); ?></td>
                        <td><?php echo htmlspecialchars($data['available_time']); ?></td>
                        <td>
                            <!-- Appointment Booking Form -->
                            <form method="POST">
                                <input type="hidden" name="advisor_id" value="<?php echo $data['advisor_id']; ?>">
                                <input type="hidden" name="advisor_name" value="<?php echo $data['advisor_name']; ?>">
                                <input type="hidden" name="appointment_date" value="<?php echo $data['available_date']; ?>">
                                <input type="hidden" name="appointment_time" value="<?php echo $data['available_time']; ?>">
                                <input type="hidden" name="availability_id" value="<?php echo $data['id']; ?>">
                                <button type="submit" name="book_appointment">Book Appointment</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>

        <!-- Booked Appointments -->
        <h2>📅 Your Booked Appointments</h2>
        <table>
            <thead>
                <tr>
                    <th>Advisor Name</th>
                    <th>Date</th>
                    <th>Time</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($booked_appointments)): ?>
                    <tr>
                        <td colspan="4">You have no booked appointments.</td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($booked_appointments as $appointment): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($appointment['advisor_name']); ?></td>
                        <td><?php echo htmlspecialchars($appointment['appointment_date']); ?></td>
                        <td><?php echo htmlspecialchars($appointment['appointment_time']); ?></td>
                        <td><?php echo ucfirst($appointment['status']); ?></td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</body>
</html>