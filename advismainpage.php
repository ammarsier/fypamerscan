<?php
session_start(); // Start the session

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Check if the user is logged in
if (!isset($_SESSION['advisor_id'])) {
    header('Location: login.html'); // Redirect to login page if not logged in
    exit();
}

// Assumes advisor_id and advisor_name are stored in the session
$advisor_id = $_SESSION['advisor_id'] ?? '';
$advisor_name = $_SESSION['advisor_name'] ?? '';

// Optional: Validate the session variables or fetch from the database if not set
if (empty($advisor_name)) {
    $conn = new mysqli("localhost", "root", "", "fyp");
    if ($conn->connect_error) {
        die("Database connection failed: " . $conn->connect_error);
    }

    $stmt = $conn->prepare("SELECT advisor_name FROM advisor WHERE advisor_id = ?");
    $stmt->bind_param("s", $advisor_id);
    $stmt->execute();
    $stmt->bind_result($retrieved_name);
    if ($stmt->fetch()) {
        $advisor_name = $retrieved_name;
        $_SESSION['advisor_name'] = $advisor_name; // Store in session for future use
    }
    $stmt->close();
    $conn->close();
}

// Fetch upcoming appointments for the advisor
$conn = new mysqli("localhost", "root", "", "fyp");
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$upcoming_appointments = [];
$completed_appointments = [];
$stmt = $conn->prepare("SELECT id, student_id, student_name, appointment_date, appointment_time, status FROM appointments WHERE advisor_id = ? ORDER BY appointment_date, appointment_time");
$stmt->bind_param("s", $advisor_id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    if ($row['status'] == 'done') {
        $completed_appointments[] = $row;
    } else {
        $upcoming_appointments[] = $row;
    }
}
$stmt->close();

// Fetch the latest three completed appointments for the history section
$latest_completed_appointments = array_slice($completed_appointments, -3, 3);

// Fetch meeting progress for the advisor's students
$meeting_progress = [];
$current_semester = 'Spring 2025'; // Example semester
$stmt = $conn->prepare("SELECT student_id, student_name, meeting_count FROM meeting_progress WHERE advisor_id = ? AND semester = ?");
$stmt->bind_param("ss", $advisor_id, $current_semester);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $meeting_progress[$row['student_id']] = $row;
}
$stmt->close();
$conn->close();

// Debugging: Log the upcoming appointments and meeting progress
error_log("Upcoming Appointments: " . print_r($upcoming_appointments, true));
error_log("Completed Appointments: " . print_r($completed_appointments, true));
error_log("Meeting Progress: " . print_r($meeting_progress, true));

// Handle appointment status update
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['mark_done'])) {
    $appointment_id = $_POST['appointment_id'];
    $student_id = $_POST['student_id'];
    $student_name = $_POST['student_name'];

    $conn = new mysqli("localhost", "root", "", "fyp");
    if ($conn->connect_error) {
        die("Database connection failed: " . $conn->connect_error);
    }

    // Update the appointment status
    $stmt = $conn->prepare("UPDATE appointments SET status = 'done' WHERE id = ?");
    $stmt->bind_param("i", $appointment_id);
    if ($stmt->execute()) {
        // Update the meeting progress
        $stmt = $conn->prepare("INSERT INTO meeting_progress (student_id, student_name, advisor_id, meeting_count, semester) VALUES (?, ?, ?, 1, ?) ON DUPLICATE KEY UPDATE meeting_count = meeting_count + 1");
        $stmt->bind_param("ssss", $student_id, $student_name, $advisor_id, $current_semester);
        $stmt->execute();
        echo "<script>alert('Appointment marked as done successfully!');</script>";
    } else {
        echo "<script>alert('Error marking appointment as done.');</script>";
    }
    $stmt->close();
    $conn->close();

    // Refresh the page to reflect changes
    header("Location: advismainpage.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EduConsult - Advisor Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: Arial, sans-serif;
        }

        body {
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            background:rgb(244, 244, 249);
            color: #000;
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
            flex: 1;
            padding: 40px;
        }

        h1 {
            font-size: 2.5rem;
            color: #A32753;
            margin-bottom: 20px;
        }

        .section {
            margin-bottom: 30px;
            background: #fff;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .section h2 {
            font-size: 1.5rem;
            margin-bottom: 15px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        table th, table td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }

        table th {
            background-color: #A32753;
            color: #fff;
        }

        table tr:nth-child(even) {
            background-color:rgb(249, 249, 249);
        }

        .btn {
            display: inline-block;
            padding: 10px 15px;
            margin-top: 10px;
            background: #A32753;
            color: #fff;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }

        .btn:hover {
            background: #801E40;
        }

        .status-done {
            color: green;
            font-weight: bold;
        }

        .status-pending {
            color: orange;
            font-weight: bold;
        }

        footer {
            text-align: center;
            padding: 15px;
            background-color: #333;
            color: #fff;
            margin-top: 40px;
        }

        .progress-bar {
            width: 100%;
            background-color: #ddd;
            border-radius: 5px;
            margin-top: 10px;
        }

        .progress {
            height: 20px;
            background-color: #A32753;
            border-radius: 5px;
            text-align: center;
            color: white;
            line-height: 20px;
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
            <a href="advismainpage.php">Dashboard</a>
            <a href="advisavailability.php">Appointments</a>
            <a href="history.php">History</a>
            <a href="advisprofile.php">Profile</a>
            <a href="logout.php">Logout</a>
        </nav>
    </header>

    <!-- Main Content -->
    <div class="container">
        <!-- Overview Section -->
        <section class="section">
            <h1>Welcome, <?php echo htmlspecialchars($advisor_name); ?>!</h1>
            <p>Manage your appointments, track student advisories, and organize schedules.</p>
        </section>

        <!-- Upcoming Appointments -->
        <section class="section">
            <h2>📅 Upcoming Appointments</h2>
            <table>
                <thead>
                    <tr>
                        <th>Student Name</th>
                        <th>Date</th>
                        <th>Time</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($upcoming_appointments)): ?>
                        <tr>
                            <td colspan="5">No upcoming appointments.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($upcoming_appointments as $appointment): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($appointment['student_name']); ?></td>
                                <td><?php echo htmlspecialchars($appointment['appointment_date']); ?></td>
                                <td><?php echo htmlspecialchars($appointment['appointment_time']); ?></td>
                                <td>
                                    <span class="<?php echo ($appointment['status'] == 'done') ? 'status-done' : 'status-pending'; ?>">
                                        <?php echo ucfirst($appointment['status']); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if ($appointment['status'] == 'pending'): ?>
                                        <form method="POST" action="advismainpage.php">
                                            <input type="hidden" name="appointment_id" value="<?php echo $appointment['id']; ?>">
                                            <input type="hidden" name="student_id" value="<?php echo htmlspecialchars($appointment['student_id']); ?>">
                                            <input type="hidden" name="student_name" value="<?php echo htmlspecialchars($appointment['student_name']); ?>">
                                            <button type="submit" name="mark_done" class="btn">Mark as Done</button>
                                        </form>
                                    <?php else: ?>
                                        <span class="status-done">Completed</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </section>

        <!-- Meeting Progress -->
        <section class="section">
            <h2>📈 Meeting Progress</h2>
            <table>
                <thead>
                    <tr>
                        <th>Student Name</th>
                        <th>Meeting Count</th>
                        <th>Progress</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($meeting_progress)): ?>
                        <tr>
                            <td colspan="3">No meeting progress data available.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($meeting_progress as $progress): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($progress['student_name']); ?></td>
                                <td><?php echo htmlspecialchars($progress['meeting_count']); ?></td>
                                <td>
                                    <?php
                                    $progress_percentage = ($progress['meeting_count'] / 3) * 100;
                                    ?>
                                    <div class="progress-bar">
                                        <div class="progress" style="width: <?php echo $progress_percentage; ?>%;">
                                            <?php echo $progress['meeting_count']; ?>/3
                                        </div>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </section>

        <!-- Completed Appointments (History) -->
        <section class="section">
            <h2>📜 History</h2>
            <table>
                <thead>
                    <tr>
                        <th>Student Name</th>
                        <th>Date</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($latest_completed_appointments)): ?>
                        <tr>
                            <td colspan="3">No completed appointments.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($latest_completed_appointments as $appointment): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($appointment['student_name']); ?></td>
                                <td><?php echo htmlspecialchars($appointment['appointment_date']); ?></td>
                                <td><?php echo htmlspecialchars($appointment['appointment_time']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </section>
    </div>

    <!-- Footer -->
    <footer>
        <p>&copy; 2024 EduConsult. All Rights Reserved.</p>
    </footer>
</body>
</html>