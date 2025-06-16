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

// Fetch students who are not assigned to an advisor
$students = [];
$result = $conn->query("SELECT * FROM student WHERE student_id NOT IN (SELECT student_id FROM advisor_student)");
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $students[] = $row;
    }
}

// Fetch advisors
$advisors = [];
$result = $conn->query("SELECT * FROM advisor");
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $advisors[] = $row;
    }
}

// Fetch assigned students and advisors
$assigned = [];
$result = $conn->query("SELECT s.student_name, a.advisor_name FROM advisor_student asr JOIN student s ON asr.student_id = s.student_id JOIN advisor a ON asr.advisor_id = a.advisor_id");
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $assigned[] = $row;
    }
}

// Handle form submission for assigning students to advisors
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['assign'])) {
    $student_id = $_POST['student_id'];
    $advisor_id = $_POST['advisor_id'];

    // Check if the student exists
    $stmt = $conn->prepare("SELECT * FROM student WHERE student_id = ?");
    $stmt->bind_param("s", $student_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows == 0) {
        $message = "<p style='color:red;'>Error: Student does not exist.</p>";
    } else {
        // Check if the advisor exists
        $stmt = $conn->prepare("SELECT * FROM advisor WHERE advisor_id = ?");
        $stmt->bind_param("s", $advisor_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows == 0) {
            $message = "<p style='color:red;'>Error: Advisor does not exist.</p>";
        } else {
            // Insert a new assignment
            $stmt = $conn->prepare("INSERT INTO advisor_student (advisor_id, student_id) VALUES (?, ?)");
            $stmt->bind_param("ss", $advisor_id, $student_id);

            try {
                if ($stmt->execute()) {
                    $message = "<p style='color:green;'>Student assigned to advisor successfully!</p>";

                    // Refresh the student list to remove the assigned student
                    $students = [];
                    $result = $conn->query("SELECT * FROM student WHERE student_id NOT IN (SELECT student_id FROM advisor_student)");
                    if ($result) {
                        while ($row = $result->fetch_assoc()) {
                            $students[] = $row;
                        }
                    }

                    // Refresh the assigned list to include the new assignment
                    $assigned = [];
                    $result = $conn->query("SELECT s.student_name, a.advisor_name FROM advisor_student asr JOIN student s ON asr.student_id = s.student_id JOIN advisor a ON asr.advisor_id = a.advisor_id");
                    if ($result) {
                        while ($row = $result->fetch_assoc()) {
                            $assigned[] = $row;
                        }
                    }
                } else {
                    $message = "<p style='color:red;'>Error assigning student to advisor!</p>";
                }
            } catch (mysqli_sql_exception $e) {
                $message = "<p style='color:red;'>Error assigning student to advisor: " . $e->getMessage() . "</p>";
            }

            $stmt->close();
        }
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Assign Students to Advisors</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            margin: 0;
            padding: 0;
            display: flex;
            height: 100vh;
            flex-direction: column;
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

        .table-container, .assigned-container {
            max-width: 800px;
            margin: 0 auto;
        }

        table {
            width: 100%;
            max-width: 600px;
            margin: 0 auto;
            border-collapse: collapse;
            margin-top: 20px;
        }

        table th, table td {
            border: 1px solid #ddd;
            padding: 8px;
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

        h2 {
            font-size: 2rem;
            color: #333;
            text-align: center;
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
        <h1>Assign Students to Advisors</h1>
        <div class="table-container">
            <form method="POST" action="">
                <table>
                    <thead>
                        <tr>
                            <th>Select Student</th>
                            <th>Select Advisor</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>
                                <select name="student_id" id="student_id" required>
                                    <?php foreach ($students as $student): ?>
                                        <option value="<?php echo $student['student_id']; ?>">
                                            <?php echo htmlspecialchars($student['student_name']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </td>
                            <td>
                                <select name="advisor_id" id="advisor_id" required>
                                    <?php foreach ($advisors as $advisor): ?>
                                        <option value="<?php echo $advisor['advisor_id']; ?>">
                                            <?php echo htmlspecialchars($advisor['advisor_name']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </td>
                            <td>
                                <button type="submit" name="assign">Assign</button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </form>
        </div>
        <?php if (isset($message)) echo $message; ?>
        <div class="assigned-container">
            <h2>Assigned Students and Advisors</h2>
            <table>
                <thead>
                    <tr>
                        <th>Student Name</th>
                        <th>Advisor Name</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($assigned as $assignment): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($assignment['student_name']); ?></td>
                            <td><?php echo htmlspecialchars($assignment['advisor_name']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>