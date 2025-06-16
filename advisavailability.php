<?php
include 'session_check.php';
session_start(); // Start the session

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Check if advisor_id is set in the session
if (!isset($_SESSION['advisor_id'])) {
    header('Location: login.html'); // Redirect to login page if not logged in
    exit();
}

$advisor_id = $_SESSION['advisor_id']; // Get advisor_id from the session
$advisor_id = trim($advisor_id); // Trim any leading or trailing spaces

// Database connection details
$host = "localhost";
$user = "root";
$pass = "";
$db = "fyp";

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch advisor details from the advisor table
$advisor_name = '';
if (!empty($advisor_id)) {
    $query = "SELECT advisor_name FROM advisor WHERE advisor_id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $advisor_id);
    $stmt->execute();
    $stmt->bind_result($advisor_name);
    $stmt->fetch();
    $stmt->close();

    // Check if advisor_name is empty
    if (empty($advisor_name)) {
        die("Error: advisor_id does not exist in the advisor table.");
    }
}

// Debugging statements to log the advisor_id and advisor_name
error_log("advisor_id: " . $advisor_id);
error_log("advisor_name: " . $advisor_name);

// Handle form submission for new availability
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['submit_availability'])) {
    $available_date = $_POST['available_date'];
    $available_time = $_POST['available_time'];

    $query = "INSERT INTO availability (advisor_id, advisor_name, available_date, available_time, is_booked) VALUES (?, ?, ?, ?, 0)";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ssss", $advisor_id, $advisor_name, $available_date, $available_time);
    if ($stmt->execute()) {
        echo "New availability added successfully.";
    } else {
        echo "Error: " . $stmt->error;
    }
    $stmt->close();
}

// Handle delete availability
if (isset($_POST['delete'])) {
    $delete_id = $_POST['delete_id'];
    $delete_query = "DELETE FROM availability WHERE id=?";
    $stmt = $conn->prepare($delete_query);
    $stmt->bind_param("i", $delete_id);
    $stmt->execute();
    $stmt->close();
}

// Handle edit availability (date and time)
if (isset($_POST['edit'])) {
    $edit_id = $_POST['edit_id'];
    $new_date = $_POST['new_date'];
    $new_time = $_POST['new_time'];

    $edit_query = "UPDATE availability SET available_date=?, available_time=? WHERE id=?";
    $stmt = $conn->prepare($edit_query);
    $stmt->bind_param("ssi", $new_date, $new_time, $edit_id);
    $stmt->execute();
    $stmt->close();
}

// Fetch all availability that is not booked
$availability_data = [];
$query = "SELECT id, advisor_id, advisor_name, available_date, available_time FROM availability WHERE advisor_id = ? AND is_booked = 0 ORDER BY available_date, available_time";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $advisor_id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $availability_data[] = $row;
}
$stmt->close();
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EduConsult - Advisor Availability</title>
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

        .btn-delete {
            background-color: #e74c3c;
        }

        .btn-edit {
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

        input, select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }

        input[readonly] {
            background-color: #f0f0f0;
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
            <a href="advismainpage.php">Dashboard</a>
            <a href="advisavailability.php">Appointments</a>
            <a href="history.php">History</a>
            <a href="advisprofile.php">Profile</a>
            <a href="logout.php">Logout</a>
        </nav>
    </header>

    <!-- Main Content -->
    <div class="container">
        <h1>Set Your Availability</h1>
        <!-- Advisor ID and Name Display -->
        <p><strong>Advisor ID:</strong> <?php echo htmlspecialchars($advisor_id); ?></p>
        <p><strong>Advisor Name:</strong> <?php echo htmlspecialchars($advisor_name); ?></p>

        <!-- Form to Add Availability -->
        <form method="POST">
            <div class="form-group">
                <label for="advisor_id">Advisor ID:</label>
                <input type="text" id="advisor_id" name="advisor_id" value="<?php echo htmlspecialchars($advisor_id); ?>" readonly>
            </div>
            <div class="form-group">
                <label for="advisor_name">Advisor Name:</label>
                <input type="text" id="advisor_name" name="advisor_name" value="<?php echo htmlspecialchars($advisor_name); ?>" readonly>
            </div>
            <div class="form-group">
                <label for="available_date">Available Date:</label>
                <input type="date" id="available_date" name="available_date" min="<?php echo date('Y-m-d'); ?>" required>
            </div>
            <div class="form-group">
                <label for="available_time">Available Time:</label>
                <input type="time" id="available_time" name="available_time" required>
            </div>
            <button type="submit" name="submit_availability">Submit Availability</button>
        </form>

        <!-- Display Availability -->
        <h2>Your Available Dates</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Advisor Name</th>
                    <th>Date</th>
                    <th>Time</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($availability_data as $data): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($data['id']); ?></td>
                        <td><?php echo htmlspecialchars($data['advisor_name']); ?></td>
                        <td><?php echo htmlspecialchars($data['available_date']); ?></td>
                        <td><?php echo htmlspecialchars($data['available_time']); ?></td>
                        <td>
                            <!-- Delete Form -->
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="delete_id" value="<?php echo $data['id']; ?>">
                                <button type="submit" name="delete" class="btn btn-delete" onclick="return confirm('Are you sure you want to delete this availability?');">Delete</button>
                            </form>
                            
                            <!-- Edit Modal Trigger -->
                            <button class="btn btn-edit" onclick="openEditModal(
                                '<?php echo $data['id']; ?>',
                                '<?php echo $data['available_date']; ?>',
                                '<?php echo $data['available_time']; ?>'
                            )">Edit</button>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Edit Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeEditModal()">&times;</span>
            <h2>Edit Availability</h2>
            <form method="POST">
                <input type="hidden" id="edit_id" name="edit_id">
                <div class="form-group">
                    <label for="new_date">New Date:</label>
                    <input type="date" id="new_date" name="new_date" min="<?php echo date('Y-m-d'); ?>" required>
                </div>
                <div class="form-group">
                    <label for="new_time">New Time:</label>
                    <input type="time" id="new_time" name="new_time" required>
                </div>
                <button type="submit" name="edit">Update Availability</button>
            </form>
        </div>
    </div>

    <script>
        function openEditModal(id, currentDate, currentTime) {
            document.getElementById('editModal').style.display = 'block';
            document.getElementById('edit_id').value = id;
            document.getElementById('new_date').value = currentDate;
            document.getElementById('new_time').value = currentTime;
        }

        function closeEditModal() {
            document.getElementById('editModal').style.display = 'none';
        }

        // Close modal if clicked outside
        window.onclick = function(event) {
            var modal = document.getElementById('editModal');
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }
    </script>
</body>
</html>