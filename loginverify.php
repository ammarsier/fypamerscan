<?php
session_start();

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Initialize login attempts if not set
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}

// Check if max attempts reached
if ($_SESSION['login_attempts'] > 3) {
    echo "<script>alert('Too many failed attempts. Please try again later.'); window.location.href='login.html';</script>";
    exit();
}

// Retrieve form inputs
$userID = $_POST['id'];
$userPWD = $_POST['pass'];

// DB connection variables
$host = "localhost";
$user = "root";
$pass = "";
$db = "fyp";

// Create connection
$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

function verifyUser($conn, $query, $userID, $userPWD, $userRole, $passwordField, $redirectPage) {
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $userID);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $storedPassword = $row[$passwordField];
        
        if (password_verify($userPWD, $storedPassword)) {
            // Reset login attempts on success
            $_SESSION['login_attempts'] = 0;
            
            if (password_needs_rehash($storedPassword, PASSWORD_BCRYPT)) {
                $newHash = password_hash($userPWD, PASSWORD_BCRYPT);
                $updateStmt = $conn->prepare("UPDATE $userRole SET $passwordField = ? WHERE {$userRole}_id = ?");
                $updateStmt->bind_param("ss", $newHash, $userID);
                $updateStmt->execute();
                $updateStmt->close();
            }
            
            loginSuccess($row, $userRole, $redirectPage);
            $stmt->close();
            exit();
        } 
        elseif ($storedPassword === $userPWD) {
            $hashed = password_hash($userPWD, PASSWORD_BCRYPT);
            $updateStmt = $conn->prepare("UPDATE $userRole SET $passwordField = ? WHERE {$userRole}_id = ?");
            $updateStmt->bind_param("ss", $hashed, $userID);
            $updateStmt->execute();
            $updateStmt->close();
            
            // Reset login attempts on success
            $_SESSION['login_attempts'] = 0;
            loginSuccess($row, $userRole, $redirectPage);
            $stmt->close();
            exit();
        } 
        else {
            // Increment failed attempts
            $_SESSION['login_attempts']++;
            $remaining = 3 - $_SESSION['login_attempts'];
            echo "<script>alert('Wrong password! You have $remaining attempts remaining.'); window.history.back();</script>";
        }
    } else {
        // Increment failed attempts
        $_SESSION['login_attempts']++;
        $remaining = 3 - $_SESSION['login_attempts'];
        echo "<script>alert('User not found! You have $remaining attempts remaining.'); window.history.back();</script>";
    }
    
    $stmt->close();
}

// Function to handle successful login
function loginSuccess($row, $userRole, $redirectPage) {
    // Set session variables
    $_SESSION["UserID"] = $row["{$userRole}_id"];
    $_SESSION["UserName"] = $row["{$userRole}_name"];
    $_SESSION["UserRole"] = ucfirst($userRole);
    
    if ($userRole === "admin") {
        $_SESSION["admin_id"] = $row["admin_id"];
    } elseif ($userRole === "advisor") {
        $_SESSION["advisor_id"] = $row["advisor_id"];
    } elseif ($userRole === "student") {
        $_SESSION["student_id"] = $row["student_id"];
        $_SESSION["student_name"] = $row["student_name"];
    }
    
    header("Location: $redirectPage");
}

// Verify student credentials
verifyUser($conn, "SELECT * FROM student WHERE student_id = ?", $userID, $userPWD, "student", "pass", "mainpage.php");

// Verify advisor credentials
verifyUser($conn, "SELECT * FROM advisor WHERE advisor_id = ?", $userID, $userPWD, "advisor", "password", "advismainpage.php");

// Verify admin credentials
verifyUser($conn, "SELECT * FROM admin WHERE admin_id = ?", $userID, $userPWD, "admin", "password", "adminmainpage.php");

// If no matching user is found
echo "<p style='color:red;'>User does not exist!</p>";

// Close the connection
$conn->close();
?>