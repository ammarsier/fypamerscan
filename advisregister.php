<?php
session_start();

// Prevent back button access after logout
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

$host = "localhost";
$user = "root";
$pass = "";
$db = "fyp";

// Create connection
$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . htmlspecialchars($conn->connect_error, ENT_QUOTES, 'UTF-8'));
}

// Function to validate password strength
function validatePassword($password) {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long";
    }
    
    if (!preg_match("/[A-Z]/", $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    
    if (!preg_match("/[a-z]/", $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    
    if (!preg_match("/[0-9]/", $password)) {
        $errors[] = "Password must contain at least one number";
    }
    
    if (!preg_match("/[^A-Za-z0-9]/", $password)) {
        $errors[] = "Password must contain at least one special character";
    }
    
    return $errors;
}

// Function to sanitize input
function sanitizeInput($data, $conn) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    $data = $conn->real_escape_string($data);
    return $data;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize and validate inputs
    $advisor_name = sanitizeInput($_POST['advisor_name'], $conn);
    $email = filter_var(sanitizeInput($_POST['email'], $conn), FILTER_SANITIZE_EMAIL);
    $advisor_id = sanitizeInput($_POST['advisor_id'], $conn);
    $password = $_POST['password']; // Don't sanitize password before hashing
    
    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['password_errors'] = ["Invalid email format"];
        header("Location: advisregister.php");
        exit();
    }
    
    // Validate password
    $passwordErrors = validatePassword($password);
    if (!empty($passwordErrors)) {
        $_SESSION['password_errors'] = $passwordErrors;
        header("Location: advisregister.php");
        exit();
    }
    
    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    // Prepare and execute SQL query using prepared statements
    $query = "INSERT INTO advisor (advisor_id, advisor_name, email, password) VALUES (?, ?, ?, ?)";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ssss", $advisor_id, $advisor_name, $email, $hashed_password);

    if ($stmt->execute()) {
        session_unset();
        $_SESSION['advisor_id'] = htmlspecialchars($advisor_id, ENT_QUOTES, 'UTF-8');
        $_SESSION['advisor_name'] = htmlspecialchars($advisor_name, ENT_QUOTES, 'UTF-8');
        header("Location: login.html");
        exit();
    } else {
        // Sanitize error message before output
        echo "Error: " . htmlspecialchars($stmt->error, ENT_QUOTES, 'UTF-8');
    }

    $stmt->close();
}

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
            background: linear-gradient(135deg, #FFF);
            color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-image: url('wave.png');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            height: 100vh;
            margin: 0;
            color: #fff;
        }

        .register-container {
            background: #4782c5;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }

        .register-container h1 {
            margin-bottom: 20px;
            font-size: 2rem;
            color: #FFF;
        }

        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #ddd;
        }

        .form-group input {
            width: 100%;
            padding: 10px;
            border: none;
            border-radius: 5px;
            outline: none;
            font-size: 1rem;
        }

        .form-group input:focus {
            box-shadow: 0 0 5px #A32753;
        }

        .register-btn {
            background: #000;
            color: #fff;
            border: none;
            padding: 10px;
            font-size: 1rem;
            font-weight: bold;
            width: 100%;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }

        .register-btn:hover {
            background: #801E40;
        }

        .footer-text {
            margin-top: 15px;
            font-size: 0.9rem;
            color: #bbb;
        }

        /* Password requirements styling */
        .password-requirements {
            margin: 10px 0;
            padding: 10px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 5px;
            color: #ddd;
            font-size: 0.8rem;
        }

        .password-requirements ul {
            margin-left: 20px;
            list-style-type: none;
        }

        .password-requirements li {
            margin-bottom: 5px;
            position: relative;
            padding-left: 20px;
        }

        .password-requirements li:before {
            content: "•";
            position: absolute;
            left: 5px;
        }

        .error-message {
            color: #ffcccc;
            margin: 5px 0;
            font-size: 0.8rem;
        }

        .requirement {
            color: #ddd;
        }

        .requirement.valid {
            color: #aaffaa;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h1>Sign up as Advisor</h1>
        <?php if (isset($_SESSION['password_errors'])): ?>
            <div class="error-message">
                <ul>
                    <?php foreach ($_SESSION['password_errors'] as $error): ?>
                        <li><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php unset($_SESSION['password_errors']); ?>
        <?php endif; ?>
        
        <form action="" method="POST" id="registrationForm" onsubmit="return validateForm()">
            <div class="form-group">
                <label for="advisor_name">Full Name</label>
                <input type="text" id="advisor_name" name="advisor_name" placeholder="Enter your full name" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" placeholder="Enter your email" required>
            </div>
            <div class="form-group">
                <label for="advisor_id">ID</label>
                <input type="text" id="advisor_id" name="advisor_id" placeholder="Enter your ID" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Create a password" required 
                       oninput="validatePassword()">
                <div id="passwordErrors" class="error-message"></div>
                <div class="password-requirements">
                    <strong>Password Requirements:</strong>
                    <ul>
                        <li id="length" class="requirement">At least 8 characters</li>
                        <li id="uppercase" class="requirement">At least one uppercase letter</li>
                        <li id="lowercase" class="requirement">At least one lowercase letter</li>
                        <li id="number" class="requirement">At least one number</li>
                        <li id="special" class="requirement">At least one special character</li>
                    </ul>
                </div>
            </div>
            
            <button type="submit" class="register-btn">Register</button>
            <br><br>
            <p class="footer-text">
                Already have an account? <a href="login.html" style="color:#fff;">Please Login</a>
            </p>
        </form>
    </div>

    <script>
        function validatePassword() {
            const password = document.getElementById('password').value;
            const errors = [];
            
            // Update requirement indicators
            document.getElementById('length').className = password.length >= 8 ? 'requirement valid' : 'requirement';
            document.getElementById('uppercase').className = /[A-Z]/.test(password) ? 'requirement valid' : 'requirement';
            document.getElementById('lowercase').className = /[a-z]/.test(password) ? 'requirement valid' : 'requirement';
            document.getElementById('number').className = /[0-9]/.test(password) ? 'requirement valid' : 'requirement';
            document.getElementById('special').className = /[^A-Za-z0-9]/.test(password) ? 'requirement valid' : 'requirement';
            
            // Client-side validation
            if (password.length < 8) errors.push("Password must be at least 8 characters long");
            if (!/[A-Z]/.test(password)) errors.push("Password must contain at least one uppercase letter");
            if (!/[a-z]/.test(password)) errors.push("Password must contain at least one lowercase letter");
            if (!/[0-9]/.test(password)) errors.push("Password must contain at least one number");
            if (!/[^A-Za-z0-9]/.test(password)) errors.push("Password must contain at least one special character");
            
            document.getElementById('passwordErrors').innerHTML = errors.length > 0 ? 
                '<ul><li>' + errors.join('</li><li>') + '</li></ul>' : '';
                
            return errors.length === 0;
        }
        
        function validateForm() {
            const isValid = validatePassword();
            if (!isValid) {
                // Show error message without submitting
                document.getElementById('passwordErrors').innerHTML = 
                    '<ul><li>Please follow all password requirements before submitting</li></ul>';
                return false;
            }
            return true;
        }
    </script>
</body>
</html>