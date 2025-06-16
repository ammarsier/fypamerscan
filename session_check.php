<?php
$inactive = 600; // 10 minutes

if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $inactive)) {
    session_unset();
    session_destroy();
    header("Location: login.html");
    exit();
}
$_SESSION['last_activity'] = time();
?>
<!DOCTYPE html>
<html lang="en">
<script>
    let inactivityTime = function () {
        let time;
        const maxInactivity = 600000; // 10 minutes in milliseconds

        function logout() {
            // Send logout request to server
            fetch('logout.php')
                .then(() => {
                    alert("You have been logged out due to inactivity.");
                    window.location.href = "login.html"; // Redirect to login page
                });
        }

        function resetTimer() {
            clearTimeout(time);
            time = setTimeout(logout, maxInactivity);
        }

        // Activity events
        window.onload = resetTimer;
        document.onmousemove = resetTimer;
        document.onkeypress = resetTimer;
        document.onscroll = resetTimer;
        document.onclick = resetTimer;
    };

    inactivityTime();
</script>
</html>