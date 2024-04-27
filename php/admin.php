<?php
// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Define your database connection credentials
    $servername = "localhost"; // Change this to your database server hostname
    $username = "root"; // Change this to your database username
    $password = "Sayeed$1504"; // Change this to your database password
    $dbname = "login credentials"; // Change this to your database name
    $port = 3306; // Change this to your database port if needed

    // Create a database connection
    $conn = new mysqli($servername, $username, $password, $dbname, $port);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Escape user inputs for security
    $email = $conn->real_escape_string($_POST['email']);
    $password = $conn->real_escape_string($_POST['password']);

    // Query to check admin credentials
    $sql = "SELECT * FROM admin WHERE email='$email' AND password='$password'";
    $result = $conn->query($sql);

    // If a row is returned, admin credentials are valid
    if ($result->num_rows > 0) {
        // Start a session
        session_start();
        // Store admin email in session variable
        $_SESSION['admin_email'] = $email;
        // Redirect to admin panel or dashboard
        header("Location: http://127.0.0.1:5000/admindash"); // Change this to the URL of your admin panel page
        exit();
    } else {
        // Invalid credentials, display error message
        header("Location: http://127.0.0.1:5000/login");
    }

    // Close database connection
    $conn->close();
}
?>
