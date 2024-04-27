<?php
session_start(); // Start the session at the beginning of your script

// Establish a database connection (replace these values with your database credentials)
$host = "localhost";
$username = "root";
$password = "Sayeed$1504"; // Updated password
$database = "login credentials";
$port = 3306; // Updated port

$con = new mysqli($host, $username, $password, $database, $port);

// Check connection
if ($con->connect_error) {
    die("Connection failed: " . $con->connect_error);
}

if (isset($_POST['submit'])) {
    $email = mysqli_real_escape_string($con, $_POST['email']);
    $password = mysqli_real_escape_string($con, $_POST['password']);

    $result = mysqli_query($con, "SELECT * FROM users WHERE Email='$email' AND Password='$password'") or die("Select Error: " . mysqli_error($con));

    $row = mysqli_fetch_assoc($result);

    if ($row) {
        // $_SESSION['valid'] = $row['email'];
        $_SESSION['batch'] = $row['batch'];

        // You might want to store additional session variables if needed
        $_SESSION['username'] = $row['username'];
        $_SESSION['reg_number'] = $row['reg_number'];
        // $_SESSION['id'] = $row['id'];
        echo "<div class='box'>";
        echo "<p>Welcome, " . $_SESSION['username'] . "!</p>";
        echo "<p>Your Batch: " . $_SESSION['batch'] . "</p>";
        echo "<p>Registration Number: " . $_SESSION['reg_number'] . "</p>";
        echo "</div>";
       
        header("Location: http://127.0.0.1:5000");
        
        exit();
    } else {
        echo "<div class='box'>";
        echo "<p>Wrong Username or Password</p>";
        echo "<a href='http://127.0.0.1:5000/login' class='btn'>Go Back</a>";
        echo "</div>";
    }
}


?>

<style>
    .box {
        background: #069bff67;
        display: flex;
        flex-direction: column;
        padding: 25px 25px;
        border-radius: 20px;
        box-shadow: 0 0 128px 0 rgba(0,0,0,0.1),
                    0 32px 64px -48px rgba(0,0,0,0.5);
        font-size: 30px;
        color: black;
        text-align: center;
        text-decoration: none;
    }

    .btn {
        height: 35px;
        background: rgba(0, 165, 187, 0.808);
        border: 0;
        border-radius: 5px;
        color: #fff;
        font-size: 15px;
        cursor: pointer;
        transition: all .3s;
        margin-top: 10px;
        padding: 0px 10px; 
        text-decoration: none;
    }
</style>
