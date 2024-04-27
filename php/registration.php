<?php
// registration.php

$host = "localhost";
$username = "root";
$password = "Sayeed$1504"; // Updated password
$database = "login credentials";
$port = 3306; // Updated port

$conn = new mysqli($host, $username, $password, $database, $port);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["username"];
    $email = $_POST["email"];
    $reg_number = $_POST["reg_number"];
    $password = $_POST["password"];
    $batch = $_POST["batch"];
    
    $sql = "INSERT INTO users (username, email, reg_number, password, batch) VALUES ('$username', '$email', '$reg_number', '$password', '$batch')";
    if ($conn->query($sql) === TRUE) {
        $_SESSION['reg_number'] = $reg_number;
        echo "<div class='box'>Registration successful! <a href='http://127.0.0.1:5000/login' class='btn'>Login Now</a></div>";
        echo "<div class='success'>Click Login to redirect to the login page.</div>";
    } else {
        echo "Error: " . $sql . "<br>" . $conn->error;
    }
}

$conn->close();
?>
<style>
    .box{
        background: #069bff67;
        display: flex;
        flex-direction: column;
        padding: 25px 25px;
        border-radius: 20px;
        box-shadow: 0 0 128px 0 rgba(0,0,0,0.1),
                    0 32px 64px -48px rgba(0,0,0,0.5);
        font-size: 20px;
        color: black;
        text-align: center;
        text-decoration: none;
        margin-bottom: 10px;
    }
    .success{
        font-size: 16px;
        font-weight: bold;
    }
    .btn{
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
        display: inline-block;
    }
</style>
