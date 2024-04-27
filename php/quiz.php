<?php
// quiz.php

// Database connection details
$host = "localhost";
$username = "root";
$password = "Sayeed$1504";
$database = "login credentials";
$port = 3306;

// Create connection
$conn = new mysqli($host, $username, $password, $database, $port);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch user input data from the form
$reg_number = isset($_POST['reg_number']) ? $_POST['reg_number'] : '';
$answer1 = isset($_POST['q1']) ? $_POST['q1'] : '';
$answer2 = isset($_POST['q2']) ? $_POST['q2'] : '';
$answer3 = isset($_POST['q3']) ? $_POST['q3'] : '';
$answer4 = isset($_POST['q4']) ? $_POST['q4'] : '';
$answer5 = isset($_POST['q5']) ? $_POST['q5'] : '';

// Insert quiz data into the database
$sql = "INSERT INTO quiz (Student_id, answer1, answer2, answer3, answer4, answer5) 
        VALUES (?, ?, ?, ?, ?, ?)";

// Prepare and bind the SQL statement
$stmt = $conn->prepare($sql);
$stmt->bind_param("ssssss", $reg_number, $answer1, $answer2, $answer3, $answer4, $answer5);

// Execute the statement
if ($stmt->execute()) {
    header("Location: http://127.0.0.1:5000/quiz");
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

// Close the prepared statement and database connection
$stmt->close();
$conn->close();
?>
