<?php
// Allow cross-origin requests
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

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
$username = isset($_POST['username']) ? $_POST['username'] : '';
$regNumber = isset($_POST['regNumber']) ? $_POST['regNumber'] : '';
$batch = isset($_POST['batch']) ? $_POST['batch'] : '';
$feelingsInput = isset($_POST['feelingsInput']) ? $_POST['feelingsInput'] : '';
$sentiment = isset($_POST['sentiment']) ? $_POST['sentiment'] : '';

// Check if optional keys are present in the $_POST data, otherwise set them to empty strings
$positive_count = isset($_POST['positive_count']) ? $_POST['positive_count'] : '';
$negative_count = isset($_POST['negative_count']) ? $_POST['negative_count'] : '';
$positive_percentage = isset($_POST['positive_percentage']) ? $_POST['positive_percentage'] : '';
$negative_percentage = isset($_POST['negative_percentage']) ? $_POST['negative_percentage'] : '';

// Initialize therapist advice (assuming it's not provided in the form)
$therapist_advice = '';

// Insert sentiment analysis data along with user information and timestamp into the database
$sql = "INSERT INTO analysis (batch, username, reg_number,feelingsInput, sentiment, positive_count, negative_count, positive_percentage, negative_percentage, therapist_advice, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";

// Prepare and bind the SQL statement
$stmt = $conn->prepare($sql);
$stmt->bind_param("ssssssssss", $batch, $username, $regNumber, $feelingsInput, $sentiment, $positive_count, $negative_count, $positive_percentage, $negative_percentage, $therapist_advice);

// Execute the statement
if ($stmt->execute()) {
    echo "Analysis data stored successfully";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

// Close the prepared statement and database connection
$stmt->close();
$conn->close();
?>
