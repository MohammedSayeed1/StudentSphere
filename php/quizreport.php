<?php
// Allow requests from any origin
header("Access-Control-Allow-Origin: *");
// Allow the following methods
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
// Allow the following headers
header("Access-Control-Allow-Headers: Origin, Content-Type, X-Auth-Token");

// Connect to your database
$servername = "localhost";
$username = "root";
$password = "Sayeed$1504";
$dbname = "login credentials";
$port = 3306;

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname, $port);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch data from your database
$sql = "SELECT * FROM quiz";
$result = $conn->query($sql);

$json_array = array();

if ($result) {
    // Check if any rows were returned
    if ($result->num_rows > 0) {
        // Fetch rows and add them to the $json_array
        while($row = $result->fetch_assoc()) {
            $json_array[] = $row;
        }
    } else {
        echo "No records found";
    }
} else {
    echo "Error: " . $conn->error;
}

// Close connection
$conn->close();

// Encode data to JSON format
echo json_encode($json_array);
?>
