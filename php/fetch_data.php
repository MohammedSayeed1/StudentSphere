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
$password = "Sayeed$1504"; // Updated password
$dbname = "login credentials";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch data from your database
$sql = "SELECT * FROM analysis";
$result = mysqli_query($conn, $sql);

$json_array = array();

if ($result) {
    // Check if any rows were returned
    if ($result->num_rows > 0) {
        // Fetch rows and add them to the $json_array
        while($data = mysqli_fetch_assoc($result)) {
            $json_array[] = $data;
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
