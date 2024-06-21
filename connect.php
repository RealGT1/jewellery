<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
	if (isset($_POST['register'])) {
		// Registration logic
		$firstName = isset($_POST['firstName']) ? htmlspecialchars($_POST['firstName']) : '';
		$lastName = isset($_POST['lastName']) ? htmlspecialchars($_POST['lastName']) : '';
		$gender = isset($_POST['gender']) ? htmlspecialchars($_POST['gender']) : '';
		$email = isset($_POST['email']) ? htmlspecialchars($_POST['email']) : '';
		$password = isset($_POST['password']) ? $_POST['password'] : '';
		$confirmPassword = isset($_POST['confirm_password']) ? $_POST['confirm_password'] : '';
		$number = isset($_POST['number']) ? htmlspecialchars($_POST['number']) : '';

		// Check if passwords match
		if ($password !== $confirmPassword) {
			echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: red;">';
			echo '<p style="font-weight: bold;">Passwords do not match.</p>';
			echo '</div>';
			exit();
		}

		// Hash the password
		$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

		// Database connection
		$conn = new mysqli('localhost', 'root', '', 'test');
		if ($conn->connect_error) {
			die("Connection Failed: " . $conn->connect_error);
		} else {
			$stmt = $conn->prepare("INSERT INTO registration (firstName, lastName, gender, email, password, number) VALUES (?, ?, ?, ?, ?, ?)");

			if ($stmt) {
				$stmt->bind_param("ssssss", $firstName, $lastName, $gender, $email, $hashedPassword, $number);
				$execVal = $stmt->execute();

				if ($execVal) {
					$_SESSION['user'] = $firstName; // Store the user's name in the session
					echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: green;">';
					echo '<i class="lnr lnr-checkmark-circle"></i>';
					echo '<p style="font-weight: bold;">Registration successful...</p>';
					echo '</div>';
					// Redirect to index.html after 2 seconds
					echo '<meta http-equiv="refresh" content="2;url=index.html">';
				} else {
					echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: red;">';
					echo '<p style="font-weight: bold;">Error: ' . $stmt->error . '</p>';
					echo '</div>';
				}

				$stmt->close();
			} else {
				echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: red;">';
				echo '<p style="font-weight: bold;">Error: ' . $conn->error . '</p>';
				echo '</div>';
			}

			$conn->close();
		}
	} elseif (isset($_POST['login'])) {
		// Login logic
		$email = isset($_POST['email']) ? htmlspecialchars($_POST['email']) : '';
		$password = isset($_POST['password']) ? $_POST['password'] : '';

		// Database connection
		$conn = new mysqli('localhost', 'root', '', 'test');
		if ($conn->connect_error) {
			die("Connection Failed: " . $conn->connect_error);
		} else {
			$stmt = $conn->prepare("SELECT * FROM registration WHERE email = ?");
			$stmt->bind_param("s", $email);
			$stmt->execute();
			$result = $stmt->get_result();

			if ($result->num_rows > 0) {
				$row = $result->fetch_assoc();
				$storedPassword = $row['password'];

				// Check password
				if (password_verify($password, $storedPassword)) {
					$_SESSION['user'] = $row['firstName']; // Store the user's name in the session
					echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: green;">';
					echo '<i class="lnr lnr-checkmark-circle"></i>';
					echo '<p style="font-weight: bold;">Sign In successful...</p>';
					echo '</div>';
					// Redirect to index.html after 2 seconds
					echo '<meta http-equiv="refresh" content="2;url=index.html">';
				} else {
					echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: red;">';
					echo '<p style="font-weight: bold;">Incorrect password...</p>';
					echo '</div>';
				}
			} else {
				echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: red;">';
				echo '<p style="font-weight: bold;">Email not found...</p>';
				echo '</div>';
			}

			// Add error handling
			if ($stmt->error) {
				echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: red;">';
				echo '<p style="font-weight: bold;">Error: ' . $stmt->error . '</p>';
				echo '</div>';
			}

			$stmt->close();
			$conn->close();
		}
	} else {
		echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: red;">';
		echo '<p style="font-weight: bold;">Invalid request...</p>';
		echo '</div>';
	}
} else {
	echo '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; font-size: 3em; color: red;">';
	echo '<p style="font-weight: bold;">Invalid request...</p>';
	echo '</div>';
}
