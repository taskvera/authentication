<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TaskveraAuth - Login</title>
    <style>
        /* Basic styling for the login form */
        body { 
            font-family: Arial, sans-serif; 
            background-color: #f4f4f4; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            height: 100vh; 
        }
        .login-container { 
            background-color: #fff; 
            padding: 20px; 
            border-radius: 5px; 
            box-shadow: 0 0 10px rgba(0,0,0,0.1); 
            width: 300px; 
        }
        h2 { 
            text-align: center; 
            margin-bottom: 20px; 
        }
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 10px; 
            margin: 5px 0 15px 0; 
            border: 1px solid #ccc; 
            border-radius: 3px; 
        }
        button { 
            width: 100%; 
            padding: 10px; 
            background-color: #28a745; 
            border: none; 
            border-radius: 3px; 
            color: #fff; 
            font-size: 16px; 
        }
        button:hover { 
            background-color: #218838; 
        }
        .error { 
            color: red; 
            text-align: center; 
            margin-bottom: 15px; 
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Login</h2>
        <?php if(isset($_GET['error'])): ?>
            <div class="error"><?php echo htmlspecialchars($_GET['error']); ?></div>
        <?php endif; ?>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
