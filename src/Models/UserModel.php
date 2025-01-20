<?php
namespace App\Models;

class UserModel
{
    public static function createUser($pdo, $id, $username, $plainPassword, $email)
    {
        // Argon2ID is recommended; you can pass options for memory_cost, time_cost, threads, etc.
        $hash = password_hash($plainPassword, PASSWORD_ARGON2ID);

        $sql = "INSERT INTO core_users (id, username, password_hash, email) 
                VALUES (:id, :username, :hash, :email)";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            'id'       => $id,  // supply your own ID or generate it
            'username' => $username,
            'hash'     => $hash,
            'email'    => $email,
        ]);

        return $stmt->rowCount() > 0;
    }
}
