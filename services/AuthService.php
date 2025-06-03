<?php
require_once __DIR__ . '/DatabaseService.php';
require_once __DIR__ . '/TokenService.php';

class AuthService
{
    private $db;

    public function __construct()
    {
        $this->db = DatabaseService::getInstance();
    }

    /**
     * Crée un nouvel utilisateur.
     */
    public function createUser(string $username, string $email, string $password): bool
    {
        // Hash du mot de passe
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        // Insertion utilisateur
        $this->db->insert('users', [
            'username' => $username,
            'email' => $email,
            'password_hash' => $passwordHash,
            'role' => 'user',
            'email_verified' => 0
        ]);

        return $this->db->id() !== null;
    }

    /**
     * Vérifie qu’un utilisateur ou un email n’existe pas déjà.
     */
    public function userOrEmailExists(string $username, string $email): bool
    {
        return $this->db->has('users', [
            'OR' => [
                'username' => $username,
                'email' => $email
            ]
        ]);
    }

    /**
     * Vérifie les identifiants utilisateur (login).
     * Retourne le user si OK, sinon false.
     */
    public function verifyCredentials(string $usernameOrEmail, string $password)
    {
        $user = $this->db->get('users', '*', [
            'OR' => [
                'username' => $usernameOrEmail,
                'email' => $usernameOrEmail
            ]
        ]);

        if ($user && password_verify($password, $user['password_hash'])) {
            return $user;
        }
        return false;
    }

    /**
     * Génère et stocke un token de vérification d'email pour un utilisateur.
     * Retourne le token généré.
     */
    public function createEmailVerificationToken(int $userId): string
    {
        $token = TokenService::generateToken(64);
        $expiresAt = date('Y-m-d H:i:s', strtotime('+1 day'));

        $this->db->delete('email_verification_tokens', ['user_id' => $userId]);
        $this->db->insert('email_verification_tokens', [
            'user_id' => $userId,
            'token' => $token,
            'expires_at' => $expiresAt
        ]);
        return $token;
    }

    /**
     * Vérifie un token de vérification d'email.
     * Retourne true si validé, false sinon.
     */
    public function verifyEmailToken(string $token): bool
    {
        $record = $this->db->get('email_verification_tokens', ['user_id', 'expires_at'], [
            'token' => $token
        ]);

        if (!$record)
            return false;
        if (strtotime($record['expires_at']) < time())
            return false;

        $this->db->update('users', ['email_verified' => 1], ['id' => $record['user_id']]);
        $this->db->delete('email_verification_tokens', ['user_id' => $record['user_id']]);
        return true;
    }


}

?>