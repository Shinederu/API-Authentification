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
    public function createEmailVerificationToken(int $userId, ?string $newEmail = null): string
    {
        $token = TokenService::generateToken(64);
        $expiresAt = date('Y-m-d H:i:s', strtotime('+1 day'));

        // Supprime les anciens tokens de l’utilisateur (évite les doublons)
        $this->db->delete('email_verification_tokens', ['user_id' => $userId]);

        $this->db->insert('email_verification_tokens', [
            'user_id' => $userId,
            'token' => $token,
            'expires_at' => $expiresAt,
            'new_email' => $newEmail
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


    /**
     * Supprime un utilisateur et toutes ses données associées.
     * Attention, irréversible !
     */
    public function deleteUser($userId)
    {
        $this->db->delete('users', ['id' => $userId]);
        // (Tu peux aussi supprimer d’autres tables reliées si besoin)
    }
    /**
     * Récupère un utilisateur par son ID.
     * Retourne l'utilisateur ou false si non trouvé.
     */
    public function getUserById($userId)
    {
        return $this->db->get('users', '*', ['id' => $userId]);
    }


    /**
     * Crée un token de réinitialisation de mot de passe pour un utilisateur.
     * Retourne le token généré.
     */
    public function createPasswordResetToken(int $userId): string
    {
        $token = TokenService::generateToken(64);
        $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));

        // Supprime les anciens tokens éventuels pour ce user
        $this->db->delete('password_reset_tokens', ['user_id' => $userId]);

        $this->db->insert('password_reset_tokens', [
            'user_id' => $userId,
            'token' => $token,
            'expires_at' => $expiresAt
        ]);
        return $token;
    }

    /**
     * Vérifie un token de réinitialisation de mot de passe.
     * Retourne l'ID utilisateur si valide, false sinon.
     */
    public function verifyPasswordResetToken(string $token)
    {
        $record = $this->db->get('password_reset_tokens', ['user_id', 'expires_at'], [
            'token' => $token
        ]);
        if (!$record)
            return false;
        if (strtotime($record['expires_at']) < time())
            return false;
        return $record['user_id'];
    }

    /**
     * Consomme (supprime) un token de réinitialisation de mot de passe.
     */
    public function consumePasswordResetToken(string $token)
    {
        $this->db->delete('password_reset_tokens', ['token' => $token]);
    }

    /**
     * Met à jour le mot de passe d'un utilisateur.
     * Retourne true si succès, false sinon.
     */
    public function updatePassword(int $userId, string $newPassword): bool
    {
        $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        $this->db->update('users', ['password_hash' => $passwordHash], ['id' => $userId]);
        return $this->db->error === null;
    }

    /**
     * Récupère un utilisateur par son email.
     * Retourne l'utilisateur ou false si non trouvé.
     */
    public function getUserByEmail(string $email)
    {
        return $this->db->get('users', '*', ['email' => $email]);
    }

    public function getEmailVerificationToken(string $token)
    {
        return $this->db->get('email_verification_tokens', '*', ['token' => $token]);
    }

    public function updateUserEmail(int $userId, string $newEmail): bool
    {
        $this->db->update('users', [
            'email' => $newEmail,
            'email_verified' => 1 // On valide direct
        ], [
            'id' => $userId
        ]);
        return $this->db->error === null;
    }

    public function consumeEmailVerificationToken(string $token)
    {
        $this->db->delete('email_verification_tokens', ['token' => $token]);
    }

    // Envoie un nouvel e-mail de vérification
    public function resendVerificationEmail(int $userId, string $email): void
    {
        $token = $this->createEmailVerificationToken($userId);
        $link = "https://auth.shinederu.lol/?action=verifyEmail&token=$token";
        MailService::send(
            $email,
            'Vérification de votre compte',
            "Bienvenue! Cliquez ici pour vérifier votre adresse : $link"
        );
    }

    // Annule l'inscription d'un utilisateur via le token de vérification
    public function cancelRegistration(string $token): bool
    {
        $record = $this->db->get('email_verification_tokens', '*', ['token' => $token]);
        if (!$record) {
            return false;
        }
        $this->db->delete('users', ['id' => $record['user_id'], 'email_verified' => 0]);
        $this->consumeEmailVerificationToken($token);
        return true;
    }

    public function updateUsername(int $userId, string $username): bool
    {
        $this->db->update('users', ['username' => $username], ['id' => $userId]);
        return $this->db->error === null;
    }

    public function updateAvatar(int $userId, string $avatarUrl): bool
    {
        $this->db->update('users', ['avatar_url' => $avatarUrl], ['id' => $userId]);
        return $this->db->error === null;
    }

    public function updateUserRole(int $userId, string $role): bool
    {
        $this->db->update('users', ['role' => $role], ['id' => $userId]);
        return $this->db->error === null;
    }




}

?>