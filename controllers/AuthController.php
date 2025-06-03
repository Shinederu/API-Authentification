<?php
require_once __DIR__ . '/../utils/sanitize.php';
require_once __DIR__ . '/../services/AuthService.php';
require_once __DIR__ . '/../services/MailService.php';
require_once __DIR__ . '/../services/SessionService.php';

class AuthController
{
    /**
     * Inscription
     */
    public function register(array $data)
    {
        $input = sanitizeRegisterInput($data);
        $username = $input['username'];
        $email = $input['email'];
        $password = $input['password'];

        // Validation classique
        if (strlen($username) < 3 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 6) {
            http_response_code(400);
            echo json_encode(['error' => 'Données invalides']);
            exit;
        }

        $auth = new AuthService();

        if ($auth->userOrEmailExists($username, $email)) {
            http_response_code(409);
            echo json_encode(['error' => 'Utilisateur ou email déjà utilisé']);
            exit;
        }

        if (!$auth->createUser($username, $email, $password)) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur serveur lors de la création du compte']);
            exit;
        }

        // Récupère l’ID nouvellement créé
        $db = DatabaseService::getInstance();
        $userId = $db->id();

        // Génère le token de vérif + envoie le mail
        $token = $auth->createEmailVerificationToken($userId);
        $link = "https://auth.shinederu.lol/?action=verifyEmail&token=$token";

        MailService::send(
            $email,
            "Vérification de votre compte",
            "Bienvenue ! Cliquez ici pour vérifier votre adresse : $link"
        );

        echo json_encode(['success' => true, 'message' => 'Inscription réussie, vérifiez votre email !']);
    }

    /**
     * Vérification email (GET /verify-email?token=...)
     */
    public function verifyEmail(array $params)
    {
        $input = sanitizeVerifyEmailInput($params);
        $token = $input['token'];

        $auth = new AuthService();
        $ok = $auth->verifyEmailToken($token);

        if ($ok) {
            echo json_encode(['success' => true, 'message' => 'Email vérifié, vous pouvez vous connecter !']);
        } else {
            http_response_code(400);
            echo json_encode(['error' => 'Lien invalide ou expiré']);
        }
    }

    /**
     * Connexion
     */
    public function login(array $data)
    {
        $input = sanitizeLoginInput($data);
        $usernameOrEmail = $input['username'];
        $password = $input['password'];

        $auth = new AuthService();
        $user = $auth->verifyCredentials($usernameOrEmail, $password);

        if (!$user) {
            http_response_code(401);
            echo json_encode(['error' => 'Identifiants invalides']);
            exit;
        }

        if (!$user['email_verified']) {
            http_response_code(403);
            echo json_encode(['error' => 'Email non vérifié']);
            exit;
        }

        // Crée la session en DB
        $sessionService = new SessionService();
        $sessionId = $sessionService->createSession($user['id']);

        echo json_encode(['success' => true, 'session_id' => $sessionId]);
    }
}
?>