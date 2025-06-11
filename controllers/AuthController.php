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


    /**
     * Déconnexion
     */
    public function logout(array $data = [])
    {
        // Récupérer le session_id (via cookie ou header)
        $sessionId = $_COOKIE['session_id'] ?? ($_SERVER['HTTP_SESSION_ID'] ?? null);

        if (!$sessionId) {
            http_response_code(401);
            echo json_encode(['error' => 'Non authentifié']);
            exit;
        }

        $sessionService = new SessionService();
        $sessionService->deleteSession($sessionId);

        // Tu peux aussi supprimer le cookie côté client (si besoin)
        setcookie('session_id', '', time() - 3600, '/', '.shinederu.lol', true, true);

        echo json_encode(['success' => true, 'message' => 'Déconnexion réussie']);
    }

    /**
     * Déconnexion de tous les appareils
     */
    public function logoutAll(array $data = [])
    {
        $sessionId = $_COOKIE['session_id'] ?? ($_SERVER['HTTP_SESSION_ID'] ?? null);

        if (!$sessionId) {
            http_response_code(401);
            echo json_encode(['error' => 'Non authentifié']);
            exit;
        }

        $sessionService = new SessionService();
        $userId = $sessionService->getUserIdFromSession($sessionId);

        if (!$userId) {
            http_response_code(401);
            echo json_encode(['error' => 'Session invalide']);
            exit;
        }

        $sessionService->deleteAllSessionsForUser($userId);

        setcookie('session_id', '', time() - 3600, '/', '.shinederu.lol', true, true);

        echo json_encode(['success' => true, 'message' => 'Déconnexion de tous les appareils réussie']);
    }

    /**
     * Demande de reset mot de passe (envoi du mail)
     */
    public function requestPasswordReset(array $data = [])
    {
        $email = trim($data['email'] ?? $_REQUEST['email'] ?? '');

        if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['error' => 'Email invalide']);
            exit;
        }

        $auth = new AuthService();
        $user = $auth->getUserByEmail($email);

        // Toujours répondre OK même si l'utilisateur n'existe pas (évite de leak qui est inscrit !)
        if (!$user) {
            echo json_encode(['success' => true, 'message' => 'Si un compte existe, un mail a été envoyé.']);
            return;
        }

        $token = $auth->createPasswordResetToken($user['id']);
        $resetLink = "https://auth.shinederu.lol/?action=resetPassword?token=$token";

        // Envoie le mail
        MailService::send(
            $email,
            "Modification de votre mot de passe",
            "Pour modifier votre mot de passe, cliquez sur ce lien : $resetLink"
        );

        echo json_encode(['success' => true, 'message' => 'Si un compte existe, un mail a été envoyé.']);
    }

    /**
     * Validation du reset de mot de passe via token
     */
    public function resetPassword(array $data = [])
    {
        // Récupère le token et le nouveau mot de passe
        $token = trim($data['token'] ?? $_REQUEST['token'] ?? '');
        $newPassword = $data['password'] ?? $_REQUEST['password'] ?? '';

        if (!$token || strlen($newPassword) < 6) {
            http_response_code(400);
            echo json_encode(['error' => 'Paramètres invalides']);
            exit;
        }

        $auth = new AuthService();
        $userId = $auth->verifyPasswordResetToken($token);
        if (!$userId) {
            http_response_code(400);
            echo json_encode(['error' => 'Lien invalide ou expiré']);
            exit;
        }

        $auth->updatePassword($userId, $newPassword);
        $auth->consumePasswordResetToken($token);

        $sessionService = new SessionService();
        $sessionService->deleteAllSessionsForUser($userId);


        echo json_encode(['success' => true, 'message' => 'Mot de passe réinitialisé avec succès !']);
    }

    /**
     * Demande de mise à jour de l'email
     * Envoie un mail de confirmation à la nouvelle adresse
     */
    public function requestEmailUpdate(array $data)
    {
        $sessionId = $_COOKIE['session_id'] ?? ($_SERVER['HTTP_SESSION_ID'] ?? null);
        if (!$sessionId) {
            http_response_code(401);
            echo json_encode(['error' => 'Non authentifié']);
            exit;
        }

        $sessionService = new SessionService();
        $userId = $sessionService->getUserIdFromSession($sessionId);
        if (!$userId) {
            http_response_code(401);
            echo json_encode(['error' => 'Session invalide']);
            exit;
        }

        $newEmail = trim($data['email'] ?? $_REQUEST['email'] ?? '');
        if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['error' => 'Email invalide']);
            exit;
        }

        $authService = new AuthService();
        if ($authService->userOrEmailExists('', $newEmail)) {
            http_response_code(409);
            echo json_encode(['error' => 'Email déjà utilisé']);
            exit;
        }

        // Génère un token de vérification email lié à l’update
        $token = $authService->createEmailVerificationToken($userId, $newEmail);
        $link = "https://auth.shinederu.lol/?action=confirmEmailUpdate?token=$token";

        MailService::send(
            $newEmail,
            "Confirmation de changement d’e-mail",
            "Cliquez sur ce lien pour confirmer votre nouvelle adresse e-mail : $link"
        );

        echo json_encode(['success' => true, 'message' => 'Un mail de confirmation a été envoyé à la nouvelle adresse.']);
    }

    public function confirmEmailUpdate(array $params)
    {
        $token = trim($data['token'] ?? $_REQUEST['token'] ?? '');

        $authService = new AuthService();
        $record = $authService->getEmailVerificationToken($token);

        if (!$record || strtotime($record['expires_at']) < time() || empty($record['new_email'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Lien invalide ou expiré']);
            exit;
        }

        // Update l’email en base
        $authService->updateUserEmail($record['user_id'], $record['new_email']);

        // Supprime le token
        $authService->consumeEmailVerificationToken($token);

        echo json_encode(['success' => true, 'message' => 'Adresse e-mail modifiée et confirmée !']);
    }
}
?>