<?php

require_once __DIR__ . '/../utils/sanitize.php';
require_once __DIR__ . '/../services/SessionService.php';
require_once __DIR__ . '/../services/AuthService.php';
require_once __DIR__ . '/../services/ProfileService.php';

class UserController
{
    /**
     * Supprime le compte utilisateur et déconnecte.
     * Attend un tableau de données avec 'password' pour confirmation.
     */
    public function deleteAccount(array $data = [])
    {
        $sessionId = $_COOKIE['sid'] ?? $_COOKIE['session_id'] // legacy
            ?? $_SERVER['HTTP_X_SESSION_ID']                       // header: X-Session-Id
            ?? $_SERVER['HTTP_SESSION_ID']                         // legacy header
            ?? null;
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

        // Vérifie le mot de passe pour confirmer la suppression
        $password = $data['password'] ?? ($_REQUEST['password'] ?? '');
        $authService = new AuthService();
        $user = $authService->getUserById($userId);
        if (!$user || !password_verify($password, $user['password_hash'])) {
            http_response_code(403);
            echo json_encode(['error' => 'Mot de passe incorrect']);
            exit;
        }

        // Supprime l’utilisateur
        $authService = new AuthService();
        $authService->deleteUser($userId);

        // Supprime toutes ses sessions
        $sessionService->deleteAllSessionsForUser($userId);

        // Efface le cookie côté client
        setcookie('session_id', '', time() - 3600, '/', '.shinederu.lol', true, true);

        echo json_encode(['success' => true, 'message' => 'Compte supprimé et déconnecté']);
    }


    public function updateProfile(array $data, int $userId)
    {

        $array = sanitizeArray($data);
        $username = $array['username'];

        if (strlen($username) < 4) {
            http_response_code(400);
            echo json_encode(['error' => 'Nom d’utilisateur trop court (minimum 4 caractères)']);
            exit;
        }

        if (strlen($username) > 64) {
            http_response_code(400);
            echo json_encode(['error' => 'Nom d’utilisateur trop long (maximum 64 caractères)']);
            exit;
        }

        $profileService = new ProfileService();
        if (!$profileService->updateProfile($userId, $username)) {
            http_response_code(400);
            echo json_encode(['error' => 'Nom d’utilisateur déjà pris']);
            exit;
        }
        echo json_encode(['success' => true, 'message' => 'Profil mis à jour']);
    }
}


?>