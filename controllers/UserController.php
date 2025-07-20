<?php

require_once __DIR__ . '/../services/SessionService.php';
require_once __DIR__ . '/../services/AuthService.php';

class UserController
{
    /**
     * Supprime le compte utilisateur et déconnecte.
     * Attend un tableau de données avec 'password' pour confirmation.
     */
    public function deleteAccount(array $data = [])
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
}


?>