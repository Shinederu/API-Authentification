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

    /**
     * Mise à jour du profil (pseudo et avatar)
     */
    public function updateProfile(array $data)
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

        $username = trim($data['username'] ?? ($_REQUEST['username'] ?? ''));
        $avatar = trim($data['avatar_url'] ?? ($_REQUEST['avatar_url'] ?? ''));
        $role = trim($data['role'] ?? ($_REQUEST['role'] ?? ''));

        $authService = new AuthService();
        if ($username) {
            $authService->updateUsername($userId, $username);
        }
        if ($avatar) {
            $authService->updateAvatar($userId, $avatar);
        }
        if ($role) {
            $this->updateRole($userId, $role);
        }

        echo json_encode(['success' => true]);
    }

    private function updateRole(int $userId, string $role): void
    {
        $authService = new AuthService();
        $authService->updateUserRole($userId, $role);
    }

    public function getProfile()
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

        $authService = new AuthService();
        $user = $authService->getUserById($userId);
        if (!$user) {
            http_response_code(404);
            echo json_encode(['error' => 'Utilisateur non trouvé']);
            exit;
        }
        $profile = [
            'username' => $user['username'],
            'avatar_url' => $user['avatar_url'] ?? null,
            'role' => $user['role']
        ];

        echo json_encode(['success' => true, 'profile' => $profile]);
    }
}


?>