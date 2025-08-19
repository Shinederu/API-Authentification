<?php

require_once __DIR__ . '/../utils/sanitize.php';
require_once __DIR__ . '/../services/SessionService.php';
require_once __DIR__ . '/../services/AuthService.php';
require_once __DIR__ . '/../services/ProfileService.php';
require_once __DIR__ . '/../config/config.php';

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


    public function getAvatar(array $data)
    {
        $userId = isset($data['user_id']) ? (int) $data['user_id'] : 0;

        $profileService = new ProfileService();
        $avatar = $profileService->getAvatar($userId);
        if (!$avatar) {
            http_response_code(404);
            echo json_encode(['error' => 'Avatar non trouvé']);
            exit;
        }

        header('Content-Type: image/png');
        header('Cache-Control: public, max-age=31536000, immutable');
        echo $avatar;
        exit;

    }

    public function updateAvatar(array $data, int $userId)
    {
        $avatarBytes = null;

        // JSON base64 (PUT/POST application/json)
        if (!empty($data['image_base64'])) {
            $avatarBytes = base64_decode(
                preg_replace('#^data:image/\w+;base64,#', '', $data['image_base64']),
                true
            );
        }
        // Multipart (POST form-data)
        elseif (!empty($_FILES['file']) && is_uploaded_file($_FILES['file']['tmp_name'])) {
            $avatarBytes = file_get_contents($_FILES['file']['tmp_name']);
        }

        if (!$avatarBytes) {
            http_response_code(400);
            echo json_encode(['error' => 'Aucune image PNG reçue']);
            exit;
        }

        // limite de taille
        if (strlen($avatarBytes) > 5 * 1024 * 1024) { // 5 MB
            http_response_code(400);
            echo json_encode(['error' => 'Image trop lourde (max 5 Mo).']);
            exit;
        }
        // Vérif MIME (depuis les octets, pas le nom de fichier)
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo ? $finfo->buffer($avatarBytes) : null;
        $allowed = ['image/png', 'image/jpeg', 'image/webp']; // <-- inline (simple)
        if (!$mime || !in_array($mime, $allowed, true)) {
            http_response_code(400);
            echo json_encode(['error' => 'Type non autorisé (PNG, JPEG ou WebP).']);
            return;
        }

        $profile = new ProfileService();
        $png = $profile->normalizeToPng($avatarBytes);
        $result = $profile->saveUploadedPng($userId, $png);

        if (!$result) {
            http_response_code(500);
            echo json_encode(['error' => 'Échec de la mise à jour de l’image de profil dans la base de données']);
            exit;
        }
        echo json_encode(['success' => true, 'message' => 'Image de profil mise à jour']);
    }

}


?>