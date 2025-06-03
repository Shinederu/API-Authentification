<?php
require_once __DIR__ . '/../services/SessionService.php';

class AuthMiddleware
{
    /**
     * Vérifie que l'utilisateur est connecté (session valide).
     * Peut être appelé au début d'un endpoint "protégé".
     */
    public static function check(): int
    {
        // Récupère le session_id (via cookie ou header, à adapter à ton besoin)
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
            echo json_encode(['error' => 'Session invalide ou expirée']);
            exit;
        }

        // Tu peux faire passer le user_id à la suite comme tu veux (ex : global, request, etc.)
        return $userId;
    }
}

?>