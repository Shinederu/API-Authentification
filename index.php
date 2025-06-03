<?php
require_once('controllers/AuthController.php');
require_once('middlewares/CorsMiddleware.php'); // à décommenter si tu veux les CORS
CorsMiddleware::apply(); // Idem ici

header('Content-Type: application/json; charset=utf-8');

// Récupération des données POST/PUT (body JSON ou formulaire)
$body = [];
if (in_array($_SERVER['REQUEST_METHOD'], ['POST', 'PUT'])) {
    $rawInput = file_get_contents('php://input');
    if (!empty($rawInput)) {
        $parsedJson = json_decode($rawInput, true);
        if (is_array($parsedJson)) {
            $body = $parsedJson;
        }
    }
    // Fallback formulaire si besoin
    if (empty($body) && !empty($_POST)) {
        $body = $_POST;
    }
}

try {
    $method = $_SERVER['REQUEST_METHOD'];
    $action = null;

    switch ($method) {
        case 'GET':
            $action = $_GET['action'] ?? null;
            switch ($action) {
                case 'verifyEmail':
                    (new AuthController())->verifyEmail($_GET);
                    exit;
                // Ajoute d'autres actions GET ici
                default:
                    unknownAction('GET');
                    exit;
            }

        case 'POST':
            $action = $body['action'] ?? $_POST['action'] ?? null;
            switch ($action) {
                case 'register':
                    (new AuthController())->register($body);
                    exit;
                case 'login':
                    (new AuthController())->login($body);
                    exit;
                // Ajoute d'autres actions POST ici
                default:
                    unknownAction('POST');
                    exit;
            }

        case 'PUT':
            $action = $body['action'] ?? $_REQUEST['action'] ?? null;
            switch ($action) {
                // Ajoute des actions PUT ici
                default:
                    unknownAction('PUT');
                    exit;
            }

        case 'DELETE':
            $action = $body['action'] ?? $_REQUEST['action'] ?? null;
            switch ($action) {
                // Ajoute des actions DELETE ici
                default:
                    unknownAction('DELETE');
                    exit;
            }

        default:
            notAllowedMethod();
            break;
    }

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Database Error: ' . $e->getMessage()
    ]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Application Error: ' . $e->getMessage()
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Unknown Error: ' . $e->getMessage()
    ]);
} finally {
    exit;
}

// Fonctions utilitaires

function unknownAction($method)
{
    http_response_code(404);
    echo json_encode([
        'status' => 'error',
        'message' => "Unknown action for $method method"
    ]);
}

function notAllowedMethod()
{
    http_response_code(405);
    echo json_encode([
        'status' => 'error',
        'message' => 'Method not allowed'
    ]);
}
