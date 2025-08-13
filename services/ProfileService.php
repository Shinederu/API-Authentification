<?php
require_once __DIR__ . '/DatabaseService.php';


class ProfileService
{

    private $db;

    public function __construct()
    {
        $this->db = DatabaseService::getInstance();
    }

    public function updateProfile(int $userId, $username): bool
    {
        $usernameAlreadyExist = $this->db->has('users', [
            'username' => $username
        ]);
        if ($usernameAlreadyExist) {
            return false;
        }

        $this->db->update('users', [
            'username' => $username
        ], [
            'id' => $userId
        ]);
        return true;
    }


}
?>