<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../vendor/autoload.php';
require_once(__DIR__ . '/../config/mail.php');

class MailService
{
    private static function getMailer(): PHPMailer
    {
        $mail = new PHPMailer(true);

        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = SMTP_AUTH;
        $mail->Username = SMTP_USER;
        $mail->Password = SMTP_PASS;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;

        $mail->CharSet = 'UTF-8';
        $mail->setFrom(SMTP_FROM, SMTP_NAME);
        return $mail;
    }

    public static function send(string $to, string $subject, string $body, bool $isHtml = false): bool
    {
        $mail = self::getMailer();
        $mail->addAddress($to);

        $mail->Subject = $subject;
        if ($isHtml) {
            $mail->isHTML(true);
            $mail->Body = $body;
        } else {
            $mail->Body = $body;
        }

        try {
            return $mail->send();
        } catch (Exception $e) {
            // Tu peux logger l’erreur ici si besoin ($mail->ErrorInfo)
            return false;
        }
    }
}
?>