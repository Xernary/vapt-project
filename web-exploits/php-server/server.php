<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        if ($file['error'] === UPLOAD_ERR_OK) {
            $destination = __DIR__ . '/' . basename($file['name']);
            move_uploaded_file($file['tmp_name'], $destination);
        } else {
            echo "Errore nell'upload: codice " . $file['error'];
        }
    } else {
        echo "Nessun file ricevuto.";
    }
} 
