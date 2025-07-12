<?php
// Ottieni il metodo della richiesta
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'POST') {
    // Leggi il corpo della richiesta
    $input = file_get_contents('php://input');

    // Stampa nel terminale del server
    error_log("POST ricevuto:\n$input\n");
    
    // Risposta al client
    echo "POST ricevuto!";
} else {
    echo "Questo endpoint accetta solo richieste POST.";
}
