Προγραμματισμός και Συστήματα στον Παγκόσμιο Ιστό 
"Σύστημα Υποστήριξης Διπλωματικών Εργασιών"

Βερύκιος Άγγελος 1100500

Βογιαντζής Αναστάσιος 1100506

Κολύβρας Κωνσταντίνος 1103826


Απαιτείται αρχείο dbConfig.js με την παρακάτω δομή προκειμένου να συνδεθεί επιτυχώς με την βάση δεδομένων και να τρέξει ο κώδικας 
module.exports = {
    port: 'yourport',
    host: 'yourlocalhost',
    user: 'yourname',
    password: 'yourpswd',
    database: 'yourdb'
  }

Παρατήρηση:
Για την σωστή λειτουργία της βάσης θα πρέπει να προστεθεί και το παρακάτω trigger:

DELIMITER $$

CREATE TRIGGER trg_log_status_change
AFTER UPDATE ON thesis
FOR EACH ROW
BEGIN
  IF OLD.status <> NEW.status THEN
    INSERT INTO thesis_status_history (thesis_id, old_status, new_status)
    VALUES (NEW.id, OLD.status, NEW.status);
  END IF;
END$$

DELIMITER ;


