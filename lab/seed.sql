-- Synthetic, disposable data only. No production accounts or secrets.
CREATE DATABASE IF NOT EXISTS boolrace_lab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE boolrace_lab;
CREATE TABLE specimens (
    id INT PRIMARY KEY,
    label VARCHAR(100) NOT NULL,
    note TEXT NULL,
    quantity INT NULL
) ENGINE=InnoDB;
SET NAMES utf8mb4;
INSERT INTO specimens (id, label, note, quantity) VALUES
    (1, 'synthetic-alpha', NULL, 7),
    (2, 'synthetic-empty', '', 0),
    (3, '測試 café 😀', 'Unicode stays intact', -3),
    (4, 'synthetic-separator', CONCAT('left', CHAR(31), 'right'), 42),
    (5, 'synthetic-markup', '<tag>& "quotes"', NULL),
    (6, 'synthetic-whitespace', CONCAT('  padded', CHAR(10), 'line  '), 100);
CREATE USER 'lab_reader'@'%' IDENTIFIED BY 'synthetic-only';
GRANT SELECT ON boolrace_lab.* TO 'lab_reader'@'%';
