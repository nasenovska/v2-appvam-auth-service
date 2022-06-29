CREATE TABLE if not exists users (
    id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
    name NVARCHAR(100) NOT NULL,
    username VARCHAR(20) NOT NULL,
    email VARCHAR(50) NOT NULL,
    password VARCHAR(120) NOT NULL,
    phone VARCHAR(12),
    address VARCHAR(50)
);

CREATE TABLE if not exists roles (
    id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE
)
