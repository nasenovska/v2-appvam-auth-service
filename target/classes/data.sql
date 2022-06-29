INSERT INTO roles (name)
SELECT 'ROLE_ADMIN'
FROM DUAL
WHERE NOT EXISTS(SELECT *
                 FROM roles
                 WHERE name = 'ROLE_ADMIN');

INSERT INTO roles (name)
SELECT 'ROLE_USER'
FROM DUAL
WHERE NOT EXISTS(SELECT *
                 FROM roles
                 WHERE name = 'ROLE_USER');

INSERT INTO roles (name)
SELECT 'ROLE_TEACHER'
FROM DUAL
WHERE NOT EXISTS(SELECT *
                 FROM roles
                 WHERE name = 'ROLE_TEACHER');

INSERT INTO roles (name)
SELECT 'ROLE_STUDENT'
FROM DUAL
WHERE NOT EXISTS(SELECT *
                 FROM roles
                 WHERE name = 'ROLE_STUDENT');
