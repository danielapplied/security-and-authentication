/*Secure users*/

CREATE TABLE Users (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    Username VARCHAR(100),
    FullName VARCHAR(100) NOT NULL,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARCHAR(255) NOT NULL,
    RoleId INT NOT NULL,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (RoleId) REFERENCES Roles(RoleId)
);

/* Roles */

CREATE TABLE Roles (
    RoleId INT AUTO_INCREMENT PRIMARY KEY,
    RoleName VARCHAR(50) NOT NULL UNIQUE
);

INSERT INTO Roles (RoleName) VALUES ('Admin'), ('User');

/* Permissions Table */

CREATE TABLE Permissions (
    PermissionId INT AUTO_INCREMENT PRIMARY KEY,
    PermissionName VARCHAR(100) NOT NULL
);

/*Role-Permissions Mapping*/

CREATE TABLE RolePermissions (
    RoleId INT,
    PermissionId INT,
    PRIMARY KEY (RoleId, PermissionId),
    FOREIGN KEY (RoleId) REFERENCES Roles(RoleId),
    FOREIGN KEY (PermissionId) REFERENCES Permissions(PermissionId)
);

/*Use Prepared Statements and procedures*/

PREPARE stmt FROM 'SELECT * FROM Users WHERE Email = ?';
SET @email = 'test@example.com';
EXECUTE stmt USING @email;
DEALLOCATE PREPARE stmt;

DELIMITER $$

CREATE PROCEDURE GetUserByEmail(IN userEmail VARCHAR(100))
BEGIN
    SELECT Id, FullName, Email, RoleId
    FROM Users
    WHERE Email = userEmail;
END $$

DELIMITER ;

/* Password Handling BCrypt / Argon2 hash */

INSERT INTO Users (FullName, Email, PasswordHash, RoleId)
VALUES ('John Doe', 'john@example.com', '$2a$12$hashedvalue...', 2);

/* Role-Based Query */

SELECT u.FullName, u.Email, r.RoleName
FROM Users u
JOIN Roles r ON u.RoleId = r.RoleId
WHERE u.Email = ?;

/* Restrict Database User Privileges */

CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'StrongPassword!';
GRANT SELECT, INSERT, UPDATE, DELETE ON yourdb.* TO 'app_user'@'localhost';

/* Prevent Injection via MySQL Settings Allow User Variables=true;AllowBatch=false;  */

/* Input Validation Query Example */ 

SELECT * FROM Users
WHERE Email = ?
AND Email REGEXP '^[^@]+@[^@]+\\.[^@]+$';
