-- Drop existing database and user
DROP DATABASE IF EXISTS user_management;
DROP USER IF EXISTS 'app_user'@'localhost';

-- Create database
CREATE DATABASE IF NOT EXISTS user_management;
USE user_management;

-- Create user and grant privileges
CREATE USER IF NOT EXISTS 'app_user'@'localhost' IDENTIFIED BY 'App_password123!';
GRANT ALL PRIVILEGES ON user_management.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;

-- Create tables
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_profiles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    bio TEXT,
    location VARCHAR(100),
    phone VARCHAR(20),
    address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insert test data
INSERT INTO users (username, password, email, is_admin) VALUES 
    ('admin', 'admin123', 'admin@example.com', TRUE),
    ('user1', 'user123', 'user1@example.com', FALSE),
    ('user2', 'user123', 'user2@example.com', FALSE);

INSERT INTO user_profiles (user_id, bio, location, phone, address) VALUES 
    (1, 'System administrator', 'New York', '555-0101', '123 Admin St'),
    (2, 'Regular user', 'Los Angeles', '555-0102', '456 User Ave'),
    (3, 'Another user', 'Chicago', '555-0103', '789 User Blvd'); 