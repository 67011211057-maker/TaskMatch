
-- =========================================================
-- TASKMATCH DATABASE SCHEMA
-- MySQL / MariaDB / XAMPP / phpMyAdmin
-- =========================================================
--
-- Database: taskmatch
--
-- Tables:
--   1. users
--   2. categories
--   3. jobs
--   4. applications
--   5. sessions
--
-- =========================================================


-- =========================================================
-- 1. CREATE DATABASE
-- =========================================================

CREATE DATABASE IF NOT EXISTS taskmatch
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE taskmatch;


-- =========================================================
-- 2. USERS
-- =========================================================
--
-- role:
--   customer = ผู้ว่าจ้าง
--   worker   = ผู้รับงาน
--   admin    = ผู้ดูแลระบบ
--
-- password_hash เก็บรหัสผ่านที่ผ่านการ Hash แล้วเท่านั้น
-- ห้ามเก็บรหัสผ่านจริงเป็นข้อความธรรมดา
-- =========================================================

CREATE TABLE IF NOT EXISTS users (

    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    name VARCHAR(150) NOT NULL,

    email VARCHAR(255) NOT NULL,

    password_hash VARCHAR(255) NOT NULL,

    role ENUM(
        'customer',
        'worker',
        'admin'
    ) NOT NULL DEFAULT 'worker',

    created_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_users_email (email),

    KEY idx_users_role (role)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- 3. CATEGORIES
-- =========================================================
--
-- หมวดหมู่งานสำหรับให้ผู้ว่าจ้างเลือก
-- =========================================================

CREATE TABLE IF NOT EXISTS categories (

    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    name VARCHAR(150) NOT NULL,

    PRIMARY KEY (id),

    UNIQUE KEY uq_categories_name (name)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- 4. JOBS
-- =========================================================
--
-- status:
--   open      = เปิดรับสมัคร
--   assigned  = มีผู้รับงานแล้ว
--   completed = งานเสร็จสิ้น
--
-- owner_id อ้างอิงผู้ว่าจ้างจาก users
-- category_id อ้างอิงหมวดหมู่จาก categories
-- =========================================================

CREATE TABLE IF NOT EXISTS jobs (

    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    owner_id BIGINT UNSIGNED NOT NULL,

    category_id BIGINT UNSIGNED NOT NULL,

    title VARCHAR(200) NOT NULL,

    description TEXT NOT NULL,

    price DECIMAL(10,2) NOT NULL,

    deadline DATE NOT NULL,

    status ENUM(
        'open',
        'assigned',
        'completed'
    ) NOT NULL DEFAULT 'open',

    created_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    KEY idx_jobs_owner (owner_id),

    KEY idx_jobs_category (category_id),

    KEY idx_jobs_status (status),

    KEY idx_jobs_created (created_at),

    CONSTRAINT fk_jobs_owner
        FOREIGN KEY (owner_id)
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_jobs_category
        FOREIGN KEY (category_id)
        REFERENCES categories(id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    CONSTRAINT chk_jobs_price
        CHECK (price >= 0)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- 5. APPLICATIONS
-- =========================================================
--
-- status:
--   pending  = รอพิจารณา
--   accepted = ได้รับเลือก
--   rejected = ไม่ได้รับเลือก
--
-- UNIQUE(job_id, worker_id):
--   ผู้รับงาน 1 คน สมัครงานเดียวกันได้เพียง 1 ครั้ง
-- =========================================================

CREATE TABLE IF NOT EXISTS applications (

    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    job_id BIGINT UNSIGNED NOT NULL,

    worker_id BIGINT UNSIGNED NOT NULL,

    status ENUM(
        'pending',
        'accepted',
        'rejected'
    ) NOT NULL DEFAULT 'pending',

    created_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_applications_job_worker (
        job_id,
        worker_id
    ),

    KEY idx_applications_worker (worker_id),

    KEY idx_applications_status (status),

    CONSTRAINT fk_applications_job
        FOREIGN KEY (job_id)
        REFERENCES jobs(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_applications_worker
        FOREIGN KEY (worker_id)
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- 6. SESSIONS
-- =========================================================
--
-- ใช้เก็บ Session สำหรับผู้ใช้ที่เข้าสู่ระบบ
--
-- token_hash:
--   เก็บค่า Hash ของ Session Token
--
-- expires_at:
--   เวลาหมดอายุของ Session
-- =========================================================

CREATE TABLE IF NOT EXISTS sessions (

    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    user_id BIGINT UNSIGNED NOT NULL,

    token_hash CHAR(64) NOT NULL,

    expires_at DATETIME NOT NULL,

    created_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_sessions_token_hash (
        token_hash
    ),

    KEY idx_sessions_user (user_id),

    KEY idx_sessions_expires (expires_at),

    CONSTRAINT fk_sessions_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- 7. DEFAULT CATEGORIES
-- =========================================================
--
-- INSERT IGNORE ป้องกันการเพิ่มชื่อหมวดหมู่ซ้ำ
-- เมื่อรัน schema.sql อีกครั้ง
-- =========================================================

INSERT IGNORE INTO categories (name)
VALUES
    ('ออกแบบกราฟิก'),
    ('เขียนโปรแกรม'),
    ('พัฒนาเว็บไซต์'),
    ('แปลภาษา'),
    ('เขียนบทความ'),
    ('ตัดต่อวิดีโอ'),
    ('ถ่ายภาพ'),
    ('การตลาดออนไลน์'),
    ('จัดการข้อมูล'),
    ('งานเอกสาร'),
    ('สอนพิเศษ'),
    ('งานทั่วไป');


-- =========================================================
-- 8. VERIFY DATABASE
-- =========================================================

SHOW TABLES;

SELECT
    id,
    name
FROM categories
ORDER BY id;


-- =========================================================
-- END OF TASKMATCH DATABASE SCHEMA
-- =========================================================
