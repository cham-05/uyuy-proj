-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 05, 2026 at 03:01 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `uy`
--

-- --------------------------------------------------------

--
-- Table structure for table `admins`
--

CREATE TABLE `admins` (
  `id` int(11) NOT NULL,
  `username` varchar(100) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admins`
--

INSERT INTO `admins` (`id`, `username`, `password`) VALUES
(1, 'Jbretalyasgwapo@gmail.com', 'scrypt:32768:8:1$bxjJEQYUNpyBVusi$275c55336af5a213076a44902cdecb42d576b02d36f11a4f2a9ae7ef068c5cce3fd1de64d22c8fc4098a2796729c8310de735909a172930fc9f0a1c110146157');

-- --------------------------------------------------------

--
-- Table structure for table `products`
--

CREATE TABLE `products` (
  `id` int(11) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `price` decimal(10,2) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `picture` varchar(255) DEFAULT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'pending'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `products`
--

INSERT INTO `products` (`id`, `name`, `description`, `price`, `created_at`, `picture`, `status`) VALUES
(1, 'shuk', 'goodshitt', 500.06, '2026-02-22 13:02:31', 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTQj_TBC7UB-0Mmuu-8uXlD6M_qUF-s_BAnkw&s', 'done'),
(2, 'tube', 'pares sa goodshit', 360.00, '2026-02-22 13:04:13', 'https://preview.redd.it/shuk-mix-crumble-v0-a6hdichqc6qe1.jpg?width=1080&crop=smart&auto=webp&s=f57dea3c81dc88f0830737d035c0a7f9f3ed8e1f', 'done'),
(3, 'eheh', 'asd', 3000.00, '2026-02-22 13:06:02', 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTQj_TBC7UB-0Mmuu-8uXlD6M_qUF-s_BAnkw&s', 'pending');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `role` enum('admin','user') NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `role`, `name`, `email`, `password`, `created_at`) VALUES
(1, 'user', 'Jerald Uy', 'jUyalyaspogi@gmail.com', 'scrypt:32768:8:1$BCBBrfOUm9Jq4toR$b62c7160a9b7701541b2209284d876ab110c582d85ba8500875d5b8c76e6988657bb05242412a2347c926b7cdfa5760041a591c3a0425bbe3b868ad8894a67cc', '2026-02-22 12:31:14'),
(2, 'admin', 'bruce wayne', 'brucewaynebat@gmail.com', 'scrypt:32768:8:1$rtu5JsKqQC1SHYzk$8b78e7566db37910a47edf0b3815b1032a82d460939204104b403dda65c1c1ce223fd38e7db49da4acfa5e9444e6095dc3bd8faa5c485bbe15573e2ba9927839', '2026-02-22 13:00:22');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admins`
--
ALTER TABLE `admins`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `products`
--
ALTER TABLE `products`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admins`
--
ALTER TABLE `admins`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `products`
--
ALTER TABLE `products`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
