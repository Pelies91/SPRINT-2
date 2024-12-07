-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Hôte : 127.0.0.1
-- Généré le : jeu. 21 nov. 2024 à 17:19
-- Version du serveur : 10.4.32-MariaDB
-- Version de PHP : 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de données : `project`
--

-- --------------------------------------------------------

--
-- Structure de la table `useraccounts`
--

CREATE TABLE `useraccounts` (
  `id` mediumint(9) NOT NULL,
  `nom` char(40) NOT NULL,
  `prenom` char(40) NOT NULL,
  `email` char(40) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email_verified` tinyint(1) NOT NULL DEFAULT 0,
  `verification_code` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `useraccounts`
--

INSERT INTO `useraccounts` (`id`, `nom`, `prenom`, `email`, `password`, `email_verified`, `verification_code`) VALUES
(5, 'Rayou', 'legoat', 'steinkido1234@gmail.com', 'scrypt:32768:8:1$8513Z4ddEUQzgwOs$5fc2e9f89a199d7cca4ea787e1da85afdce07fb767015dd538c56bdf362314b644cbfaddb687f3c5eb398ea0c40fd8b21cec7fe231da60aba21ae5e2c2c1fbe2', 1, NULL),
(6, 'Fathi', 'Mohamed', 'fathimohamed93400@gmail.com', 'scrypt:32768:8:1$O4WoPMlOy6pgIdAr$e01efa2ffff269aeb8005cbfe3b1d7aa73d3c2b5398c4379c3676872c29428796b2b1179656dd87835d180fb06b3c3645988a5fe27764cfd21b23ec6ce3b2d00', 1, NULL);

--
-- Index pour les tables déchargées
--

--
-- Index pour la table `useraccounts`
--
ALTER TABLE `useraccounts`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT pour les tables déchargées
--

--
-- AUTO_INCREMENT pour la table `useraccounts`
--
ALTER TABLE `useraccounts`
  MODIFY `id` mediumint(9) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
