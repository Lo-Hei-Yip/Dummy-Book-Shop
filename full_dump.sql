-- MySQL dump 10.14  Distrib 5.5.68-MariaDB, for Linux (x86_64)
--
-- Host: localhost    Database: bookstore
-- ------------------------------------------------------
-- Server version	5.5.68-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `categories`
--

DROP TABLE IF EXISTS `categories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `categories` (
  `catid` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`catid`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `categories`
--

LOCK TABLES `categories` WRITE;
/*!40000 ALTER TABLE `categories` DISABLE KEYS */;
INSERT INTO `categories` VALUES (1,'Fiction'),(2,'Non-Fiction'),(3,'Comic Books');
/*!40000 ALTER TABLE `categories` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `order_items`
--

DROP TABLE IF EXISTS `order_items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `order_items` (
  `orderItemID` int(11) NOT NULL AUTO_INCREMENT,
  `orderID` int(11) NOT NULL,
  `pid` int(11) NOT NULL,
  `quantity` int(11) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  PRIMARY KEY (`orderItemID`),
  KEY `orderID` (`orderID`),
  KEY `pid` (`pid`),
  CONSTRAINT `order_items_ibfk_1` FOREIGN KEY (`orderID`) REFERENCES `orders` (`orderID`) ON DELETE CASCADE,
  CONSTRAINT `order_items_ibfk_2` FOREIGN KEY (`pid`) REFERENCES `products` (`pid`)
) ENGINE=InnoDB AUTO_INCREMENT=49 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `order_items`
--

LOCK TABLES `order_items` WRITE;
/*!40000 ALTER TABLE `order_items` DISABLE KEYS */;
INSERT INTO `order_items` VALUES (1,1,2,1,29.99),(2,1,10,1,16.99),(3,2,7,2,18.99),(4,2,12,1,12.99),(5,3,8,1,25.99),(6,3,2,1,29.99),(7,3,10,1,16.99),(8,4,7,1,18.99),(9,4,3,1,27.99),(10,5,3,1,27.99),(11,5,7,1,18.99),(12,6,12,2,12.99),(13,6,4,1,32.99),(14,7,10,2,16.99),(15,7,5,2,19.99),(16,8,1,2,24.99),(17,9,2,1,29.99),(18,9,11,3,18.99),(19,10,6,1,22.99),(20,10,10,1,16.99),(21,11,4,1,32.99),(22,12,1,1,24.99),(23,12,6,1,22.99),(24,12,9,1,14.99),(25,13,2,1,29.99),(26,14,9,1,14.99),(27,15,1,1,24.99),(28,16,3,1,27.99),(29,17,2,1,29.99),(30,18,8,6,25.99),(31,19,1,1,24.99),(32,19,7,1,18.99),(33,19,11,1,18.99),(34,20,6,1,22.99),(35,20,5,1,19.99),(36,20,12,1,12.99),(37,21,1,1,24.99),(38,22,1,1,24.99),(39,23,7,1,18.99),(40,24,3,1,27.99),(41,25,4,4,32.99),(42,25,8,1,25.99),(43,26,2,3,29.99),(44,27,9,5,14.99),(45,28,1,1,24.99),(46,29,1,3,24.99),(47,29,9,1,14.99),(48,30,2,2,29.99);
/*!40000 ALTER TABLE `order_items` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `orders`
--

DROP TABLE IF EXISTS `orders`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `orders` (
  `orderID` int(11) NOT NULL AUTO_INCREMENT,
  `userID` int(11) DEFAULT NULL,
  `total` decimal(10,2) NOT NULL,
  `digest` varchar(64) NOT NULL,
  `salt` varchar(32) NOT NULL,
  `currency` char(3) NOT NULL DEFAULT 'USD',
  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `status` enum('pending','failed','confirmed') NOT NULL DEFAULT 'pending',
  PRIMARY KEY (`orderID`),
  KEY `userID` (`userID`),
  CONSTRAINT `orders_ibfk_1` FOREIGN KEY (`userID`) REFERENCES `users` (`userid`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `orders`
--

LOCK TABLES `orders` WRITE;
/*!40000 ALTER TABLE `orders` DISABLE KEYS */;
INSERT INTO `orders` VALUES (1,NULL,46.98,'b64ac2ba2a188ed231f0bb4eb3b9e50458ac75a121a13c8c843f55f467538d40','f9710b11d6729b372eecfe67cca01ba5','USD','2025-04-12 17:25:01','pending'),(2,2,50.97,'cf82df18cc37bfc721e4ce3204bcd803f2e405b6dbfe2efe0636102c62f8765e','d80a0c74e2cc2d74e52721257af8563b','USD','2025-04-12 17:27:07','pending'),(3,1,72.97,'923d2b44d925b59844688b9f9d19013ba0143699417c07d8af6be325f43f5ad0','622d16a70d6a12b197f4d443de03ede9','USD','2025-04-12 17:40:17','pending'),(4,NULL,46.98,'284a69827a663015af0e3d226f821efd28b5eda653b034af6df6e0baa3e25e3c','a3165f89557492b42b083935cb2a08e7','USD','2025-04-13 07:58:06','pending'),(5,NULL,46.98,'8577fc635af2e65aac5889471bb79f240c5c917cb4fd8c42fe0a1e2173844497','c991eb4cb3ba4a6fe6dcbe7b40d81627','USD','2025-04-13 07:59:23','pending'),(6,NULL,58.97,'f286612cd10865e18c0897d7e63e40635649f21e6892f918bba35e7414c013d7','5e18610746bc653038e166f3c7548d80','USD','2025-04-13 08:21:24','confirmed'),(7,NULL,73.96,'754c5886f201073cfb2e1c7ec257e9dcab199b68cb648759e5c7d38a993874aa','898f12d815ff3ade16982ac6f2b62454','USD','2025-04-13 08:56:24','confirmed'),(8,NULL,49.98,'42affe0c27f8bf43113f5e2b5f9e5e550e6508ceb949015e6f81345d417038b7','d388821a2e4beaa6d85cf145b031e88e','USD','2025-04-13 09:03:41','confirmed'),(9,NULL,86.96,'a4a21cfa6213a73bba26b616da9d62b45635a1d9900523a3484e8405400b57e7','ad5e582131d377f6ca2d8f29150f9b90','USD','2025-04-13 09:19:13','confirmed'),(10,NULL,39.98,'acdf7396fabb2fb389b6ad6ab5a4de518a37c7c7d0c1e97956c0c2aba3fd2d9b','968c2961f00779e6d23326ff2f77b28a','USD','2025-04-13 09:30:26','confirmed'),(11,NULL,32.99,'39c1e1213a16803edb9ed42eaeea5a3b18e37472aa596db0c6bb4ac26ef842e2','c4615c3ef2cc2fb133b56c8e476f7558','USD','2025-04-13 09:32:28','failed'),(12,2,62.97,'4886fd5db0174f91862a92f8c76e8f7d72bc4e91b77cfd2cfe6058f98f950cc1','955cd2e69c82348fb0d8bfbdca5ea852','USD','2025-04-13 09:53:37','failed'),(13,2,29.99,'d77c67bda76b18d51bf440bf242e66a5127ec606d5113fd84ef1242224aba240','b0a6ecc7c6aa7adb348037e9da46d52a','USD','2025-04-13 09:56:49','confirmed'),(14,NULL,14.99,'7c3aa41eb7ec921b4a5058c63e1d1371263934bbb2fb1e1ac347e7038ad6475c','29b682d3bc410e8d2df575d9a7feb68f','USD','2025-04-13 10:10:40','failed'),(15,1,24.99,'d72a5d72b47d8ab9a3a9d9bd4b3a4af3d465f19aa4bd70430f96411765f0b338','7eed401b47d69a9a37121dc96afd5874','USD','2025-04-13 10:30:59','failed'),(16,NULL,27.99,'3375a8aa397dd42ffd0e804b4ea72ac9766df3ca54128e902e180398562d29cb','8f1f74af83bd49f4aeada3cfe707c76c','USD','2025-04-13 11:19:14','failed'),(17,NULL,29.99,'4d541b6ad3c231ed4497c439f02af4b66836fc1ed7612c15e1b90bdd96681830','f788da35c58f8dd4689d99885f43d6b8','USD','2025-04-13 11:21:20','confirmed'),(18,2,155.94,'c072b78364b15ce29d235e545c7f1cfdbe419b002138b9a0f7735a91fbbda2cb','bac04884f5a0cecea132263d271ae0fc','USD','2025-04-13 12:39:16','confirmed'),(19,2,62.97,'35fda0c3c9e39fcb71e3c98e4c2fb11c8b7ae135a27ea96731fec09beecdf0b7','cb9104b80d133b89c77bb1ababa0bfc1','USD','2025-04-13 12:40:58','confirmed'),(20,2,55.97,'88a348097342418300d35159b9068d5343db6e396f76bcb670ff3cf001d6a669','2062118d4a858b428d8e4f50a95ab31e','USD','2025-04-13 12:41:48','confirmed'),(21,2,24.99,'a4d8006c26abd1e7438957b1f356128ca789b45ada162178ff890f85a228fd55','f831fb6cccdbde319d423c39e52bffac','USD','2025-04-13 12:42:41','failed'),(22,NULL,24.99,'5b7ccf279de0501cf83ca6bf54512dc046f772fbe9dbb54380fbcaf31cec0f97','79962d4bceec2019ea2c9f2116398901','USD','2025-04-14 08:49:45','failed'),(23,NULL,18.99,'b9f61f63f84dbca7095bf80f73c5dcd122b159c02d8bea665f0ef51bc1492760','6413a0e12f883b22e7935eab7035cb1e','USD','2025-04-14 08:51:21','failed'),(24,NULL,27.99,'e46aa7676d990408bc4ed432430d12e35c43d35af214a4fa12149e819109f1e8','5f0ae3de7b4bc9a9bd23d1fe96327100','USD','2025-04-14 09:07:12','failed'),(25,1,157.95,'0bc18de97108264b1129bf94abb9d0eb9a8bb28c7cbe07877a9e1d6d2fdbc3f5','6f335f7ea7480f7c160c5ca2f6cd26d1','USD','2025-04-14 11:11:53','confirmed'),(26,1,89.97,'eb547f218afd6b615d6cb6fce514c0cbfb6483a02ef58caf283e3dce228f124b','ce8ceb80ff63041f31c29b21960877dc','USD','2025-04-14 11:12:59','failed'),(27,1,74.95,'06bf2d4411fdb4554f086ccc843a85f9af331615dbb5c294f2fbcec57e1b0b60','a7cbea026d25fec60b4f6133af7208e2','USD','2025-04-14 11:28:14','confirmed'),(28,1,24.99,'bd4fb68e65829a2a3bcf65f11be3caad604fc9baeb1bc52388bb842a866ed12a','32d465e1c5fd12da530d3a32ae47ceb4','USD','2025-04-14 11:28:54','failed'),(29,NULL,89.96,'95f4afd2e64ecf0e001672840428026629e340c3b5bf637f261a0805c2b2068f','14fe4930c78f88fb753503098f576b04','USD','2025-04-14 13:06:56','failed'),(30,NULL,59.98,'30b6ba42f0f1221c4d1cbcbe44401257f26a4cdcda02e965d331dd84f9b96711','daf5685d9759deba5b1aaaa387c62a9b','USD','2025-04-17 14:25:36','failed');
/*!40000 ALTER TABLE `orders` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `products`
--

DROP TABLE IF EXISTS `products`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `products` (
  `pid` int(11) NOT NULL AUTO_INCREMENT,
  `catid` int(11) DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `description` text,
  `image` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`pid`),
  KEY `catid` (`catid`),
  CONSTRAINT `products_ibfk_1` FOREIGN KEY (`catid`) REFERENCES `categories` (`catid`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `products`
--

LOCK TABLES `products` WRITE;
/*!40000 ALTER TABLE `products` DISABLE KEYS */;
INSERT INTO `products` VALUES (1,1,'Harry Potter and the Philospher Stone',24.99,'This is a fascinating fiction book that takes you on an incredible journey through uncharted territories and epic adventures. Perfect for readers who love a gripping narrative.','1.jpg'),(2,1,'Star Wars Folded Flyers',29.99,'This is an engaging fiction book that delves into intriguing mysteries and thrilling adventures. Perfect for readers who enjoy suspenseful and captivating stories.','2.jpg'),(3,1,'The Little Prince',27.99,'This is an intriguing fiction book that unfolds the mysteries of a hidden world. Perfect for readers who are fascinated by tales of suspense and wonder.','3.jpg'),(4,1,'A Game of Thrones',32.99,'This is an exhilarating fiction book that explores the adventures of brave heroes and mythical creatures. Ideal for readers who love epic tales and grand journeys.','4.jpg'),(5,2,'The Ink Trail Hong Kong',19.99,'This is an insightful non-fiction book that explores fascinating real-world topics. Ideal for readers who enjoy learning about various subjects in depth.','5.jpg'),(6,2,'Chinese Made Easy For KIDS',22.99,'This book provides an in-depth look at important historical events and their impact on the world. Perfect for history enthusiasts and those who enjoy factual narratives.','6.jpg'),(7,2,'Remembering Bruce Lee and Jon Benn Other Adventure',18.99,'This non-fiction book offers a detailed analysis of scientific discoveries and their implications for the future. Ideal for readers interested in science and innovation.','7.jpg'),(8,2,'Hong Kong Landscapes Shaping the Barren Rock',25.99,'This is a comprehensive non-fiction book that delves into the intricacies of human psychology and behavior. Perfect for readers who are curious about the inner workings of the human mind.','8.jpg'),(9,3,'Dog Man Grime and Punishment',14.99,'This comic book tells the story of a brave hero adventures in a fantastical world. Perfect for readers who enjoy thrilling and visually stunning narratives.','9.jpg'),(10,3,'City of Dragons The Awakening Storm',16.99,'Dive into the exciting world of superheroes and villains with this comic book. Ideal for readers who love action-packed stories and dynamic artwork.','10.jpg'),(11,3,'Displacement',18.99,'Explore the captivating tales of this comic book, filled with imaginative worlds and unforgettable characters. A perfect addition for fans of creative storytelling.','11.jpg'),(12,3,'Heartstopper',12.99,'Immerse yourself in the riveting world of Comic Book 4, where imagination meets incredible artistry. Ideal for those who appreciate profound storytelling and striking visuals.','12.jpg');
/*!40000 ALTER TABLE `products` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `userid` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `isAdmin` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`userid`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'admin@example.com','$2b$10$FaH92y2qK/rmHwGPx7L8ROp8.hYFwwBsuTjNik.ThBKokj1qkVH42',1),(2,'user@example.com','$2b$10$XBr56t70kl6cIYFXtB1JKejBznHvqJVZxQZWPpBUXcLjdwiL3WmdG',0),(3,'user2@example.com','$2b$10$O3uXsfL0gh8rBMBLSlSl5.tApfR0QwzDUQfkIdnnX2t1etcawrtZ2',0);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-04-23 10:11:02
