#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import sqlite3
import time
import random
import os
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
import logging
import queue

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import des dépendances avec gestion d'erreur améliorée
try:
    import requests
except ImportError:
    logger.error("Module 'requests' manquant. Installez-le avec: pip install requests")
    exit(1)

try:
    import irc.bot
    import irc.strings
except ImportError:
    logger.error("Module 'irc' manquant. Installez-le avec: pip install irc")
    exit(1)

try:
    from cryptography.fernet import Fernet
except ImportError:
    logger.error("Module 'cryptography' manquant. Installez-le avec: pip install cryptography")
    exit(1)

@dataclass
class BotProfile:
    name: str
    age: int
    gender: str
    city: str
    role: str
    nickname: str
    target_criteria: Dict

@dataclass
class UserProfile:
    username: str
    age: Optional[int] = None
    gender: Optional[str] = None
    city: Optional[str] = None
    last_seen: Optional[str] = None
    conversation_count: int = 0
    targeted: bool = False
    whois_info: Optional[Dict] = None

@dataclass
class ConversationTab:
    username: str
    messages: List[Dict]
    active: bool
    last_activity: str
    user_profile: Optional[UserProfile] = None

class SecurityManager:
    """Gestionnaire de sécurité pour l'application"""
    
    def __init__(self):
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

    def _load_or_create_key(self):
        key_file = "security.key"
        try:
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    return f.read()
            else:
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
                return key
        except Exception as e:
            logger.error(f"Erreur lors de la gestion de la clé de sécurité: {e}")
            raise

    def encrypt_data(self, data: str) -> str:
        try:
            return self.cipher.encrypt(data.encode()).decode()
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement: {e}")
            raise

    def decrypt_data(self, encrypted_data: str) -> str:
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            logger.error(f"Erreur lors du déchiffrement: {e}")
            raise

class DatabaseManager:
    def __init__(self, db_path="bot_data.db"):
        self.db_path = db_path
        self.write_queue = queue.Queue()
        self.running = True
        self._init_database()
        
        # Worker unique pour les écritures
        self.writer_thread = threading.Thread(target=self._database_writer, daemon=True)
        self.writer_thread.start()

    def _init_database(self):
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            cursor = conn.cursor()
            
            # Configuration WAL pour améliorer la concurrence
            cursor.execute("PRAGMA journal_mode = WAL")
            cursor.execute("PRAGMA synchronous = NORMAL")
            cursor.execute("PRAGMA busy_timeout = 30000")
            cursor.execute("PRAGMA cache_size = -10000")  # 10MB cache
            
            # Table des utilisateurs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    age INTEGER,
                    gender TEXT,
                    city TEXT,
                    last_seen TEXT,
                    conversation_count INTEGER DEFAULT 0,
                    targeted BOOLEAN DEFAULT 0,
                    whois_info TEXT,
                    created_at TEXT
                )
            ''')
            
            # Table des conversations
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    message TEXT,
                    timestamp TEXT,
                    bot_response TEXT,
                    prompt_used TEXT,
                    sentiment REAL
                )
            ''')
            
            # Table des configurations de bot
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bot_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_name TEXT UNIQUE,
                    config_data TEXT,
                    created_at TEXT
                )
            ''')
            
            # Table des clés API
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    service_name TEXT PRIMARY KEY,
                    config_value TEXT,
                    updated_at TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Base de données initialisée avec succès en mode WAL")
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")
            raise

    def _database_writer(self):
        """Worker unique pour toutes les écritures en base"""
        while self.running:
            try:
                operation, data = self.write_queue.get(timeout=1)
                self._execute_write_operation(operation, data)
                self.write_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Erreur writer DB: {e}")

    def _execute_write_operation(self, operation, data):
        """Exécute les opérations d'écriture de manière sérialisée"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            cursor = conn.cursor()
            
            if operation == 'save_user':
                cursor.execute('''
                    INSERT OR REPLACE INTO users (username, age, gender, city, last_seen,
                    conversation_count, targeted, whois_info, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', data)
            elif operation == 'save_conversation':
                cursor.execute('''
                    INSERT INTO conversations (username, message, timestamp, bot_response, prompt_used, sentiment)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', data)
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Erreur opération {operation}: {e}")

    def save_user_profile(self, user_profile: UserProfile):
        """Sauvegarde asynchrone via queue"""
        data = (
            user_profile.username,
            user_profile.age,
            user_profile.gender,
            user_profile.city,
            user_profile.last_seen or datetime.now().isoformat(),
            user_profile.conversation_count,
            user_profile.targeted,
            json.dumps(user_profile.whois_info) if user_profile.whois_info else None,
            datetime.now().isoformat()
        )
        self.write_queue.put(('save_user', data))

    def get_user_profile(self, username: str) -> UserProfile:
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return UserProfile(
                    username=result[0],
                    age=result[1],
                    gender=result[2],
                    city=result[3],
                    last_seen=result[4],
                    conversation_count=result[5],
                    targeted=bool(result[6]),
                    whois_info=json.loads(result[7]) if result[7] else None
                )
            return UserProfile(username=username)
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du profil utilisateur {username}: {e}")
            return UserProfile(username=username)

    def get_all_users(self):
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            cursor = conn.cursor()
            cursor.execute('SELECT username, age, gender, city, targeted FROM users ORDER BY last_seen DESC')
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de tous les utilisateurs: {e}")
            return []

    def save_conversation(self, username: str, message: str, bot_response: str, prompt_used: str = "", sentiment: float = 0.0):
        """Sauvegarde asynchrone via queue"""
        data = (username, message, datetime.now().isoformat(), bot_response, prompt_used, sentiment)
        self.write_queue.put(('save_conversation', data))

    def get_conversation_history(self, username: str, limit: int = 50):
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT message, bot_response, timestamp FROM conversations
                WHERE username = ? ORDER BY timestamp DESC LIMIT ?
            ''', (username, limit))
            result = cursor.fetchall()
            conn.close()
            return result
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'historique de conversation pour {username}: {e}")
            return []

class DeepSeekIntegration:
    def __init__(self, api_key=None):
        self.api_key = api_key or self._load_api_key()
        self.base_url = "https://api.deepseek.com/v1"
        self.conversation_history = {}

    def _load_api_key(self):
        # Priorité 1: Variable d'environnement
        api_key = os.getenv('DEEPSEEK_API_KEY')
        if api_key:
            return api_key

        # Priorité 2: Fichier de configuration
        config_file = "deepseek_config.txt"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    return f.read().strip()
            except Exception as e:
                logger.warning(f"Erreur lors de la lecture du fichier de configuration: {e}")

        # Priorité 3: Base de données
        try:
            conn = sqlite3.connect("bot_data.db", timeout=30.0)
            cursor = conn.cursor()
            cursor.execute("SELECT config_value FROM api_keys WHERE service_name = 'deepseek'")
            result = cursor.fetchone()
            conn.close()
            if result:
                security = SecurityManager()
                return security.decrypt_data(result[0])
        except Exception as e:
            logger.warning(f"Erreur lors de la récupération de la clé API depuis la base de données: {e}")

        return None

    def save_api_key(self, api_key: str) -> bool:
        try:
            conn = sqlite3.connect("bot_data.db", timeout=30.0)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    service_name TEXT PRIMARY KEY,
                    config_value TEXT,
                    updated_at TEXT
                )
            ''')
            
            security = SecurityManager()
            encrypted_key = security.encrypt_data(api_key)
            
            cursor.execute('''
                INSERT OR REPLACE INTO api_keys (service_name, config_value, updated_at)
                VALUES (?, ?, ?)
            ''', ('deepseek', encrypted_key, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            self.api_key = api_key
            logger.info("Clé API DeepSeek sauvegardée avec succès")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la clé API: {e}")
            return False

    def generate_response(self, message: str, user_profile: UserProfile, bot_profile: BotProfile, conversation_context: str = "") -> str:
        if not self.api_key:
            return "⚠️ Clé API DeepSeek non configurée. Allez dans Configuration API."

        system_prompt = self._create_system_prompt(bot_profile, user_profile, conversation_context)

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message}
                ],
                "max_tokens": 150,
                "temperature": 0.7
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return data['choices'][0]['message']['content'].strip()
            elif response.status_code == 401:
                return "❌ Clé API invalide. Vérifiez votre configuration."
            elif response.status_code == 429:
                return "⏳ Limite de taux atteinte. Attendez un moment."
            else:
                return f"❌ Erreur API: {response.status_code}"

        except requests.exceptions.Timeout:
            return "⏰ Timeout de l'API. Réessayez."
        except requests.exceptions.ConnectionError:
            return "🌐 Problème de connexion à l'API."
        except Exception as e:
            logger.error(f"Erreur lors de la génération de réponse: {e}")
            return self._get_fallback_response(bot_profile)

    def _create_system_prompt(self, bot_profile: BotProfile, user_profile: UserProfile, conversation_context: str) -> str:
        return f"""Tu es {bot_profile.name}, {bot_profile.age} ans, {bot_profile.gender},
habitant à {bot_profile.city}, {bot_profile.role}.

Tu discutes avec {user_profile.username} sur IRC. Réponds de manière naturelle et engageante.
Adapte ton style à la personne avec qui tu parles.

Contexte de la conversation précédente: {conversation_context}

Règles importantes:
- Reste dans le personnage
- Sois naturel et authentique
- Évite les réponses trop longues
- Pose des questions pour maintenir la conversation"""

    def _get_fallback_response(self, bot_profile: BotProfile) -> str:
        responses = [
            f"Salut ! Comment ça va ? Je suis {bot_profile.name} de {bot_profile.city} 😊",
            "C'est intéressant ce que tu dis ! Raconte-moi en plus ?",
            "Ah oui, je vois ! Moi aussi j'ai vécu ça récemment.",
            f"En tant que {bot_profile.role}, je peux te dire que...",
            "Haha, c'est marrant ! Tu as l'air sympa 😄"
        ]
        return f"[Mode démo] {random.choice(responses)}"

class IRCBotAdvanced(irc.bot.SingleServerIRCBot):
    def __init__(self, bot_profile: BotProfile, app_instance):
        # Configuration du serveur IRC AVANT l'appel au parent
        server_list = [("irc.europnet.org", 6667)]
        nickname = bot_profile.nickname
        realname = bot_profile.nickname
        
        # APPEL OBLIGATOIRE au constructeur parent EN PREMIER
        super().__init__(server_list, nickname, realname)
        
        # Ensuite vos attributs personnalisés
        self.bot_profile = bot_profile
        self.app = app_instance
        self.conversations = {}
        self.deepseek = DeepSeekIntegration()
        self.users_being_analyzed = set()
        self.channel = "#accueil"
        self._connection_lock = threading.Lock()
        self.analysis_semaphore = threading.Semaphore(3)  # Max 3 analyses simultanées
        self.analysis_queue = queue.Queue(maxsize=50)     # Buffer réduit

    def _is_connected(self, connection) -> bool:
        try:
            return connection.is_connected()
        except Exception:
            return False

    def on_welcome(self, connection, event):
        try:
            if self._is_connected(connection):
                connection.join(self.channel)
                self.app.log_message("Système", f"Connecté au serveur IRC en tant que {self.bot_profile.nickname}")
                connection.names(self.channel)
            else:
                self.app.log_message("Erreur", "Connexion IRC non établie lors de l'appel à on_welcome.")
        except Exception as e:
            self.app.log_message("Erreur", f"Erreur dans on_welcome: {e}")

    def on_namreply(self, connection, event):
        try:
            names = event.arguments[2].split()
            self.app.log_message("Système", f"Utilisateurs détectés: {len(names)}")
            
            # Traitement par batch limité pour éviter la surcharge
            for name in names[:20]:  # Limite réduite à 20 utilisateurs
                clean_name = name.lstrip('@+%&~')
                if clean_name != self.bot_profile.nickname and clean_name not in self.users_being_analyzed:
                    self.users_being_analyzed.add(clean_name)
                    try:
                        self.analysis_queue.put((connection, clean_name), block=False)
                    except queue.Full:
                        self.app.log_message("Warning", "Queue d'analyse pleine")
                        break
                        
            # Démarrage du worker d'analyse si pas déjà fait
            if not hasattr(self, 'analysis_worker_started'):
                threading.Thread(target=self._analysis_worker, daemon=True).start()
                self.analysis_worker_started = True
                
        except Exception as e:
            self.app.log_message("Erreur", f"Erreur dans on_namreply: {e}")

    def _analysis_worker(self):
        """Worker pour traiter les analyses d'utilisateurs"""
        while True:
            try:
                connection, username = self.analysis_queue.get(timeout=5)
                with self.analysis_semaphore:
                    self._analyze_user(connection, username)
                self.analysis_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.app.log_message("Erreur", f"Erreur worker analyse: {e}")

    def _analyze_user(self, connection, username: str):
        try:
            self.app.log_message("Analyse", f"Analyse de {username} en cours...")
            user_profile = self.app.db.get_user_profile(username)
            user_profile.last_seen = datetime.now().isoformat()

            # Analyse améliorée du nom d'utilisateur
            analyzed_info = self._analyze_username(username)
            
            # Mise à jour des informations si elles n'existent pas déjà
            if not user_profile.age and analyzed_info.get('age'):
                user_profile.age = analyzed_info['age']
            if not user_profile.gender and analyzed_info.get('gender'):
                user_profile.gender = analyzed_info['gender']
            if not user_profile.city and analyzed_info.get('city'):
                user_profile.city = analyzed_info['city']

            user_profile.targeted = self._matches_targeting_criteria(user_profile)
            self.app.db.save_user_profile(user_profile)
            
            # Mise à jour de l'interface utilisateur
            self.app.root.after(0, self.app.update_users_list)

            # Initiation de conversation si ciblé et première fois
            if user_profile.targeted and user_profile.conversation_count == 0:
                self._initiate_conversation(connection, username, user_profile)

            self.app.log_message("Analyse", f"Utilisateur {username} analysé - Ciblé: {user_profile.targeted}")

        except Exception as e:
            self.app.log_message("Erreur", f"Erreur analyse {username}: {str(e)}")
        finally:
            self.users_being_analyzed.discard(username)

    def _analyze_username(self, username: str) -> Dict:
        username_lower = username.lower()
        
        # Indicateurs de genre améliorés
        male_indicators = ['alex', 'max', 'tom', 'ben', 'sam', 'mike', 'dave', 'john', 'paul', 'marc', 'pierre', 'jean']
        female_indicators = ['anna', 'lisa', 'emma', 'sara', 'julie', 'marie', 'chloe', 'lea', 'nina', 'eva', 'sophie', 'claire']
        
        # Villes françaises étendues
        cities = ['paris', 'lyon', 'marseille', 'toulouse', 'nice', 'nantes', 'strasbourg', 'bordeaux', 'lille', 'rennes']
        
        result = {}
        
        # Détection du genre
        for indicator in male_indicators:
            if indicator in username_lower:
                result['gender'] = 'Homme'
                break
        
        if 'gender' not in result:
            for indicator in female_indicators:
                if indicator in username_lower:
                    result['gender'] = 'Femme'
                    break
        
        # Détection de l'âge basée sur l'année de naissance
        current_year = datetime.now().year
        for year in range(1980, 2010):
            if str(year) in username:
                result['age'] = current_year - year
                break
        
        # Détection de l'âge directe
        if 'age' not in result:
            for i in range(18, 100):
                if str(i) in username:
                    result['age'] = i
                    break
        
        # Détection de la ville
        for city in cities:
            if city in username_lower:
                result['city'] = city.capitalize()
                break
        
        return result

    def _matches_targeting_criteria(self, user_profile: UserProfile) -> bool:
        criteria = self.bot_profile.target_criteria
        
        # Vérification de l'âge
        if user_profile.age:
            min_age = criteria.get('age_min', 18)
            max_age = criteria.get('age_max', 99)
            if not (min_age <= user_profile.age <= max_age):
                return False
        
        # Vérification du genre
        target_gender = criteria.get('gender', 'Tous')
        if target_gender != 'Tous' and user_profile.gender:
            if user_profile.gender != target_gender:
                return False
        
        return True

    def _initiate_conversation(self, connection, username: str, user_profile: UserProfile):
        try:
            if not self._is_connected(connection):
                self.app.log_message("Erreur", f"Pas de connexion IRC lors de l'initiation de conversation avec {username}.")
                return

            # Messages d'ouverture personnalisés
            opening_messages = [
                f"Salut {username} ! Comment ça va ?",
                f"Hello {username} ! Tu es souvent sur ce salon ?",
                f"Coucou {username} ! Belle journée n'est-ce pas ?",
                f"Salut {username} ! Tu fais quoi de beau ?",
            ]

            # Personnalisation basée sur le profil
            if user_profile.city:
                opening_messages.append(f"Salut {username} ! Tu es de {user_profile.city} aussi ?")
            
            if user_profile.age and 18 <= user_profile.age <= 25:
                opening_messages.append(f"Hey {username} ! Tu es étudiant ?")

            message = random.choice(opening_messages)
            
            with self._connection_lock:
                connection.privmsg(username, message)
            
            user_profile.conversation_count += 1
            self.app.db.save_user_profile(user_profile)
            
            # Mise à jour de l'interface
            self.app.root.after(0, lambda: self.app.add_conversation_message(username, "", message, is_bot=True))
            self.app.log_message("Bot", f"Conversation initiée avec {username}: {message}")

        except Exception as e:
            self.app.log_message("Erreur", f"Erreur initiation conversation avec {username}: {str(e)}")

    def on_pubmsg(self, connection, event):
        try:
            nick = event.source.nick
            message = event.arguments[0]
            
            if nick == self.bot_profile.nickname:
                return

            user_profile = self.app.db.get_user_profile(nick)
            user_profile.last_seen = datetime.now().isoformat()
            self.app.db.save_user_profile(user_profile)
            
            self.app.log_message("Public", f"<{nick}> {message}")
        except Exception as e:
            self.app.log_message("Erreur", f"Erreur dans on_pubmsg: {e}")

    def on_privmsg(self, connection, event):
        try:
            nick = event.source.nick
            message = event.arguments[0]
            
            if nick == self.bot_profile.nickname:
                return

            self.app.log_message("Privé", f"{nick}: {message}")

            if not self._is_connected(connection):
                self.app.log_message("Erreur", f"Tentative d'envoi de message à {nick} alors que la connexion IRC n'est pas active.")
                return

            response = self._generate_intelligent_response(nick, message)
            if response:
                with self._connection_lock:
                    connection.privmsg(nick, response)
                self.app.root.after(0, lambda: self.app.add_conversation_message(nick, message, response, is_bot=False))

        except Exception as e:
            self.app.log_message("Erreur", f"Erreur dans on_privmsg: {e}")

    def on_join(self, connection, event):
        try:
            nick = event.source.nick
            if nick != self.bot_profile.nickname:
                self.app.log_message("Système", f"{nick} a rejoint le salon")
                if nick not in self.users_being_analyzed:
                    self.users_being_analyzed.add(nick)
                    try:
                        self.analysis_queue.put((connection, nick), block=False)
                    except queue.Full:
                        self.app.log_message("Warning", "Queue d'analyse pleine pour nouveau utilisateur")
        except Exception as e:
            self.app.log_message("Erreur", f"Erreur dans on_join: {e}")

    def _generate_intelligent_response(self, username: str, message: str) -> str:
        try:
            user_profile = self.app.db.get_user_profile(username)
            context = self.app.db.get_conversation_history(username, 5)
            
            response = self.deepseek.generate_response(
                message,
                user_profile,
                self.bot_profile,
                str(context)
            )
            
            self.app.db.save_conversation(username, message, response)
            return response
        except Exception as e:
            self.app.log_message("Erreur", f"Erreur génération réponse pour {username}: {e}")
            return "Désolé, j'ai eu un petit problème technique. Peux-tu répéter ?"

class BotControlApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bot IRC Intelligent - Version Améliorée")
        self.root.geometry("1200x800")
        
        # Variables de configuration
        self.config_vars = {
            "name_var": tk.StringVar(),
            "age_var": tk.StringVar(),
            "gender_var": tk.StringVar(),
            "city_var": tk.StringVar(),
            "role_var": tk.StringVar(),
            "nickname_var": tk.StringVar()
        }

        self.target_age_min = tk.StringVar(value="18")
        self.target_age_max = tk.StringVar(value="35")
        self.target_gender = tk.StringVar(value="Tous")
        self.status_var = tk.StringVar(value="Bot arrêté")

        # Variables API
        self.api_key_var = tk.StringVar()
        self.api_status_var = tk.StringVar(value="❌ Clé API non configurée")
        self.api_entry = None

        # Gestion de la base de données
        self.db = DatabaseManager()

        # Variables d'interface
        self.logs_display = None
        self.users_tree = None
        self.conversation_tabs = {}
        
        # Bot IRC
        self.bot_instance = None
        self.bot_thread = None

        # Création de l'interface
        self._create_ui()
        
        # Chargement initial
        self._load_existing_api_key()

    def _create_ui(self):
        # Menu principal
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Fichier", menu=file_menu)
        file_menu.add_command(label="Nouveau profil", command=self.create_new_profile)
        file_menu.add_command(label="Charger profil", command=self.load_profile)
        file_menu.add_command(label="Exporter logs", command=self.export_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit)

        # Notebook pour les onglets
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self._create_logs_tab()
        self._create_config_tab()
        self._create_api_config_tab()
        self._create_users_tab()
        self._create_conversations_tab()
        self._create_stats_tab()

    def _create_logs_tab(self):
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📝 Logs")

        # Zone d'affichage des logs
        self.logs_display = tk.Text(
            logs_frame, 
            state=tk.DISABLED, 
            wrap=tk.WORD, 
            bg="black", 
            fg="green", 
            font=("Courier", 9)
        )
        
        logs_scrollbar = ttk.Scrollbar(logs_frame, orient=tk.VERTICAL, command=self.logs_display.yview)
        self.logs_display.configure(yscrollcommand=logs_scrollbar.set)
        
        self.logs_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        logs_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

        # Contrôles des logs
        logs_control = ttk.Frame(logs_frame)
        logs_control.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        ttk.Button(logs_control, text="🗑️ Effacer", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(logs_control, text="💾 Sauvegarder", command=self.save_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(logs_control, text="📁 Ouvrir dossier", command=self.open_logs_folder).pack(side=tk.LEFT, padx=5)

    def _create_config_tab(self):
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="🔧 Configuration")

        # Configuration du bot
        bot_config = ttk.LabelFrame(config_frame, text="Configuration du Bot", padding=10)
        bot_config.pack(fill=tk.X, padx=10, pady=5)

        fields = [
            ("Nom:", "name_var"),
            ("Âge:", "age_var"),
            ("Genre:", "gender_var"),
            ("Ville:", "city_var"),
            ("Rôle:", "role_var"),
            ("Pseudo IRC:", "nickname_var")
        ]

        for i, (label, var_name) in enumerate(fields):
            ttk.Label(bot_config, text=label).grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
            ttk.Entry(bot_config, textvariable=self.config_vars[var_name], width=30).grid(row=i, column=1, padx=5, pady=2)

        # Critères de ciblage
        targeting_frame = ttk.LabelFrame(config_frame, text="Critères de Ciblage", padding=10)
        targeting_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(targeting_frame, text="Âge min:").grid(row=0, column=0, padx=5)
        ttk.Entry(targeting_frame, textvariable=self.target_age_min, width=10).grid(row=0, column=1, padx=5)

        ttk.Label(targeting_frame, text="Âge max:").grid(row=0, column=2, padx=5)
        ttk.Entry(targeting_frame, textvariable=self.target_age_max, width=10).grid(row=0, column=3, padx=5)

        ttk.Label(targeting_frame, text="Genre:").grid(row=1, column=0, padx=5, pady=5)
        gender_combo = ttk.Combobox(
            targeting_frame, 
            textvariable=self.target_gender,
            values=["Tous", "Homme", "Femme"], 
            state="readonly"
        )
        gender_combo.grid(row=1, column=1, padx=5, pady=5)

        # Contrôles
        control_frame = ttk.Frame(config_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(control_frame, text="💾 Sauvegarder Profil", command=self.save_profile).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🚀 Démarrer Bot", command=self.start_bot).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="⏹️ Arrêter Bot", command=self.stop_bot).pack(side=tk.LEFT, padx=5)

        status_label = ttk.Label(
            control_frame, 
            textvariable=self.status_var, 
            foreground="red", 
            font=("Arial", 10, "bold")
        )
        status_label.pack(side=tk.RIGHT, padx=10)

    def _create_api_config_tab(self):
        api_frame = ttk.Frame(self.notebook)
        self.notebook.add(api_frame, text="🔑 Configuration API")

        # Configuration DeepSeek
        deepseek_frame = ttk.LabelFrame(api_frame, text="Configuration DeepSeek API", padding=15)
        deepseek_frame.pack(fill=tk.X, padx=10, pady=10)

        info_text = """🔗 Pour obtenir votre clé API DeepSeek :
1. Allez sur https://platform.deepseek.com/
2. Créez un compte ou connectez-vous
3. Allez dans "API Keys" dans votre dashboard
4. Créez une nouvelle clé API
5. Copiez la clé et collez-la ci-dessous"""

        info_label = ttk.Label(deepseek_frame, text=info_text, justify=tk.LEFT)
        info_label.pack(anchor=tk.W, pady=(0, 10))

        # Champ de saisie de la clé API
        api_key_frame = ttk.Frame(deepseek_frame)
        api_key_frame.pack(fill=tk.X, pady=5)

        ttk.Label(api_key_frame, text="Clé API DeepSeek:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        self.api_entry = ttk.Entry(api_key_frame, textvariable=self.api_key_var, show="*", width=60)
        self.api_entry.pack(fill=tk.X, pady=5)

        # Boutons de contrôle
        buttons_frame = ttk.Frame(deepseek_frame)
        buttons_frame.pack(fill=tk.X, pady=10)

        ttk.Button(buttons_frame, text="💾 Sauvegarder", command=self.save_api_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="🔍 Afficher/Masquer", command=self.toggle_api_visibility).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="🧪 Tester", command=self.test_api_key).pack(side=tk.LEFT, padx=5)

        # Statut de l'API
        status_label = ttk.Label(deepseek_frame, textvariable=self.api_status_var, font=("Arial", 10, "bold"))
        status_label.pack(pady=10)

    def _create_users_tab(self):
        users_frame = ttk.Frame(self.notebook)
        self.notebook.add(users_frame, text="👥 Utilisateurs")

        # Filtres
        filter_frame = ttk.LabelFrame(users_frame, text="Filtres", padding=10)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)

        # Filtres par genre
        gender_frame = ttk.Frame(filter_frame)
        gender_frame.pack(fill=tk.X, pady=5)

        self.filter_homme = tk.BooleanVar(value=True)
        self.filter_femme = tk.BooleanVar(value=True)
        self.filter_autre = tk.BooleanVar(value=True)

        ttk.Checkbutton(gender_frame, text="Homme", variable=self.filter_homme, command=self.update_users_list).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(gender_frame, text="Femme", variable=self.filter_femme, command=self.update_users_list).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(gender_frame, text="Autre", variable=self.filter_autre, command=self.update_users_list).pack(side=tk.LEFT, padx=10)

        # Autres filtres
        controls_frame = ttk.Frame(filter_frame)
        controls_frame.pack(fill=tk.X, pady=5)

        ttk.Label(controls_frame, text="Âge:").pack(side=tk.LEFT, padx=5)
        self.age_filter = tk.StringVar(value="Tous")
        age_combo = ttk.Combobox(
            controls_frame, 
            textvariable=self.age_filter,
            values=["Tous", "18-25", "26-35", "36-45", "46+"], 
            state="readonly", 
            width=10
        )
        age_combo.pack(side=tk.LEFT, padx=5)
        age_combo.bind('<<ComboboxSelected>>', lambda e: self.update_users_list())

        ttk.Label(controls_frame, text="Rechercher:").pack(side=tk.LEFT, padx=(20, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(controls_frame, textvariable=self.search_var, width=20)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<KeyRelease>', lambda e: self.update_users_list())

        ttk.Button(controls_frame, text="🔄", command=self.refresh_users).pack(side=tk.LEFT, padx=5)

        # Liste des utilisateurs
        columns = ('Pseudo', 'Age', 'Ville', 'Genre', 'Ciblé', 'Dernière activité')
        self.users_tree = ttk.Treeview(users_frame, columns=columns, show='headings', height=15)

        for col in columns:
            self.users_tree.heading(col, text=col)
            
        self.users_tree.column('Pseudo', width=120)
        self.users_tree.column('Age', width=60)
        self.users_tree.column('Ville', width=100)
        self.users_tree.column('Genre', width=80)
        self.users_tree.column('Ciblé', width=60)
        self.users_tree.column('Dernière activité', width=150)

        users_scrollbar = ttk.Scrollbar(users_frame, orient=tk.VERTICAL, command=self.users_tree.yview)
        self.users_tree.configure(yscrollcommand=users_scrollbar.set)

        self.users_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        users_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)

        # Actions sur les utilisateurs
        action_frame = ttk.Frame(users_frame)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(action_frame, text="💬 Ouvrir conversation", command=self.open_user_conversation).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="🎯 Basculer ciblage", command=self.toggle_user_targeting).pack(side=tk.LEFT, padx=5)

    def _create_conversations_tab(self):
        conv_frame = ttk.Frame(self.notebook)
        self.notebook.add(conv_frame, text="💬 Conversations")

        # Zone principale pour les conversations
        self.conversations_notebook = ttk.Notebook(conv_frame)
        self.conversations_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _create_stats_tab(self):
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="📊 Statistiques")

        # Statistiques générales
        general_stats = ttk.LabelFrame(stats_frame, text="Statistiques Générales", padding=10)
        general_stats.pack(fill=tk.X, padx=10, pady=5)

        self.stats_text = tk.Text(general_stats, height=10, state=tk.DISABLED)
        self.stats_text.pack(fill=tk.BOTH, expand=True)

        ttk.Button(general_stats, text="🔄 Actualiser", command=self.update_stats).pack(pady=5)

    # Méthodes de gestion des profils
    def create_new_profile(self):
        names = ["Alex", "Sam", "Jordan", "Casey", "Morgan", "Riley", "Avery", "Quinn"]
        cities = ["Paris", "Lyon", "Marseille", "Toulouse", "Nice", "Nantes", "Strasbourg"]
        roles = ["Étudiant", "Développeur", "Designer", "Photographe", "Musicien", "Écrivain"]

        self.config_vars["name_var"].set(random.choice(names))
        self.config_vars["age_var"].set(str(random.randint(20, 30)))
        self.config_vars["gender_var"].set(random.choice(["Homme", "Femme", "Non-binaire"]))
        self.config_vars["city_var"].set(random.choice(cities))
        self.config_vars["role_var"].set(random.choice(roles))
        
        nickname = f"{self.config_vars['name_var'].get()}{random.randint(10, 99)}"
        self.config_vars["nickname_var"].set(nickname)

    def save_profile(self):
        try:
            profile_data = {
                "name": self.config_vars["name_var"].get(),
                "age": int(self.config_vars["age_var"].get() or 25),
                "gender": self.config_vars["gender_var"].get(),
                "city": self.config_vars["city_var"].get(),
                "role": self.config_vars["role_var"].get(),
                "nickname": self.config_vars["nickname_var"].get(),
                "target_criteria": {
                    "age_min": int(self.target_age_min.get()),
                    "age_max": int(self.target_age_max.get()),
                    "gender": self.target_gender.get()
                }
            }

            conn = sqlite3.connect(self.db.db_path, timeout=30.0)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO bot_configs (profile_name, config_data, created_at)
                VALUES (?, ?, ?)
            ''', (profile_data["name"], json.dumps(profile_data), datetime.now().isoformat()))
            conn.commit()
            conn.close()

            messagebox.showinfo("Succès", "Profil sauvegardé avec succès!")
            self.log_message("Système", f"Profil {profile_data['name']} sauvegardé")

        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la sauvegarde: {str(e)}")

    def load_profile(self):
        try:
            conn = sqlite3.connect(self.db.db_path, timeout=30.0)
            cursor = conn.cursor()
            cursor.execute('SELECT profile_name, config_data FROM bot_configs ORDER BY created_at DESC')
            profiles = cursor.fetchall()
            conn.close()

            if not profiles:
                messagebox.showinfo("Info", "Aucun profil sauvegardé")
                return

            # Fenêtre de sélection de profil
            profile_window = tk.Toplevel(self.root)
            profile_window.title("Charger un profil")
            profile_window.geometry("400x300")

            ttk.Label(profile_window, text="Sélectionnez un profil:", font=("Arial", 12)).pack(pady=10)

            profile_listbox = tk.Listbox(profile_window)
            profile_listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

            for profile_name, _ in profiles:
                profile_listbox.insert(tk.END, profile_name)

            def load_selected():
                selection = profile_listbox.curselection()
                if selection:
                    profile_name, config_data = profiles[selection[0]]
                    data = json.loads(config_data)

                    # Chargement des données dans l'interface
                    self.config_vars["name_var"].set(data.get("name", ""))
                    self.config_vars["age_var"].set(str(data.get("age", "")))
                    self.config_vars["gender_var"].set(data.get("gender", ""))
                    self.config_vars["city_var"].set(data.get("city", ""))
                    self.config_vars["role_var"].set(data.get("role", ""))
                    self.config_vars["nickname_var"].set(data.get("nickname", ""))

                    criteria = data.get("target_criteria", {})
                    self.target_age_min.set(str(criteria.get("age_min", "18")))
                    self.target_age_max.set(str(criteria.get("age_max", "35")))
                    self.target_gender.set(criteria.get("gender", "Tous"))

                    profile_window.destroy()
                    messagebox.showinfo("Succès", f"Profil '{profile_name}' chargé!")
                    self.log_message("Système", f"Profil '{profile_name}' chargé")

            ttk.Button(profile_window, text="Charger", command=load_selected).pack(pady=10)

        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur: {str(e)}")

    # Méthodes de gestion de l'API
    def _load_existing_api_key(self):
        try:
            deepseek = DeepSeekIntegration()
            if deepseek.api_key:
                self.api_key_var.set(deepseek.api_key)
                self.api_status_var.set("✅ Clé API configurée")
            else:
                self.api_status_var.set("❌ Clé API non configurée")
        except Exception as e:
            self.log_message("Erreur", f"Erreur chargement clé API: {e}")

    def save_api_key(self):
        api_key = self.api_key_var.get().strip()
        if not api_key:
            messagebox.showerror("Erreur", "Veuillez saisir une clé API")
            return

        deepseek = DeepSeekIntegration()
        if deepseek.save_api_key(api_key):
            self.api_status_var.set("✅ Clé API sauvegardée")
            messagebox.showinfo("Succès", "Clé API sauvegardée avec succès!")
            self.log_message("API", "Clé API DeepSeek sauvegardée")
        else:
            self.api_status_var.set("❌ Erreur sauvegarde")
            messagebox.showerror("Erreur", "Erreur lors de la sauvegarde de la clé API")

    def toggle_api_visibility(self):
        if self.api_entry['show'] == '*':
            self.api_entry.config(show='')
        else:
            self.api_entry.config(show='*')

    def test_api_key(self):
        api_key = self.api_key_var.get().strip()
        if not api_key:
            messagebox.showerror("Erreur", "Veuillez saisir une clé API")
            return

        # Test simple de l'API
        deepseek = DeepSeekIntegration(api_key)
        test_profile = UserProfile(username="test")
        bot_profile = BotProfile(
            name="Test", age=25, gender="Test", city="Test", 
            role="Test", nickname="test", target_criteria={}
        )
        
        response = deepseek.generate_response("Hello", test_profile, bot_profile)
        
        if "❌" in response or "⚠️" in response:
            self.api_status_var.set("❌ Clé API invalide")
            messagebox.showerror("Erreur", "Clé API invalide ou problème de connexion")
        else:
            self.api_status_var.set("✅ Clé API valide")
            messagebox.showinfo("Succès", "Clé API testée avec succès!")

    # Méthodes de gestion du bot
    def start_bot(self):
        try:
            # Validation des données
            if not all([
                self.config_vars["name_var"].get(),
                self.config_vars["nickname_var"].get(),
                self.config_vars["age_var"].get()
            ]):
                messagebox.showerror("Erreur", "Veuillez remplir tous les champs obligatoires")
                return

            # Création du profil bot
            bot_profile = BotProfile(
                name=self.config_vars["name_var"].get(),
                age=int(self.config_vars["age_var"].get()),
                gender=self.config_vars["gender_var"].get(),
                city=self.config_vars["city_var"].get(),
                role=self.config_vars["role_var"].get(),
                nickname=self.config_vars["nickname_var"].get(),
                target_criteria={
                    "age_min": int(self.target_age_min.get()),
                    "age_max": int(self.target_age_max.get()),
                    "gender": self.target_gender.get()
                }
            )

            # Démarrage du bot
            self.bot_instance = IRCBotAdvanced(bot_profile, self)
            self.bot_thread = threading.Thread(target=self.bot_instance.start, daemon=True)
            self.bot_thread.start()

            self.status_var.set("Bot en cours de démarrage...")
            self.log_message("Bot", f"Démarrage du bot {bot_profile.nickname}")
            
            # Mise à jour du statut après un délai
            self.root.after(3000, lambda: self.status_var.set("✅ Bot actif"))

        except Exception as e:
            self.log_message("Erreur", f"Erreur démarrage bot: {e}")
            messagebox.showerror("Erreur", f"Erreur lors du démarrage: {str(e)}")

    def stop_bot(self):
        try:
            if self.bot_instance:
                self.bot_instance.die("Arrêt du bot")
                self.bot_instance = None
                self.bot_thread = None
                self.status_var.set("⏹️ Bot arrêté")
                self.log_message("Bot", "Bot arrêté")
            else:
                messagebox.showinfo("Info", "Aucun bot en cours d'exécution")
        except Exception as e:
            self.log_message("Erreur", f"Erreur arrêt bot: {e}")

    # Méthodes de gestion des logs
    def log_message(self, source: str, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {source}: {message}\n"

        # Affichage dans l'interface
        if hasattr(self, "logs_display") and self.logs_display:
            self.logs_display.config(state="normal")
            self.logs_display.insert("end", log_entry)
            self.logs_display.config(state="disabled")
            self.logs_display.see("end")

        # Sauvegarde sur disque
        try:
            with open("bot_logs.txt", "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            logger.error(f"Erreur sauvegarde log: {e}")

    def clear_logs(self):
        if messagebox.askyesno("Confirmation", "Effacer tous les logs affichés ?"):
            self.logs_display.config(state="normal")
            self.logs_display.delete(1.0, "end")
            self.logs_display.config(state="disabled")
            self.log_message("Système", "Logs effacés")

    def save_logs(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                content = self.logs_display.get(1.0, "end-1c")
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Succès", f"Logs sauvegardés vers {filename}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur: {str(e)}")

    def export_logs(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                logs_content = self.logs_display.get(1.0, "end-1c")
                export_data = {
                    "export_date": datetime.now().isoformat(),
                    "logs": logs_content
                }
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Succès", f"Logs exportés vers {filename}")
                self.log_message("Export", f"Logs exportés vers {filename}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur d'export: {str(e)}")

    def open_logs_folder(self):
        import subprocess
        import platform
        
        logs_dir = os.path.dirname(os.path.abspath("bot_logs.txt"))
        try:
            if platform.system() == "Windows":
                os.startfile(logs_dir)
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", logs_dir])
            else:  # Linux
                subprocess.run(["xdg-open", logs_dir])
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'ouvrir le dossier: {str(e)}")

    # Méthodes de gestion des utilisateurs
    def update_users_list(self):
        try:
            # Effacement de la liste actuelle
            for item in self.users_tree.get_children():
                self.users_tree.delete(item)

            # Récupération des utilisateurs
            users = self.db.get_all_users()
            search_term = self.search_var.get().lower() if hasattr(self, 'search_var') else ""

            for user in users:
                username, age, gender, city, targeted = user
                
                # Application des filtres
                if search_term and search_term not in username.lower():
                    continue
                
                # Filtre par genre
                if hasattr(self, 'filter_homme'):
                    if gender == "Homme" and not self.filter_homme.get():
                        continue
                    elif gender == "Femme" and not self.filter_femme.get():
                        continue
                    elif gender not in ["Homme", "Femme"] and not self.filter_autre.get():
                        continue

                # Filtre par âge
                if hasattr(self, 'age_filter'):
                    age_filter = self.age_filter.get()
                    if age_filter != "Tous" and age:
                        if age_filter == "18-25" and not (18 <= age <= 25):
                            continue
                        elif age_filter == "26-35" and not (26 <= age <= 35):
                            continue
                        elif age_filter == "36-45" and not (36 <= age <= 45):
                            continue
                        elif age_filter == "46+" and age < 46:
                            continue

                # Ajout à la liste
                self.users_tree.insert('', 'end', values=(
                    username,
                    age or "N/A",
                    city or "N/A",
                    gender or "N/A",
                    "✅" if targeted else "❌",
                    "Récemment"
                ))

        except Exception as e:
            self.log_message("Erreur", f"Erreur mise à jour liste utilisateurs: {e}")

    def refresh_users(self):
        self.update_users_list()
        self.log_message("Système", "Liste des utilisateurs actualisée")

    def open_user_conversation(self):
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Attention", "Veuillez sélectionner un utilisateur")
            return

        item = self.users_tree.item(selection[0])
        username = item['values'][0]
        
        # Création d'un onglet de conversation
        self._create_conversation_tab(username)

    def toggle_user_targeting(self):
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Attention", "Veuillez sélectionner un utilisateur")
            return

        item = self.users_tree.item(selection[0])
        username = item['values'][0]
        
        user_profile = self.db.get_user_profile(username)
        user_profile.targeted = not user_profile.targeted
        self.db.save_user_profile(user_profile)
        
        self.update_users_list()
        self.log_message("Système", f"Ciblage basculé pour {username}: {user_profile.targeted}")

    def _create_conversation_tab(self, username: str):
        # Vérification si l'onglet existe déjà
        for tab_id in self.conversations_notebook.tabs():
            if self.conversations_notebook.tab(tab_id, "text") == username:
                self.conversations_notebook.select(tab_id)
                return

        # Création du nouvel onglet
        conv_frame = ttk.Frame(self.conversations_notebook)
        self.conversations_notebook.add(conv_frame, text=username)
        self.conversations_notebook.select(conv_frame)

        # Zone d'affichage des messages
        messages_frame = ttk.Frame(conv_frame)
        messages_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        messages_display = tk.Text(messages_frame, state=tk.DISABLED, wrap=tk.WORD, height=20)
        messages_scrollbar = ttk.Scrollbar(messages_frame, orient=tk.VERTICAL, command=messages_display.yview)
        messages_display.configure(yscrollcommand=messages_scrollbar.set)

        messages_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        messages_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Zone de saisie (partie manquante ajoutée)
        input_frame = ttk.Frame(conv_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        message_var = tk.StringVar()
        message_entry = ttk.Entry(input_frame, textvariable=message_var)
        message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        def send_message():
            message = message_var.get().strip()
            if message and self.bot_instance:
                try:
                    if hasattr(self.bot_instance, 'connection') and self.bot_instance.connection:
                        self.bot_instance.connection.privmsg(username, message)
                        self.add_conversation_message(username, "", message, is_bot=True)
                        message_var.set("")
                    else:
                        self.log_message("Erreur", "Bot non connecté")
                except Exception as e:
                    self.log_message("Erreur", f"Erreur envoi message: {e}")

        ttk.Button(input_frame, text="Envoyer", command=send_message).pack(side=tk.RIGHT)
        message_entry.bind('<Return>', lambda e: send_message())

        # Stockage de la référence pour mise à jour
        self.conversation_tabs[username] = {
            'frame': conv_frame,
            'display': messages_display,
            'entry': message_entry
        }

        # Chargement de l'historique
        self._load_conversation_history(username, messages_display)


    def refresh_users(self):
        self.update_users_list()
        self.log_message("Système", "Liste des utilisateurs actualisée")

    def open_user_conversation(self):
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Attention", "Veuillez sélectionner un utilisateur")
            return

        item = self.users_tree.item(selection[0])
        username = item['values'][0]
        
        # Création d'un onglet de conversation
        self._create_conversation_tab(username)

    def toggle_user_targeting(self):
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Attention", "Veuillez sélectionner un utilisateur")
            return

        item = self.users_tree.item(selection[0])
        username = item['values'][0]
        
        user_profile = self.db.get_user_profile(username)
        user_profile.targeted = not user_profile.targeted
        self.db.save_user_profile(user_profile)
        
        self.update_users_list()
        self.log_message("Système", f"Ciblage basculé pour {username}: {user_profile.targeted}")

    def _create_conversation_tab(self, username: str):
        # Vérification si l'onglet existe déjà
        for tab_id in self.conversations_notebook.tabs():
            if self.conversations_notebook.tab(tab_id, "text") == username:
                self.conversations_notebook.select(tab_id)
                return

        # Création du nouvel onglet
        conv_frame = ttk.Frame(self.conversations_notebook)
        self.conversations_notebook.add(conv_frame, text=username)
        self.conversations_notebook.select(conv_frame)

        # Zone d'affichage des messages
        messages_frame = ttk.Frame(conv_frame)
        messages_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        messages_display = tk.Text(messages_frame, state=tk.DISABLED, wrap=tk.WORD, height=20)
        messages_scrollbar = ttk.Scrollbar(messages_frame, orient=tk.VERTICAL, command=messages_display.yview)
        messages_display.configure(yscrollcommand=messages_scrollbar.set)

        messages_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        messages_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Zone de saisie
        input_frame = ttk.Frame(conv_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        message_var = tk.StringVar()
        message_entry = ttk.Entry(input_frame, textvariable=message_var)
        message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        def send_message():
            message = message_var.get().strip()
            if message and self.bot_instance:
                try:
                    # Correction: utilisation correcte de la connexion IRC
                    if hasattr(self.bot_instance, 'connection') and self.bot_instance.connection:
                        self.bot_instance.connection.privmsg(username, message)
                        self.add_conversation_message(username, "", message, is_bot=True)
                        message_var.set("")
                    else:
                        self.log_message("Erreur", "Bot non connecté")
                except Exception as e:
                    self.log_message("Erreur", f"Erreur envoi message: {e}")

        ttk.Button(input_frame, text="Envoyer", command=send_message).pack(side=tk.RIGHT)
        message_entry.bind('<Return>', lambda e: send_message())

        # Stockage de la référence pour mise à jour
        self.conversation_tabs[username] = {
            'frame': conv_frame,
            'display': messages_display,
            'entry': message_entry
        }

        # Chargement de l'historique
        self._load_conversation_history(username, messages_display)

    def _load_conversation_history(self, username: str, display_widget):
        try:
            history = self.db.get_conversation_history(username, 20)
            display_widget.config(state=tk.NORMAL)
            for message, bot_response, timestamp in reversed(history):
                display_widget.insert(tk.END, f"[{timestamp}] {username}: {message}\n")
                display_widget.insert(tk.END, f"[{timestamp}] Bot: {bot_response}\n\n")
            display_widget.config(state=tk.DISABLED)
            display_widget.see(tk.END)
        except Exception as e:
            self.log_message("Erreur", f"Erreur chargement historique: {e}")

    def add_conversation_message(self, username: str, user_message: str, bot_message: str, is_bot: bool = False):
        """Ajoute un message à l'onglet de conversation"""
        try:
            # Créer l'onglet s'il n'existe pas
            if username not in self.conversation_tabs:
                self._create_conversation_tab(username)
            
            if username in self.conversation_tabs:
                display = self.conversation_tabs[username]['display']
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                display.config(state=tk.NORMAL)
                if not is_bot and user_message:
                    display.insert(tk.END, f"[{timestamp}] {username}: {user_message}\n")
                if bot_message:
                    display.insert(tk.END, f"[{timestamp}] Bot: {bot_message}\n\n")
                display.config(state=tk.DISABLED)
                display.see(tk.END)
        except Exception as e:
            self.log_message("Erreur", f"Erreur ajout message conversation: {e}")

    def update_stats(self):
        try:
            conn = sqlite3.connect(self.db.db_path, timeout=30.0)
            cursor = conn.cursor()
            
            # Statistiques générales
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE targeted = 1")
            targeted_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM conversations")
            total_conversations = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT username) FROM conversations")
            users_with_conversations = cursor.fetchone()[0]
            
            conn.close()
            
            # Calcul des pourcentages avec protection division par zéro
            taux_ciblage = (targeted_users / total_users * 100) if total_users > 0 else 0
            taux_conversation = (users_with_conversations / total_users * 100) if total_users > 0 else 0
            
            stats_text = f"""📊 STATISTIQUES GÉNÉRALES

👥 Utilisateurs total: {total_users}
🎯 Utilisateurs ciblés: {targeted_users}
💬 Messages échangés: {total_conversations}
🗣️ Utilisateurs ayant conversé: {users_with_conversations}

📈 Taux de ciblage: {taux_ciblage:.1f}%
📈 Taux de conversation: {taux_conversation:.1f}%

🤖 Statut bot: {self.status_var.get()}
🔑 API: {self.api_status_var.get()}
"""
            
            self.stats_text.config(state=tk.NORMAL)
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats_text)
            self.stats_text.config(state=tk.DISABLED)
            
        except Exception as e:
            self.log_message("Erreur", f"Erreur mise à jour statistiques: {e}")

# Point d'entrée principal
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = BotControlApp(root)
        root.mainloop()
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        messagebox.showerror("Erreur fatale", f"L'application a rencontré une erreur fatale:\n{e}")
