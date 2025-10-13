#!/usr/bin/env python3
"""
Create Test Browser History Database for Chrome and Firefox (Safari is not supported for this MVP)
"""

import sqlite3
import os
from datetime import datetime, timedelta

def create_test_browser_database():
    """Create fake Chrome history database"""
    
    
    os.makedirs('test_data/browser', exist_ok=True)
    
    db_path = 'test_data/browser/test_chrome_history.db'
    
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Removed existing database: {db_path}")
    
    # Connect and create database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER NOT NULL,
            hidden INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER,
            transition INTEGER DEFAULT 0,
            segment_id INTEGER,
            visit_duration INTEGER DEFAULT 0
        )
    ''')
    
    # Chrome uses microseconds since January 1, 1601 (Windows epoch)
    def to_chrome_timestamp(dt):
        """Convert Python datetime to Chrome timestamp format"""
        epoch_start = datetime(1601, 1, 1)
        delta = dt - epoch_start
        return int(delta.total_seconds() * 1000000)
    
    base_time = datetime.now() - timedelta(days=7)
    
    # Fake browsing data - mix of legitimate and suspicious sites
    fake_urls = [
        {
            'url': 'https://github.com/forensics/toolkit',
            'title': 'Digital Forensics Toolkit - GitHub',
            'visit_count': 8,
            'typed_count': 2,
            'time_offset': timedelta(days=7, hours=10)
        },
        {
            'url': 'https://stackoverflow.com/questions/python-sqlite-forensics',
            'title': 'How to extract browser history with Python? - Stack Overflow',
            'visit_count': 3,
            'typed_count': 0,
            'time_offset': timedelta(days=6, hours=14)
        },
        {
            'url': 'https://docs.python.org/3/library/sqlite3.html',
            'title': 'sqlite3 — DB-API 2.0 interface for SQLite databases',
            'visit_count': 5,
            'typed_count': 1,
            'time_offset': timedelta(days=6, hours=15)
        },
        {
            'url': 'https://www.linkedin.com/jobs/cybersecurity',
            'title': 'Cybersecurity Jobs | LinkedIn',
            'visit_count': 12,
            'typed_count': 4,
            'time_offset': timedelta(days=5, hours=9)
        },
        {
            'url': 'https://suspicious-download-site.onion/malware.exe',
            'title': 'Free Software Download',
            'visit_count': 1,
            'typed_count': 0,
            'time_offset': timedelta(days=4, hours=2)
        },
        {
            'url': 'https://www.reddit.com/r/cybersecurity',
            'title': 'r/cybersecurity - Reddit',
            'visit_count': 15,
            'typed_count': 3,
            'time_offset': timedelta(days=3, hours=20)
        },
        {
            'url': 'https://darkweb-marketplace.onion/illegal-goods',
            'title': 'Anonymous Marketplace',
            'visit_count': 2,
            'typed_count': 0,
            'time_offset': timedelta(days=2, hours=3)
        },
        {
            'url': 'https://www.anthropic.com',
            'title': 'Anthropic - AI Safety and Research',
            'visit_count': 4,
            'typed_count': 1,
            'time_offset': timedelta(days=1, hours=16)
        },
        {
            'url': 'https://gmail.com',
            'title': 'Gmail',
            'visit_count': 25,
            'typed_count': 10,
            'time_offset': timedelta(hours=8)
        },
        {
            'url': 'https://leaked-credentials-db.com/search',
            'title': 'Credential Database Search',
            'visit_count': 1,
            'typed_count': 0,
            'time_offset': timedelta(hours=4)
        }
    ]
    
    url_id = 1
    for entry in fake_urls:
        visit_time = to_chrome_timestamp(base_time + entry['time_offset'])
        
        cursor.execute('''
            INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time, hidden)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        ''', (url_id, entry['url'], entry['title'], entry['visit_count'], 
              entry['typed_count'], visit_time))
        
        for visit_num in range(entry['visit_count']):
            visit_time_offset = timedelta(hours=visit_num * 2)
            visit_timestamp = to_chrome_timestamp(base_time + entry['time_offset'] + visit_time_offset)
            
            cursor.execute('''
                INSERT INTO visits (url, visit_time, transition, visit_duration)
                VALUES (?, ?, 0, ?)
            ''', (url_id, visit_timestamp, 30000 + (visit_num * 10000)))  # Duration in microseconds
        
        url_id += 1
    
    conn.commit()
    
    cursor.execute('SELECT COUNT(*) FROM urls')
    url_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM visits')
    visit_count = cursor.fetchone()[0]
    
    print("Test Browser Database Created Successfully!")
    print(f"Location: {db_path}")
    print(f"URLs: {url_count}")
    print(f"Total Visits: {visit_count}")
    print(f"\nDatabase includes:")
    print("  - Legitimate sites (GitHub, Stack Overflow, Gmail)")
    print("  - Suspicious sites (.onion domains, malware)")
    print("  - Realistic visit counts and timestamps")
    print(f"{'='*50}\n")
    
    conn.close()
    
    return db_path

def create_test_firefox_database():
    """Create a fake Firefox history database"""
    
    os.makedirs('test_data/browser', exist_ok=True)
    
    db_path = 'test_data/browser/test_firefox_places.sqlite'
    
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Removed existing database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create Firefox's moz_places table structure
    cursor.execute('''
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            title TEXT,
            rev_host TEXT,
            visit_count INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0,
            typed INTEGER DEFAULT 0,
            frecency INTEGER DEFAULT -1,
            last_visit_date INTEGER,
            guid TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_visit INTEGER,
            place_id INTEGER,
            visit_date INTEGER,
            visit_type INTEGER,
            session INTEGER
        )
    ''')
    
    # Firefox uses microseconds since Unix epoch (1970-01-01)
    def to_firefox_timestamp(dt):
        """Convert Python datetime to Firefox timestamp format"""
        return int(dt.timestamp() * 1000000)
    
    base_time = datetime.now() - timedelta(days=7)
    
    fake_urls = [
        {
            'url': 'https://www.kali.org/tools/',
            'title': 'Kali Linux Tools Listing',
            'visit_count': 6,
            'typed': 1,
            'time_offset': timedelta(days=7, hours=11)
        },
        {
            'url': 'https://www.wireshark.org/docs/',
            'title': 'Wireshark Documentation',
            'visit_count': 4,
            'typed': 1,
            'time_offset': timedelta(days=6, hours=16)
        },
        {
            'url': 'https://owasp.org/www-project-top-ten/',
            'title': 'OWASP Top 10 Security Risks',
            'visit_count': 7,
            'typed': 2,
            'time_offset': timedelta(days=5, hours=13)
        },
        {
            'url': 'https://www.exploit-db.com/',
            'title': 'Exploit Database - Exploits for Penetration Testers',
            'visit_count': 3,
            'typed': 0,
            'time_offset': timedelta(days=5, hours=14)
        },
        {
            'url': 'https://tor-browser-downloads.onion/packages',
            'title': 'Tor Browser Downloads',
            'visit_count': 2,
            'typed': 0,
            'time_offset': timedelta(days=4, hours=22)
        },
        {
            'url': 'https://darknet-forums.onion/hacking',
            'title': 'Underground Hacking Forum',
            'visit_count': 5,
            'typed': 0,
            'time_offset': timedelta(days=3, hours=3)
        },
        {
            'url': 'https://news.ycombinator.com/news',
            'title': 'Hacker News',
            'visit_count': 18,
            'typed': 5,
            'time_offset': timedelta(days=2, hours=10)
        },
        {
            'url': 'https://haveibeenpwned.com/',
            'title': 'Have I Been Pwned: Check if your email has been compromised',
            'visit_count': 2,
            'typed': 1,
            'time_offset': timedelta(days=1, hours=15)
        },
        {
            'url': 'https://pastebin.com/raw/stolen_data_dump',
            'title': 'Database Leak - Pastebin.com',
            'visit_count': 1,
            'typed': 0,
            'time_offset': timedelta(days=1, hours=4)
        },
        {
            'url': 'https://www.virustotal.com/gui/home/upload',
            'title': 'VirusTotal - File and URL Analysis',
            'visit_count': 9,
            'typed': 2,
            'time_offset': timedelta(hours=12)
        }
    ]
    
    place_id = 1
    for entry in fake_urls:
        visit_time = to_firefox_timestamp(base_time + entry['time_offset'])
        
        from urllib.parse import urlparse
        parsed = urlparse(entry['url'])
        rev_host = '.'.join(reversed(parsed.netloc.split('.')))
        
        cursor.execute('''
            INSERT INTO moz_places 
            (id, url, title, rev_host, visit_count, typed, last_visit_date, guid)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (place_id, entry['url'], entry['title'], rev_host,
              entry['visit_count'], entry['typed'], visit_time,
              f"guid{place_id:08d}"))
        
        for visit_num in range(entry['visit_count']):
            visit_time_offset = timedelta(hours=visit_num * 3)
            visit_timestamp = to_firefox_timestamp(base_time + entry['time_offset'] + visit_time_offset)
            
            cursor.execute('''
                INSERT INTO moz_historyvisits (place_id, visit_date, visit_type, session)
                VALUES (?, ?, 1, ?)
            ''', (place_id, visit_timestamp, place_id))
        
        place_id += 1
    
    conn.commit()
    
    cursor.execute('SELECT COUNT(*) FROM moz_places')
    url_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM moz_historyvisits')
    visit_count = cursor.fetchone()[0]
    
    print("Test Firefox Database Created Successfully!")
    print(f"Location: {db_path}")
    print(f"URLs: {url_count}")
    print(f"Total Visits: {visit_count}")
    print(f"\nDatabase includes:")
    print("  - Security tools (Kali, Wireshark, OWASP)")
    print("  - Suspicious sites (.onion domains, data leaks)")
    print("  - Realistic visit patterns")
    
    conn.close()
    
    return db_path


if __name__ == "__main__":
    print("Creating test browser databases...\n")
    create_test_browser_database()
    create_test_firefox_database()
    print("\nAll test databases created successfully!")