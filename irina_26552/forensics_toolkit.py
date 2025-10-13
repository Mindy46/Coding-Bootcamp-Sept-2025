r"""
Digital Forensics Toolkit - File Metadata & Hash Analysis
This script scans a specified directory for files, collects metadata,
computes hashes, and generates a report.
Assumption: all electronic evidences are stored in some directory strucutured similar to test_data folder.

Usage:
    python forensics_toolkit.py /path/to/evidence_directory


Generated Reports:
  reports/file_metadata_report.json - Complete file inventory
  reports/forensic_findings.json - Suspicious activity analysis
  reports/image_analysis.json - Image EXIF & GPS data
  reports/altered_images.json - Potentially altered images
  reports/timeline.json - Chronological timeline of all events
  Summary is printed to console and also saved to: reports/summary.txt

NOTES.
    Note 1: Kept in one module for easier submission through bootcamp platform; ideally, would be split into multiple files.
    Note 2: Some images were downloaded from 
         https://exiftool.org/sample_images.html
         https://github.com/ianare/exif-samples/tree/master
    Note 3: For browser's history:
    Currently supports only Google Chrome and Mozilla Firefox, Safari is not supported due to different database format.
    
    Dummy DB was created with dummy_test_database.py script for testing purposes.

    For real browser data, copy database files to evidence/browser/ directory:
    
    Chrome locations:
    - macOS: ~/Library/Application Support/Google/Chrome/Default/History
    - Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\History
    - Linux: ~/.config/google-chrome/Default/History
    
    Firefox locations:
    - macOS: ~/Library/Application Support/Firefox/Profiles/*/places.sqlite
    - Windows: %APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite
    - Linux: ~/.mozilla/firefox/*/places.sqlite



Rationale:
When security incidents occur, investigators need to quickly understand what happened by examining digital evidence left behind
 in files and systems. This toolkit will demonstrate core forensic techniques by extracting and analyzing metadata that most people 
 don't realize exists. The tool will examine file timestamps and modification dates to build activity timelines, 
 extract GPS coordinates and camera information from photos, calculate file hashes to verify evidence integrity,
   and analyze browser history to understand user activity patterns. It will then generate a proper forensic report documenting 
   all findings with timestamps and file paths. This project teaches essential incident response skills - 
   how to systematically collect digital evidence and piece together what occurred during a security event. Note that this toolkit
     focuses on analyzing existing files and metadata only; it does not attempt to recover deleted files, which would require more 
     complex disk-level analysis. The goal is to create a practical tool that demonstrates real forensic methodology 
     while being achievable within the bootcamp timeframe.



    
    """

import sys
import os
import hashlib
import datetime
import json

from pathlib import Path
from typing import Dict, List, Any

#for image EXIF extraction
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
try:
    import pillow_heif
    pillow_heif.register_heif_opener()
    print("HEIC format support enabled")
except ImportError:
    print("WARNING: pillow-heif not installed. HEIC files may not have EXIF extracted.")

#for browser history extraction
import sqlite3
import shutil
import tempfile
from datetime import datetime, timedelta
import io



class ForensicScanner:
    SUSPICIOUS_KEYWORDS = ['onion', 'darkweb', 'darknet', 'malware', 'hack', 
                                        'exploit', 'leaked', 'stolen', 'dump', 'credential', 
                                        'anonymous', 'illegal', 'underground','murder','weapon','drugs','traffic']
    def __init__(self, evidence_path: str) -> None:
        self.evidence_path = Path(evidence_path)
        self.artifacts: List[Dict[str, Any]] = []
        # forensic stats
        self.forensic_stats = {
        'suspicious_urls': 0,
        'suspicious_keywords': {},
        'images_total': 0,
        'images_with_exif': 0,
        'images_with_gps': 0,
        'images_without_exif': 0,
        'unknown_files': 0
        }

    
    def scan_directory(self) -> List[Dict[str, Any]]:
        """Recursively scan directory and collect file metadata,
        skipping hidden and system files (for this MVP).
        """
        print("=" * 40)
        print(f"Starting forensic scan of: {self.evidence_path}")
       
        file_count = 0
        for root, dirs, files in os.walk(self.evidence_path):
            for filename in files:
                # skip hidden files and system files
                if filename.startswith('.'):
                    continue
                    
                filepath = os.path.join(root, filename)
                print(f" -- Processing: {filepath}")
                
                metadata = self.get_file_metadata(filepath)
                self.artifacts.append(metadata)
                file_count += 1
        
        print(f"\nScan complete. Processed {file_count} files.")
        return self.artifacts

    def get_file_metadata(self, filepath: str) -> Dict[str, Any]:
        """Extract file metadata"""
        try:
            stats = os.stat(filepath)
            
            file_type = self.get_file_type(filepath)
            metadata = {
                'filepath': str(filepath),
                'filename': os.path.basename(filepath),
                'size_bytes': stats.st_size,
                'size_human': self.human_readable_size(stats.st_size),
                'created': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stats.st_atime).isoformat(),
                'sha256': self.calculate_hash(filepath, 'sha256'),
                'md5': self.calculate_hash(filepath, 'md5'),
                'file_type': file_type,
            }
            if file_type == 'image':
                try:
                    print(f"  Extracting EXIF data from image...")
                    exif = self.extract_exif_data(filepath)
                    if exif:
                        metadata['exif'] = exif
                        print(f"  Found EXIF data (GPS: {'Yes' if 'gps_latitude' in exif else 'No'})")
                    else:
                        print(f"  No EXIF data found in image")
                except Exception as e:
                    metadata['exif_error'] = str(e)
                    print(f"  Error extracting EXIF: {str(e)}")

            return metadata
        except Exception as e:
            return {'filepath': str(filepath), 'error': str(e)}

    def extract_exif_data(self, filepath: str) -> Dict[str, Any]:
        """Extract EXIF metadata from image files"""
        try:
        
            image = Image.open(filepath)
            
           
           
            exif_data = None

            #  JPG/PNG
            if hasattr(image, '_getexif'):
                try:
                    exif_data = image._getexif()
                except:
                    pass

            # For TIFF and other formats
            if exif_data is None and hasattr(image, 'tag_v2'):
                exif_data = image.tag_v2
                #print(f"    [DEBUG] Using tag_v2, type: {type(exif_data)}, len: {len(exif_data)}")

            if exif_data is None and hasattr(image, 'tag'):
                exif_data = image.tag
                #print(f"    [DEBUG] Using tag, type: {type(exif_data)}, len: {len(exif_data)}")

           
       
            
            if exif_data is None:
                return {}

            # if empty (handle different types)
            try:
                if len(exif_data) == 0:
                    return {}
            except TypeError:
                return {}
            
            # human-readable names
            exif_dict = {}
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)
                exif_dict[tag_name] = value
            
            #print(f"    [DEBUG] Converted keys: {list(exif_dict.keys())}")  
 
        
            result = {}
            camera_info = self.get_camera_info(exif_dict)
            if camera_info:
                result.update(camera_info)
            gps_info = self.parse_gps_coordinates(exif_dict)
            if gps_info:
                result.update(gps_info)
            
            if 'DateTime' in exif_dict:
                result['date_taken'] = str(exif_dict['DateTime'])
            
            if 'ImageDescription' in exif_dict:
                result['description'] = exif_dict['ImageDescription']

            if 'Artist' in exif_dict:
                result['artist'] = str(exif_dict['Artist'])

            if 'Software' in exif_dict and 'software' not in result:  
                result['software'] = str(exif_dict['Software'])    
                
            
            return result
        except Exception as e:
                print(f"    [ERROR] Exception in extract_exif_data: {type(e).__name__}: {str(e)}")
                import traceback        
                traceback.print_exc()
                return {}
    
    def get_camera_info(self, exif_data: Dict) -> Dict[str, Any]:
        """Extract camera make, model, and settings from EXIF data
        Camera make/model = Device identification
        Camera settings = Authenticity verification ( if altered, may be lost - potential tampering)

        """
        camera_info = {}
        
        if 'Make' in exif_data:
            camera_info['camera_make'] = str(exif_data['Make']).strip()
        
        if 'Model' in exif_data:
            camera_info['camera_model'] = str(exif_data['Model']).strip()
        
        if 'Software' in exif_data:
            camera_info['software'] = str(exif_data['Software']).strip()
        
        if 'ISOSpeedRatings' in exif_data:
            camera_info['iso'] = exif_data['ISOSpeedRatings']
        
        if 'FNumber' in exif_data:
            camera_info['f_stop'] = float(exif_data['FNumber'])
        
        if 'ExposureTime' in exif_data:
            camera_info['exposure_time'] = float(exif_data['ExposureTime'])
        
        if 'Flash' in exif_data:
            camera_info['flash'] = exif_data['Flash']
        
        return camera_info

    def parse_gps_coordinates(self, exif_data: Dict) -> Dict[str, Any]:
        """Extract and convert GPS coordinates from EXIF data to decimal degrees
        GPS coordinates = Physical location where photo was taken
        """
        
        if 'GPSInfo' not in exif_data:
            return {}
        
        gps_data = exif_data['GPSInfo']
        
        gps_dict = {}
        for tag_id, value in gps_data.items():
            tag_name = GPSTAGS.get(tag_id, tag_id)
            gps_dict[tag_name] = value
        
        # Helper: GPS coordinates -> decimal degrees
        def convert_to_degrees(value):
            """Convert GPS coordinates stored as tuples to decimal degrees
            Formula: decimal = degrees + (minutes/60) + (seconds/3600)
            """
            d = float(value[0])  # Degrees
            m = float(value[1])  # Minutes
            s = float(value[2])  # Seconds
            return d + (m / 60.0) + (s / 3600.0)
        
        gps_info = {}
        
        try:
            # latitude
            if 'GPSLatitude' in gps_dict and 'GPSLatitudeRef' in gps_dict:
                lat = convert_to_degrees(gps_dict['GPSLatitude'])
                if gps_dict['GPSLatitudeRef'] == 'S':
                    lat = -lat  
                gps_info['gps_latitude'] = lat
            
            # longitude
            if 'GPSLongitude' in gps_dict and 'GPSLongitudeRef' in gps_dict:
                lon = convert_to_degrees(gps_dict['GPSLongitude'])
                if gps_dict['GPSLongitudeRef'] == 'W':
                    lon = -lon  
                gps_info['gps_longitude'] = lon
            
            # altitude 
            if 'GPSAltitude' in gps_dict:
                altitude = float(gps_dict['GPSAltitude'])
                if 'GPSAltitudeRef' in gps_dict and gps_dict['GPSAltitudeRef'] == 1:
                    altitude = -altitude  # below sea level
                gps_info['gps_altitude'] = altitude
            
            # GPS timestamp 
            if 'GPSDateStamp' in gps_dict and 'GPSTimeStamp' in gps_dict:
                date = gps_dict['GPSDateStamp']
                time = gps_dict['GPSTimeStamp']
                gps_info['gps_timestamp'] = f"{date} {time[0]:02d}:{time[1]:02d}:{time[2]:02d}"
            
        except Exception as e:
            return {}
        
        return gps_info


    def calculate_hash(self, filepath: str, algorithm: str = 'sha256') -> str:
        """Calculate file SHA-256 hash for integrity verification"""
        hash_func = hashlib.new(algorithm)
        try:
            with open(filepath, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"
        
    def get_file_type(self, filepath: str) -> str:
        """Determine file type from extension"""
        ext = os.path.splitext(filepath)[1].lower()
        file_types = {
            '.jpg': 'image', '.jpeg': 'image', '.png': 'image', '.gif': 'image',
            '.heic': 'image', '.heif': 'image',
            '.tiff': 'image', '.tif': 'image',    
            '.pdf': 'document', '.doc': 'document', '.docx': 'document', '.txt': 'document',
            '.mp4': 'video', '.avi': 'video', '.mov': 'video',
            '.mp3': 'audio', '.wav': 'audio',
            #for this MVP - don't deep dive into archives or DBs
            '.zip': 'archive', '.rar': 'archive', '.7z': 'archive','.tar.qz': 'archive',
            '.db': 'database', '.sqlite': 'database'
        }
        return file_types.get(ext, 'unknown')
    
    def human_readable_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def generate_report(self, output_file: str = 'reports/file_metadata_report.json') -> Dict[str, Any]:
        """Generate JSON report of findings"""
        report = {
            'case_info': {
                'evidence_path': str(self.evidence_path),
                'scan_timestamp': datetime.now().isoformat(),
                'total_files': len(self.artifacts)
            },
            'file_inventory': self.artifacts,
            'summary': self.generate_summary()
        }
        
        # Create reports directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nForensic report saved to: {output_file}")
        return report

    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        total_size = sum(a.get('size_bytes', 0) for a in self.artifacts if 'size_bytes' in a)
        file_types: Dict[str, int] = {}
        
        for artifact in self.artifacts:
            ftype = artifact.get('file_type', 'unknown')
            file_types[ftype] = file_types.get(ftype, 0) + 1
        
        return {
            'total_size_bytes': total_size,
            'total_size_human': self.human_readable_size(total_size),
            'file_types': file_types
        }
    
    def print_summary(self) -> None:
        """Print readable summary"""
        summary = self.generate_summary()
        stats = self.forensic_stats 

        print("\n" + "="*40)
        print("="*40)
        print("SUMMARY")
        
        print(f"Total Files Analyzed: {len(self.artifacts)}")
        print(f"Total Size: {summary['total_size_human']}")
        print(f"\nFile Type Breakdown:")
        for ftype, count in summary['file_types'].items():
            print(f"  {ftype.capitalize()}: {count}")
        
        browser_artifacts = [a for a in self.artifacts if a.get('artifact_type') == 'browser_history']
        if browser_artifacts:
            total_entries = sum(a.get('total_entries', 0) for a in browser_artifacts)
            print(f"\nBrowser History: {total_entries} entries found")
            if stats['suspicious_urls'] > 0:
                print(f"  Suspicious URLs: {stats['suspicious_urls']}")
                print(f"  Keyword frequency:")
                for keyword, count in stats['suspicious_keywords'].items():
                    print(f"    - '{keyword}': {count}")
        
        # images
        if stats['images_total'] > 0:
            print(f"\nImage Analysis:")
            print(f"  Total Images: {stats['images_total']}")
            print(f"  Images with EXIF: {stats['images_with_exif']}")
            print(f"  Images with GPS: {stats['images_with_gps']}")
            if stats['images_without_exif'] > 0:
                print(f"  Images without EXIF (potentially altered): {stats['images_without_exif']}")
        
        # suspicious files 
        if stats['unknown_files'] > 0:
            print(f"\n  Unknown File Types: {stats['unknown_files']} (require further inspection)")
        
        print("="*40)

        print("="*40)
        print("\nGenerated Reports:")
        print("  reports/file_metadata_report.json - Complete file inventory")
        print("  reports/forensic_findings.json - Suspicious activity analysis")
        print("  reports/image_analysis.json - Image EXIF & GPS data")
        print("  reports/altered_images.json - Potentially altered images")
        print("  reports/timeline.json - Chronological timeline of all events")
        print("="*40)
        print("="*40)


    def save_summary_to_file(self, output_file: str = 'reports/summary.txt') -> None:
        """Save the console summary to a text file"""
      
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        self.print_summary()
        
        # Restore stdout
        sys.stdout = old_stdout
        
        summary_text = captured_output.getvalue()
        
        print(summary_text, end='')
        
        os.makedirs('reports', exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(summary_text)
        
        print(f"\nSummary also saved to: {output_file}")

    def extract_browser_history(self, db_path: str) -> List[Dict[str, Any]]:
        r"""Extract browsing history from Chrome or Firefox SQLite database (Safari - is not supported at the moment).
        For real browser data, copy database files to evidence/browser/ directory:
        
        Chrome locations:
        - macOS: ~/Library/Application Support/Google/Chrome/Default/History
        - Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\History
        - Linux: ~/.config/google-chrome/Default/History
        
        Firefox locations:
        - macOS: ~/Library/Application Support/Firefox/Profiles/*/places.sqlite
        - Windows: %APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite
        - Linux: ~/.mozilla/firefox/*/places.sqlite
        
        Args:
            db_path: Path to browser SQLite database file
            
        Returns:
            List of dictionaries containing browsing history entries
        """
       
        history_entries = []
        
        try:
            #  to avoid locking issues create temp copy of database
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            temp_db.close()
            shutil.copy2(db_path, temp_db.name)
            
            print(f"  Analyzing browser database: {os.path.basename(db_path)}")
            
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            if 'urls' in tables and 'visits' in tables:
                print(f"  Detected Chrome history format")
                history_entries = self._extract_chrome_history(cursor)
            elif 'moz_places' in tables and 'moz_historyvisits' in tables:
                print(f"  Detected Firefox history format")
                history_entries = self._extract_firefox_history(cursor)
            else:
                print(f"  Unknown database format")
            
            conn.close()
            os.unlink(temp_db.name)  # Clean up temp file
            
            print(f"  Extracted {len(history_entries)} history entries")
            
        except Exception as e:
            print(f"  Error extracting browser history: {str(e)}")
        
        return history_entries    
    
    def _extract_chrome_history(self, cursor) -> List[Dict[str, Any]]:
        """Extract history from Chrome database format.
        
        Args:
            cursor: SQLite cursor connected to Chrome History database
            
        Returns:
            List of dictionaries with url, title, visit_count, last_visit, browser
        """
        
        
        entries = []
        
        try:
            # timestamps - microseconds since 1601-01-01 (Windows epoch)
            cursor.execute('''
                SELECT urls.url, urls.title, urls.visit_count, urls.last_visit_time
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 100
            ''')
            
            chrome_epoch = datetime(1601, 1, 1)
            
            for row in cursor.fetchall():
                url, title, visit_count, chrome_time = row

                if chrome_time:
                    try:
                        timestamp = chrome_epoch + timedelta(microseconds=chrome_time)
                        iso_time = timestamp.isoformat()
                    except:
                        iso_time = "Unknown"
                else:
                    iso_time = "Unknown"
                
                entries.append({
                    'url': url,
                    'title': title or 'No title',
                    'visit_count': visit_count,
                    'last_visit': iso_time,
                    'browser': 'Chrome'
                })
        
        except Exception as e:
            print(f"  Error parsing Chrome history: {str(e)}")
        
        return entries
    
    def _extract_firefox_history(self, cursor) -> List[Dict[str, Any]]:
        """Extract history from Firefox database format.
        
        Args:
            cursor: SQLite cursor connected to Firefox places.sqlite database
            
        Returns:
            List of dictionaries with url, title, visit_count, last_visit, browser
        """

        
        entries = []
        
        try:
            #  timestamps - microseconds since Unix epoch
            cursor.execute('''
                SELECT url, title, visit_count, last_visit_date
                FROM moz_places
                WHERE last_visit_date IS NOT NULL
                ORDER BY last_visit_date DESC
                LIMIT 100
            ''')
            
            for row in cursor.fetchall():
                url, title, visit_count, firefox_time = row
                
                if firefox_time:
                    try:
                        timestamp = datetime.fromtimestamp(firefox_time / 1000000)
                        iso_time = timestamp.isoformat()
                    except:
                        iso_time = "Unknown"
                else:
                    iso_time = "Unknown"
                
                entries.append({
                    'url': url,
                    'title': title or 'No title',
                    'visit_count': visit_count,
                    'last_visit': iso_time,
                    'browser': 'Firefox'
                })
        
        except Exception as e:
            print(f"  Error parsing Firefox history: {str(e)}")
        
        return entries
    
    def analyze_browser_artifacts(self) -> None:
        r"""Scan for and analyze browser database files in the browser/ subdirectory.
        
        Supports Chrome and Firefox databases only (Safari not supported).
        
        To analyze your real browser history:
        1. Create 'browser/' subdirectory in your evidence folder
        2. Copy browser database files from the locations below
        
        Chrome:
        - macOS: ~/Library/Application Support/Google/Chrome/Default/History
        - Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\History
        - Linux: ~/.config/google-chrome/Default/History
        
        Firefox:
        - macOS: ~/Library/Application Support/Firefox/Profiles/*/places.sqlite
        - Windows: %APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite
        - Linux: ~/.mozilla/firefox/*/places.sqlite
        
        Note: Close your browser before copying files to avoid database lock issues.
        """
        browser_dir = self.evidence_path / 'browser'
        
        if not browser_dir.exists():
            print("\nNo browser directory found. To analyze browser history:")
            print("    1. Create 'browser' subdirectory in evidence folder")
            print("    2. Copy browser database files:")
            print("\n    Chrome (Mac):")
            print("      ~/Library/Application Support/Google/Chrome/Default/History")
            print("\n    Firefox (Mac):")
            print("      ~/Library/Application Support/Firefox/Profiles/*/places.sqlite")
            return
        
        print(f"\n{'='*40}")
        print("BROWSER HISTORY ANALYSIS")

        
        db_files = []
        for ext in ['*.db', '*.sqlite', '*History*']:
            db_files.extend(browser_dir.glob(ext))
        
        if not db_files:
            print("      No browser database files found in browser directory")
            return
        
        
        all_browser_history = []
        for db_file in db_files:
            history = self.extract_browser_history(str(db_file))
            all_browser_history.extend(history)
        
        if all_browser_history:
            self.artifacts.append({
                'artifact_type': 'browser_history',
                'total_entries': len(all_browser_history),
                'entries': all_browser_history[:50],  # Limit to 50 most recent in report
                'note': f'Full history: {len(all_browser_history)} entries (showing 50 most recent)'
            })
        return

    #simple forensic analysis
    def generate_forensic_findings_report(self, output_file: str = 'reports/forensic_findings.json') -> Dict[str, Any]:
        """
        Generate separate report for suspicious findings and forensic insights
        """
        
        suspicious_browser = []
        suspicious_files = []
        
        suspicious_keywords = {k: 0 for k in self.SUSPICIOUS_KEYWORDS}
        
        for artifact in self.artifacts:
            if artifact.get('artifact_type') == 'browser_history':
                entries = artifact.get('entries', [])
                for entry in entries:
                    url_lower = entry['url'].lower()
                    title_lower = entry.get('title', '').lower()
                    
                    is_suspicious = False
                    for keyword in suspicious_keywords.keys():
                        if keyword in url_lower or keyword in title_lower:
                            suspicious_keywords[keyword] += 1
                            is_suspicious = True
                    
                    if is_suspicious:
                        suspicious_browser.append({
                            'url': entry['url'],
                            'title': entry['title'],
                            'browser': entry['browser'],
                            'last_visit': entry['last_visit'],
                            'visit_count': entry['visit_count'],
                            'risk_level': 'HIGH' if 'malware' in url_lower or 'illegal' in url_lower else 'MEDIUM'
                        })
        self.forensic_stats['suspicious_urls'] = len(suspicious_browser)
        self.forensic_stats['suspicious_keywords'] = {k: v for k, v in suspicious_keywords.items() if v > 0}
   
        # suspicious file patterns
        for artifact in self.artifacts:
            if artifact.get('file_type') in ['unknown', 'archive']:
                suspicious_files.append({
                    'filepath': artifact['filepath'],
                    'filename': artifact['filename'],
                    'type': artifact['file_type'],
                    'size': artifact['size_human'],
                    'note': 'Unknown file type or archive - requires further inspection'
                })
        self.forensic_stats['unknown_files'] = len([a for a in self.artifacts if a.get('file_type') == 'unknown'])

        findings = {
            'case_info': {
                'evidence_path': str(self.evidence_path),
                'analysis_timestamp': datetime.now().isoformat(),
            },
            'suspicious_browser_activity': {
                'total_flagged': len(suspicious_browser),
                'entries': suspicious_browser
            },
            'suspicious_files': {
                'total_flagged': len(suspicious_files),
                'entries': suspicious_files
            },
            'risk_summary': {
                'high_risk_urls': len([s for s in suspicious_browser if s.get('risk_level') == 'HIGH']),
                'medium_risk_urls': len([s for s in suspicious_browser if s.get('risk_level') == 'MEDIUM']),
                'unknown_files': len(suspicious_files)
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
        
        print(f"Forensic findings report saved to: {output_file}")
        return findings



    def generate_image_analysis_report(self, output_file: str = 'reports/image_analysis.json') -> Dict[str, Any]:
        """Generate separate report for all image EXIF data and GPS locations"""
        
        images_with_exif = []
        images_without_exif = []
        images_with_gps = []
        
        for artifact in self.artifacts:
            if artifact.get('file_type') == 'image':
                image_info = {
                    'filepath': artifact['filepath'],
                    'filename': artifact['filename'],
                    'size': artifact['size_human'],
                    'modified': artifact['modified']
                }
                
                if 'exif' in artifact:
                    exif = artifact['exif']
                    image_info['exif'] = exif
                    
                    # Check for GPS
                    if 'gps_latitude' in exif and 'gps_longitude' in exif:
                        images_with_gps.append({
                            'filename': artifact['filename'],
                            'location': {
                                'latitude': exif['gps_latitude'],
                                'longitude': exif['gps_longitude'],
                                'altitude': exif.get('gps_altitude', 'N/A')
                            },
                            'camera': {
                                'make': exif.get('camera_make', 'Unknown'),
                                'model': exif.get('camera_model', 'Unknown')
                            },
                            'date_taken': exif.get('date_taken', 'Unknown')
                        })
                    
                    images_with_exif.append(image_info)
                else:
                    image_info['note'] = 'No EXIF data - possibly edited/stripped metadata'
                    images_without_exif.append(image_info)
        
        self.forensic_stats['images_total'] = len(images_with_exif) + len(images_without_exif)
        self.forensic_stats['images_with_exif'] = len(images_with_exif)
        self.forensic_stats['images_with_gps'] = len(images_with_gps)
        self.forensic_stats['images_without_exif'] = len(images_without_exif)
        
        report = {
            'case_info': {
                'evidence_path': str(self.evidence_path),
                'analysis_timestamp': datetime.now().isoformat(),
            },
            'summary': {
                'total_images': len(images_with_exif) + len(images_without_exif),
                'images_with_exif': len(images_with_exif),
                'images_without_exif': len(images_without_exif),
                'images_with_gps': len(images_with_gps)
            },
            'gps_locations': images_with_gps,
            'images_with_exif': images_with_exif,
            'potentially_altered_images': images_without_exif
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Image analysis report saved to: {output_file}")
        return report
    
    def generate_altered_images_report(self, output_file: str = 'reports/altered_images.json') -> Dict[str, Any]:
        """Generate separate report for potentially altered or suspicious images"""
        
        altered_images = []
        
        for artifact in self.artifacts:
            if artifact.get('file_type') == 'image':
                flags = []
                
                # Flag 1: No EXIF data at all
                if 'exif' not in artifact or not artifact['exif']:
                    flags.append('NO_EXIF_DATA')
                
                # Flag 2: Has EXIF but no GPS (when GPS would be expected)
                elif artifact.get('exif'):
                    exif = artifact['exif']
                    if 'gps_latitude' not in exif and 'gps_longitude' not in exif:
                        flags.append('NO_GPS_DATA')
                    
                    # Flag 3: Has camera info but missing other expected EXIF fields
                    if 'camera_make' in exif or 'camera_model' in exif:
                        if 'date_taken' not in exif:
                            flags.append('MISSING_TIMESTAMP')
                
                # Only add to report if any flags exist
                if flags:
                    altered_images.append({
                        'filepath': artifact['filepath'],
                        'filename': artifact['filename'],
                        'size': artifact['size_human'],
                        'modified': artifact['modified'],
                        'flags': flags,
                        'risk_assessment': self._assess_image_risk(flags),
                        'exif_present': 'exif' in artifact and bool(artifact['exif']),
                        'camera_info': {
                            'make': artifact.get('exif', {}).get('camera_make', 'N/A'),
                            'model': artifact.get('exif', {}).get('camera_model', 'N/A')
                        } if artifact.get('exif') else None
                    })
        
        report = {
            'case_info': {
                'evidence_path': str(self.evidence_path),
                'analysis_timestamp': datetime.now().isoformat(),
            },
            'summary': {
                'total_altered_images': len(altered_images),
                'no_exif': len([img for img in altered_images if 'NO_EXIF_DATA' in img['flags']]),
                'no_gps': len([img for img in altered_images if 'NO_GPS_DATA' in img['flags']]),
                'missing_timestamp': len([img for img in altered_images if 'MISSING_TIMESTAMP' in img['flags']]),
                'high_risk': len([img for img in altered_images if img['risk_assessment'] == 'HIGH']),
                'medium_risk': len([img for img in altered_images if img['risk_assessment'] == 'MEDIUM']),
                'low_risk': len([img for img in altered_images if img['risk_assessment'] == 'LOW'])
            },
            'potentially_altered_images': altered_images,
            'analysis_notes': {
                'NO_EXIF_DATA': 'Image has no EXIF metadata - likely edited with photo software or metadata stripped',
                'NO_GPS_DATA': 'Image has EXIF but no GPS coordinates - location services may have been disabled or data removed',
                'MISSING_TIMESTAMP': 'Camera info present but no capture timestamp - unusual and potentially suspicious'
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Altered images report saved to: {output_file}")
        return report

    def _assess_image_risk(self, flags: List[str]) -> str:
        """Assess risk level based on flags"""
        if 'NO_EXIF_DATA' in flags:
            return 'HIGH'  # Complete metadata removal is most suspicious
        elif 'MISSING_TIMESTAMP' in flags:
            return 'MEDIUM'  # Selective removal is moderately suspicious
        elif 'NO_GPS_DATA' in flags:
            return 'LOW'  # Could be legitimate (GPS disabled)
        return 'LOW'

    def build_timeline(self, timeline_file: str = 'reports/timeline.json') -> Dict[str, Any]:
        """Build a timeline of file and activity events from all artifacts.
        
        Gathers events from:
        - File created/modified/accessed (source: file)
        - EXIF date_taken (source: image_exif)
        - Browser last_visit (source: browser)
        
        Outputs reports/timeline.json as a single list sorted by timestamp.
        
        Returns:
            Dict containing timeline metadata and sorted events
        """
        
        timeline_events = []
        
        # Process all artifacts in one loop
        for artifact in self.artifacts:
            # File system events
            if 'created' in artifact:
                timeline_events.append({
                    'timestamp': artifact['created'],
                    'source': 'file',
                    'event': 'File Created',
                    'path': artifact['filepath']
                })
            if 'modified' in artifact:
                timeline_events.append({
                    'timestamp': artifact['modified'],
                    'source': 'file',
                    'event': 'File Modified',
                    'path': artifact['filepath']
                })
            if 'accessed' in artifact:
                timeline_events.append({
                    'timestamp': artifact['accessed'],
                    'source': 'file',
                    'event': 'File Accessed',
                    'path': artifact['filepath']
                })
            
            # Image EXIF events
            if artifact.get('file_type') == 'image' and 'exif' in artifact:
                exif = artifact['exif']
                if 'date_taken' in exif:
                    timeline_events.append({
                        'timestamp': exif['date_taken'],
                        'source': 'image_exif',
                        'event': 'Photo Taken',
                        'path': artifact['filepath'],
                        'camera': f"{exif.get('camera_make', '')} {exif.get('camera_model', '')}".strip()
                    })
            
            # Browser history events
            if artifact.get('artifact_type') == 'browser_history':
                entries = artifact.get('entries', [])
                for entry in entries:
                    if entry.get('last_visit') and entry.get('url'):
                        timeline_events.append({
                            'timestamp': entry['last_visit'],
                            'source': f"browser_{entry.get('browser', 'unknown').lower()}",
                            'event': 'Visited URL',
                            'url': entry['url'],
                            'title': entry.get('title', '')
                        })
        
        # Helper function to parse timestamps
        def parse_timestamp(ts: str):
            """Parse various timestamp formats to datetime object"""
            if not ts or ts == "Unknown":
                return None
            
            formats = [
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y:%m:%d %H:%M:%S",  # EXIF format
                "%Y-%m-%d %H:%M:%S"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(ts, fmt)
                except (ValueError, AttributeError):
                    continue
            return None
        
        # Filter out events with unparseable timestamps and sort
        valid_events = [e for e in timeline_events if parse_timestamp(e['timestamp']) is not None]
        valid_events.sort(key=lambda x: parse_timestamp(x['timestamp']))
        
        # Create timeline report
        timeline_report = {
            'case_info': {
                'evidence_path': str(self.evidence_path),
                'generated_at': datetime.now().isoformat(),
                'total_events': len(valid_events)
            },
            'timeline': valid_events
        }
        
        # Save to JSON
        os.makedirs('reports', exist_ok=True)
        with open(timeline_file, 'w') as f:
            json.dump(timeline_report, f, indent=2)
        
        print(f"Timeline report saved to: {timeline_file}")
        print(f"  Total events: {len(valid_events)}")
        
        return timeline_report

        

def main():
    
    if len(sys.argv) < 2:
        print("Usage: python3 forensics_toolkit.py <evidence_directory>")
        print("Example: python3 forensics_toolkit.py test_data/")
        sys.exit(1)
    
    evidence_path = sys.argv[1]
    
    if not os.path.exists(evidence_path):
        print(f"Error: Path '{evidence_path}' does not exist.")
        sys.exit(1)
    
    scanner = ForensicScanner(evidence_path)
    
    artifacts = scanner.scan_directory()

    scanner.analyze_browser_artifacts()

    scanner.generate_report() #main report with all information, complete inventory
    scanner.generate_forensic_findings_report()  # Suspicious URLs, unknown files, risk summary
    scanner.generate_image_analysis_report()  # All images with EXIF, GPS locations, altered images
    scanner.generate_altered_images_report()    # altered images potentially

    scanner.build_timeline()   # timeline of file and activity events

    scanner.save_summary_to_file() # print summary to both console and text file
    
if __name__ == "__main__":
    main()