# Digital Forensics Toolkit

A Python-based forensic analysis tool for investigating security incidents by extracting and analyzing digital evidence from files, images, and browser history.

## Project Overview

This toolkit demonstrates core digital forensics techniques used in incident response and cybersecurity investigations. It systematically collects metadata, analyzes images for hidden information, examines browser activity, and generates comprehensive forensic reports.

Rationale:

When security incidents occur, investigators need to quickly understand what happened by examining digital evidence left behind in files and systems. This toolkit will demonstrate core forensic techniques by extracting and analyzing metadata that most people don't realize exists. The tool will examine file timestamps and modification dates to build activity timelines, extract GPS coordinates and camera information from photos, calculate file hashes to verify evidence integrity,and analyze browser history to understand user activity patterns. It will then generate a proper forensic report documenting all findings with timestamps and file paths. This project teaches essential incident response skills - how to systematically collect digital evidence and piece together what occurred during a security event. Note that this toolkit focuses on analyzing existing files and metadata only; it does not attempt to recover deleted files, which would require more complex disk-level analysis. The goal is to create a practical tool that demonstrates real forensic methodology while being achievable within the bootcamp timeframe.


## Features

### Core Functionality
- **File Metadata Extraction**: Timestamps, file sizes, and hash values (SHA-256, MD5)
- **EXIF Data Analysis**: GPS coordinates, camera information, and photo metadata from images
- **Browser History Parsing**: Chrome and Firefox browsing history analysis
- **Timeline Generation**: Chronological reconstruction of file and user activity
- **Threat Detection**: Identifies suspicious URLs and potentially altered images

### Supported File Types
- **Images**: JPG, PNG, TIFF, HEIC, GIF
- **Documents**: PDF, TXT, DOC, DOCX
- **Browsers**: Chrome, Firefox (Safari not supported)

## Requirements

### Python Version
- Python 3.7 or higher

### Dependencies
```bash
pip install pillow
```

### Optional (for HEIC support)
```bash
pip install pillow-heif
```

**Built-in libraries used:** `sqlite3`, `hashlib`, `datetime`, `json`, `pathlib`

## Installation

1. **Clone or download this repository**
```bash
git clone <repository-url>
cd forensics-toolkit
```

2. **Install required packages**
```bash
pip install pillow
pip install pillow-heif  # Optional, for HEIC image support
```

3. **Set up test data** (optional)
```bash
python3 create_test_browser_db.py
```

## 📖 Usage

### Basic Usage
```bash
python3 forensics_toolkit.py <evidence_directory>
```

### Example
```bash
python3 forensics_toolkit.py test_data/
```

### Directory Structure
Your evidence directory should be organized as:
```
evidence_folder/
├── documents/          # Documents to analyze
├── images/            # Images with potential EXIF data
└── browser/           # Browser database files (optional)
```

### Adding Real Browser Data

**Chrome:**
```bash
# macOS
cp ~/Library/Application\ Support/Google/Chrome/Default/History evidence_folder/browser/

# Windows
copy %LOCALAPPDATA%\Google\Chrome\User Data\Default\History evidence_folder\browser\

# Linux
cp ~/.config/google-chrome/Default/History evidence_folder/browser/
```

**Firefox:**
```bash
# macOS
cp ~/Library/Application\ Support/Firefox/Profiles/*/places.sqlite evidence_folder/browser/

# Windows
copy %APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite evidence_folder\browser\

# Linux
cp ~/.mozilla/firefox/*/places.sqlite evidence_folder/browser/
```

**Note:** Close your browser before copying database files to avoid locking issues.

## Generated Reports

The toolkit generates six comprehensive reports in the `reports/` directory:

1. **file_metadata_report.json** - Complete inventory of all files with metadata and hashes
2. **forensic_findings.json** - Suspicious URLs, unknown file types, and risk assessment
3. **image_analysis.json** - All images with EXIF data and GPS locations
4. **altered_images.json** - Images flagged as potentially tampered or edited
5. **timeline.json** - Chronological timeline of all file and activity events
6. **summary.txt** - Human-readable summary of findings

## What It Analyzes

### File System Evidence
- File creation, modification, and access timestamps
- File integrity hashes (SHA-256 and MD5)
- File type identification
- Unknown and suspicious file types

### Image Forensics
- **GPS Coordinates**: Latitude, longitude, altitude from photo metadata
- **Camera Information**: Make, model, software version
- **Camera Settings**: ISO, aperture, exposure time, flash usage
- **Timestamps**: When photos were taken
- **Tampering Detection**: Identifies images with missing or stripped EXIF data

### Browser Forensics
- **Browsing History**: URLs visited, page titles, visit counts
- **Timestamps**: When sites were accessed
- **Threat Detection**: Flags suspicious URLs (dark web, malware, illegal content)
- **Risk Assessment**: HIGH/MEDIUM/LOW risk classification

### Timeline Reconstruction
- Combines file activity, photo captures, and browser visits
- Sorted chronologically for incident analysis
- Shows complete picture of user activity



## Example Output

### Console Summary
```
========================================
========================================
SUMMARY
Total Files Analyzed: 786
Total Size: 94.70 MB

File Type Breakdown:
  Document: 3
  Image: 773
  Unknown: 8
  Database: 2

Browser History: 20 entries found
  Suspicious URLs: 8
  Keyword frequency:
    - 'onion': 4
    - 'darkweb': 1
    - 'darknet': 1
    - 'malware': 1
    - 'hack': 2
    - 'exploit': 1
    - 'leaked': 1
    - 'stolen': 1
    - 'dump': 1
    - 'credential': 1
    - 'anonymous': 1
    - 'illegal': 1
    - 'underground': 1

Image Analysis:
  Total Images: 773
  Images with EXIF: 727
  Images with GPS: 26
  Images without EXIF (potentially altered): 46

  Unknown File Types: 7 (require further inspection)
========================================
========================================

Generated Reports:
  reports/file_metadata_report.json - Complete file inventory
  reports/forensic_findings.json - Suspicious activity analysis
  reports/image_analysis.json - Image EXIF & GPS data
  reports/altered_images.json - Potentially altered images
  reports/timeline.json - Chronological timeline of all events
========================================
========================================

Summary also saved to: reports/summary.txt

```

## Limitations

- **Safari Not Supported**: Only Chrome and Firefox browsers are currently supported
- **No File Recovery**: Does not attempt to recover deleted files (requires disk-level analysis)
- **Metadata Only**: Analyzes existing metadata, does not examine file contents
- **Static Analysis**: Does not perform dynamic analysis or execute files



## License

Educational project for cybersecurity bootcamp coursework.

## Author

Irina Astrovskaya, capstone project for cybersecurity bootcamp.


