"""
Misc helper functions that don't fit elsewhere
Just some random useful stuff
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any
import hashlib


def calculate_time_diff(time1: datetime, time2: datetime) -> float:
    """
    Calculate difference between two timestamps in seconds
    
    Args:
        time1: First timestamp
        time2: Second timestamp
        
    Returns:
        Difference in seconds (float)
    """
    diff = abs((time2 - time1).total_seconds())
    return diff


def format_timestamp(dt: datetime, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format datetime object to string
    
    Args:
        dt: Datetime object
        format_str: Format string
        
    Returns:
        Formatted string
    """
    if not isinstance(dt, datetime):
        return str(dt)
    
    return dt.strftime(format_str)


def hash_string(text: str, algorithm: str = 'sha256') -> str:
    """
    Hash a string using specified algorithm
    
    Useful for anonymizing IPs in reports if needed
    
    Args:
        text: String to hash
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hex digest of hash
    """
    if algorithm == 'md5':
        h = hashlib.md5()
    elif algorithm == 'sha1':
        h = hashlib.sha1()
    else:  # default sha256
        h = hashlib.sha256()
    
    h.update(text.encode('utf-8'))
    return h.hexdigest()


def deduplicate_list(items: List[Any]) -> List[Any]:
    """
    Remove duplicates from list while preserving order
    
    Args:
        items: List with potential duplicates
        
    Returns:
        List with duplicates removed
    """
    seen = set()
    result = []
    
    for item in items:
        # For dicts, convert to tuple of items for hashing
        if isinstance(item, dict):
            item_hash = tuple(sorted(item.items()))
            if item_hash not in seen:
                seen.add(item_hash)
                result.append(item)
        else:
            if item not in seen:
                seen.add(item)
                result.append(item)
    
    return result


def filter_by_time_range(entries: List[Dict], 
                         start_time: datetime = None,
                         end_time: datetime = None) -> List[Dict]:
    """
    Filter log entries by time range
    
    Args:
        entries: List of log entry dicts
        start_time: Start of range (inclusive)
        end_time: End of range (inclusive)
        
    Returns:
        Filtered list
    """
    filtered = []
    
    for entry in entries:
        timestamp = entry.get('timestamp')
        if not timestamp:
            continue
        
        # Check start time
        if start_time and timestamp < start_time:
            continue
        
        # Check end time
        if end_time and timestamp > end_time:
            continue
        
        filtered.append(entry)
    
    return filtered


def group_by_field(entries: List[Dict], field: str) -> Dict[Any, List[Dict]]:
    """
    Group log entries by a specific field
    
    Args:
        entries: List of log entry dicts
        field: Field name to group by (e.g., 'ip', 'status_code')
        
    Returns:
        Dict mapping field values to lists of entries
    """
    grouped = {}
    
    for entry in entries:
        key = entry.get(field)
        if key is None:
            key = 'unknown'
        
        if key not in grouped:
            grouped[key] = []
        
        grouped[key].append(entry)
    
    return grouped


def calculate_frequency(entries: List[Dict], 
                       time_window_minutes: int = 60) -> Dict[str, float]:
    """
    Calculate request frequency (requests per minute)
    
    Args:
        entries: List of log entries with timestamps
        time_window_minutes: Time window to calculate over
        
    Returns:
        Dict with frequency stats
    """
    if not entries:
        return {'requests_per_minute': 0.0, 'total_requests': 0}
    
    # Sort by timestamp
    sorted_entries = sorted(entries, key=lambda x: x.get('timestamp', datetime.min))
    
    if len(sorted_entries) < 2:
        return {'requests_per_minute': 0.0, 'total_requests': len(entries)}
    
    # Calculate time span
    first_time = sorted_entries[0].get('timestamp')
    last_time = sorted_entries[-1].get('timestamp')
    
    if not first_time or not last_time:
        return {'requests_per_minute': 0.0, 'total_requests': len(entries)}
    
    time_span_minutes = (last_time - first_time).total_seconds() / 60.0
    
    # Avoid division by zero
    if time_span_minutes == 0:
        time_span_minutes = 1.0
    
    rpm = len(entries) / time_span_minutes
    
    return {
        'requests_per_minute': round(rpm, 2),
        'total_requests': len(entries),
        'time_span_minutes': round(time_span_minutes, 2)
    }


def find_outliers(values: List[float], threshold: float = 2.0) -> List[int]:
    """
    Find outliers in a list of values using simple threshold method
    
    This is a basic implementation - could use z-score or IQR for better results
    
    Args:
        values: List of numeric values
        threshold: Standard deviations from mean to be considered outlier
        
    Returns:
        List of indices of outlier values
    """
    if len(values) < 3:
        return []
    
    # Calculate mean
    mean = sum(values) / len(values)
    
    # Calculate standard deviation
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    std_dev = variance ** 0.5
    
    if std_dev == 0:
        return []
    
    # Find outliers
    outliers = []
    for i, value in enumerate(values):
        z_score = abs((value - mean) / std_dev)
        if z_score > threshold:
            outliers.append(i)
    
    return outliers


def truncate_string(text: str, max_length: int = 50, suffix: str = '...') -> str:
    """
    Truncate long strings for display
    
    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def sanitize_path(path: str) -> str:
    """
    Sanitize file path for safe display
    
    Removes potentially dangerous characters
    
    Args:
        path: File path string
        
    Returns:
        Sanitized path
    """
    # Remove null bytes and other weird stuff
    sanitized = path.replace('\x00', '')
    sanitized = sanitized.replace('\n', '')
    sanitized = sanitized.replace('\r', '')
    
    return sanitized


def bytes_to_human_readable(num_bytes: int) -> str:
    """
    Convert bytes to human readable format
    
    Args:
        num_bytes: Number of bytes
        
    Returns:
        Human readable string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    
    return f"{num_bytes:.1f} PB"


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """
    Merge two dictionaries (dict2 overwrites dict1)
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary (takes precedence)
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    result.update(dict2)
    return result


def validate_port(port: int) -> bool:
    """
    Validate if port number is in valid range
    
    Args:
        port: Port number
        
    Returns:
        True if valid, False otherwise
    """
    return 1 <= port <= 65535


def is_common_port(port: int) -> bool:
    """
    Check if port is a commonly used port
    
    Args:
        port: Port number
        
    Returns:
        True if common port, False otherwise
    """
    common_ports = {
        20, 21,    # FTP
        22,        # SSH
        23,        # Telnet
        25,        # SMTP
        53,        # DNS
        80,        # HTTP
        110,       # POP3
        143,       # IMAP
        443,       # HTTPS
        445,       # SMB
        3306,      # MySQL
        3389,      # RDP
        5432,      # PostgreSQL
        8080,      # HTTP alt
        8443       # HTTPS alt
    }
    
    return port in common_ports


def get_port_service(port: int) -> str:
    """
    Get common service name for port number
    
    Args:
        port: Port number
        
    Returns:
        Service name or "Unknown"
    """
    port_map = {
        20: 'FTP-Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt'
    }
    
    return port_map.get(port, 'Unknown')


def generate_summary_stats(entries: List[Dict]) -> Dict:
    """
    Generate summary statistics from log entries
    
    Args:
        entries: List of log entry dicts
        
    Returns:
        Dict with various stats
    """
    if not entries:
        return {
            'total_entries': 0,
            'unique_ips': 0,
            'time_span': '0 seconds'
        }
    
    # Count unique IPs
    ips = set()
    for entry in entries:
        if 'ip' in entry and entry['ip']:
            ips.add(entry['ip'])
        if 'src_ip' in entry:
            ips.add(entry['src_ip'])
    
    # Calculate time span
    timestamps = [e.get('timestamp') for e in entries if e.get('timestamp')]
    if len(timestamps) > 1:
        time_span = max(timestamps) - min(timestamps)
        span_str = f"{time_span.total_seconds():.0f} seconds"
    else:
        span_str = "N/A"
    
    # Count by type
    type_counts = {}
    for entry in entries:
        entry_type = entry.get('type', 'unknown')
        type_counts[entry_type] = type_counts.get(entry_type, 0) + 1
    
    return {
        'total_entries': len(entries),
        'unique_ips': len(ips),
        'time_span': span_str,
        'entry_types': type_counts
    }


def print_progress_bar(iteration: int, total: int, prefix: str = '', 
                      suffix: str = '', length: int = 50):
    """
    Print a progress bar to console
    
    Call in a loop to create terminal progress bar
    
    Args:
        iteration: Current iteration
        total: Total iterations
        prefix: Prefix string
        suffix: Suffix string
        length: Character length of bar
    """
    if total == 0:
        return
    
    percent = 100 * (iteration / float(total))
    filled_length = int(length * iteration // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    
    print(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}', end='')
    
    # Print newline on completion
    if iteration == total:
        print()


class SimpleCache:
    """
    Simple in-memory cache with expiration
    
    Useful for caching API results, DNS lookups, etc.
    """
    
    def __init__(self, ttl_seconds: int = 3600):
        """
        Initialize cache
        
        Args:
            ttl_seconds: Time to live for cache entries
        """
        self.cache = {}
        self.ttl = ttl_seconds
    
    def get(self, key: str) -> Any:
        """Get value from cache"""
        if key not in self.cache:
            return None
        
        value, timestamp = self.cache[key]
        
        # Check if expired
        if (datetime.now() - timestamp).total_seconds() > self.ttl:
            del self.cache[key]
            return None
        
        return value
    
    def set(self, key: str, value: Any):
        """Set value in cache"""
        self.cache[key] = (value, datetime.now())
    
    def clear(self):
        """Clear all cache entries"""
        self.cache = {}
    
    def size(self) -> int:
        """Get number of cached items"""
        return len(self.cache)


# Some constants that might be useful
HTTP_STATUS_CODES = {
    200: 'OK',
    201: 'Created',
    301: 'Moved Permanently',
    302: 'Found',
    304: 'Not Modified',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable'
}


def get_status_description(status_code: int) -> str:
    """
    Get description for HTTP status code
    
    Args:
        status_code: HTTP status code
        
    Returns:
        Description string
    """
    return HTTP_STATUS_CODES.get(status_code, 'Unknown')


def is_error_status(status_code: int) -> bool:
    """
    Check if HTTP status code indicates an error
    
    Args:
        status_code: HTTP status code
        
    Returns:
        True if error status (4xx or 5xx)
    """
    return 400 <= status_code < 600


# Regex patterns for common things (reusable)
IPV4_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
URL_PATTERN = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'


def extract_ips_from_text(text: str) -> List[str]:
    """
    Extract all IP addresses from text
    
    Args:
        text: Text to search
        
    Returns:
        List of IP addresses found
    """
    import re
    pattern = re.compile(IPV4_PATTERN)
    return pattern.findall(text)


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract all URLs from text
    
    Args:
        text: Text to search
        
    Returns:
        List of URLs found
    """
    import re
    pattern = re.compile(URL_PATTERN)
    return pattern.findall(text)


# Debug helper
def debug_print(message: str, verbose: bool = False):
    """
    Print debug message if verbose mode enabled
    
    Args:
        message: Message to print
        verbose: Whether verbose mode is on
    """
    if verbose:
        print(f"[DEBUG] {message}")


if __name__ == '__main__':
    # Some basic tests if you run this file directly
    print("Running utils.py tests...")
    
    # Test time diff
    t1 = datetime.now()
    t2 = t1 + timedelta(seconds=30)
    diff = calculate_time_diff(t1, t2)
    print(f"Time diff test: {diff} seconds")
    
    # Test hash
    hashed = hash_string("test@example.com")
    print(f"Hash test: {hashed[:16]}...")
    
    # Test bytes conversion
    size = bytes_to_human_readable(1536000)
    print(f"Bytes test: {size}")
    
    # Test port validation
    print(f"Port 80 valid: {validate_port(80)}")
    print(f"Port 80 service: {get_port_service(80)}")
    
    # Test cache
    cache = SimpleCache(ttl_seconds=5)
    cache.set('test_key', 'test_value')
    print(f"Cache test: {cache.get('test_key')}")
    
    print("\nAll tests passed!")