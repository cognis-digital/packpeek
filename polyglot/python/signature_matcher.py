"""
polyglot/python/signature_matcher.py

A complete, self-contained signature matcher for packpeek's static analysis toolchain.
Handles UPX/ASPack/Themida/MPRESS/VMProtect + entropy detection.
Emits YARA rules and SARIF reports. JSON output, CI-ready.
"""

from __future__ import annotations

import json
import math
import re
import struct
import sys
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, BinaryIO, Callable, Generator, Optional, TextIO, Tuple


# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

DEFAULT_ENTROPY_THRESHOLD = 7.5
DEFAULT_MIN_FILE_SIZE = 4096
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
DEFAULT_SAMPLE_SIZE = 8192


class MatchType(Enum):
    """Types of matches found."""
    EXACT = auto()
    HEX_PATTERN = auto()
    MAGIC_BYTE = auto()
    ENTROPY_HIGH = auto()
    FUZZY = auto()
    UNKNOWN = auto()


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass(frozen=True)
class HexPattern:
    """A hex pattern with optional wildcards."""
    raw: str
    regex: str = field(default=None, repr=False)
    
    def __post_init__(self):
        if self.regex is None:
            # Convert "UPX000142" to regex "[0-9a-f]{6}" with optional wildcards
            parts = []
            i = 0
            while i < len(self.raw):
                if self.raw[i] == '?':
                    parts.append('[0-9a-fA-F]{1}')
                    i += 1
                elif self.raw[i:i+2].lower() == '??':
                    parts.append('[0-9a-fA-F]{2}')
                    i += 2
                else:
                    hex_val = self.raw[i:i+2]
                    if len(hex_val) < 2:
                        break
                    # Convert to regex byte range
                    lo = int(hex_val, 16) & 0xFF
                    hi = ((lo + 15) & 0xFF) | 0x0F  # Allow up to 15 bytes off
                    parts.append(f'[0-9a-fA-F]{{2}}')
                    i += 2
            
            self.regex = ''.join(parts)


@dataclass
class Match:
    """A single match result."""
    pattern: HexPattern
    offset: int
    length: int
    data: bytes
    match_type: MatchType = MatchType.EXACT
    confidence: float = 1.0
    
    def to_dict(self) -> dict[str, Any]:
        return {
            'pattern': self.pattern.raw,
            'offset': self.offset,
            'length': self.length,
            'data_hex': self.data.hex(),
            'match_type': self.match_type.name,
            'confidence': round(self.confidence, 3)
        }


@dataclass
class FileResult:
    """Results for a single file."""
    path: str
    size: int
    entropy: float = 0.0
    matches: list[Match] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            'path': self.path,
            'size': self.size,
            'entropy': round(self.entropy, 4),
            'matches': [m.to_dict() for m in self.matches],
            'metadata': self.metadata
        }


@dataclass
class AnalysisResult:
    """Complete analysis result."""
    files: list[FileResult] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default=None, repr=False)
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
    
    def to_dict(self) -> dict[str, Any]:
        return {
            'files': [f.to_dict() for f in self.files],
            'summary': self.summary,
            'timestamp': self.timestamp
        }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    
    # Count byte frequencies
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    return entropy


def read_file_safe(path_or_stream: str | BinaryIO, 
                   max_size: int = DEFAULT_MAX_FILE_SIZE) -> Generator[bytes, None, None]:
    """Read file in chunks, yielding data up to max_size."""
    if isinstance(path_or_stream, (str, Path)):
        path = Path(path_or_stream)
        if not path.exists():
            return
        
        size = path.stat().st_size
        if size > max_size:
            # Truncate large files for analysis
            with open(path, 'rb') as f:
                data = f.read(max_size)
                yield data
                return
        
        with open(path, 'rb') as f:
            data = f.read()
            yield data
    else:
        # Already a stream - read all into memory
        data = path_or_stream.read()
        if len(data) > max_size:
            data = data[:max_size]
        yield data


def get_magic_bytes(data: bytes, offset: int = 0, length: int = 4) -> Optional[bytes]:
    """Extract magic bytes from a specific offset."""
    if len(data) < offset + length:
        return None
    return data[offset:offset + length]


# =============================================================================
# SIGNATURE DATABASE
# =============================================================================

class SignatureDatabase:
    """In-memory database of known packer signatures."""
    
    # Common PE magic bytes (little-endian)
    PE_MAGIC = b'MZ'  # 0x4D5A
    
    # Known packer/protector signatures
    PACKER_SIGNATURES = {
        'UPX': {
            'magic': b'UPX!',
            'offsets': [0, 64],
            'description': 'Ultimate Packer for eXecutables',
            'entropy_threshold': 7.8
        },
        'ASPack': {
            'magic': b'\x52\x45\x4C\x4F',  # "RELO"
            'offsets': [0, 64],
            'description': 'ASPack PE Packer'
        },
        'Themida': {
            'magic': b'TH',
            'offsets': [0, 128],
            'description': 'Themida Protection System'
        },
        'VMProtect': {
            'magic': b'\x56\x4D',  # "VM"
            'offsets': [0, 64],
            'description': 'VMProtect Virtual Machine'
        },
        'MPRESS': {
            'magic': b'MP',
            'offsets': [0, 128],
            'description': 'MPress Packer'
        }
    }
    
    # Hex patterns for common signatures (with wildcards)
    HEX_PATTERNS = [
        # UPX variants
        HexPattern('UPX?', description='UPX with optional version'),
        HexPattern('?P?X?!', description='UPX magic with wildcards'),
        
        # ASPack variants  
        HexPattern('RELO', description='ASPack standard'),
        HexPattern('??4501', description='ASPack variant 1'),
        HexPattern('??4502', description='ASPack variant 2'),
        
        # Themida variants
        HexPattern('TH?', description='Themida with optional char'),
        HexPattern('?H?M?D?A?', description='Themida scrambled'),
    ]
    
    def __init__(self):
        self._compiled_patterns: list[re.Pattern] = []
        self._load_compiled()
    
    def _load_compiled(self) -> None:
        """Compile all hex patterns into regex objects."""
        for pattern in self.HEX_PATTERNS:
            if not hasattr(pattern, 'regex'):
                pattern.regex = re.compile(pattern.raw.encode()).pattern
            try:
                self._compiled_patterns.append(re.compile(pattern.regex))
            except re.error as e:
                print(f"Warning: Failed to compile pattern {pattern.raw}: {e}")
    
    def search(self, data: bytes) -> list[Match]:
        """Search for all known signatures in the given data."""
        matches = []
        
        # 1. Check magic bytes at common offsets
        for name, info in self.PACKER_SIGNATURES.items():
            for offset in info['offsets']:
                if len(data) > offset:
                    magic = get_magic_bytes(data, offset, 4)
                    if magic and magic.lower() == info['magic'].lower():
                        matches.append(Match(
                            pattern=HexPattern(info['description']),
                            offset=offset,
                            length=len(magic),
                            data=magic,
                            match_type=MatchType.MAGIC_BYTE,
                            confidence=1.0
                        ))
        
        # 2. Search hex patterns
        for compiled in self._compiled_patterns:
            for m in compiled.finditer(data):
                matches.append(Match(
                    pattern=self.HEX_PATTERNS[
                        self._compiled_patterns.index(compiled)
                    ],
                    offset=m.start(),
                    length=len(m.group()),
                    data=m.group().encode() if isinstance(m, re.Match) else m.group(),
                    match_type=MatchType.HEX_PATTERN,
                    confidence=0.95
                ))
        
        # 3. Check entropy (high entropy often indicates packing)
        if len(data) >= DEFAULT_MIN_FILE_SIZE:
            ent = calculate_entropy(data[:DEFAULT_SAMPLE_SIZE])
            for name, info in self.PACKER_SIGNATURES.items():
                if ent > info.get('entropy_threshold', DEFAULT_ENTROPY_THRESHOLD):
                    # Avoid duplicate entropy matches
                    existing = [m for m in matches 
                               if m.match_type == MatchType.ENTROPY_HIGH]
                    if not existing:
                        matches.append(Match(
                            pattern=HexPattern(f'High Entropy ({ent:.2f})'),
                            offset=0,
                            length=len(data),
                            data=data[:DEFAULT_SAMPLE_SIZE],
                            match_type=MatchType.ENTROPY_HIGH,
                            confidence=min(ent / 8.0, 1.0)
                        ))
        
        # Deduplicate matches (same pattern + offset within tolerance)
        seen = set()
        unique_matches = []
        for m in matches:
            key = (m.pattern.raw.lower(), m.offset, len(m.data))
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)
        
        return unique_matches


# =============================================================================
# YARA RULE GENERATOR
# =============================================================================

class YaraRuleGenerator:
    """Generate YARA rules from matched signatures."""
    
    def __init__(self, prefix: str = 'packpeek'):
        self.prefix = prefix
    
    def generate(self, result: AnalysisResult) -> str:
        """Generate a complete YARA rule file content."""
        lines = [
            f'// Auto-generated by packpeek signature matcher',
            f'// Generated: {time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())}',
            '',
            f'rule {self.prefix}_PackerDetection {{',
            '  meta:',
            '    description = "Auto-detected packer signatures"',
            '    author = "packpeek toolchain"',
            '',
        ]
        
        # Group matches by type
        entropy_matches = [m for m in result.files[0].matches 
                          if m.match_type == MatchType.ENTROPY_HIGH]
        
        if entropy_matches:
            lines.extend([
                '  strings:',
                f'    $high_entropy = {DEFAULT_ENTROPY_THRESHOLD} bits;',
                '',
            ])
        
        # Add known packer rules
        for name, info in self.PACKER_SIGNATURES.items():
            lines.append(f'  // {info["description"]}')
            lines.append(f'  strings:')
            lines.append(f'    $upx = "{info["magic"].hex()}" {{')
            lines.append(f'      context: 100;')
            lines.append(f'      width: {len(info["magic"])};')
            lines.append(f'    }}')
            lines.append('')
        
        # Add hex pattern rules
        for i, (pattern, desc) in enumerate(zip(
            self.HEX_PATTERNS, 
            [p.description for p in self.HEX_PATTERNS]
        )):
            if hasattr(pattern, 'regex'):
                lines.append(f'  // {desc}')
                lines.append(f'  strings:')
                lines.append(f'    $pattern_{i} = /{pattern.regex}/ {{')
                lines.append(f'      context: 256;')
                lines.append(f'      width: 100;')
                lines.append(f'    }}')
                lines.append('')
        
        # Add entropy rule
        if entropy_matches:
            max_ent = max(m.confidence for m in entropy_matches)
            lines.extend([
                '  // High entropy detection',
                f'  condition:',
                f'    $high_entropy and',
                f'    (filesize > {DEFAULT_MIN_FILE_SIZE} and filesize < {DEFAULT_MAX_FILE_SIZE}) and',
                f'    (entropy >= {max_ent:.2f})',
            ])
        
        lines.append('}')
        return '\n'.join(lines)


# =============================================================================
# SARIF REPORT BUILDER
# =============================================================================

class SarifReportBuilder:
    """Build SARIF 2.1.0 compliant reports."""
    
    def __init__(self, tool_name: str = 'packpeek-signature-matcher'):
        self.tool_name = tool_name
    
    def build(self, result: AnalysisResult) -> dict[str, Any]:
        """Build a complete SARIF report."""
        # Calculate summary statistics
        total_files = len(result.files)
        total_matches = sum(len(f.matches) for f in result.files)
        high_entropy_files = [f for f in result.files if f.entropy > DEFAULT_ENTROPY_THRESHOLD]
        
        # Build runs array
        runs = [{
            'tool': {
                'driver': {
                    'name': self.tool_name,
                    'version': '1.0.0',
                    'informationUri': 'https://github.com/packpeek/signature-matcher',
                    'rules': [],
                },
            },
            'results': []
        }]
        
        # Build results for each file with matches
        for file_result in result.files:
            if not file_result.matches:
                continue
            
            locations = []
            for match in file_result.matches:
                locations.append({
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': file_result.path,
                        },
                        'region': {
                            'startLine': 1,  # Simplified - could calculate from offset
                            'startColumn': 1,
                            'snippet': match.data.hex()[:64],
                        }
                    }
                })
            
            runs[0]['results'].append({
                'ruleId': f'{self.tool_name}:{file_result.path}',
                'level': 'note' if len(file_result.matches) < 3 else 'error',
                'message': {
                    'text': f"Found {len(file_result.matches)} signature match(es)",
                    'arguments': [f"{match.match_type.name}" for match in file_result.matches]
                },
                'locations': locations,
            })
        
        # Build rules metadata
        rule_ids = set()
        for result_item in runs[0]['results']:
            if result_item['ruleId'] not in rule_ids:
                rule_ids.add(result_item['ruleId'])
                level_map = {
                    'EXACT': 'error',
                    'HEX_PATTERN': 'note',
                    'MAGIC_BYTE': 'info',
                    'ENTROPY_HIGH': 'warning',
                    'FUZZY': 'note',
                }
                runs[0]['tool']['driver