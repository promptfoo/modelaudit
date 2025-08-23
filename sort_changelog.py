#!/usr/bin/env python3
"""
Changelog Organizer Script

Sorts entries within each changelog section for better organization:
- Added: Sort by type priority (feat > docs > test > ci), then by PR number descending
- Changed: Sort by type priority (perf > chore > refactor > style), then by PR number descending  
- Fixed: Sort by PR number descending
- Security: Sort by PR number descending
- Removed: Sort by PR number descending
"""

import re
from typing import List, Tuple, Dict, Optional
from pathlib import Path


class ChangelogEntry:
    def __init__(self, line: str):
        self.original_line = line.strip()
        self.type = self._extract_type()
        self.pr_number = self._extract_pr_number()
        
    def _extract_type(self) -> str:
        """Extract conventional commit type from entry."""
        match = re.search(r'\*\*(\w+)\*\*:', self.original_line)
        return match.group(1) if match else ""
    
    def _extract_pr_number(self) -> int:
        """Extract PR number from entry."""
        # Look for (#123) or (abc1234) patterns
        match = re.search(r'\(#(\d+)\)', self.original_line)
        if match:
            return int(match.group(1))
        
        # Look for commit hash pattern (7 chars)
        match = re.search(r'\(([0-9a-f]{7})\)', self.original_line)
        if match:
            # For commit hashes, use 0 as PR number to sort last
            return 0
            
        return 0
    
    def __str__(self) -> str:
        return self.original_line


class ChangelogSorter:
    def __init__(self, changelog_path: str):
        self.changelog_path = Path(changelog_path)
        
        # Define type priority for each section
        self.type_priorities = {
            'Added': {'feat': 1, 'docs': 2, 'test': 3, 'ci': 4},
            'Changed': {'perf': 1, 'chore': 2, 'refactor': 3, 'style': 4},
            'Fixed': {},  # Just sort by PR number
            'Security': {},  # Just sort by PR number
            'Removed': {}  # Just sort by PR number
        }
    
    def parse_changelog(self) -> List[str]:
        """Parse changelog into lines."""
        with open(self.changelog_path, 'r', encoding='utf-8') as f:
            return f.readlines()
    
    def find_sections(self, lines: List[str]) -> Dict[str, Tuple[int, int]]:
        """Find the start and end line numbers for each section."""
        sections = {}
        current_version = None
        current_section = None
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Version headers
            if re.match(r'^## \[', line):
                # End previous section if exists
                if current_section and current_section in sections:
                    sections[current_section][1] = i
                current_version = line
                current_section = None
                continue
            
            # Section headers
            if re.match(r'^### (Added|Changed|Fixed|Security|Removed)', line):
                # End previous section if exists
                if current_section and current_section in sections:
                    sections[current_section][1] = i
                    
                section_name = re.match(r'^### (\w+)', line).group(1)
                current_section = f"{current_version}_{section_name}" if current_version else section_name
                sections[current_section] = [i, None]
                continue
        
        # Handle last section
        if current_section and current_section in sections:
            sections[current_section][1] = len(lines)
                
        return sections
    
    def sort_section_entries(self, entries: List[str], section_type: str) -> List[str]:
        """Sort entries within a section."""
        if not entries:
            return entries
        
        # Separate entry lines from empty lines and other content
        entry_lines = []
        other_lines = []
        
        for line in entries:
            stripped = line.strip()
            if stripped.startswith('- **') and '**:' in stripped:
                entry_lines.append(ChangelogEntry(stripped))
            else:
                other_lines.append(line)
        
        # Sort entries
        if section_type in self.type_priorities:
            priorities = self.type_priorities[section_type]
            
            def sort_key(entry: ChangelogEntry):
                # Primary sort: type priority (lower number = higher priority)
                type_priority = priorities.get(entry.type, 999)
                # Secondary sort: PR number descending (higher number first)
                return (type_priority, -entry.pr_number)
            
            entry_lines.sort(key=sort_key)
        else:
            # For unknown sections, just sort by PR number descending
            entry_lines.sort(key=lambda x: -x.pr_number)
        
        # Reconstruct section with sorted entries
        result = []
        
        # Add sorted entries
        for entry in entry_lines:
            result.append(f"- {entry.original_line[2:]}\n")  # Remove original "- " and add back with newline
        
        # Add other lines (empty lines, etc.)
        result.extend(other_lines)
        
        return result
    
    def process_changelog(self) -> str:
        """Process the entire changelog and return sorted version."""
        lines = self.parse_changelog()
        sections = self.find_sections(lines)
        
        # Create a copy of lines to modify
        result_lines = lines.copy()
        
        # Process each section (in reverse order to maintain line indices)
        for section_key in reversed(sorted(sections.keys())):
            start_idx, end_idx = sections[section_key]
            section_type = section_key.split('_')[-1]  # Extract section type (Added, Changed, etc.)
            
            # Extract section content (excluding the header)
            section_content = result_lines[start_idx + 1:end_idx]
            
            # Sort the section
            sorted_content = self.sort_section_entries(section_content, section_type)
            
            # Replace in result
            result_lines[start_idx + 1:end_idx] = sorted_content
        
        return ''.join(result_lines)
    
    def write_sorted_changelog(self, output_path: Optional[str] = None) -> str:
        """Write sorted changelog to file."""
        if output_path is None:
            output_path = self.changelog_path
        
        sorted_content = self.process_changelog()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(sorted_content)
        
        return sorted_content


def main():
    """Main function to run the changelog sorter."""
    import sys
    
    changelog_path = sys.argv[1] if len(sys.argv) > 1 else 'CHANGELOG.md'
    
    sorter = ChangelogSorter(changelog_path)
    
    print(f"Sorting changelog: {changelog_path}")
    
    try:
        sorted_content = sorter.write_sorted_changelog()
        print("✅ Changelog sorted successfully!")
        
        # Show some statistics
        lines = sorted_content.split('\n')
        entry_count = len([line for line in lines if line.strip().startswith('- **')])
        version_count = len([line for line in lines if line.strip().startswith('## [')])
        
        print(f"📊 Statistics:")
        print(f"   - {version_count} versions processed")
        print(f"   - {entry_count} changelog entries sorted")
        
    except Exception as e:
        print(f"❌ Error sorting changelog: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()